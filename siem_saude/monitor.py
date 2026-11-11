"""Protótipo acadêmico: auditoria de acessos a prontuários fictícios."""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path


# BLOCO 1: formato esperado. Adaptar ao log de auditoria da aplicação real.
PADRAO_LOG = re.compile(
    r"(?P<horario>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})) "
    r"usuario=(?P<usuario>[A-Za-z0-9_.-]{1,64}) "
    r"ip=(?P<ip>[0-9a-fA-F:.]+) "
    r"acao=(?P<acao>[A-Z_]+) "
    r"prontuario=(?P<prontuario>[A-Za-z0-9_-]{1,64}) "
    r"resultado=(?P<resultado>SUCESSO|NEGADO)"
)


@dataclass(frozen=True)
class Acesso:
    horario: datetime
    usuario: str
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    acao: str
    prontuario: str
    resultado: str


def interpretar_linha(linha: str) -> Acesso:
    """re extrai campos; datetime e ipaddress validam os valores extraídos."""
    correspondencia = PADRAO_LOG.fullmatch(linha.rstrip("\r\n"))
    if correspondencia is None:
        raise ValueError("formato inesperado")
    dados = correspondencia.groupdict()
    horario = datetime.fromisoformat(dados["horario"].replace("Z", "+00:00"))
    ip = ipaddress.ip_address(dados["ip"])
    # ::ffff:10.20.0.1 representa um IPv4; aplicar a mesma faixa autorizada.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return Acesso(
        horario.astimezone(timezone.utc), dados["usuario"], ip,
        dados["acao"], dados["prontuario"], dados["resultado"],
    )


@dataclass
class HistoricoUsuario:
    # Cada prontuário ocupa uma entrada, mesmo após várias consultas.
    ultimas_consultas: dict[str, datetime] = field(default_factory=dict)
    ultimo_horario: datetime | None = None
    acima_do_limite: bool = False


# BLOCO 2: regras independentes do monitoramento de arquivos.
class Analisador:
    def __init__(self, redes: list[str], limite: int = 50, minutos: int = 60):
        if not redes or limite < 1 or minutos < 1:
            raise ValueError("informe redes e limites positivos")
        self.redes = [ipaddress.ip_network(rede, strict=True) for rede in redes]
        self.limite = limite
        self.janela = timedelta(minutes=minutos)
        self.usuarios: dict[str, HistoricoUsuario] = {}

    def analisar(self, acesso: Acesso) -> list[dict]:
        # As regras tratam visualizações efetivamente realizadas.
        if acesso.acao != "VISUALIZAR" or acesso.resultado != "SUCESSO":
            return []

        alertas = []
        contexto = {
            "horario": acesso.horario.isoformat(),
            "usuario": acesso.usuario,
            "ip": str(acesso.ip),
        }

        # IP privado não significa IP autorizado: consultar a lista CIDR.
        interno = any(acesso.ip in rede for rede in self.redes)
        if not interno:
            alertas.append({
                **contexto, "tipo": "IP_FORA_DA_REDE",
                "mensagem": "Visualização realizada fora das faixas autorizadas.",
            })

        historico = self.usuarios.setdefault(acesso.usuario, HistoricoUsuario())
        # Premissa explícita deste protótipo: ordem cronológica por usuário.
        if historico.ultimo_horario is not None and acesso.horario < historico.ultimo_horario:
            alertas.append({
                **contexto, "tipo": "HORARIO_FORA_DE_ORDEM",
                "mensagem": "Registro não contado na regra de volume; revisar coleta e relógios.",
            })
            return alertas

        # Janela móvel (t - 60 min, t]: exatamente 60 min já fica de fora.
        corte = acesso.horario - self.janela
        historico.ultimas_consultas = {
            prontuario: horario
            for prontuario, horario in historico.ultimas_consultas.items()
            if horario > corte
        }
        if len(historico.ultimas_consultas) <= self.limite:
            historico.acima_do_limite = False

        historico.ultimas_consultas[acesso.prontuario] = acesso.horario
        historico.ultimo_horario = acesso.horario
        quantidade = len(historico.ultimas_consultas)
        # Um alerta na ultrapassagem; evita um novo alerta a cada leitura
        # enquanto a contagem permanecer acima do limite.
        if quantidade > self.limite and not historico.acima_do_limite:
            historico.acima_do_limite = True
            alertas.append({
                **contexto, "tipo": "VOLUME_PRONTUARIOS",
                "quantidade_distintos": quantidade,
                "janela_minutos": int(self.janela.total_seconds() / 60),
                "mensagem": "Limite de prontuários distintos ultrapassado na janela móvel.",
            })
        return alertas


# BLOCO 3: leitura incremental, sem reler o arquivo inteiro a cada alteração.
class LeitorIncremental:
    def __init__(self, caminho: Path, desde_inicio: bool = False):
        self.caminho = caminho
        self.arquivo = caminho.open("rb")
        self.pendente = b""
        self.descartar = False
        if not desde_inicio:
            # Se já existia uma linha incompleta, ignorar também sua continuação.
            tamanho = self.arquivo.seek(0, os.SEEK_END)
            if tamanho:
                self.arquivo.seek(-1, os.SEEK_END)
                self.descartar = self.arquivo.read(1) != b"\n"

    def _drenar(self, processar):
        while trecho := self.arquivo.read(65536):
            partes = (self.pendente + trecho).split(b"\n")
            self.pendente = partes.pop()
            for linha in partes:
                if self.descartar:
                    self.descartar = False
                elif len(linha) <= 8192:
                    processar(linha.rstrip(b"\r"))
                else:
                    logging.warning("Linha maior que 8192 bytes descartada.")
            if len(self.pendente) > 8192:
                self.pendente = b""
                self.descartar = True
                logging.warning("Linha parcial maior que 8192 bytes descartada.")

    def ler_novas(self, processar):
        try:
            atual = self.caminho.stat()
        except FileNotFoundError:
            # Em uma rotação por renomeação, ainda pode haver bytes no arquivo antigo.
            self._drenar(processar)
            return
        aberto = os.fstat(self.arquivo.fileno())
        if (atual.st_dev, atual.st_ino) != (aberto.st_dev, aberto.st_ino):
            self._drenar(processar)
            self.arquivo.close()
            self.arquivo = self.caminho.open("rb")
            self.pendente = b""
            self.descartar = False
        elif atual.st_size < self.arquivo.tell():
            # Truncamento observado: recomeçar no início do mesmo arquivo.
            self.arquivo.seek(0)
            self.pendente = b""
            self.descartar = False
        self._drenar(processar)

    def fechar(self):
        self.arquivo.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arquivo", type=Path, default=Path("logs/acessos.log"))
    parser.add_argument("--alertas", type=Path, default=Path("saida/alertas.jsonl"))
    parser.add_argument("--rede", action="append", required=True,
                        help="CIDR autorizado; repetir para incluir outras redes")
    parser.add_argument("--limite", type=int, default=50)
    parser.add_argument("--janela-minutos", type=int, default=60)
    parser.add_argument("--desde-inicio", action="store_true",
                        help="reprocessar também as linhas existentes")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        analisador = Analisador(args.rede, args.limite, args.janela_minutos)
    except ValueError as erro:
        parser.error(str(erro))
    if args.arquivo.resolve() == args.alertas.resolve():
        parser.error("log de entrada e arquivo de alertas precisam ser diferentes")

    # Importação local permite testar as regras usando apenas a biblioteca padrão.
    try:
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer
    except ImportError:
        parser.exit(2, "Instale a dependência: python -m pip install -r requirements.txt\n")

    args.arquivo.parent.mkdir(parents=True, exist_ok=True)
    args.arquivo.touch(exist_ok=True)
    args.alertas.parent.mkdir(parents=True, exist_ok=True)
    caminho = args.arquivo.resolve()
    sinal = threading.Event()

    # BLOCO 4: watchdog avisa que há alterações; a thread principal faz a leitura.
    class AvisoAlteracao(FileSystemEventHandler):
        def on_any_event(self, evento):
            if evento.is_directory:
                return
            if evento.event_type not in {"modified", "created", "moved", "deleted", "closed"}:
                return
            origens = [evento.src_path, getattr(evento, "dest_path", "")]
            if any(origem and Path(origem).resolve() == caminho for origem in origens):
                sinal.set()

    # BLOCO 5: alertas no terminal e em JSONL, sem nome ou conteúdo clínico.
    with args.alertas.open("a", encoding="utf-8") as saida:
        def processar(linha: bytes):
            try:
                acesso = interpretar_linha(linha.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                logging.warning("Registro inválido descartado; revisar o formato da fonte.")
                return
            for alerta in analisador.analisar(acesso):
                texto = json.dumps(alerta, ensure_ascii=False)
                saida.write(texto + "\n")
                saida.flush()
                print(texto, flush=True)

        leitor = LeitorIncremental(caminho, args.desde_inicio)
        observador = Observer()
        observador.schedule(AvisoAlteracao(), str(caminho.parent), recursive=False)
        observador.start()
        logging.info("Monitorando %s. Encerrar: Ctrl+C.", caminho)
        try:
            while True:
                leitor.ler_novas(processar)
                # Verificação periódica complementa os avisos de watchdog.
                sinal.wait(timeout=1.0)
                sinal.clear()
        except KeyboardInterrupt:
            logging.info("Monitor encerrado.")
        finally:
            observador.stop()
            observador.join()
            leitor.fechar()


if __name__ == "__main__":
    main()
