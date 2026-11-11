"""Valida os limites da detecção e a leitura incremental de arquivos."""

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from monitor import Analisador, LeitorIncremental, interpretar_linha


INICIO = datetime(2026, 11, 6, 12, tzinfo=timezone.utc)


def acesso(numero=1, segundos=0, usuario="teste", ip="10.20.0.10", resultado="SUCESSO"):
    horario = (INICIO + timedelta(seconds=segundos)).isoformat()
    return interpretar_linha(
        f"{horario} usuario={usuario} ip={ip} acao=VISUALIZAR "
        f"prontuario=FICTICIO_{numero} resultado={resultado}"
    )


class TestRegras(unittest.TestCase):
    def setUp(self):
        self.analisador = Analisador(["10.20.0.0/24"])

    def test_alerta_somente_no_51_distinto(self):
        for i in range(50):
            self.assertEqual(self.analisador.analisar(acesso(i, i)), [])
        alertas = self.analisador.analisar(acesso(50, 50))
        self.assertEqual([a["tipo"] for a in alertas], ["VOLUME_PRONTUARIOS"])
        self.assertEqual(alertas[0]["quantidade_distintos"], 51)
        self.assertEqual(self.analisador.analisar(acesso(51, 51)), [])

    def test_mesmo_prontuario_nao_aumenta_distintos(self):
        for i in range(100):
            self.assertEqual(self.analisador.analisar(acesso(1, i)), [])

    def test_exatamente_uma_hora_fica_fora(self):
        for i in range(50):
            self.analisador.analisar(acesso(i, 0))
        self.assertEqual(self.analisador.analisar(acesso(50, 3600)), [])

    def test_uma_hora_menos_um_segundo_dispara(self):
        for i in range(50):
            self.analisador.analisar(acesso(i, 0))
        self.assertEqual(self.analisador.analisar(acesso(50, 3599))[0]["tipo"],
                         "VOLUME_PRONTUARIOS")

    def test_janela_move_entre_horas_do_relogio(self):
        for i in range(50):
            self.analisador.analisar(acesso(i, 50 * 60))
        self.assertEqual(self.analisador.analisar(acesso(50, 70 * 60))[0]["tipo"],
                         "VOLUME_PRONTUARIOS")

    def test_consultas_de_usuarios_diferentes_nao_se_somam(self):
        for i in range(50):
            self.analisador.analisar(acesso(i, i, usuario="usuario_a"))
        self.assertEqual(self.analisador.analisar(acesso(100, 51, usuario="usuario_b")), [])

    def test_atualiza_ultima_consulta_do_mesmo_prontuario(self):
        self.analisador.analisar(acesso(1, 0))
        self.analisador.analisar(acesso(1, 3500))
        for i in range(2, 51):
            self.analisador.analisar(acesso(i, 3600))
        self.assertEqual(self.analisador.analisar(acesso(51, 3601))[0]["tipo"],
                         "VOLUME_PRONTUARIOS")

    def test_ip_externo_e_privado_nao_autorizado(self):
        for ip in ["203.0.113.10", "192.168.1.10", "10.20.1.10", "2001:db8::1"]:
            with self.subTest(ip=ip):
                alertas = self.analisador.analisar(acesso(ip=ip))
                self.assertEqual(alertas[0]["tipo"], "IP_FORA_DA_REDE")

    def test_ipv6_e_multiplas_redes(self):
        analisador = Analisador(["10.20.0.0/24", "2001:db8:1::/64"])
        self.assertEqual(analisador.analisar(acesso(ip="2001:db8:1::10")), [])
        self.assertEqual(analisador.analisar(acesso(ip="::ffff:10.20.0.10")), [])

    def test_acesso_negado_nao_entra_nas_regras(self):
        self.assertEqual(self.analisador.analisar(acesso(ip="203.0.113.1", resultado="NEGADO")), [])

    def test_duas_regras_no_mesmo_acesso(self):
        for i in range(50):
            self.analisador.analisar(acesso(i, i))
        tipos = {a["tipo"] for a in self.analisador.analisar(acesso(50, 50, ip="203.0.113.1"))}
        self.assertEqual(tipos, {"IP_FORA_DA_REDE", "VOLUME_PRONTUARIOS"})

    def test_fora_de_ordem_avisa_e_ainda_verifica_ip(self):
        self.analisador.analisar(acesso(1, 10))
        tipos = {a["tipo"] for a in self.analisador.analisar(acesso(2, 5, ip="203.0.113.1"))}
        self.assertEqual(tipos, {"IP_FORA_DA_REDE", "HORARIO_FORA_DE_ORDEM"})

    def test_rearma_alerta_apos_expiracao(self):
        for i in range(51):
            self.analisador.analisar(acesso(i, 0))
        self.assertEqual(self.analisador.analisar(acesso(100, 3600)), [])
        alertas = []
        for i in range(101, 151):
            alertas += self.analisador.analisar(acesso(i, 3601))
        self.assertEqual(len(alertas), 1)

    def test_rejeita_ip_data_e_formato_invalidos(self):
        linha = "2026-11-06T12:00:00Z usuario=teste ip=10.20.0.10 acao=VISUALIZAR prontuario=F1 resultado=SUCESSO"
        for invalida in ["lixo", linha.replace("10.20.0.10", "999.1.1.1"),
                         linha.replace("2026-11-06", "2026-02-30"), linha + " lixo"]:
            with self.subTest(linha=invalida), self.assertRaises(ValueError):
                interpretar_linha(invalida)

    def test_normaliza_fusos(self):
        linha = "2026-11-06T09:00:00-03:00 usuario=teste ip=10.20.0.10 acao=VISUALIZAR prontuario=F1 resultado=SUCESSO"
        self.assertEqual(interpretar_linha(linha).horario, INICIO)


class TestLeitura(unittest.TestCase):
    def setUp(self):
        self.pasta = tempfile.TemporaryDirectory()
        self.addCleanup(self.pasta.cleanup)
        self.caminho = Path(self.pasta.name) / "acessos.log"
        self.caminho.write_bytes(b"")
        self.leitor = LeitorIncremental(self.caminho, desde_inicio=True)
        self.addCleanup(self.leitor.fechar)
        self.lidas = []

    def escrever(self, dados):
        with self.caminho.open("ab") as arquivo:
            arquivo.write(dados)

    def ler(self):
        self.leitor.ler_novas(self.lidas.append)

    def test_nao_duplica_e_aguarda_linha_completa(self):
        self.escrever(b"primeira\npar")
        self.ler()
        self.ler()
        self.assertEqual(self.lidas, [b"primeira"])
        self.escrever(b"cial\r\n")
        self.ler()
        self.assertEqual(self.lidas, [b"primeira", b"parcial"])

    def test_truncamento_observado(self):
        self.escrever(b"linha longa original\n")
        self.ler()
        self.caminho.write_bytes(b"nova\n")
        self.ler()
        self.assertEqual(self.lidas, [b"linha longa original", b"nova"])

    def test_rotacao_por_renomeacao(self):
        self.escrever(b"antiga\n")
        self.caminho.rename(self.caminho.with_suffix(".log.1"))
        self.caminho.write_bytes(b"nova\n")
        self.ler()
        self.assertEqual(self.lidas, [b"antiga", b"nova"])

    def test_inicio_no_final_descarta_continuacao_preexistente(self):
        self.leitor.fechar()
        self.caminho.write_bytes(b"antiga\nparcial")
        self.leitor = LeitorIncremental(self.caminho)
        self.addCleanup(self.leitor.fechar)
        self.escrever(b" terminada\nnova\n")
        self.ler()
        self.assertEqual(self.lidas, [b"nova"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
