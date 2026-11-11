"""Acrescenta somente dados fictícios ao log para uma demonstração local."""

import argparse
import time
from datetime import datetime, timezone
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arquivo", type=Path, default=Path("logs/acessos.log"))
    parser.add_argument("--intervalo", type=float, default=0.03)
    args = parser.parse_args()
    if args.intervalo < 0:
        parser.error("o intervalo precisa ser não negativo")
    args.arquivo.parent.mkdir(parents=True, exist_ok=True)

    # Identificadores exclusivos se a demonstração for executada novamente.
    lote = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    with args.arquivo.open("a", encoding="utf-8") as arquivo:
        def registrar(usuario, ip, prontuario, resultado="SUCESSO"):
            horario = datetime.now(timezone.utc).isoformat(timespec="microseconds")
            arquivo.write(
                f"{horario} usuario={usuario} ip={ip} acao=VISUALIZAR "
                f"prontuario={prontuario} resultado={resultado}\n"
            )
            arquivo.flush()
            time.sleep(args.intervalo)

        print("1. Dez consultas normais: nenhum alerta esperado.", flush=True)
        for i in range(10):
            registrar(f"normal_{lote}", "10.20.0.10", f"FICTICIO_{i:03}")

        print("2. Sessenta consultas ao mesmo prontuário: nenhum alerta de volume.", flush=True)
        for _ in range(60):
            registrar(f"repetido_{lote}", "10.20.0.11", "FICTICIO_001")

        print("3. Cinquenta e um prontuários distintos: um alerta de volume.", flush=True)
        for i in range(51):
            registrar(f"volume_{lote}", "10.20.0.12", f"FICTICIO_{i:03}")

        print("4. IP fora da rede configurada: um alerta de origem.", flush=True)
        # 203.0.113.0/24 é reservado para exemplos, não representa um atacante real.
        registrar(f"externo_{lote}", "203.0.113.10", "FICTICIO_900")

        print("5. Acesso negado: não é uma visualização realizada.", flush=True)
        registrar(f"negado_{lote}", "203.0.113.11", "FICTICIO_901", "NEGADO")

    print("Fim: 123 registros; dois alertas esperados para este lote.")


if __name__ == "__main__":
    main()
