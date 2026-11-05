import json
from pathlib import Path

CAMINHO_REGRAS = (
    Path(__file__).resolve().parent.parent
    / "config"
    / "regras.json"
)


def carregar_regras():
    """Carrega as regras de detecção do arquivo JSON."""
    with open(CAMINHO_REGRAS, "r", encoding="utf-8") as arquivo:
        return json.load(arquivo)


def validar_regras(regras):
    """Verifica se as regras essenciais estão configuradas."""
    obrigatorias = [
        "brute_force",
        "port_scan",
        "blacklist"
    ]

    for regra in obrigatorias:
        if regra not in regras:
            raise ValueError(f"Regra ausente: {regra}")

    return True