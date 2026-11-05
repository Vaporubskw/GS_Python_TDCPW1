
import json
from pathlib import Path
from collections import defaultdict


CAMINHO_REGRAS = (
    Path(__file__).resolve().parent.parent
    / "config"
    / "regras.json"
)


def carregar_regras():
    """Carrega as regras de detecção do projeto."""
    with open(CAMINHO_REGRAS, "r", encoding="utf-8") as arquivo:
        return json.load(arquivo)


def detectar_ataques(eventos):
    """
    Analisa eventos e identifica:
    - Brute Force
    - Port Scan
    - IPs presentes na Blacklist
    """

    regras = carregar_regras()
    alertas = []

    falhas_por_ip = defaultdict(int)
    portas_por_ip = defaultdict(set)
    ips_encontrados = set()

    # Verifica se a entrada é uma lista
    if not isinstance(eventos, list):
        raise ValueError("Os eventos devem ser enviados em uma lista.")

    # Analisa os eventos recebidos
    for evento in eventos:

        if not isinstance(evento, dict):
            continue

        ip = evento.get("ip")

        if not ip:
            continue

        ips_encontrados.add(ip)

        event_type = evento.get("event_type", evento.get("tipo", ""))
        source = evento.get("source", evento.get("fonte", ""))
        details = evento.get("details") or {}

        if not isinstance(details, dict):
            details = {}

        # Detecção de tentativas de login malsucedidas
        if event_type == "login_failed":
            falhas_por_ip[ip] += 1

        # Identificação de portas acessadas
        if source == "firewall":
            porta = details.get("porta", details.get("port"))

            if porta is not None:
                portas_por_ip[ip].add(str(porta))

    # DETECÇÃO DE BRUTE FORCE
    limite_falhas = regras["brute_force"]["max_failed_attempts"]

    for ip, quantidade in falhas_por_ip.items():

        if quantidade >= limite_falhas:
            alertas.append({
                "ip": ip,
                "tipo": "BRUTE FORCE",
                "severidade": regras["brute_force"]["severity"],
                "quantidade": quantidade,
                "descricao": (
                    f"{quantidade} tentativas de login malsucedidas."
                )
            })

    # DETECÇÃO DE PORT SCAN
    limite_portas = regras["port_scan"]["min_distinct_ports"]

    for ip, portas in portas_por_ip.items():

        if len(portas) >= limite_portas:
            alertas.append({
                "ip": ip,
                "tipo": "PORT SCAN",
                "severidade": regras["port_scan"]["severity"],
                "quantidade": len(portas),
                "descricao": (
                    f"Acessou {len(portas)} portas diferentes."
                )
            })

    # DETECÇÃO DE BLACKLIST
    blacklist = set(regras["blacklist"]["ips"])

    for ip in ips_encontrados:

        if ip in blacklist:
            alertas.append({
                "ip": ip,
                "tipo": "BLACKLIST",
                "severidade": regras["blacklist"]["severity"],
                "quantidade": 1,
                "descricao": "IP encontrado na lista de bloqueio."
            })

    return alertas
