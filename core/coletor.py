
import re
from datetime import datetime


def coletar_auth(caminho):
    eventos = []

    with open(caminho, "r", encoding="utf-8") as arquivo:
        for linha in arquivo:
            linha = linha.strip()

            if not linha:
                continue

            padrao = r"(\w{3}\s+\d+\s+\d+:\d+:\d+).*?(Failed|Accepted) password for (\S+) from ([\d.]+) port (\d+)"
            resultado = re.search(padrao, linha)

            if resultado:
                data, resultado_login, usuario, ip, porta = resultado.groups()

                eventos.append({
                    "timestamp": data,
                    "source": "auth",
                    "ip": ip,
                    "event_type": "login_failed" if resultado_login == "Failed" else "login_success",
                    "details": {
                        "usuario": usuario,
                        "porta": int(porta)
                    },
                    "raw": linha
                })

    return eventos


def coletar_firewall(caminho):
    eventos = []

    with open(caminho, "r", encoding="utf-8") as arquivo:
        for linha in arquivo:
            linha = linha.strip()

            if not linha:
                continue

            padrao = r"(\w{3}\s+\d+\s+\d+:\d+:\d+).*?\[UFW (BLOCK|ALLOW)\].*?SRC=([\d.]+).*?DST=([\d.]+).*?PROTO=(\w+).*?DPT=(\d+)"
            resultado = re.search(padrao, linha)

            if resultado:
                data, acao, origem, destino, protocolo, porta = resultado.groups()

                eventos.append({
                    "timestamp": data,
                    "source": "firewall",
                    "ip": origem,
                    "event_type": "connection_blocked" if acao == "BLOCK" else "connection_allowed",
                    "details": {
                        "destino": destino,
                        "protocolo": protocolo,
                        "porta": int(porta)
                    },
                    "raw": linha
                })

    return eventos


def coletar_web(caminho):
    eventos = []

    with open(caminho, "r", encoding="utf-8") as arquivo:
        for linha in arquivo:
            linha = linha.strip()

            if not linha:
                continue

            padrao = r'^([\d.]+).*?\[([^\]]+)\]\s+"(\w+)\s+(\S+)\s+HTTP/[\d.]+"\s+(\d+)\s+(\d+)'
            resultado = re.search(padrao, linha)

            if resultado:
                ip, data, metodo, rota, status, tamanho = resultado.groups()

                eventos.append({
                    "timestamp": data,
                    "source": "web",
                    "ip": ip,
                    "event_type": "http_request",
                    "details": {
                        "metodo": metodo,
                        "rota": rota,
                        "status": int(status),
                        "tamanho": int(tamanho)
                    },
                    "raw": linha
                })

    return eventos


def coletar_todos():
    eventos = []

    eventos.extend(coletar_auth("logs/auth.log"))
    eventos.extend(coletar_firewall("logs/firewall.log"))
    eventos.extend(coletar_web("logs/web_access.log"))

    return eventos
