import ipaddress

from core.regras import carregar_regras


def enriquecer_evento(evento):
    """Adiciona informações de risco ao evento."""
    evento = evento.copy()

    ip = evento.get("ip")

    if not ip:
        evento["risco"] = "DESCONHECIDO"
        return evento

    try:
        endereco = ipaddress.ip_address(ip)
    except ValueError:
        evento["risco"] = "IP_INVALIDO"
        return evento

    regras = carregar_regras()
    blacklist = regras.get("blacklist", {}).get("ips", [])

    if ip in blacklist:
        risco = "CRITICO"
    elif endereco.is_private:
        risco = "BAIXO"
    else:
        risco = "MODERADO"

    evento["risco"] = risco
    evento["ip_privado"] = endereco.is_private
    evento["ip_valido"] = True

    return evento


def enriquecer_eventos(eventos):
    """Enriquece uma lista de eventos."""
    return [
        enriquecer_evento(evento)
        for evento in eventos
    ]