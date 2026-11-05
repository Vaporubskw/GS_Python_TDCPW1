
import json
import hashlib
import hmac
from pathlib import Path

import joblib


PASTA_PROJETO = Path(__file__).resolve().parent.parent
CAMINHO_MODELO = PASTA_PROJETO / "modelo.pkl"
CAMINHO_HASH = PASTA_PROJETO / "modelo.sha256"
CAMINHO_REGRAS = PASTA_PROJETO / "config" / "regras.json"


def carregar_regras():
    with open(CAMINHO_REGRAS, "r", encoding="utf-8") as arquivo:
        return json.load(arquivo)


def calcular_hash(caminho):
    sha256 = hashlib.sha256()

    with open(caminho, "rb") as arquivo:
        for bloco in iter(lambda: arquivo.read(4096), b""):
            sha256.update(bloco)

    return sha256.hexdigest()


def verificar_integridade():
    if not CAMINHO_MODELO.exists() or not CAMINHO_HASH.exists():
        return False

    hash_atual = calcular_hash(CAMINHO_MODELO)

    with open(CAMINHO_HASH, "r", encoding="utf-8") as arquivo:
        hash_original = arquivo.read().strip()

    return hmac.compare_digest(hash_atual, hash_original)


def extrair_caracteristicas(eventos, ip, ips_blacklist=None):
    tentativas_falhas = 0
    portas = set()
    erros_web = 0

    if ips_blacklist is None:
        regras = carregar_regras()
        ips_blacklist = regras["blacklist"]["ips"]

    for evento in eventos:
        if evento.get("ip") != ip:
            continue

        tipo = evento.get("event_type")
        detalhes = evento.get("details", {})

        if tipo == "login_failed":
            tentativas_falhas += 1

        if evento.get("source") == "firewall":
            porta = detalhes.get("porta")

            if porta is not None:
                portas.add(str(porta))

        if tipo == "http_request":
            try:
                status = int(detalhes.get("status", 0))

                if status >= 400:
                    erros_web += 1

            except (ValueError, TypeError):
                pass

    return [
        tentativas_falhas,
        len(portas),
        int(ip in ips_blacklist),
        erros_web
    ]


def classificar_ip(ip, eventos):
    if not verificar_integridade():
        raise ValueError(
            "Integridade do modelo comprometida ou arquivos ausentes."
        )

    modelo = joblib.load(CAMINHO_MODELO)

    caracteristicas = extrair_caracteristicas(eventos, ip)

    previsao = modelo.predict([caracteristicas])[0]
    probabilidades = modelo.predict_proba([caracteristicas])[0]

    indice_ataque = list(modelo.classes_).index("ATAQUE")
    pontuacao = round(probabilidades[indice_ataque] * 100, 2)

    return {
        "ip": ip,
        "classificacao": previsao,
        "pontuacao_risco": pontuacao,
        "caracteristicas": {
            "tentativas_falhas": caracteristicas[0],
            "portas_distintas": caracteristicas[1],
            "presenca_blacklist": caracteristicas[2],
            "erros_web": caracteristicas[3]
        }
    }


def classificar_todos(eventos):
    ips = set(
        evento.get("ip")
        for evento in eventos
        if evento.get("ip")
    )

    resultados = []

    for ip in sorted(ips):
        resultados.append(classificar_ip(ip, eventos))

    return resultados
