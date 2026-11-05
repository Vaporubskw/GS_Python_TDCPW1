
import os
import hmac
from functools import wraps
from flask import request, jsonify
from dotenv import load_dotenv

load_dotenv()

TOKEN_API = os.getenv("SECURAPY_API_TOKEN")


def token_obrigatorio(funcao):
    @wraps(funcao)
    def verificar_token(*args, **kwargs):

        autorizacao = request.headers.get("Authorization", "")

        if not TOKEN_API:
            return jsonify({
                "erro": "Token da API não configurado."
            }), 500

        if not autorizacao.startswith("Bearer "):
            return jsonify({
                "erro": "Token não informado."
            }), 401

        token = autorizacao.split(" ", 1)[1]

        if not hmac.compare_digest(token, TOKEN_API):
            return jsonify({
                "erro": "Token inválido."
            }), 401

        return funcao(*args, **kwargs)

    return verificar_token
