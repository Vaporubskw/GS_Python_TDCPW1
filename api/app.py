
import os
import secrets
import hmac
from functools import wraps

from flask import session, redirect, url_for

from db.mysql_repo import (
    conectar_mysql,
    criar_tabela_usuarios,
    autenticar_usuario
)
from core.enriquecimento import enriquecer_eventos
from ia.assistente import analisar_alerta
from pathlib import Path
import ipaddress

from flask import Flask, jsonify, request, render_template
from bson import ObjectId

from db.mongo_repo import (
    conectar_mongodb,
    salvar_eventos,
    salvar_alertas
)

from core.coletor import coletar_todos
from core.detector import detectar_ataques
from api.auth import token_obrigatorio
from ml.classificar import classificar_ip


PASTA_TEMPLATES = (
    Path(__file__).resolve().parent.parent / "web" / "templates"
)

app = Flask(
    __name__,
    template_folder=str(PASTA_TEMPLATES)
)

app.json.ensure_ascii = False

# Configuração de sessão
app.secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    "chave-local-apenas-para-desenvolvimento"
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(
        os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
    )
)


# Proteção contra CSRF
def obter_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)

    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = obter_csrf_token


def validar_csrf():
    token_sessao = session.get("csrf_token", "")
    token_formulario = request.form.get("csrf_token", "")

    return (
        bool(token_sessao)
        and bool(token_formulario)
        and hmac.compare_digest(token_sessao, token_formulario)
    )


# Protege páginas que exigem login
def login_obrigatorio(funcao):
    @wraps(funcao)
    def verificar_login(*args, **kwargs):
        if "usuario_id" not in session:
            return redirect(url_for("login"))

        return funcao(*args, **kwargs)

    return verificar_login


# Registro de acessos
@app.before_request
def registrar_acesso():
    app.logger.info(
        "Acesso: metodo=%s rota=%s ip=%s usuario=%s",
        request.method,
        request.path,
        request.remote_addr,
        session.get("usuario_email", "anonimo")
    )


# Cabeçalhos de segurança
@app.after_request
def adicionar_cabecalhos_seguranca(resposta):
    resposta.headers["X-Content-Type-Options"] = "nosniff"
    resposta.headers["X-Frame-Options"] = "DENY"
    resposta.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resposta.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "object-src 'none'"
    )
    resposta.headers["Cache-Control"] = "no-store"

    return resposta


# Login de operadores pelo MySQL
@app.route("/login", methods=["GET", "POST"])
def login():

    if "usuario_id" in session:
        return redirect(url_for("dashboard"))

    erro = None

    if request.method == "POST":

        if not validar_csrf():
            return "Solicitação inválida. Atualize a página.", 400

        email = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")

        if not email or not senha:
            erro = "Preencha o e-mail e a senha."

        else:
            conexao = None

            try:
                conexao = conectar_mysql()
                criar_tabela_usuarios(conexao)

                usuario = autenticar_usuario(
                    conexao,
                    email,
                    senha
                )

                if usuario:
                    session.clear()

                    session["csrf_token"] = secrets.token_urlsafe(32)
                    session["usuario_id"] = usuario["id"]
                    session["usuario_nome"] = usuario["nome"]
                    session["usuario_email"] = usuario["email"]
                    session["nivel_acesso"] = usuario["nivel_acesso"]

                    app.logger.info(
                        "Login realizado com sucesso: %s",
                        email
                    )

                    return redirect(url_for("dashboard"))

                app.logger.warning(
                    "Tentativa de login recusada: %s",
                    email
                )

                erro = "E-mail ou senha incorretos."

            except Exception:
                app.logger.exception("Erro durante a autenticação.")
                erro = "Não foi possível realizar o login."

            finally:
                if conexao is not None:
                    conexao.close()

    return render_template("login.html", erro=erro)


# Logout do operador
@app.route("/logout", methods=["POST"])
def logout():

    if not validar_csrf():
        return "Solicitação inválida. Atualize a página.", 400

    email = session.get("usuario_email", "desconhecido")

    app.logger.info("Logout realizado: %s", email)

    session.clear()

    return redirect(url_for("login"))

def preparar_documento(documento):
    documento["_id"] = str(documento["_id"])
    return documento


@app.route("/api/status", methods=["GET"])
def status():
    return jsonify({
        "sistema": "SecuraPy",
        "status": "online"
    }), 200


@app.route("/api/eventos", methods=["GET"])
def listar_eventos():
    cliente = None

    try:
        cliente, banco = conectar_mongodb()

        filtro = {}

        ip = request.args.get("ip")
        if ip:
            filtro["ip"] = ip

        fonte = request.args.get("fonte")
        if fonte:
            filtro["source"] = fonte

        pagina = max(request.args.get("pagina", 1, type=int), 1)
        limite = min(max(request.args.get("limite", 10, type=int), 1), 100)

        total = banco["eventos"].count_documents(filtro)

        eventos = banco["eventos"].find(filtro).sort(
            "timestamp", -1
        ).skip(
            (pagina - 1) * limite
        ).limit(limite)

        resultado = [
            preparar_documento(evento) for evento in eventos
        ]

        return jsonify({
            "total": total,
            "pagina": pagina,
            "eventos": resultado
        }), 200

    except Exception:
        app.logger.exception("Erro ao consultar eventos.")
        return jsonify({
            "erro": "Não foi possível consultar os eventos."
        }), 500

    finally:
        if cliente is not None:
            cliente.close()


@app.route("/api/alertas", methods=["POST"])
@token_obrigatorio
def cadastrar_alerta():
    cliente = None

    try:
        dados = request.get_json(silent=True)

        if not isinstance(dados, dict):
            return jsonify({
                "erro": "Envie um objeto JSON válido."
            }), 400

        campos_obrigatorios = [
            "ip",
            "tipo",
            "severidade",
            "descricao"
        ]

        for campo in campos_obrigatorios:
            if not isinstance(dados.get(campo), str) or not dados[campo].strip():
                return jsonify({
                    "erro": f"O campo {campo} é obrigatório e deve ser um texto."
                }), 400

        try:
            ipaddress.ip_address(dados["ip"].strip())
        except ValueError:
            return jsonify({
                "erro": "Endereço IP inválido."
            }), 400

        severidade = dados["severidade"].strip().upper()

        severidades_permitidas = [
            "BAIXA",
            "MEDIA",
            "ALTA",
            "CRITICA"
        ]

        if severidade not in severidades_permitidas:
            return jsonify({
                "erro": "Severidade inválida."
            }), 400

        dados["ip"] = dados["ip"].strip()
        dados["tipo"] = dados["tipo"].strip()
        dados["severidade"] = severidade
        dados["descricao"] = dados["descricao"].strip()

        cliente, banco = conectar_mongodb()

        resultado = banco["alertas"].insert_one(dados)

        return jsonify({
            "mensagem": "Alerta cadastrado com sucesso!",
            "id": str(resultado.inserted_id)
        }), 201

    except Exception:
        app.logger.exception("Erro ao cadastrar alerta.")
        return jsonify({
            "erro": "Não foi possível cadastrar o alerta."
        }), 500

    finally:
        if cliente is not None:
            cliente.close()


@app.route("/api/alertas/<id>", methods=["GET"])
def consultar_alerta(id):
    cliente = None

    try:
        if not ObjectId.is_valid(id):
            return jsonify({
                "erro": "Identificador de alerta inválido."
            }), 400

        cliente, banco = conectar_mongodb()

        alerta = banco["alertas"].find_one({
            "_id": ObjectId(id)
        })

        if alerta is None:
            return jsonify({
                "erro": "Alerta não encontrado."
            }), 404

        return jsonify(preparar_documento(alerta)), 200

    except Exception:
        app.logger.exception("Erro ao consultar alerta.")
        return jsonify({
            "erro": "Não foi possível consultar o alerta."
        }), 500

    finally:
        if cliente is not None:
            cliente.close()


@app.route("/api/alertas", methods=["GET"])
def listar_alertas():
    cliente = None

    try:
        cliente, banco = conectar_mongodb()

        alertas = banco["alertas"].find()

        resultado = [
            preparar_documento(alerta) for alerta in alertas
        ]

        return jsonify({
            "total": len(resultado),
            "alertas": resultado
        }), 200

    except Exception:
        app.logger.exception("Erro ao listar alertas.")
        return jsonify({
            "erro": "Não foi possível consultar os alertas."
        }), 500

    finally:
        if cliente is not None:
            cliente.close()


@app.route("/api/ip/<ip>", methods=["GET"])
def consultar_ip(ip):
    cliente = None

    try:
        ipaddress.ip_address(ip)

        cliente, banco = conectar_mongodb()

        eventos = banco["eventos"].find({"ip": ip})
        alertas = banco["alertas"].find({"ip": ip})

        resultado_eventos = [
            preparar_documento(evento) for evento in eventos
        ]

        resultado_alertas = [
            preparar_documento(alerta) for alerta in alertas
        ]

        resultado_ml = (
            classificar_ip(ip, resultado_eventos)
            if resultado_eventos else None
        )

        return jsonify({
            "ip": ip,
            "total_eventos": len(resultado_eventos),
            "total_alertas": len(resultado_alertas),
            "eventos": resultado_eventos,
            "alertas": resultado_alertas,
            "machine_learning": resultado_ml
        }), 200

    except ValueError:
        return jsonify({
            "erro": "Endereço IP inválido."
        }), 400

    except Exception:
        app.logger.exception("Erro ao consultar IP.")
        return jsonify({
            "erro": "Não foi possível consultar o IP."
        }), 500

    finally:
        if cliente is not None:
            cliente.close()


@app.route("/api/analisar", methods=["POST"])
@token_obrigatorio
def analisar():
    cliente = None

    try:
        dados = request.get_json(silent=True) or {}

        if not isinstance(dados, dict):
            return jsonify({
                "erro": "Envie um objeto JSON válido."
            }), 400

        if "eventos" in dados:
            if not isinstance(dados["eventos"], list):
                return jsonify({
                    "erro": "O campo eventos deve ser uma lista."
                }), 400

            eventos = dados["eventos"]

        else:
            eventos = coletar_todos()

        eventos = enriquecer_eventos(eventos)

        alertas = detectar_ataques(eventos)

        cliente, banco = conectar_mongodb()

        total_eventos = salvar_eventos(banco, eventos)
        total_alertas = salvar_alertas(banco, alertas)

        return jsonify({
            "mensagem": "Análise concluída com sucesso!",
            "eventos_analisados": total_eventos,
            "alertas_identificados": total_alertas
        }), 200

    except Exception:
        app.logger.exception("Erro ao realizar análise.")
        return jsonify({
            "erro": "Não foi possível realizar a análise."
        }), 500

    finally:
        if cliente is not None:
            cliente.close()


@app.route("/dashboard", methods=["GET"])
@login_obrigatorio
def dashboard():
    cliente = None

    try:
        cliente, banco = conectar_mongodb()

        total_eventos = banco["eventos"].count_documents({})
        total_alertas = banco["alertas"].count_documents({})
        total_ips = len(banco["eventos"].distinct("ip"))

        alertas_criticos = banco["alertas"].count_documents({
            "severidade": {"$in": ["CRITICA", "CRÍTICA"]}
        })

        alertas_por_severidade = list(
            banco["alertas"].aggregate([
                {
                    "$group": {
                        "_id": "$severidade",
                        "total": {"$sum": 1}
                    }
                },
                {"$sort": {"total": -1}}
            ])
        )

        top_ips = list(
            banco["alertas"].aggregate([
                {
                    "$group": {
                        "_id": "$ip",
                        "total": {"$sum": 1}
                    }
                },
                {"$sort": {"total": -1}},
                {"$limit": 10}
            ])
        )

        eventos_por_fonte = list(
            banco["eventos"].aggregate([
                {
                    "$group": {
                        "_id": "$source",
                        "total": {"$sum": 1}
                    }
                },
                {"$sort": {"total": -1}}
            ])
        )

        ip_consultado = request.args.get("ip", "").strip()
        eventos_ip = []
        alertas_ip = []
        resultado_ml = None
        erro_pesquisa = None

        if ip_consultado:
            try:
                ipaddress.ip_address(ip_consultado)

                eventos_ip = [
                    preparar_documento(evento)
                    for evento in banco["eventos"].find(
                        {"ip": ip_consultado}
                    ).sort("timestamp", -1)
                ]

                alertas_ip = [
                    preparar_documento(alerta)
                    for alerta in banco["alertas"].find(
                        {"ip": ip_consultado}
                    )
                ]

                if eventos_ip:
                    resultado_ml = classificar_ip(
                        ip_consultado,
                        eventos_ip
                    )

                else:
                    erro_pesquisa = "Nenhum evento encontrado para este IP."

            except ValueError:
                erro_pesquisa = "Digite um endereço IP válido."

        return render_template(
            "dashboard.html",
            total_eventos=total_eventos,
            total_alertas=total_alertas,
            total_ips=total_ips,
            alertas_criticos=alertas_criticos,
            alertas_por_severidade=alertas_por_severidade,
            top_ips=top_ips,
            eventos_por_fonte=eventos_por_fonte,
            ip_consultado=ip_consultado,
            eventos_ip=eventos_ip,
            alertas_ip=alertas_ip,
            resultado_ml=resultado_ml,
            erro_pesquisa=erro_pesquisa
        )

    except Exception:
        app.logger.exception("Erro ao carregar o dashboard.")
        return "Não foi possível carregar o dashboard. Verifique o servidor.", 500

    finally:
        if cliente is not None:
            cliente.close()

@app.route("/api/assistente", methods=["POST"])
@token_obrigatorio
def assistente():
    dados = request.get_json(silent=True)

    if not isinstance(dados, dict):
        return jsonify({
            "erro": "Envie os dados do alerta em formato JSON."
        }), 400

    resultado = analisar_alerta(dados)

    return jsonify(resultado), 200

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False    )
