import os

from pymongo import MongoClient, DESCENDING


def conectar_mongodb():
    uri = os.getenv(
        "MONGO_URI",
        "mongodb://localhost:27017/"
    )

    cliente = MongoClient(uri, serverSelectionTimeoutMS=5000)
    banco = cliente["securapy"]

    return cliente, banco


def criar_indices(banco):
    banco["eventos"].create_index("ip")
    banco["eventos"].create_index("timestamp")
    banco["eventos"].create_index("source")

    banco["alertas"].create_index("ip")
    banco["alertas"].create_index("timestamp")
    banco["alertas"].create_index("severidade")


def salvar_eventos(banco, eventos):
    if eventos:
        resultado = banco["eventos"].insert_many(eventos)
        return len(resultado.inserted_ids)

    return 0


def salvar_alertas(banco, alertas):
    if alertas:
        resultado = banco["alertas"].insert_many(alertas)
        return len(resultado.inserted_ids)

    return 0


def listar_eventos(banco, limite=10):
    return list(
        banco["eventos"]
        .find()
        .sort("timestamp", DESCENDING)
        .limit(limite)
    )


def listar_alertas(banco, limite=10):
    return list(
        banco["alertas"]
        .find()
        .sort("timestamp", DESCENDING)
        .limit(limite)
    )


if __name__ == "__main__":
    cliente = None

    try:
        cliente, banco = conectar_mongodb()
        cliente.admin.command("ping")
        criar_indices(banco)

        print("Conexão com MongoDB realizada com sucesso!")
        print("Coleções e índices preparados.")

    except Exception as erro:
        print("Erro ao trabalhar com MongoDB:", erro)

    finally:
        if cliente is not None:
            cliente.close()