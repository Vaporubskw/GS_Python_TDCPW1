
import socket
import json
import threading

clientes = []
bloqueio = threading.Lock()


def enviar_para_clientes(alerta):
    mensagem = json.dumps(alerta, ensure_ascii=False) + "\n"

    with bloqueio:
        for cliente in clientes.copy():
            try:
                cliente.sendall(mensagem.encode("utf-8"))
            except OSError:
                clientes.remove(cliente)
                cliente.close()


def atender_conexao(conexao, endereco):
    try:
        arquivo = conexao.makefile("r", encoding="utf-8")

        tipo = arquivo.readline().strip()

        if tipo == "CLIENTE":
            with bloqueio:
                clientes.append(conexao)

            print(f"Cliente conectado: {endereco}")

            while arquivo.readline():
                pass

        elif tipo == "PUBLICADOR":
            print(f"Sistema de alertas conectado: {endereco}")

            for linha in arquivo:
                try:
                    alerta = json.loads(linha)
                    enviar_para_clientes(alerta)
                except json.JSONDecodeError:
                    print("Mensagem inválida recebida.")

    except OSError as erro:
        print("Erro na conexão:", erro)

    finally:
        with bloqueio:
            if conexao in clientes:
                clientes.remove(conexao)

        conexao.close()


def iniciar_servidor(host="0.0.0.0", porta=5000):
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind((host, porta))
    servidor.listen()

    print(f"Servidor iniciado na porta {porta}...")
    print("Aguardando conexões...\n")

    while True:
        conexao, endereco = servidor.accept()

        thread = threading.Thread(
            target=atender_conexao,
            args=(conexao, endereco),
            daemon=True
        )

        thread.start()


def enviar_alerta(alerta, host="127.0.0.1", porta=5000):
    with socket.create_connection((host, porta)) as conexao:
        conexao.sendall(b"PUBLICADOR\n")

        mensagem = json.dumps(alerta, ensure_ascii=False) + "\n"
        conexao.sendall(mensagem.encode("utf-8"))
