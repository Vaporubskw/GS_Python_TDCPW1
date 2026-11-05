
import socket
import json


def iniciar_cliente(host="127.0.0.1", porta=5000):

    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        cliente.connect((host, porta))

        # Informa ao servidor que este é um cliente receptor
        cliente.sendall(b"CLIENTE\n")

        print("Conectado ao servidor de alertas!")
        print("Aguardando alertas...\n")

        buffer = ""

        while True:
            dados = cliente.recv(4096)

            if not dados:
                break

            buffer += dados.decode("utf-8")

            while "\n" in buffer:
                mensagem, buffer = buffer.split("\n", 1)

                if mensagem:
                    alerta = json.loads(mensagem)

                    print("--- NOVO ALERTA ---")
                    print("IP:", alerta.get("ip"))
                    print("Tipo:", alerta.get("tipo"))
                    print("Severidade:", alerta.get("severidade"))
                    print("Descrição:", alerta.get("descricao"))
                    print("-------------------\n")

    except ConnectionRefusedError:
        print("Não foi possível conectar. Verifique se o servidor está ligado.")

    except OSError as erro:
        print("Erro na comunicação:", erro)

    finally:
        cliente.close()


if __name__ == "__main__":
    iniciar_cliente()
