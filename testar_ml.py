
from core.coletor import coletar_todos
from ml.classificar import classificar_ip

eventos = coletar_todos()

ips_teste = [
    "185.220.101.1",
    "192.168.1.10"
]

print("\n--- TESTE DO MACHINE LEARNING ---")

for ip in ips_teste:
    resultado = classificar_ip(ip, eventos)

    print("\nIP:", resultado["ip"])
    print("Classificação:", resultado["classificacao"])
    print("Pontuação de risco:", resultado["pontuacao_risco"], "%")
    print("Características:", resultado["caracteristicas"])

