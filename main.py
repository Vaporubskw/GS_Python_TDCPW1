
from core.coletor import coletar_todos
from core.detector import detectar_ataques
from alertas.servidor_alertas import enviar_alerta
from db.mongo_repo import (
    conectar_mongodb,
    criar_indices,
    salvar_eventos,
    salvar_alertas
)

# 1. Coletar os eventos
eventos = coletar_todos()

# 2. Identificar possíveis ataques
alertas = detectar_ataques(eventos)

print("Total de eventos:", len(eventos))
print("Total de alertas:", len(alertas))

print("\n--- ALERTAS IDENTIFICADOS ---")

# 3. Exibir e enviar os alertas pelo TCP
for alerta in alertas:
    print(alerta)

    try:
        enviar_alerta(alerta)
        print("Alerta enviado ao servidor!\n")
    except OSError as erro:
        print("Erro ao enviar alerta:", erro)

# 4. Conectar ao MongoDB e armazenar os dados
try:
    cliente, banco = conectar_mongodb()

    criar_indices(banco)

    total_eventos = salvar_eventos(banco, eventos)
    total_alertas = salvar_alertas(banco, alertas)

    print("\n--- ARMAZENAMENTO NO MONGODB ---")
    print("Eventos salvos:", total_eventos)
    print("Alertas salvos:", total_alertas)

    cliente.close()

except Exception as erro:
    print("Erro ao salvar no MongoDB:", erro)

print("\nAnálise finalizada!")
