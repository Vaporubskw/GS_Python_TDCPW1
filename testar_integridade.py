
from ml.classificar import verificar_integridade

print("\n--- VERIFICAÇÃO DE INTEGRIDADE ---")

if verificar_integridade():
    print("Integridade confirmada!")
    print("O modelo não foi alterado.")
else:
    print("ATENÇÃO: integridade comprometida!")
