
import mysql.connector

from db.mysql_repo import (
    conectar_mysql,
    cadastrar_usuario,
    autenticar_usuario
)

conexao = conectar_mysql()
cursor = conexao.cursor()

email = "teste_seguranca@securapy.com"

# Limpar somente o usuário fictício deste teste
cursor.execute(
    "DELETE FROM usuarios WHERE email = %s",
    (email,)
)
conexao.commit()

# 1. Cadastrar usuário
cadastrar_usuario(
    conexao,
    "Teste Segurança",
    email,
    "Senha123",
    3
)

print("1. Cadastro realizado com sucesso!")

# 2. Testar e-mail duplicado
try:
    cadastrar_usuario(
        conexao,
        "Outro Usuário",
        email,
        "Senha456",
        2
    )
except mysql.connector.IntegrityError:
    print("2. E-mail duplicado bloqueado com sucesso!")

# 3. Testar senha incorreta
usuario = autenticar_usuario(
    conexao,
    email,
    "SenhaErrada"
)

if usuario is None:
    print("3. Senha incorreta rejeitada com sucesso!")

# 4. Testar SQL Injection
usuario = autenticar_usuario(
    conexao,
    "' OR '1'='1",
    "qualquer"
)

if usuario is None:
    print("4. SQL Injection bloqueado com sucesso!")

cursor.close()
conexao.close()
