
from db.mysql_repo import (
    conectar_mysql,
    criar_tabela_usuarios,
    cadastrar_usuario,
    autenticar_usuario,
    listar_usuarios
)

try:
    conexao = conectar_mysql()

    criar_tabela_usuarios(conexao)

    # Cadastrar usuário de teste
    identificador = cadastrar_usuario(
        conexao,
        "Usuario Teste",
        "teste@securapy.com",
        "SenhaTeste123",
        3
    )

    print("Usuário cadastrado com sucesso!")
    print("ID:", identificador)

    # Testar autenticação
    usuario = autenticar_usuario(
        conexao,
        "teste@securapy.com",
        "SenhaTeste123"
    )

    if usuario:
        print("Autenticação realizada com sucesso!")
        print("Nível de acesso:", usuario["nivel_acesso"])

    # Consultar usuários
    usuarios = listar_usuarios(conexao)
    print("Total de usuários cadastrados:", len(usuarios))

    conexao.close()

except Exception as erro:
    print("Erro durante o teste:", erro)
