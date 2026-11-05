

import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash


def conectar_mysql():
    import os

    conexao = mysql.connector.connect(
        host=os.getenv("MYSQL_HOST", "localhost"),
        port=int(os.getenv("MYSQL_PORT", "3306")),
        user=os.getenv("MYSQL_USER", "securapy_user"),
        password=os.getenv("MYSQL_PASSWORD", "securapy123"),
        database=os.getenv("MYSQL_DATABASE", "securapy")
    )

    return conexao


def criar_tabela_usuarios(conexao):
    cursor = conexao.cursor()

    comando = """
        CREATE TABLE IF NOT EXISTS usuarios (
            id INT AUTO_INCREMENT PRIMARY KEY,
            nome VARCHAR(100) NOT NULL,
            email VARCHAR(150) NOT NULL UNIQUE,
            senha_hash VARCHAR(255) NOT NULL,
            nivel_acesso INT NOT NULL,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            CHECK (nivel_acesso BETWEEN 1 AND 5)
        )
    """

    cursor.execute(comando)
    conexao.commit()
    cursor.close()


def cadastrar_usuario(conexao, nome, email, senha, nivel):
    if nivel < 1 or nivel > 5:
        raise ValueError("O nível de acesso deve estar entre 1 e 5.")

    senha_hash = generate_password_hash(senha)

    cursor = conexao.cursor()

    comando = """
        INSERT INTO usuarios (nome, email, senha_hash, nivel_acesso)
        VALUES (%s, %s, %s, %s)
    """

    cursor.execute(comando, (nome, email, senha_hash, nivel))

    conexao.commit()

    identificador = cursor.lastrowid
    cursor.close()

    return identificador


def autenticar_usuario(conexao, email, senha):
    cursor = conexao.cursor(dictionary=True)

    comando = """
        SELECT * FROM usuarios WHERE email = %s
    """

    cursor.execute(comando, (email,))
    usuario = cursor.fetchone()

    cursor.close()

    if usuario and check_password_hash(usuario["senha_hash"], senha):
        return usuario

    return None


def listar_usuarios(conexao):
    cursor = conexao.cursor(dictionary=True)

    cursor.execute("""
        SELECT id, nome, email, nivel_acesso, criado_em
        FROM usuarios
    """)

    usuarios = cursor.fetchall()
    cursor.close()

    return usuarios


def alterar_nivel_acesso(conexao, identificador, novo_nivel):
    if novo_nivel < 1 or novo_nivel > 5:
        raise ValueError("O nível de acesso deve estar entre 1 e 5.")

    cursor = conexao.cursor()

    comando = """
        UPDATE usuarios
        SET nivel_acesso = %s
        WHERE id = %s
    """

    cursor.execute(comando, (novo_nivel, identificador))

    conexao.commit()

    cursor.close()


if __name__ == "__main__":
    try:
        conexao = conectar_mysql()

        criar_tabela_usuarios(conexao)

        print("Conexão com MySQL realizada com sucesso!")
        print("Tabela de usuários criada ou já existente!")

        conexao.close()

    except mysql.connector.Error as erro:
        print("Erro ao trabalhar com MySQL:", erro)
