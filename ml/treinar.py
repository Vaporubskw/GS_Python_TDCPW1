
import hashlib
from pathlib import Path

import joblib
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


PASTA_PROJETO = Path(__file__).resolve().parent.parent

CAMINHO_MODELO = PASTA_PROJETO / "modelo.pkl"
CAMINHO_HASH = PASTA_PROJETO / "modelo.sha256"


def gerar_base_treinamento():
    aleatorio = np.random.default_rng(42)

    caracteristicas = []
    classificacoes = []

    # Exemplos de comportamentos normais
    for _ in range(250):
        caracteristicas.append([
            aleatorio.integers(0, 6),
            aleatorio.integers(1, 6),
            0,
            aleatorio.integers(0, 5)
        ])
        classificacoes.append("NORMAL")

    # Exemplos de tentativas de força bruta
    for _ in range(70):
        caracteristicas.append([
            aleatorio.integers(10, 26),
            aleatorio.integers(1, 7),
            0,
            aleatorio.integers(0, 5)
        ])
        classificacoes.append("ATAQUE")

    # Exemplos de varredura de portas
    for _ in range(70):
        caracteristicas.append([
            aleatorio.integers(0, 9),
            aleatorio.integers(7, 21),
            0,
            aleatorio.integers(0, 6)
        ])
        classificacoes.append("ATAQUE")

    # Exemplos de IPs presentes na blacklist
    for _ in range(70):
        caracteristicas.append([
            aleatorio.integers(0, 21),
            aleatorio.integers(1, 21),
            1,
            aleatorio.integers(0, 11)
        ])
        classificacoes.append("ATAQUE")

    # Exemplos de erros web suspeitos
    for _ in range(70):
        caracteristicas.append([
            aleatorio.integers(0, 9),
            aleatorio.integers(1, 7),
            0,
            aleatorio.integers(6, 21)
        ])
        classificacoes.append("ATAQUE")

    return np.array(caracteristicas), np.array(classificacoes)


def calcular_hash(caminho):
    sha256 = hashlib.sha256()

    with open(caminho, "rb") as arquivo:
        for bloco in iter(lambda: arquivo.read(4096), b""):
            sha256.update(bloco)

    return sha256.hexdigest()


def treinar_modelo():
    X, y = gerar_base_treinamento()

    modelo = Pipeline([
        ("normalizacao", StandardScaler()),
        ("classificador", RandomForestClassifier(
            n_estimators=150,
            random_state=42
        ))
    ])

    validacao = StratifiedKFold(
        n_splits=5,
        shuffle=True,
        random_state=42
    )

    metricas = cross_validate(
        modelo,
        X,
        y,
        cv=validacao,
        scoring=["precision_macro", "recall_macro", "f1_macro"]
    )

    modelo.fit(X, y)

    joblib.dump(modelo, CAMINHO_MODELO)

    hash_modelo = calcular_hash(CAMINHO_MODELO)

    with open(CAMINHO_HASH, "w", encoding="utf-8") as arquivo:
        arquivo.write(hash_modelo)

    print("\n--- TREINAMENTO DO MODELO ---")
    print("Total de exemplos:", len(X))
    print("Treinamento concluído!")

    print("\n--- MÉTRICAS DE VALIDAÇÃO ---")
    print("Precisão:", round(metricas["test_precision_macro"].mean(), 4))
    print("Recall:", round(metricas["test_recall_macro"].mean(), 4))
    print("F1-score:", round(metricas["test_f1_macro"].mean(), 4))

    print("\n--- ARQUIVOS GERADOS ---")
    print("Modelo:", CAMINHO_MODELO)
    print("Hash SHA-256:", hash_modelo)

    return modelo


if __name__ == "__main__":
    treinar_modelo()
