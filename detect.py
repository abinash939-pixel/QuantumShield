import numpy as np
import pandas as pd
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
from qiskit.quantum_info import Statevector

sim = AerSimulator(method="statevector")

# Angle-encoding scale: features in [0, 1] become rotation angles in [0, ENCODING_SCALE].
# This is the quantum model's counterpart of the classical RBF width. pi/2 was chosen over
# pi and 2*pi by comparing accuracy on 20 synthetic seeds (our own choice, not a standard).
ENCODING_SCALE = np.pi / 2

def feature_map(x):
    qc = QuantumCircuit(2)
    for _ in range(2):
        qc.h([0, 1])
        qc.rz(2 * x[0], 0)
        qc.rz(2 * x[1], 1)
        qc.cx(0, 1)
        qc.rz(2 * (np.pi - x[0]) * (np.pi - x[1]), 1)
        qc.cx(0, 1)
    return qc

def state(x):
    qc = feature_map(x)
    qc.save_statevector()
    sv = sim.run(qc).result().get_statevector()
    return np.array(sv)

def states(X):
    return np.array([state(x) for x in X])

def quantum_kernel(A, B):
    return np.abs(A.conj() @ B.T) ** 2

def rbf_kernel(A, B, gamma=10.0):
    d = ((A[:, None, :] - B[None, :, :]) ** 2).sum(axis=-1)
    return np.exp(-gamma * d)

def kernel_ridge_predict(K_train, y_train, K_test, lam=0.1):
    t = np.where(y_train == 1, 1.0, -1.0)
    alpha = np.linalg.solve(K_train + lam * np.eye(len(t)), t)
    return (K_test @ alpha > 0).astype(int)

def make_data(seed, n_each=30):
    rng = np.random.default_rng(seed)
    normal = rng.normal([0.3, 0.3], 0.12, size=(n_each, 2))
    fraud = rng.normal([0.7, 0.72], 0.12, size=(n_each, 2))
    X = np.clip(np.vstack([normal, fraud]), 0, 1)
    y = np.array([0] * n_each + [1] * n_each)
    idx = rng.permutation(len(y))
    return X[idx], y[idx]

def make_hard_data(seed, n_each=40):
    """Card-testing story. Normal: everyday purchases and big daytime purchases.
    Fraud: big purchases at risky hours AND tiny test charges at risky hours,
    so no single straight line separates the two classes."""
    rng = np.random.default_rng(seed)
    h = n_each // 2
    blob = lambda c: rng.normal(c, 0.09, size=(h, 2))
    normal = np.vstack([blob([0.30, 0.25]), blob([0.78, 0.22])])
    fraud = np.vstack([blob([0.78, 0.78]), blob([0.10, 0.80])])
    X = np.clip(np.vstack([normal, fraud]), 0, 1)
    y = np.array([0] * len(normal) + [1] * len(fraud))
    idx = rng.permutation(len(y))
    return X[idx], y[idx]


def predict_one(model, amount, time_risk):
    """Verdicts from both trained models for a single new transaction."""
    x = np.array([[amount, time_risk]])
    s_new = states(x * ENCODING_SCALE)
    q = kernel_ridge_predict(quantum_kernel(model["S_tr"], model["S_tr"]), model["y_tr"],
                             quantum_kernel(s_new, model["S_tr"]))
    c = kernel_ridge_predict(rbf_kernel(model["X_tr"], model["X_tr"]), model["y_tr"],
                             rbf_kernel(x, model["X_tr"]))
    names = {0: "Normal", 1: "Fraud"}
    return {"quantum": names[int(q[0])], "classical": names[int(c[0])]}


def run_detection(seed=1, hard=False):
    X, y = make_hard_data(seed) if hard else make_data(seed)
    split = int(len(y) * 0.75) if hard else 40
    X_tr, X_te = X[:split], X[split:]
    y_tr, y_te = y[:split], y[split:]

    S_tr = states(X_tr * ENCODING_SCALE)
    S_te = states(X_te * ENCODING_SCALE)

    q_pred = kernel_ridge_predict(
        quantum_kernel(S_tr, S_tr), y_tr, quantum_kernel(S_te, S_tr)
    )
    c_pred = kernel_ridge_predict(
        rbf_kernel(X_tr, X_tr), y_tr, rbf_kernel(X_te, X_tr)
    )

    names = {0: "Normal", 1: "Fraud"}
    df = pd.DataFrame({
        "Amount": X_te[:, 0],
        "Time risk": X_te[:, 1],
        "Actual": [names[v] for v in y_te],
        "Quantum model says": [names[v] for v in q_pred],
    })
    return {
        "q_acc": float((q_pred == y_te).mean()),
        "c_acc": float((c_pred == y_te).mean()),
        "df": df,
        "model": {"X_tr": X_tr, "y_tr": y_tr, "S_tr": S_tr},
    }


def boundary_grid(model, res=24):
    """Ask both trained models for a verdict at every point of a res x res grid.
    Returns a DataFrame with columns amount, risk, x2, y2 (cell corner), quantum, classical."""
    xs = np.linspace(0, 1, res)
    G = np.array([[a, b] for b in xs for a in xs])
    S = np.array([Statevector(feature_map(g * ENCODING_SCALE)).data for g in G])
    K_tr_q = quantum_kernel(model["S_tr"], model["S_tr"])
    q = kernel_ridge_predict(K_tr_q, model["y_tr"], quantum_kernel(S, model["S_tr"]))
    c = kernel_ridge_predict(rbf_kernel(model["X_tr"], model["X_tr"]), model["y_tr"],
                             rbf_kernel(G, model["X_tr"]))
    names = {0: "Normal", 1: "Fraud"}
    step = 1.0 / (res - 1)
    return pd.DataFrame({
        "amount": G[:, 0], "risk": G[:, 1],
        "x2": G[:, 0] + step, "y2": G[:, 1] + step,
        "quantum": [names[int(v)] for v in q],
        "classical": [names[int(v)] for v in c],
    })