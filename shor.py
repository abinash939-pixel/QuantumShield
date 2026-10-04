import math
import random
from fractions import Fraction

import numpy as np
import pandas as pd
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator

N = 15
N_COUNT = 6
VALID_A = [2, 4, 7, 8, 11, 13]
sim = AerSimulator()


def controlled_mult(a, power):
    """Controlled 'multiply by a, repeated power times, modulo 15' on 4 qubits.
    For N = 15 this multiplication is just a rotation of the 4 bits (plus a bit flip)."""
    u = QuantumCircuit(4)
    for _ in range(power % 4):  # every a here repeats after at most 4 steps
        if a in (2, 13):
            u.swap(2, 3)
            u.swap(1, 2)
            u.swap(0, 1)
        if a in (7, 8):
            u.swap(0, 1)
            u.swap(1, 2)
            u.swap(2, 3)
        if a in (4, 11):
            u.swap(1, 3)
            u.swap(0, 2)
        if a in (7, 11, 13):
            for q in range(4):
                u.x(q)
    gate = u.to_gate()
    gate.name = f"{a}^{power} mod 15"
    return gate.control()


def inverse_qft(qc, qubits):
    n = len(qubits)
    for i in range(n // 2):
        qc.swap(qubits[i], qubits[n - 1 - i])
    for j in range(n):
        for m in range(j):
            qc.cp(-np.pi / float(2 ** (j - m)), qubits[m], qubits[j])
        qc.h(qubits[j])


def build_circuit(a):
    qc = QuantumCircuit(4 + N_COUNT, N_COUNT)
    for q in range(N_COUNT):
        qc.h(q)
    qc.x(3 + N_COUNT)  # target register starts as a nonzero number
    for q in range(N_COUNT):
        if (2 ** q) % 4 != 0:
            qc.append(controlled_mult(a, 2 ** q), [q] + [i + N_COUNT for i in range(4)])
    inverse_qft(qc, list(range(N_COUNT)))
    qc.measure(range(N_COUNT), range(N_COUNT))
    return qc


def run_circuit(a, shots):
    qc = transpile(build_circuit(a), sim)
    return sim.run(qc, shots=shots).result().get_counts()


def phase_histogram(a=7, shots=1024):
    counts = run_circuit(a, shots)
    data = {}
    for bits, c in counts.items():
        phase = int(bits, 2) / 2 ** N_COUNT
        data[f"{phase:.2f}"] = data.get(f"{phase:.2f}", 0) + c / shots
    df = pd.DataFrame({"Probability": data}).sort_index()
    df.index.name = "Measured phase"
    return df


def post_process(a, value):
    """Turn one measurement into a guess for the factors of 15.
    Returns (phase, r, message, factors or None)."""
    phase = value / 2 ** N_COUNT
    r = Fraction(phase).limit_denominator(N).denominator
    if pow(a, r, N) != 1:
        return phase, r, "Bad period guess, try again", None
    if r % 2 != 0:
        return phase, r, "Odd period, try again", None
    x = pow(a, r // 2, N)
    if x == N - 1:
        return phase, r, "Trivial result, try again", None
    p, q = math.gcd(x - 1, N), math.gcd(x + 1, N)
    if p in (1, N) or q in (1, N):
        return phase, r, "No useful factor, try again", None
    return phase, r, f"Success: {min(p, q)} x {max(p, q)}", (min(p, q), max(p, q))


def factor_with_shor(max_attempts=12):
    """Run Shor's algorithm for N = 15 until it finds the factors."""
    attempts = []
    for k in range(1, max_attempts + 1):
        a = random.choice(VALID_A)
        counts = run_circuit(a, 1)
        value = int(next(iter(counts)), 2)
        phase, r, message, factors = post_process(a, value)
        attempts.append({
            "Attempt": k,
            "Random a": a,
            "Measured phase": round(phase, 4),
            "Guessed period r": r,
            "Result": message,
        })
        if factors:
            return attempts, factors
    return attempts, None


def make_toy_rsa():
    p, q = 3, 5
    e = 3
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return {"N": N, "e": e, "d": d, "p": p, "q": q, "phi": phi}