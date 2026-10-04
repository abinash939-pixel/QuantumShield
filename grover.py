"""Key-strength numbers for the 'How long would a key last?' section.
Pure Python + pandas, no quantum libraries needed."""
import math
import pandas as pd

SECONDS_PER_YEAR = 3.156e7

SYMMETRIC = [("AES-128", 128), ("AES-192", 192), ("AES-256", 256)]

PUBLIC_KEY_TABLE = pd.DataFrame([
    {"Algorithm": "RSA-2048", "Quantum attack": "Shor's algorithm",
     "Result": "Broken in polynomial time once a large error-corrected quantum computer exists",
     "Fix": "ML-KEM (key exchange), ML-DSA (signatures)"},
    {"Algorithm": "RSA-4096", "Quantum attack": "Shor's algorithm",
     "Result": "Same. A bigger key only costs the attacker a few more qubits",
     "Fix": "ML-KEM, ML-DSA"},
    {"Algorithm": "ECC P-256", "Quantum attack": "Shor's algorithm",
     "Result": "Broken the same way (needs fewer qubits than RSA-2048)",
     "Fix": "ML-KEM, ML-DSA"},
])

GROVER_NOTE = (
    "Grover's algorithm only gives a square-root speed-up, so it halves a symmetric key's "
    "strength (AES-128 acts like 64 bits). Each Grover step on AES is slow and the steps "
    "cannot be split across machines easily, so AES-128 is not considered broken in practice, "
    "and AES-256 stays safe. The speeds above are assumptions you can change. "
    "Shor's algorithm is the real danger: it breaks RSA and ECC outright, and bigger keys "
    "do not save them."
)


def log10_years(bits, steps_per_second):
    """log10 of the years needed to do 2**bits steps at the given speed."""
    return bits * math.log10(2) - math.log10(steps_per_second * SECONDS_PER_YEAR)


def fmt_years(log10_y):
    if log10_y < 0:
        return "under 1 year"
    return f"~1e{round(log10_y)} years"


def verdict(effective_bits):
    if effective_bits >= 128:
        return "Strong"
    if effective_bits >= 96:
        return "Acceptable"
    return "Weakened"


def crack_table(classical_rate, quantum_rate):
    rows = []
    for name, bits in SYMMETRIC:
        eff = bits // 2  # Grover: 2**(bits/2) steps
        rows.append({
            "Algorithm": name,
            "Key bits": bits,
            "Strength vs quantum (bits)": eff,
            "Classical brute force": fmt_years(log10_years(bits, classical_rate)),
            "Quantum (Grover)": fmt_years(log10_years(eff, quantum_rate)),
            "Verdict": verdict(eff),
        })
    return pd.DataFrame(rows)