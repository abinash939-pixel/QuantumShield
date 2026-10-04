import random
import numpy as np
import pandas as pd
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
from qiskit_aer.noise import NoiseModel, depolarizing_error, ReadoutError

BASIS_NAME = {0: "Z", 1: "X"}
ALARM_LEVEL = 0.11


def make_sim(noise):
    """noise is a probability between 0 and 1 (for example 0.03 = 3%)."""
    if noise <= 0:
        return AerSimulator()
    model = NoiseModel()
    model.add_all_qubit_quantum_error(depolarizing_error(noise, 1), ["h", "x"])
    model.add_all_qubit_readout_error(
        ReadoutError([[1 - noise, noise], [noise, 1 - noise]])
    )
    return AerSimulator(noise_model=model)


def send_and_measure(sim, bit, send_basis, measure_basis):
    """Prepare a qubit, then measure it. Basis 0 = Z, 1 = X."""
    qc = QuantumCircuit(1, 1)
    if bit == 1:
        qc.x(0)
    if send_basis == 1:
        qc.h(0)
    if measure_basis == 1:
        qc.h(0)
    qc.measure(0, 0)
    counts = sim.run(qc, shots=1).result().get_counts()
    return int(list(counts.keys())[0])


def run_bb84_detailed(n=200, eve=False, noise=0.0):
    """Returns alice_key, bob_key, error_rate, per-qubit table, error-rate chart data."""
    sim = make_sim(noise)

    alice_bits = [random.randint(0, 1) for _ in range(n)]
    alice_bases = [random.randint(0, 1) for _ in range(n)]
    bob_bases = [random.randint(0, 1) for _ in range(n)]
    eve_bases = [random.randint(0, 1) for _ in range(n)]

    rows = []
    bob_bits = []
    for i in range(n):
        eve_bit = None
        if eve:
            # Eve measures Alice's qubit, then resends what she saw
            eve_bit = send_and_measure(sim, alice_bits[i], alice_bases[i], eve_bases[i])
            bob_bit = send_and_measure(sim, eve_bit, eve_bases[i], bob_bases[i])
        else:
            bob_bit = send_and_measure(sim, alice_bits[i], alice_bases[i], bob_bases[i])
        bob_bits.append(bob_bit)

        if alice_bases[i] != bob_bases[i]:
            outcome = "Discarded (bases differ)"
        elif alice_bits[i] == bob_bit:
            outcome = "Kept, bits match"
        else:
            outcome = "Kept, ERROR"

        rows.append({
            "Qubit": i + 1,
            "Alice bit": alice_bits[i],
            "Alice basis": BASIS_NAME[alice_bases[i]],
            "Eve basis": BASIS_NAME[eve_bases[i]] if eve else "-",
            "Eve saw": str(eve_bit) if eve else "-",
            "Bob basis": BASIS_NAME[bob_bases[i]],
            "Bob bit": bob_bit,
            "Outcome": outcome,
        })

    table = pd.DataFrame(rows)

    # Keep only the positions where Alice and Bob used the same basis
    keep = [i for i in range(n) if alice_bases[i] == bob_bases[i]]
    alice_key = [alice_bits[i] for i in keep]
    bob_key = [bob_bits[i] for i in keep]

    flags = np.array([a != b for a, b in zip(alice_key, bob_key)], dtype=float)
    error_rate = float(flags.sum() / len(flags)) if len(flags) else 0.0

    if len(flags):
        running = np.cumsum(flags) / np.arange(1, len(flags) + 1) * 100
        chart = pd.DataFrame(
            {
                "Error rate so far (%)": running,
                "Alarm level (%)": ALARM_LEVEL * 100,
            },
            index=[i + 1 for i in keep],
        )
        chart.index.name = "Qubits sent"
    else:
        chart = pd.DataFrame()

    return alice_key, bob_key, error_rate, table, chart


def run_bb84_compare(n=400, noise=0.0):
    """Run BB84 twice on the SAME random choices: once with no eavesdropper and once with Eve.
    Because everything else is identical, the only difference between the two runs is Eve."""
    sim = make_sim(noise)

    alice_bits = [random.randint(0, 1) for _ in range(n)]
    alice_bases = [random.randint(0, 1) for _ in range(n)]
    bob_bases = [random.randint(0, 1) for _ in range(n)]
    eve_bases = [random.randint(0, 1) for _ in range(n)]

    bob_clean, bob_eve, eve_bits = [], [], []
    for i in range(n):
        # Without Eve: Alice's qubit goes straight to Bob.
        bob_clean.append(send_and_measure(sim, alice_bits[i], alice_bases[i], bob_bases[i]))
        # With Eve: she measures first, then resends what she saw.
        seen = send_and_measure(sim, alice_bits[i], alice_bases[i], eve_bases[i])
        eve_bits.append(seen)
        bob_eve.append(send_and_measure(sim, seen, eve_bases[i], bob_bases[i]))

    keep = [i for i in range(n) if alice_bases[i] == bob_bases[i]]
    if not keep:
        return None

    clean_flags = np.array([alice_bits[i] != bob_clean[i] for i in keep], dtype=float)
    eve_flags = np.array([alice_bits[i] != bob_eve[i] for i in keep], dtype=float)
    steps = np.arange(1, len(keep) + 1)
    chart = pd.DataFrame(
        {
            "Without Eve (%)": np.cumsum(clean_flags) / steps * 100,
            "With Eve (%)": np.cumsum(eve_flags) / steps * 100,
            "Alarm level (%)": ALARM_LEVEL * 100,
        },
        index=[i + 1 for i in keep],
    )
    chart.index.name = "Qubits sent"

    return {
        "n": n,
        "kept": len(keep),
        "err_clean": float(clean_flags.mean()),
        "err_eve": float(eve_flags.mean()),
        "chart": chart,
        # Eve picked the same basis as Alice: she learned that bit for certain.
        "eve_certain": float(np.mean([eve_bases[i] == alice_bases[i] for i in keep])),
        # Eve's copy of the key (right-basis bits plus lucky guesses) vs Alice's real key.
        "eve_match": float(np.mean([eve_bits[i] == alice_bits[i] for i in keep])),
    }


def run_bb84(n=200, eve=False, noise=0.0):
    a_key, b_key, err, _, _ = run_bb84_detailed(n=n, eve=eve, noise=noise)
    return a_key, b_key, err


if __name__ == "__main__":
    for eve in (False, True):
        a_key, b_key, err = run_bb84(n=200, eve=eve)
        print(f"Eve listening: {eve}")
        print(f"  Key length: {len(a_key)}")
        print(f"  Error rate: {err:.1%}")
        print("  Verdict:", "INTRUDER DETECTED" if err > ALARM_LEVEL else "Channel is safe")