# QuantumShield

**Find the weak spots. Break the old lock. Lock the channel. Watch the traffic.**

Quantum computers will one day break the encryption that banks and websites use today (RSA and elliptic-curve
cryptography). Attackers can also record encrypted traffic now and decrypt it later ("harvest now, decrypt later").
QuantumShield is a small Streamlit app, built with Qiskit, that shows this whole story and what can be done about it.

## What it does

| Tab | What you can do |
|---|---|
| Overview | The story, what breaks and what survives a quantum computer, and the demo order. |
| Scan | Check a website's certificate and whether its server picks a post-quantum key exchange (ML-KEM). Bulk scan, 0-100 readiness score, downloadable report, and a "is your data already at risk?" calculator. |
| Attack demo | Shor's algorithm factors the toy RSA number 15 on a quantum circuit and reads a secret message. |
| Protect | BB84 quantum key exchange with noise and an eavesdropper (with and without Eve), ML-KEM key exchange, ML-DSA signatures, encrypt a file, a live encrypted chat (Bob, Alice, Eve), and a Grover/Shor key-strength calculator. |
| Detect | A quantum-kernel fraud detector vs a classical model on synthetic data, with a try-it-yourself box. |
| Summary | One-page summary of the demo results. |

## Run it

```
## Run it yourself

You need Python 3.10 or newer.

**Option A: with git**
```
git clone https://github.com/abinash939-pixel/QuantumShield.git
cd QuantumShield
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

**Option B: without git**
1. On the repo page click **Code**, then **Download ZIP**, and unzip it.
2. Open a terminal inside the folder that contains `app.py`. The ZIP may unzip into a folder inside a folder, so go into the inner one with `cd QuantumShield-main`.
3. Run `python -m pip install -r requirements.txt` (the first time takes a few minutes).
4. Run `python -m streamlit run app.py`.

```

Then open http://localhost:8501. The Scan tab needs internet; it also has a built-in saved snapshot for offline use.

## Honest limits

- Everything quantum runs on the Qiskit **Aer simulator**. We did not run on real quantum hardware.
- Shor's algorithm is shown on a toy key (N = 15). Breaking real RSA-2048 needs far more error-corrected qubits than exist today.
- BB84 is a simulation. Real quantum key distribution needs special optical hardware.
- The quantum fraud detector does **not** beat the classical model. We test a quantum method and do not claim quantum advantage. The data is synthetic.
- ML-KEM and ML-DSA use the teaching libraries `kyber-py` and `dilithium-py`. They are not audited or production-grade.
- In the Scan tab, "No" means "post-quantum key exchange not observed in our probe", not proof that a site is unprotected.
- The readiness score is our own simple rubric, not a standard.

## Main files

`app.py` (the web app), `bb84.py`, `shor.py`, `scanner.py`, `pqprobe.py`, `risk.py`, `grover.py`, `detect.py`,
`mlkem_demo.py`, `mldsa_demo.py`, `mlkem_file.py`, `mlkem_chat.py`, `explain.py`, `summary.py`.
`QuantumShield_Summary_and_Judge_QA.pdf` has a plain-English summary, a glossary and likely questions with answers.
