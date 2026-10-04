"""Builds the one-page demo summary (markdown) from what the user ran in this session.
Plain Python: it only reads the values the app keeps in session state."""
from datetime import datetime

from risk import readiness_score
from scanner import PQ_LABEL

TOY_N = 15
TOY_E = 3


def _yes_no(flag):
    return "Yes" if flag else "No"


def build_demo_summary(state, alarm_level=0.11):
    L = [
        "# QuantumShield: demo summary",
        "",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "",
        "QuantumShield shows the 'harvest now, decrypt later' quantum threat and the fix. "
        "Everything below comes from the runs made in this session. Anything marked "
        "'not run' was not demonstrated. All quantum parts ran on a local simulator "
        "(Qiskit Aer), not on real quantum hardware.",
        "",
    ]

    # ---- 1. Scan
    L += ["## 1. Scan: who is exposed", ""]
    rows = state.get("report_rows")
    if rows:
        reachable = [r for r in rows if r["risk"] != "Unreachable"]
        exposed = [r for r in reachable if r["risk"] in ("High", "Critical")]
        pq = sum(r.get("pq_kex") is True for r in reachable)
        scores = [readiness_score(r) for r in reachable]
        avg = round(sum(scores) / len(scores)) if scores else None
        source = state.get("report_source", "not recorded")
        if source.startswith("Live scan"):
            source = "Live scan run during this session."
        L += [
            f"Source: {source}",
            "",
            f"- Websites checked: {len(rows)} (reachable: {len(reachable)})",
            f"- Certificates using RSA or elliptic-curve keys (quantum-vulnerable): {len(exposed)}",
            f"- Post-quantum key exchange observed: {pq}",
            f"- Average readiness score: {avg if avg is not None else 'n/a'} / 100 "
            "(our own rubric, not a standard)",
            "",
            "| Website | Key type | TLS | PQ key exchange | Score |",
            "|---------|----------|-----|-----------------|-------|",
        ]
        for r in rows:
            sc = readiness_score(r)
            L.append(f"| {r['host']} | {r['algorithm']} | {r['tls_version']} | "
                     f"{PQ_LABEL[r.get('pq_kex')]} | {sc if sc is not None else '-'} |")
        L += ["", "'No' means 'not observed in our probe', not proof that a site is unprotected.", ""]
    else:
        L += ["Not run in this session.", ""]

    # ---- 2. Attack demo
    L += ["## 2. Attack demo: Shor's algorithm on a toy RSA key", ""]
    s = state.get("shor")
    if s:
        L += [f"- Toy public key: N = {TOY_N}, e = {TOY_E}",
              f"- Secret number Alice sent: {s['secret']} (encrypted on the wire as {s['cipher']})",
              f"- Quantum attempts made: {len(s['attempts'])} (some attempts fail by design)"]
        if s["factors"]:
            p, q = s["factors"]
            phi = (p - 1) * (q - 1)
            d = pow(TOY_E, -1, phi)
            recovered = pow(s["cipher"], d, TOY_N)
            L.append(f"- Factors found by the Qiskit Shor circuit: {TOY_N} = {p} x {q}")
            L.append(f"- Private key rebuilt: d = {d}")
            L.append(f"- Number the attacker decrypted: {recovered} "
                     f"({'matches' if recovered == s['secret'] else 'does not match'} the secret)")
        else:
            L.append("- No factors were found in that run.")
        L += ["",
              "This is a toy size. Published resource estimates for breaking RSA-2048 are about "
              "20 million noisy qubits (Gidney and Ekera, 2019) and under 1 million noisy qubits "
              "(Gidney, 2025). They are estimates, not a demonstrated attack.", ""]
    else:
        L += ["Not run in this session.", ""]

    # ---- 3. Protect
    L += ["## 3. Protect", "", "### BB84 quantum key exchange (simulation)", ""]
    res = state.get("result")
    if res:
        a_key, err = res[0], res[2]
        eve_on = state.get("eve_was_on", False)
        if err > alarm_level and eve_on:
            verdict = "Intruder detected. Key discarded."
        elif err > alarm_level:
            verdict = "Error rate too high (noise). Key discarded."
        else:
            verdict = "Channel secure. Key accepted."
        L += [f"- Eavesdropper listening: {_yes_no(eve_on)}",
              f"- Key length kept: {len(a_key)} bits",
              f"- Error rate: {err:.1%} (alarm level {alarm_level:.0%})",
              f"- Result: {verdict}", ""]
    else:
        L += ["Not run in this session.", ""]

    L += ["### ML-KEM key exchange (works on normal computers today)", ""]
    m = state.get("mlkem")
    if m:
        L += [f"- Public key: {m['public_key_len']} bytes; ciphertext: {m['kem_ciphertext_len']} bytes; "
              f"shared secret: {m['secret_len']} bytes",
              f"- Alice and Bob derived the same key: {_yes_no(m['secrets_match'])}",
              f"- Eve could read the message with her own key: {_yes_no(m['eve_read'])}",
              "- Demo library is for teaching, not production use.", ""]
    else:
        L += ["Not run in this session.", ""]

    L += ["### ML-DSA signatures", ""]
    d = state.get("mldsa")
    if d:
        L += [f"- Public key: {len(d['public_key'])} bytes; signature: {len(d['signature'])} bytes"]
        rejected = state.get("dsa_forgery_rejected")
        if rejected is not None:
            L.append(f"- Eve's forged message was rejected: {_yes_no(rejected)}")
        L += ["- Demo library is for teaching, not production use.", ""]
    else:
        L += ["Not run in this session.", ""]

    L += ["### Encrypt a file (ML-KEM + AES-256-GCM)", ""]
    e = state.get("encfile")
    if e:
        L += [f"- File: {e['name']}",
              f"- Original size: {e['size']} bytes; encrypted size: {len(e['package'])} bytes "
              f"(overhead {len(e['package']) - e['size']} bytes)", ""]
    else:
        L += ["Not run in this session.", ""]

    # ---- 4. Detect
    L += ["## 4. Detect: quantum-kernel fraud model vs classical model", ""]
    out = state.get("detect")
    if out:
        df = out["df"]
        wrong = int((df["Actual"] != df["Quantum model says"]).sum())
        L += [f"- Dataset: {state.get('detect_dataset', 'not recorded')} (synthetic, not real bank data)",
              f"- Test transactions: {len(df)}",
              f"- Quantum kernel accuracy: {out['q_acc']:.0%} (test transactions it got wrong: {wrong})",
              f"- Classical model accuracy: {out['c_acc']:.0%}",
              "",
              "We tested a quantum method. We do not claim quantum advantage.", ""]
    else:
        L += ["Not run in this session.", ""]

    # ---- Honesty
    L += [
        "## Honesty and limits",
        "",
        "- Quantum parts ran on a local simulator (Qiskit Aer). Nothing ran on real IBM quantum hardware.",
        "- The Shor demo uses N = 15, a textbook toy.",
        "- BB84 here is a simulation. Real BB84 needs quantum hardware. ML-KEM is the practical option today.",
        "- The scanner reports what it observed. 'No' means 'not observed'.",
        "- The readiness score is our own rubric.",
        "- The fraud data is synthetic.",
    ]
    return "\n".join(L)