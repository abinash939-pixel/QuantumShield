import altair as alt
import pandas as pd
import streamlit as st

from bb84 import run_bb84_detailed, run_bb84_compare, ALARM_LEVEL
from scanner import scan_site, scan_many, build_report_md, DEFAULT_SITES, PQ_LABEL, fix_plan, save_snapshot, load_snapshot
from detect import run_detection, predict_one, boundary_grid
from risk import readiness_score, harvest_verdict
from grover import crack_table, PUBLIC_KEY_TABLE, GROVER_NOTE
from mlkem_demo import run_mlkem
from mldsa_demo import sign_message, check
from mlkem_file import encrypt_file, decrypt_package, tamper
from mlkem_chat import render_mlkem_chat
import hashlib
from shor import (
    N, VALID_A, factor_with_shor, make_toy_rsa, phase_histogram, build_circuit,
)
from explain import explain_factoring
from summary import build_demo_summary


def bits_to_bytes(bits):
    usable = len(bits) - len(bits) % 8
    return bytes(int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, usable, 8))


ALARM_HTML = """
<style>
@keyframes pulse {0% {background:#6b0000;} 50% {background:#ff1a1a;} 100% {background:#6b0000;}}
.alarm {animation:pulse 0.9s infinite; color:white; text-align:center; padding:1.3rem;
        border-radius:12px; font-size:2.2rem; font-weight:800; letter-spacing:3px;}
.alarm small {display:block; font-size:1rem; font-weight:400; letter-spacing:0; margin-top:.4rem;}
</style>
<div class="alarm">INTRUDER DETECTED<small>Error rate __ERR__ is above the alarm level.
Key discarded. Nothing was sent.</small></div>
"""

st.set_page_config(page_title="QuantumShield", page_icon="🛡️", layout="wide")
st.title("QuantumShield")
st.caption("Find the weak spots. Break the old lock. Lock the channel. Watch the traffic.")

tab_overview, tab_scan, tab_attack, tab_protect, tab_detect, tab_summary = st.tabs(
    ["Overview", "Scan", "Attack demo", "Protect", "Detect", "Summary"]
)

# ------------------------------------------------------------ OVERVIEW
with tab_overview:
    st.subheader("The problem: harvest now, decrypt later")
    st.write(
        "Attackers can record encrypted traffic today and unlock it years later, once a large "
        "quantum computer exists. Anything that must stay secret for a long time is already "
        "exposed to that plan. QuantumShield shows the threat and the fix, step by step."
    )
    o1, o2, o3, o4 = st.columns(4)
    o1.markdown("**1. Scan**  \nFind which websites still rely on quantum-vulnerable "
                "cryptography, and which already use post-quantum key exchange.")
    o2.markdown("**2. Attack demo**  \nWatch Shor's algorithm (a real Qiskit circuit) break a "
                "toy RSA key.")
    o3.markdown("**3. Protect**  \nBB84 quantum key exchange with an eavesdropper alarm, plus "
                "ML-KEM and ML-DSA, the post-quantum standards usable today.")
    o4.markdown("**4. Detect**  \nA quantum-kernel fraud model compared honestly with a "
                "classical one.")

    st.divider()
    st.subheader("What breaks, what survives, what replaces it")
    st.dataframe(pd.DataFrame([
        {"Today": "RSA, elliptic-curve (key exchange and signatures)",
         "Against a large quantum computer": "Broken by Shor's algorithm",
         "Replacement": "ML-KEM (key exchange), ML-DSA (signatures)"},
        {"Today": "AES-256 (encrypting the data)",
         "Against a large quantum computer": "Still strong (Grover only halves the key strength)",
         "Replacement": "Keep it"},
        {"Today": "AES-128",
         "Against a large quantum computer": "Weakened but not considered broken in practice",
         "Replacement": "Prefer AES-256"},
    ]), hide_index=True)
    st.caption("ML-KEM (FIPS 203) and ML-DSA (FIPS 204) are NIST standards. The demos in this "
               "app use small teaching libraries, not production code.")

    st.divider()
    st.subheader("Suggested demo order")
    st.markdown(
        "1. **Scan** tab: scan all sites, compare Google (partly protected) with GitHub.  \n"
        "2. **Attack demo** tab: break the toy RSA key.  \n"
        "3. **Protect** tab: BB84 with Eve off and on, then ML-KEM, ML-DSA and the file encryption.  \n"
        "4. **Detect** tab: train, then try a transaction yourself.  \n"
        "5. **Summary** tab: download the one-page demo summary."
    )

    with st.expander("Honesty and limits"):
        st.markdown(
            "- Everything quantum runs on a **local simulator** (Qiskit Aer). Nothing ran on "
            "real IBM quantum hardware.  \n"
            "- The Shor demo uses **N = 15**, a textbook toy. Breaking RSA-2048 needs far more "
            "error-corrected qubits than exist today.  \n"
            "- The scanner says **'not observed'**, not 'not protected': a server may enable "
            "post-quantum key exchange only for some clients.  \n"
            "- The fraud data is **synthetic**. We test a quantum method and do **not** claim "
            "quantum advantage; the classical model wins or ties.  \n"
            "- The readiness score is **our own rubric**, not a standard.  \n"
            "- BB84 here is a simulation. Real BB84 needs quantum hardware, which is why "
            "ML-KEM is the practical option for banks today."
        )

# ---------------------------------------------------------------- SCAN
with tab_scan:
    st.subheader("Quantum risk scanner")
    url = st.text_input("Website to check", "google.com")
    if st.button("Scan website"):
        try:
            with st.spinner("Checking certificate..."):
                r = scan_site(url)
            c1, c2, c3 = st.columns(3)
            c1.metric("Key type", r["algorithm"])
            c2.metric("Key size (bits)", r["key_size"] if r["key_size"] else "n/a")
            c3.metric("TLS version", r["tls_version"])
            st.write(f"Certificate expires: {r['expires']} ({r['days_left']} days left)")
            st.write(f"**Post-quantum key exchange:** {PQ_LABEL[r['pq_kex']]}")
            st.write(f"**Readiness score:** {readiness_score(r)} / 100")
            if r["risk"] == "Critical" or (r["risk"] == "High" and r.get("pq_kex") is not True):
                st.error(f"Quantum risk (certificate key): {r['risk'].upper()}. " + r["advice"])
            elif r["risk"] == "High":
                st.warning("Partly protected. Certificate key: HIGH quantum risk, but the traffic "
                           "key exchange is post-quantum. " + r["advice"])
            else:
                st.warning(r["advice"])
            st.write("**Fix-it plan**")
            for pr, text in fix_plan(r):
                st.markdown(f"- **{pr}:** {text}")
        except Exception as e:
            st.warning(f"Could not scan that site: {e}")

    st.divider()
    st.subheader("Quantum readiness report")
    st.caption("Scan many websites at once and download a report. One website per line.")
    sites_text = st.text_area("Websites", "\n".join(DEFAULT_SITES), height=200)
    bs1, bs2 = st.columns(2)
    if bs1.button("Scan all and build report"):
        hosts = [s.strip() for s in sites_text.splitlines() if s.strip()]
        with st.spinner(f"Scanning {len(hosts)} websites..."):
            live_rows = scan_many(hosts)
        st.session_state["report_rows"] = live_rows
        st.session_state["report_source"] = "Live scan, just now."
        save_snapshot(live_rows)
    if bs2.button("Load saved snapshot (works offline)"):
        snap_rows, snap_time = load_snapshot()
        st.session_state["report_rows"] = snap_rows
        st.session_state["report_source"] = (f"Saved snapshot from {snap_time}. "
                                             "This is NOT a live scan.")

    if "report_rows" in st.session_state:
        rows = st.session_state["report_rows"]
        st.caption("Source: " + st.session_state.get("report_source", "live scan"))
        table = pd.DataFrame([{
            "Website": r["host"],
            "Key type": r["algorithm"],
            "Key size (bits)": str(r["key_size"]) if r["key_size"] else "n/a",
            "TLS": r["tls_version"],
            "PQ key exchange": PQ_LABEL[r.get("pq_kex")],
            "Expires": r["expires"],
            "Days left": str(r["days_left"]) if r["days_left"] is not None else "-",
            "Certificate risk": r["risk"],
            "Score (of 100)": str(readiness_score(r)) if readiness_score(r) is not None else "-",
        } for r in rows])

        reachable = [r for r in rows if r["risk"] != "Unreachable"]
        exposed = [r for r in reachable if r["risk"] in ("High", "Critical")]
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Websites checked", len(rows))
        m2.metric("Reachable", len(reachable))
        m3.metric("Quantum-vulnerable certificates", len(exposed))
        scores = [readiness_score(r) for r in reachable]
        m4.metric("Average readiness score", round(sum(scores) / len(scores)) if scores else "n/a")

        st.dataframe(table, hide_index=True)
        st.caption("Score rubric (ours, not a standard): certificate key up to 40, TLS version up to 20, "
                   "post-quantum key exchange up to 40 (earned only when the server selects it).")
        st.write("**Action plan for one site**")
        pick = st.selectbox("Choose a site", [r["host"] for r in rows], key="plan_pick")
        chosen = next(r for r in rows if r["host"] == pick)
        for pr, text in fix_plan(chosen):
            st.markdown(f"- **{pr}:** {text}")
        st.caption("The downloadable report includes this plan for every site.")
        st.write("Key types found")
        st.bar_chart(table["Key type"].value_counts())

        d1, d2 = st.columns(2)
        d1.download_button(
            "Download report (.md)",
            build_report_md(rows),
            file_name="quantum_readiness_report.md",
            mime="text/markdown",
        )
        d2.download_button(
            "Download table (.csv)",
            table.to_csv(index=False),
            file_name="quantum_readiness_table.csv",
            mime="text/csv",
        )

    st.divider()
    st.subheader("Is your data already at risk?")
    st.caption("Harvest now, decrypt later: attackers can record encrypted data today and "
               "unlock it once quantum computers arrive. Nobody knows the arrival date, so "
               "the last slider is your own estimate.")
    h1, h2, h3 = st.columns(3)
    secret_years = h1.slider("Years the data must stay secret", 1, 50, 20)
    migrate_years = h2.slider("Years your organisation needs to migrate", 1, 15, 5)
    quantum_years = h3.slider("Years until a code-breaking quantum computer", 5, 40, 15)
    hv = harvest_verdict(secret_years, migrate_years, quantum_years)
    k1, k2 = st.columns(2)
    k1.metric("Years your data must be protected", hv["need"])
    k2.metric("Years until quantum arrives (your estimate)", quantum_years)
    tl = pd.DataFrame([
        {"phase": "Migration", "start": 0, "end": migrate_years, "row": "Your timeline"},
        {"phase": "Data must stay secret", "start": migrate_years, "end": hv["need"],
         "row": "Your timeline"},
    ])
    x_max = max(50, hv["need"], quantum_years) + 2
    bars = alt.Chart(tl).mark_bar(size=40).encode(
        x=alt.X("start:Q", title="Years from today", scale=alt.Scale(domain=[0, x_max])),
        x2="end:Q",
        y=alt.Y("row:N", title=None),
        color=alt.Color("phase:N", title=None, scale=alt.Scale(
            domain=["Migration", "Data must stay secret"], range=["#f4a261", "#457b9d"])),
    )
    rule = alt.Chart(pd.DataFrame({"x": [quantum_years]})).mark_rule(
        color="#ff2d2d", strokeWidth=4).encode(x="x:Q")
    rule_label = alt.Chart(pd.DataFrame({"x": [quantum_years], "t": ["Quantum arrives"]})).mark_text(
        align="left", dx=6, color="#ff6b6b", fontWeight="bold").encode(
        x="x:Q", y=alt.value(10), text="t:N")
    st.altair_chart((bars + rule + rule_label).properties(height=110), use_container_width=True)
    st.caption("Red line = when you think a code-breaking quantum computer arrives. If the bar "
               "reaches past the red line, recorded data would be readable while it still matters.")
    if hv["at_risk"]:
        st.error(f"AT RISK NOW. Data recorded today would be readable for about {hv['gap']} "
                 "years before you finish migrating. Start moving to post-quantum "
                 "cryptography immediately.")
    else:
        st.success(f"Safe on these numbers, with {-hv['gap']} years to spare. You must finish "
                   f"migrating within {hv['migrate_deadline']} years.")

# -------------------------------------------------------------- ATTACK
with tab_attack:
    st.subheader("Breaking RSA with Shor's algorithm (toy example)")
    st.caption(
        "A real RSA key has hundreds of digits. This demo uses N = 15, the standard textbook "
        "size for a real Shor circuit, so you can watch every step. A normal computer breaks "
        "N = 15 instantly. Breaking real RSA-2048 would need far more error-corrected qubits "
        "than exist today."
    )

    rsa_key = make_toy_rsa()
    st.write(f"**Public key:** N = {rsa_key['N']}, e = {rsa_key['e']}  "
             "(the private key is hidden from the attacker)")

    secret = st.number_input("Secret number Alice sends (2 to 14)", 2, 14, 7)
    st.caption("With this toy key, 4, 5, 6, 9, 10, 11 and 14 encrypt to themselves. "
               "Pick another number to see the scrambling.")
    cipher = pow(int(secret), rsa_key["e"], rsa_key["N"])
    st.write(f"**Encrypted number sent over the wire:** {cipher}")

    if st.button("Attack with Shor's algorithm"):
        with st.spinner("Running the quantum circuit..."):
            attempts, factors = factor_with_shor()
            hist = phase_histogram(7, 1024)
        st.session_state["shor"] = {
            "attempts": attempts, "factors": factors, "hist": hist,
            "cipher": cipher, "secret": int(secret),
        }

    if "shor" in st.session_state:
        s = st.session_state["shor"]
        st.write("**Step 1: the quantum computer finds a hidden repeating pattern (period)**")
        st.caption("Measured phases cluster at 0, 0.25, 0.5 and 0.75 because the pattern "
                   "repeats every 4 steps (for a = 7). Those peaks reveal the period.")
        st.bar_chart(s["hist"])

        st.write("**Step 2: each run gives a guess, and some guesses fail**")
        st.dataframe(pd.DataFrame(s["attempts"]), hide_index=True)

        if s["factors"]:
            p, q = s["factors"]
            phi = (p - 1) * (q - 1)
            d = pow(rsa_key["e"], -1, phi)
            recovered = pow(s["cipher"], d, N)
            st.write("**Step 3: use the factors to rebuild the private key**")
            st.success(f"{N} = {p} x {q}. Then phi = {phi} and the private key d = {d}.")
            st.write("**Step 4: decrypt the message**")
            if recovered == s["secret"]:
                st.error(f"Attack succeeded. The attacker read the secret number: {recovered}")
            else:
                st.warning("Recovered number did not match. Change the secret and try again.")
        else:
            st.warning("No factors found in this run. Press the attack button again.")

        with st.expander("Show the quantum circuit (a = 7)"):
            st.code(str(build_circuit(7).draw(output="text", fold=140)))

    st.divider()
    st.subheader("Why does this work? The math behind the quantum step")
    st.caption(
        "Shor's algorithm turns factoring into pattern finding. Pick a number a and watch its "
        "powers mod 15 repeat. The quantum computer's only job is to find the length of that "
        "cycle, called the period r. The rest is simple arithmetic you can follow below."
    )
    if "shor" in st.session_state and st.session_state["shor"]["factors"]:
        used_a = st.session_state["shor"]["attempts"][-1]["Random a"]
        st.caption(f"In the attack above, the successful run used a = {used_a}.")
    a_pick = st.selectbox("Pick a", VALID_A, index=VALID_A.index(7), key="explain_a")
    ex = explain_factoring(int(a_pick))
    if ex["table"]:
        st.dataframe(pd.DataFrame(ex["table"]), hide_index=True)
    for i, step in enumerate(ex["steps"], start=1):
        st.markdown(f"**{i}.** {step}")
    if ex["ok"]:
        st.success(ex["message"])
    else:
        st.warning(ex["message"])
    st.caption(
        "Why do some quantum runs fail? Each run measures a phase s / r for a random s. If s is 0, "
        "or s shares a factor with r (for example 2 / 4 shows up as 1 / 2), the guess for r is "
        "wrong and the attack simply runs again. That is why the attempt log above can show "
        "failed rows."
    )

    st.divider()
    st.subheader("Reality check: what breaking real RSA-2048 would need")
    st.dataframe(pd.DataFrame([
        {"What": "This app's toy Shor demo (N = 15)", "Qubits": "10",
         "Runtime": "seconds, on a simulator", "Kind": "Demo"},
        {"What": "RSA-2048, Gidney and Ekera 2019", "Qubits": "about 20 million noisy",
         "Runtime": "about 8 hours", "Kind": "Published estimate"},
        {"What": "RSA-2048, Gidney 2025 (Google Quantum AI)", "Qubits": "under 1 million noisy",
         "Runtime": "under a week", "Kind": "Published estimate"},
    ]), hide_index=True)
    st.caption("Both estimates assume a 0.1% gate error rate, a square grid of qubits and "
               "other stated conditions (source: Gidney, arXiv:2505.15917). They are resource "
               "estimates, not a demonstrated attack. The point: the estimate fell about 20 times "
               "in six years, which is why migrating early matters.")


# ------------------------------------------------------------- PROTECT
with tab_protect:
    sub_bb84, sub_kem, sub_dsa, sub_file, sub_chat, sub_grover = st.tabs(
        ["BB84 (quantum key)", "ML-KEM (works today)", "ML-DSA (signatures)", "Encrypt a file", "Live chat", "Key strength"]
    )
    with sub_bb84:
        st.subheader("Secure channel: quantum key exchange (BB84)")
        n = st.slider("Number of qubits Alice sends", 100, 800, 600, step=50)
        noise_pct = st.slider("Hardware noise level (%)", 0.0, 10.0, 0.0, step=0.5)
        st.caption("Noise is simulated with a noise model. Real quantum hardware always has some noise.")
        eve = st.toggle("Eavesdropper (Eve) is listening")

        if st.button("Send the key"):
            with st.spinner("Sending qubits..."):
                st.session_state["result"] = run_bb84_detailed(
                    n=n, eve=eve, noise=noise_pct / 100
                )
                st.session_state["eve_was_on"] = eve

        if "result" in st.session_state:
            a_key, b_key, err, bb_table, bb_chart = st.session_state["result"]
            eve_on = st.session_state.get("eve_was_on", False)

            col1, col2 = st.columns(2)
            col1.metric("Key length", len(a_key))
            col2.metric("Error rate", f"{err:.1%}")

            if err > ALARM_LEVEL:
                if eve_on:
                    st.markdown(ALARM_HTML.replace("__ERR__", f"{err:.1%}"), unsafe_allow_html=True)
                else:
                    st.error("Error rate too high. Key discarded and nothing was sent. "
                             "The channel is too noisy to tell an intruder from hardware errors.")
            else:
                st.success("Channel is secure. Shared secret key created.")

            with st.expander("How the key was built, qubit by qubit", expanded=True):
                st.caption(
                    "Alice sends each bit in a random basis (Z or X). Bob measures in a random "
                    "basis. They keep only the qubits where the bases matched. If Eve guessed the "
                    "wrong basis, she disturbed the qubit, which shows up as an ERROR."
                )
                show = min(30, len(bb_table))
                st.dataframe(bb_table.head(show), hide_index=True)
                st.caption(f"Showing the first {show} of {len(bb_table)} qubits.")
                if len(bb_chart):
                    st.write("Error rate among kept bits as more qubits arrive")
                    chart_df = bb_chart.reset_index().melt(
                        "Qubits sent", var_name="Series", value_name="Percent")
                    st.altair_chart(
                        alt.Chart(chart_df).mark_line().encode(
                            x=alt.X("Qubits sent:Q", scale=alt.Scale(domain=[0, len(bb_table)])),
                            y=alt.Y("Percent:Q", scale=alt.Scale(domain=[0, 30]),
                                    title="Error rate (%)"),
                            color=alt.Color("Series:N", title=None),
                        ),
                        use_container_width=True,
                    )

            if err <= ALARM_LEVEL:
                st.divider()
                st.subheader("Send a secret message")
                msg = st.text_input("Alice's message", "Meet me at 5 pm")
                data = msg.encode()
                max_chars = len(a_key) // 8
                st.caption(f"This key can encrypt up to {max_chars} characters.")
                if len(data) > max_chars:
                    st.warning(f"Message too long for this key. Maximum {max_chars} characters. "
                               "Increase the number of qubits and send the key again.")
                elif msg:
                    cipher_bytes = bytes(d ^ k for d, k in zip(data, bits_to_bytes(a_key)))
                    st.write("Encrypted message (what travels over the wire):")
                    st.code(cipher_bytes.hex())
                    plain = bytes(c ^ k for c, k in zip(cipher_bytes, bits_to_bytes(b_key)))
                    st.write("Decrypted by Bob:")
                    if plain == data:
                        st.success(plain.decode(errors="replace"))
                    else:
                        st.warning("Noise corrupted the key, so Bob's message came out garbled: "
                                   + plain.decode(errors="replace"))

        st.divider()
        st.subheader("Side by side: with and without Eve")
        st.caption("Runs the same random choices twice, once with no spy and once with Eve "
                   "listening, so the only difference between the two lines is Eve. It uses the "
                   "noise level set above.")
        cn = st.slider("Qubits for the comparison", 100, 600, 400, step=50, key="cmp_n")
        if st.button("Run both and compare", key="cmp_run"):
            with st.spinner("Running both versions..."):
                st.session_state["bb84_cmp"] = run_bb84_compare(cn, noise_pct / 100)

        if "bb84_cmp" in st.session_state:
            cmp = st.session_state["bb84_cmp"]
            if cmp is None:
                st.warning("No qubits were kept in that run. Run it again.")
            else:
                c_left, c_right = st.columns(2)
                c_left.metric("Error rate, no Eve", f"{cmp['err_clean']:.1%}")
                c_right.metric("Error rate, Eve listening", f"{cmp['err_eve']:.1%}")
                noisy = cmp["err_clean"] > ALARM_LEVEL
                if noisy:
                    c_left.error("Too noisy: the key would be discarded even without a spy.")
                    c_right.warning("The alarm is also triggered here, but noise alone already "
                                    "triggers it, so Eve cannot be told apart from the noise.")
                else:
                    c_left.success("Channel secure. Key accepted.")
                    if cmp["err_eve"] > ALARM_LEVEL:
                        c_right.error("Intruder detected. Key discarded.")
                    else:
                        c_right.warning("Eve slipped past the alarm in this run. Run again with "
                                        "more qubits to make detection reliable.")

                chart_df = cmp["chart"].reset_index().melt(
                    "Qubits sent", var_name="Series", value_name="Percent")
                st.altair_chart(
                    alt.Chart(chart_df).mark_line().encode(
                        x=alt.X("Qubits sent:Q", scale=alt.Scale(domain=[0, cmp["n"]])),
                        y=alt.Y("Percent:Q", scale=alt.Scale(domain=[0, 40]),
                                title="Error rate so far (%)"),
                        color=alt.Color("Series:N", title=None, scale=alt.Scale(
                            domain=["Without Eve (%)", "With Eve (%)", "Alarm level (%)"],
                            range=["#2a9d8f", "#e63946", "#999999"])),
                    ),
                    use_container_width=True,
                )

                st.write("**What does Eve actually learn?**")
                k1, k2 = st.columns(2)
                k1.metric("Key bits Eve knows for certain", f"{cmp['eve_certain']:.0%}")
                k2.metric("Eve's copy matches Alice's key", f"{cmp['eve_match']:.0%}")
                st.caption(
                    "Eve measures each qubit in a random basis. When she picks the right basis "
                    "(about half the time) she learns the bit and leaves no trace. When she picks "
                    "the wrong one she can only guess, and her measurement scrambles the qubit, "
                    "which Bob sees as an error. So her copy is only about 75% right, and Alice "
                    "and Bob see about 25% errors. This is the simplest attack (intercept and "
                    "resend). Real systems also shrink the key afterwards to remove what Eve may "
                    "know; this demo does not."
                )

    with sub_kem:
        st.subheader("What banks can use today: ML-KEM (post-quantum key exchange)")
        st.caption("BB84 needs special quantum hardware. ML-KEM (NIST standard FIPS 203) is ordinary "
                   "software that runs on normal computers, and it is already used by Google and "
                   "Cloudflare. It only agrees a shared key; AES-256 then encrypts the message. "
                   "This demo uses a small teaching library (kyber-py), not production code.")
        mk_msg = st.text_input("Message to protect with ML-KEM", "Meet me at 5 pm", key="mk_msg")
        if st.button("Run ML-KEM key exchange"):
            with st.spinner("Exchanging keys..."):
                st.session_state["mlkem"] = run_mlkem(mk_msg)
        if "mlkem" in st.session_state:
            m = st.session_state["mlkem"]
            k1, k2, k3 = st.columns(3)
            k1.metric("Public key (bytes)", m["public_key_len"])
            k2.metric("Sent ciphertext (bytes)", m["kem_ciphertext_len"])
            k3.metric("Shared secret (bytes)", m["secret_len"])
            st.write("**1. Bob publishes a public key.** Everyone, including Eve, can see it:")
            st.code(m["public_key_hex"])
            st.write("**2. Alice sends back a ciphertext.** Eve can see this too:")
            st.code(m["kem_ciphertext_hex"])
            st.write("**3. Both sides now hold the same secret key:**")
            if m["secrets_match"]:
                st.success("Alice and Bob derived the same 256-bit key.")
            else:
                st.error("The keys did not match.")
            st.code("Alice: " + m["alice_secret_hex"] + "\nBob:   " + m["bob_secret_hex"])
            st.write("**4. Alice encrypts the message with that key (AES-256-GCM):**")
            st.code(m["sealed_hex"])
            st.write("**Bob decrypts:**")
            if m["bob_plain"] is not None:
                st.success(m["bob_plain"])
            st.write("**Eve tries to decrypt with her own key:**")
            st.code("Eve's key: " + m["eve_secret_hex"])
            if m["eve_read"]:
                st.error("Eve read the message.")
            else:
                st.info("Eve's key is different, so decryption fails. She learns nothing.")
            st.caption("ML-KEM is built on lattice problems that are not known to be broken by "
                       "Shor's algorithm. 'Not known to be broken' is not a proof of safety.")

        st.divider()
        st.subheader("The cost of going post-quantum: bigger keys and signatures")
        st.dataframe(pd.DataFrame([
            {"Item": "Key exchange public key", "Classical (X25519)": "32 bytes",
             "Post-quantum": "1184 bytes (ML-KEM-768)"},
            {"Item": "Key exchange reply", "Classical (X25519)": "32 bytes",
             "Post-quantum": "1088 bytes (ML-KEM-768)"},
            {"Item": "Signature public key", "Classical (X25519)": "about 64 bytes (ECDSA P-256)",
             "Post-quantum": "1952 bytes (ML-DSA-65)"},
            {"Item": "Signature", "Classical (X25519)": "about 64 bytes (ECDSA P-256)",
             "Post-quantum": "3309 bytes (ML-DSA-65)"},
        ]).rename(columns={"Classical (X25519)": "Classical today"}), hide_index=True)
        st.caption("Post-quantum sizes match what the demos measured. Classical sizes are "
                   "typical values. Bigger messages are the price of quantum safety.")

    with sub_dsa:
        st.subheader("Quantum-safe signatures: ML-DSA (proof of who sent it)")
        st.caption("RSA and elliptic-curve signatures can be forged once a big quantum computer exists "
                   "(Shor's algorithm). ML-DSA (NIST standard FIPS 204) is the replacement. "
                   "This demo uses a small teaching library (dilithium-py), not production code.")
        sg_msg = st.text_input("Message Alice signs", "Pay Bob 10 rupees", key="sg_msg")
        if st.button("Sign the message"):
            with st.spinner("Signing..."):
                st.session_state["mldsa"] = sign_message(sg_msg)
        if "mldsa" in st.session_state:
            d = st.session_state["mldsa"]
            s1, s2 = st.columns(2)
            s1.metric("Public key (bytes)", len(d["public_key"]))
            s2.metric("Signature (bytes)", len(d["signature"]))
            st.write("**Signature (first bytes):**")
            st.code(d["signature"][:24].hex() + "...")
            st.write("**What Bob receives.** Edit it to simulate someone tampering on the way:")
            received = st.text_input("Message Bob receives", d["message"], key="sg_received")
            if check(d["public_key"], received, d["signature"]):
                st.success("Signature VALID. The message is exactly what Alice signed.")
            else:
                st.error("Signature INVALID. The message was changed or was not signed by Alice.")
            st.write("**Eve tries to forge a message with her own key:**")
            st.code(d["forged_text"])
            forged_accepted = check(d["public_key"], d["forged_text"], d["forged_sig"])
            st.session_state["dsa_forgery_rejected"] = not forged_accepted
            if forged_accepted:
                st.error("Bob accepted Eve's forgery.")
            else:
                st.info("Bob rejects it. Eve does not have Alice's secret key.")
            st.caption("ML-DSA is built on lattice problems not known to be broken by Shor's "
                       "algorithm. 'Not known to be broken' is not a proof of safety.")

    with sub_file:
        st.subheader("Encrypt a real file with ML-KEM + AES-256")
        st.caption("Upload any small file (up to 5 MB). It is encrypted so only Bob's private key can "
                   "open it. ML-KEM agrees the key; AES-256-GCM encrypts the file. Teaching library, "
                   "not production code.")
        up = st.file_uploader("Choose a file", key="enc_file")
        if up is not None and st.button("Encrypt the file"):
            raw = up.getvalue()
            if len(raw) > 5 * 1024 * 1024:
                st.warning("File is larger than 5 MB. Pick a smaller one.")
            else:
                with st.spinner("Encrypting..."):
                    st.session_state["encfile"] = dict(encrypt_file(raw), name=up.name, size=len(raw))
        if "encfile" in st.session_state:
            e = st.session_state["encfile"]
            f1, f2 = st.columns(2)
            f1.metric("Original size (bytes)", e["size"])
            f2.metric("Encrypted size (bytes)", len(e["package"]))
            st.write("**What an eavesdropper sees (first bytes of the encrypted file):**")
            st.code(e["package"][:32].hex() + "...")
            st.download_button("Download encrypted file", e["package"],
                               file_name=e["name"] + ".qshield", key="dl_enc")
            st.write("**Bob decrypts with his private key:**")
            tampered = st.checkbox("Simulate tampering on the way (flip one bit)")
            incoming = tamper(e["package"]) if tampered else e["package"]
            plain = decrypt_package(e["private_key"], incoming)
            if plain is None:
                st.error("Decryption refused. The file was changed or the key is wrong, so Bob "
                         "gets nothing.")
            else:
                same = hashlib.sha256(plain).hexdigest() == e["sha256"]
                if same:
                    st.success("Decrypted. The file is identical to the original (SHA-256 matches).")
                else:
                    st.error("Decrypted data does not match the original.")
                st.download_button("Download decrypted file", plain, file_name=e["name"],
                                   key="dl_dec")

    with sub_chat:
        render_mlkem_chat(require_toggle=True)

    with sub_grover:
        st.subheader("How long would a key last? (Grover and Shor)")
        g1, g2 = st.columns(2)
        c_exp = g1.slider("Classical attacker: guesses per second (power of 10)", 6, 18, 12)
        q_exp = g2.slider("Quantum attacker: Grover steps per second (power of 10)", 3, 12, 6)
        st.write("**Symmetric keys: Grover's algorithm**")
        st.dataframe(crack_table(10.0 ** c_exp, 10.0 ** q_exp), hide_index=True)
        st.write("**Public-key crypto: Shor's algorithm**")
        st.dataframe(PUBLIC_KEY_TABLE, hide_index=True)
        st.info(GROVER_NOTE)

# -------------------------------------------------------------- DETECT
with tab_detect:
    st.subheader("Fraud detection (quantum kernel)")
    st.caption("Uses synthetic example transactions, not real bank data.")
    dataset = st.radio("Dataset", ["Simple: two clear groups", "Harder: card-testing fraud"],
                       horizontal=True)
    hard = dataset.startswith("Harder")
    if hard:
        st.caption("Fraud has two patterns: big purchases at risky hours, and tiny test charges "
                   "at risky hours. No single straight line separates fraud from normal.")
    seed = st.number_input("Random seed", 1, 999, 1)
    if st.button("Train and test"):
        with st.spinner("Training..."):
            st.session_state["detect"] = run_detection(int(seed), hard=hard)
            st.session_state["detect_dataset"] = dataset

    if "detect" in st.session_state:
        out = st.session_state["detect"]
        c1, c2 = st.columns(2)
        c1.metric("Quantum kernel accuracy", f"{out['q_acc']:.0%}")
        c2.metric("Classical model accuracy", f"{out['c_acc']:.0%}")
        st.scatter_chart(out["df"], x="Amount", y="Time risk", color="Actual")
        st.dataframe(out["df"])
        wrong = out["df"][out["df"]["Actual"] != out["df"]["Quantum model says"]]
        with st.expander(f"Where did the quantum model go wrong? ({len(wrong)} test rows)"):
            if len(wrong):
                st.dataframe(wrong, hide_index=True)
                st.caption("These are the test transactions the quantum model labelled incorrectly.")
            else:
                st.success("The quantum model got every test row right on this run.")
        if out["q_acc"] >= out["c_acc"]:
            st.info("The quantum kernel matched or beat the classical model on this run.")
        else:
            st.info("The classical model did better on this run. That is expected on a small "
                    "synthetic dataset. We are testing a quantum method, not claiming quantum "
                    "advantage.")

        st.divider()
        st.subheader("Where does each model draw the line?")
        st.caption("Green area = the model says Normal, red area = the model says Fraud. "
                   "Dots are the training transactions the models learned from.")
        if st.toggle("Show the decision map"):
            if "grid" not in out:
                with st.spinner("Asking both models about every point..."):
                    out["grid"] = boundary_grid(out["model"])
            grid = out["grid"]
            mdl = out["model"]
            tr = pd.DataFrame({
                "amount": mdl["X_tr"][:, 0], "risk": mdl["X_tr"][:, 1],
                "label": ["Fraud" if v == 1 else "Normal" for v in mdl["y_tr"]],
            })
            colors = alt.Scale(domain=["Normal", "Fraud"], range=["#2a9d8f", "#e63946"])

            def region_chart(col, title):
                bg = alt.Chart(grid).mark_rect(opacity=0.35, clip=True).encode(
                    x=alt.X("amount:Q", scale=alt.Scale(domain=[0, 1]), title="Amount"),
                    x2="x2:Q",
                    y=alt.Y("risk:Q", scale=alt.Scale(domain=[0, 1]), title="Time risk"),
                    y2="y2:Q",
                    color=alt.Color(col + ":N", scale=colors, legend=None),
                )
                pts = alt.Chart(tr).mark_circle(size=45, clip=True, stroke="white",
                                                 strokeWidth=0.6).encode(
                    x="amount:Q", y="risk:Q",
                    color=alt.Color("label:N", scale=colors, legend=None),
                )
                return (bg + pts).properties(title=title, height=300)

            m1, m2 = st.columns(2)
            m1.altair_chart(region_chart("quantum", "Quantum kernel model"),
                            use_container_width=True)
            m2.altair_chart(region_chart("classical", "Classical model"),
                            use_container_width=True)

        st.divider()
        st.subheader("Try it yourself")
        st.caption("Pick a transaction. Both models, trained above, give a verdict.")
        t1, t2 = st.columns(2)
        amount = t1.slider("Amount (0 = tiny, 1 = huge)", 0.0, 1.0, 0.5, 0.01)
        trisk = t2.slider("Time risk (0 = normal hours, 1 = very odd hours)", 0.0, 1.0, 0.5, 0.01)
        res = predict_one(out["model"], amount, trisk)
        v1, v2 = st.columns(2)
        v1.metric("Quantum model says", res["quantum"])
        v2.metric("Classical model says", res["classical"])
        if res["quantum"] != res["classical"]:
            st.warning("The two models disagree on this transaction.")

# ------------------------------------------------------------- SUMMARY
with tab_summary:
    st.subheader("Demo summary")
    st.caption("Everything you ran in this session, in one downloadable page. Parts you did not "
               "run are marked 'not run', so the summary never claims more than you showed.")
    checklist = [
        ("Scan: bulk report", "report_rows"),
        ("Attack demo: Shor on a toy RSA key", "shor"),
        ("Protect: BB84", "result"),
        ("Protect: ML-KEM", "mlkem"),
        ("Protect: ML-DSA", "mldsa"),
        ("Protect: encrypt a file", "encfile"),
        ("Detect: fraud models", "detect"),
    ]
    st.dataframe(pd.DataFrame([
        {"Step": name, "Status": "Done" if key in st.session_state else "Not run yet"}
        for name, key in checklist
    ]), hide_index=True)

    summary_md = build_demo_summary(st.session_state, ALARM_LEVEL)
    st.download_button(
        "Download demo summary (.md)",
        summary_md,
        file_name="quantumshield_demo_summary.md",
        mime="text/markdown",
        key="dl_summary",
    )
    with st.expander("Preview the summary"):
        st.markdown(summary_md)