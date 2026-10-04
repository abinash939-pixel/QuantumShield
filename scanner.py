import json
import os
import ssl
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlparse

from risk import readiness_score
from pqprobe import probe_pq_kex
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448

DEFAULT_SITES = [
    "sbi.co.in",
    "sbi.bank.in",
    "hdfcbank.com",
    "icicibank.com",
    "iitr.ac.in",
    "india.gov.in",
    "google.com",
    "github.com",
    "wikipedia.org",
    "cloudflare.com",
    "amazon.in",
]

SHOR_ADVICE = (
    "This certificate key type can be broken by a large quantum computer running Shor's "
    "algorithm, which would let an attacker forge the site's identity. Plan a move to "
    "post-quantum signatures (ML-DSA)."
)

KEX_NOTE = {
    True: "Key exchange: a hybrid post-quantum group (ML-KEM) was selected, so recorded "
          "traffic is protected against harvest-now-decrypt-later.",
    False: "Key exchange: no post-quantum group was selected in our probe, so recorded "
           "traffic could be decrypted later. Plan a move to ML-KEM.",
    None: "Key exchange: could not be determined.",
}
PQ_LABEL = {True: "Yes (ML-KEM)", False: "No", None: "Unknown"}


def fix_plan(r):
    """Short action list for one scan result: a list of (priority, text) pairs.
    Our own suggestions, not a compliance standard."""
    if r["risk"] == "Unreachable":
        return [("Check", "Could not connect on port 443. Check the address or try again.")]
    plan = []
    if r["algorithm"] == "RSA" and (r["key_size"] or 0) < 2048:
        plan.append(("Do now", "Replace the RSA certificate key: under 2048 bits is weak even today."))
    if r["tls_version"] not in ("TLSv1.3",):
        plan.append(("Do now", "Enable TLS 1.3. Post-quantum key exchange needs it."))
    if r.get("pq_kex") is False:
        plan.append(("Do now", "Enable a hybrid post-quantum key exchange (X25519MLKEM768) in the "
                               "web server, load balancer or CDN. Check your vendor's support."))
    elif r.get("pq_kex") is None:
        plan.append(("Check", "Post-quantum key exchange could not be determined. Test again or "
                              "check the server settings."))
    if r["risk"] in ("High", "Critical"):
        plan.append(("Plan", "Plan a move to post-quantum certificate signatures (ML-DSA) once your "
                             "certificate authority and clients support them."))
    if r.get("days_left") is not None and r["days_left"] < 30:
        plan.append(("Soon", f"The certificate expires in {r['days_left']} days. Renew it."))
    if not plan:
        plan.append(("OK", "No action needed from this scan."))
    return plan


def assess(algo, size):
    if algo == "RSA" and size and size < 2048:
        return "Critical", "RSA keys under 2048 bits are weak even against normal computers today."
    if algo in ("RSA", "ECC", "EdDSA"):
        return "High", SHOR_ADVICE
    return "Unknown", "Could not identify the key type."


def scan_site(url):
    host = urlparse(url if "//" in url else "//" + url).hostname

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, 443), timeout=8) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            tls_version = tls.version()

    cert = x509.load_der_x509_certificate(der)
    key = cert.public_key()

    if isinstance(key, rsa.RSAPublicKey):
        algo, size = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        algo, size = "ECC", key.key_size
    elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        algo, size = "EdDSA", None
    else:
        algo, size = "Unknown", None

    risk, advice = assess(algo, size)
    pq = probe_pq_kex(host)
    advice = advice + " " + KEX_NOTE[pq]
    expires = cert.not_valid_after_utc
    days_left = (expires - datetime.now(timezone.utc)).days

    return {
        "host": host,
        "algorithm": algo,
        "key_size": size,
        "tls_version": tls_version,
        "expires": expires.strftime("%Y-%m-%d"),
        "days_left": days_left,
        "risk": risk,
        "advice": advice,
        "pq_kex": pq,
    }


def _safe_scan(host):
    try:
        return scan_site(host)
    except Exception:
        return {
            "host": host,
            "algorithm": "Unreachable",
            "key_size": None,
            "tls_version": "-",
            "expires": "-",
            "days_left": None,
            "risk": "Unreachable",
            "advice": "Could not connect on port 443.",
            "pq_kex": None,
        }


def scan_many(hosts):
    with ThreadPoolExecutor(max_workers=6) as pool:
        return list(pool.map(_safe_scan, hosts))


def build_report_md(rows):
    """One-page markdown report from a list of scan results."""
    reachable = [r for r in rows if r["risk"] != "Unreachable"]
    exposed = [r for r in reachable if r["risk"] in ("High", "Critical")]
    lines = [
        "# Quantum Readiness Report",
        "",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "",
        "## Summary",
        "",
        f"- Sites checked: {len(rows)}",
        f"- Reachable: {len(reachable)}",
        f"- Using RSA or elliptic-curve keys (quantum-vulnerable): {len(exposed)}",
        f"- Critical (RSA below 2048 bits): {sum(r['risk'] == 'Critical' for r in rows)}",
        f"- Post-quantum key exchange observed: {sum(r.get('pq_kex') is True for r in reachable)}",
        "",
        "## Results",
        "",
        "| Website | Key type | Key size | TLS | PQ key exchange | Expires | Risk | Score (of 100) |",
        "|---------|----------|----------|-----|-----------------|---------|------|----------------|",
    ]
    for r in rows:
        size = r["key_size"] if r["key_size"] else "n/a"
        lines.append(
            f"| {r['host']} | {r['algorithm']} | {size} | {r['tls_version']} | "
            f"{PQ_LABEL[r.get('pq_kex')]} | {r['expires']} | {r['risk']} | {readiness_score(r) if readiness_score(r) is not None else '-'} |"
        )
    lines += ["", "## Action plan per site", ""]
    for r in rows:
        lines.append(f"**{r['host']}**")
        for pr, text in fix_plan(r):
            lines.append(f"- {pr}: {text}")
        lines.append("")
    lines += [
        "",
        "## What this means",
        "",
        "RSA and elliptic-curve cryptography can be broken by a large, error-corrected "
        "quantum computer running Shor's algorithm. Such machines do not exist yet, but "
        "attackers can record encrypted traffic today and decrypt it later.",
        "",
        "## Recommended actions",
        "",
        "1. Inventory where RSA and elliptic-curve keys are used.",
        "2. Move key exchange to post-quantum algorithms (for example ML-KEM).",
        "3. Move signatures to post-quantum algorithms (for example ML-DSA).",
        "4. Replace any RSA key under 2048 bits immediately.",
        "",
        "## Method and limits",
        "",
        "The tool connects to each site on port 443 and reads the public key type in the "
        "server certificate. It also sends a TLS 1.3 handshake offer that lists a hybrid "
        "post-quantum group (X25519MLKEM768) and records which group the server picks. "
        "'No' means the server did not pick one in this probe; some servers enable it only "
        "for certain clients, so treat 'No' as 'not observed'.",
    ]
    return "\n".join(lines)


# ---- Offline safety net: a saved copy of a scan, for demos when the Wi-Fi fails ----
SNAPSHOT_FILE = "last_scan.json"


def _row(host, algo, size, tls, expires, pq, risk="High"):
    return {"host": host, "algorithm": algo, "key_size": size, "tls_version": tls,
            "expires": expires, "days_left": None, "risk": risk, "advice": "", "pq_kex": pq}


# Results from the verified live run on 2026-10-04 (copied from the downloaded report).
BUILTIN_SNAPSHOT = {
    "saved_at": "2026-10-04 (verified run, built in)",
    "rows": [
        _row("sbi.co.in", "RSA", 2048, "TLSv1.3", "2026-12-31", False),
        _row("sbi.bank.in", "RSA", 2048, "TLSv1.3", "2027-02-28", False),
        _row("hdfcbank.com", "RSA", 2048, "TLSv1.3", "2027-01-15", True),
        _row("icicibank.com", "RSA", 2048, "TLSv1.3", "2026-12-20", False),
        _row("iitr.ac.in", "RSA", 4096, "TLSv1.2", "2027-02-08", None),
        {"host": "india.gov.in", "algorithm": "Unreachable", "key_size": None,
         "tls_version": "-", "expires": "-", "days_left": None, "risk": "Unreachable",
         "advice": "Could not connect on port 443.", "pq_kex": None},
        _row("google.com", "ECC", 256, "TLSv1.3", "2026-12-11", True),
        _row("github.com", "ECC", 256, "TLSv1.3", "2026-11-29", False),
        _row("wikipedia.org", "ECC", 256, "TLSv1.3", "2026-11-03", True),
        _row("cloudflare.com", "ECC", 256, "TLSv1.3", "2026-12-04", True),
        _row("amazon.in", "RSA", 2048, "TLSv1.3", "2027-02-24", False),
    ],
}


def save_snapshot(rows):
    """Remember the latest live scan on disk. Never raises."""
    try:
        with open(SNAPSHOT_FILE, "w", encoding="utf-8") as f:
            json.dump({"saved_at": datetime.now().strftime("%Y-%m-%d %H:%M"), "rows": rows}, f)
    except Exception:
        pass


def _with_days_left(rows):
    """Recompute 'days_left' from the expiry date so an old snapshot still shows a sensible number."""
    out = []
    for r in rows:
        r = dict(r)
        try:
            exp = datetime.strptime(r["expires"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            r["days_left"] = (exp - datetime.now(timezone.utc)).days
        except Exception:
            pass
        out.append(r)
    return out


def load_snapshot():
    """Return (rows, saved_at): the last saved live scan, or the built-in verified one."""
    try:
        if os.path.exists(SNAPSHOT_FILE):
            with open(SNAPSHOT_FILE, encoding="utf-8") as f:
                data = json.load(f)
            return _with_days_left(data["rows"]), data["saved_at"]
    except Exception:
        pass
    return _with_days_left(BUILTIN_SNAPSHOT["rows"]), BUILTIN_SNAPSHOT["saved_at"]