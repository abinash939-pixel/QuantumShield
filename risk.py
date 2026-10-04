"""Readiness score and the 'harvest now, decrypt later' check. Pure Python."""


def readiness_score(r):
    """0-100 readiness score for one scan result (our own simple rubric, not a standard).
    Certificate key up to 40, TLS version up to 20, post-quantum key exchange up to 40.
    RSA/ECC certificates can never earn full marks. Key exchange earns points only when
    the scan result has pq_kex=True (not detected yet, so it counts as 0 for now)."""
    if r["risk"] == "Unreachable":
        return None
    algo, size = r["algorithm"], r["key_size"] or 0
    if algo == "RSA":
        cert = 0 if size < 2048 else (15 if size >= 3072 else 10)
    elif algo == "ECC":
        cert = 15 if size >= 384 else 10
    elif algo == "EdDSA":
        cert = 10
    else:
        cert = 0
    tls = {"TLSv1.3": 20, "TLSv1.2": 10}.get(r["tls_version"], 0)
    return cert + tls + (40 if r.get("pq_kex") else 0)


def harvest_verdict(secret_years, migrate_years, quantum_years):
    """Mosca's rule: data is at risk if (years it must stay secret) + (years to migrate)
    is more than (years until a code-breaking quantum computer exists)."""
    need = secret_years + migrate_years
    return {
        "need": need,
        "at_risk": need > quantum_years,
        "gap": need - quantum_years,           # years of exposure if positive
        "migrate_deadline": quantum_years - secret_years,  # finish migrating within this
    }