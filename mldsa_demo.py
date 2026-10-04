"""Post-quantum digital signatures (ML-DSA-65, NIST FIPS 204) for the Protect tab.
Uses the pure-Python 'dilithium-py' library (educational, not for production use)."""
from dilithium_py.ml_dsa import ML_DSA_65


def sign_message(message):
    """Alice makes a key pair and signs the message. Returns what Bob would receive."""
    public_key, secret_key = ML_DSA_65.keygen()
    data = message.encode()
    signature = ML_DSA_65.sign(secret_key, data)
    # Eve signs a forged message with her OWN key, hoping Bob accepts it.
    _, eve_secret = ML_DSA_65.keygen()
    forged_text = "Send all money to Eve"
    forged_sig = ML_DSA_65.sign(eve_secret, forged_text.encode())
    return {
        "message": message,
        "public_key": public_key,
        "signature": signature,
        "forged_text": forged_text,
        "forged_sig": forged_sig,
    }


def check(public_key, message, signature):
    """True only if the signature matches this exact message and this public key."""
    try:
        return bool(ML_DSA_65.verify(public_key, message.encode(), signature))
    except Exception:
        return False