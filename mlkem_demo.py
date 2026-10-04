"""Real post-quantum key exchange (ML-KEM-768, NIST FIPS 203) for the Protect tab.
Uses the pure-Python 'kyber-py' library (educational, not for production use).
ML-KEM only agrees a shared key. We then use that key with AES-256-GCM to encrypt a message."""
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from kyber_py.ml_kem import ML_KEM_768


def run_mlkem(message):
    # Bob makes a key pair and publishes the public (encapsulation) key.
    public_key, private_key = ML_KEM_768.keygen()
    # Alice uses Bob's public key to make a shared secret plus a ciphertext to send back.
    alice_secret, kem_ciphertext = ML_KEM_768.encaps(public_key)
    # Bob recovers the same secret with his private key.
    bob_secret = ML_KEM_768.decaps(private_key, kem_ciphertext)

    # Alice encrypts the message with the shared secret.
    nonce = os.urandom(12)
    data = message.encode()
    sealed = AESGCM(alice_secret).encrypt(nonce, data, None)

    # Bob decrypts.
    try:
        bob_plain = AESGCM(bob_secret).decrypt(nonce, sealed, None).decode(errors="replace")
    except InvalidTag:
        bob_plain = None

    # Eve sees the public key, the KEM ciphertext, the nonce and the sealed message.
    # She tries her own private key, which gives her a different, useless secret.
    _, eve_private = ML_KEM_768.keygen()
    eve_secret = ML_KEM_768.decaps(eve_private, kem_ciphertext)
    try:
        AESGCM(eve_secret).decrypt(nonce, sealed, None)
        eve_read = True
    except InvalidTag:
        eve_read = False

    return {
        "public_key_len": len(public_key),
        "kem_ciphertext_len": len(kem_ciphertext),
        "secret_len": len(alice_secret),
        "public_key_hex": public_key[:16].hex() + "...",
        "kem_ciphertext_hex": kem_ciphertext[:16].hex() + "...",
        "alice_secret_hex": alice_secret.hex(),
        "bob_secret_hex": bob_secret.hex(),
        "eve_secret_hex": eve_secret.hex(),
        "secrets_match": alice_secret == bob_secret,
        "sealed_hex": sealed.hex(),
        "bob_plain": bob_plain,
        "eve_read": eve_read,
    }