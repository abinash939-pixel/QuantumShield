"""Encrypt and decrypt a file with ML-KEM-768 (key agreement) + AES-256-GCM (the file itself).
Package layout: 2-byte length of the KEM ciphertext, the KEM ciphertext, 12-byte nonce, sealed data."""
import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from kyber_py.ml_kem import ML_KEM_768


def encrypt_file(data):
    """Bob's key pair is made here; Alice encrypts the file for Bob's public key."""
    public_key, private_key = ML_KEM_768.keygen()
    secret, kem_ct = ML_KEM_768.encaps(public_key)
    nonce = os.urandom(12)
    sealed = AESGCM(secret).encrypt(nonce, data, None)
    package = len(kem_ct).to_bytes(2, "big") + kem_ct + nonce + sealed
    return {
        "private_key": private_key,
        "package": package,
        "sha256": hashlib.sha256(data).hexdigest(),
        "kem_ct_len": len(kem_ct),
    }


def tamper(package):
    """Flip one bit near the end (inside the encrypted data) to simulate tampering."""
    b = bytearray(package)
    b[-1] ^= 1
    return bytes(b)


def decrypt_package(private_key, package):
    """Returns the original bytes, or None if the file was changed or the key is wrong."""
    try:
        n = int.from_bytes(package[:2], "big")
        kem_ct = package[2:2 + n]
        nonce = package[2 + n:14 + n]
        sealed = package[14 + n:]
        secret = ML_KEM_768.decaps(private_key, kem_ct)
        return AESGCM(secret).decrypt(nonce, sealed, None)
    except (InvalidTag, ValueError):
        return None