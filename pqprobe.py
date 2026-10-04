"""Detect whether a server picks a post-quantum (hybrid ML-KEM) key exchange in TLS 1.3.

We send a TLS 1.3 ClientHello that lists X25519MLKEM768 as our preferred group but only
includes a classical X25519 key share. A server that supports and prefers the hybrid group
answers with a HelloRetryRequest naming that group; otherwise it picks a classical group.
Either way the reply's key_share extension starts with the chosen group id.
Pure Python (socket + cryptography). Never raises: returns True, False or None (unknown)."""
import os
import socket
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

PQ_GROUPS = {0x11EC, 0x11EB, 0x11ED, 0x6399}  # X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024, Kyber draft
X25519, SECP256R1, HYBRID = 0x001D, 0x0017, 0x11EC


def _ext(t, data):
    return struct.pack("!HH", t, len(data)) + data


def _u16_list(values):
    return struct.pack("!H", 2 * len(values)) + b"".join(struct.pack("!H", v) for v in values)


def build_client_hello(host):
    name = host.encode()
    pub = X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key_share = struct.pack("!HH", X25519, 32) + pub
    exts = b"".join([
        _ext(0x0000, struct.pack("!HBH", len(name) + 3, 0, len(name)) + name),   # server_name
        _ext(0x000A, _u16_list([HYBRID, X25519, SECP256R1])),                   # supported_groups
        _ext(0x000D, _u16_list([0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601])),
        _ext(0x002B, b"\x02\x03\x04"),                                           # TLS 1.3
        _ext(0x002D, b"\x01\x01"),                                               # psk modes
        _ext(0x0033, struct.pack("!H", len(key_share)) + key_share),             # key_share
    ])
    body = (b"\x03\x03" + os.urandom(32) + b"\x20" + os.urandom(32)
            + _u16_list([0x1301, 0x1302, 0x1303]) + b"\x01\x00"
            + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def parse_server_hello(data):
    """Return the chosen group id (int), 0 if the server did not use TLS 1.3, or None if unreadable."""
    if len(data) < 9 or data[0] != 0x16 or data[5] != 0x02:
        return None
    p = 9 + 2 + 32                      # record hdr(5) + hs hdr(4) + version + random
    p += 1 + data[p]                    # session id
    p += 2 + 1                          # cipher suite + compression
    ext_end = p + 2 + struct.unpack("!H", data[p:p + 2])[0]
    p += 2
    while p + 4 <= min(ext_end, len(data)):
        t, n = struct.unpack("!HH", data[p:p + 4])
        if t == 0x0033 and n >= 2:
            return struct.unpack("!H", data[p + 4:p + 6])[0]
        p += 4 + n
    return 0


def probe_pq_kex(host, timeout=6, port=443):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(build_client_hello(host))
            data = b""
            while len(data) < 5:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            if len(data) >= 5:
                need = 5 + struct.unpack("!H", data[3:5])[0]
                while len(data) < need:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
        group = parse_server_hello(data)
        if group is None:
            return None
        return group in PQ_GROUPS
    except Exception:
        return None