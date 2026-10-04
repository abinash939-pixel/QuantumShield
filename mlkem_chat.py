"""Live ML-KEM encrypted chat: Alice, Bob and Eve in separate browser tabs or devices.

How it works
  Bob   makes an ML-KEM-768 key pair and publishes the PUBLIC key.
  Alice uses that public key to create a shared secret + a 1088-byte KEM ciphertext.
  Bob   opens the KEM ciphertext with his PRIVATE key and gets the same 32-byte secret.
  Both  use that secret as an AES-256-GCM key. Only encrypted bytes go on the "wire".
  Eve   sees the wire (public key, KEM ciphertext, encrypted messages) but has no key.

Demo limits: one Streamlit server relays everything and keeps each browser session's keys
in its memory, so this shows the protocol, not a hardened deployment. kyber-py is an
educational library, not audited or constant-time.
"""
import os
import threading

import streamlit as st
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from kyber_py.ml_kem import ML_KEM_768


# ----------------------------------------------------------------------------- the "network"
class ChatRoom:
    """Everything that travels between people. Shared by all browser sessions on this server."""

    def __init__(self):
        self._lock = threading.Lock()
        self.epoch = 0                # changes whenever Bob publishes new keys or the room resets
        self.public_key = None        # Bob's ML-KEM public key
        self.kem_ciphertext = None    # Alice's ML-KEM ciphertext (carries the shared secret)
        self.wire = []                # encrypted chat messages

    def reset(self):
        with self._lock:
            self.epoch += 1
            self.public_key = None
            self.kem_ciphertext = None
            self.wire = []

    def publish_public_key(self, ek):
        with self._lock:
            self.epoch += 1
            self.public_key = ek
            self.kem_ciphertext = None
            self.wire = []
            return self.epoch

    def post_kem_ciphertext(self, epoch, ct):
        with self._lock:
            if epoch != self.epoch or self.public_key is None:
                return False
            self.kem_ciphertext = ct
            return True

    def post_message(self, epoch, sender, nonce, ct):
        with self._lock:
            if epoch != self.epoch:
                return False
            self.wire.append({"sender": sender, "nonce": nonce, "ct": ct})
            return True

    def tamper_last(self):
        """Eve flips one bit of the newest encrypted message."""
        with self._lock:
            if not self.wire:
                return False
            m = self.wire[-1]
            b = bytearray(m["ct"])
            b[0] ^= 1
            m["ct"] = bytes(b)
            return True

    def snapshot(self):
        with self._lock:
            return self.epoch, self.public_key, self.kem_ciphertext, [dict(m) for m in self.wire]


@st.cache_resource
def get_room():
    return ChatRoom()


# ----------------------------------------------------------------------------- encryption
def encrypt_message(key, sender, text):
    nonce = os.urandom(12)
    return nonce, AESGCM(key).encrypt(nonce, text.encode("utf-8"), sender.encode("utf-8"))


def decrypt_message(key, sender, nonce, ct):
    """Plain text, or None if the key is wrong or the message was altered."""
    try:
        return AESGCM(key).decrypt(nonce, ct, sender.encode("utf-8")).decode("utf-8")
    except (InvalidTag, UnicodeDecodeError, ValueError):
        return None


# ----------------------------------------------------------------------------- per-session steps
def _sync(role):
    """Read the room; forget stale keys; let Bob open Alice's KEM ciphertext when it arrives."""
    ss = st.session_state
    epoch, ek, kem_ct, wire = get_room().snapshot()
    if ss.get("chat_epoch") != epoch:
        ss.pop("chat_dk", None)
        ss.pop("chat_key", None)
        ss["chat_epoch"] = epoch
    if role == "Bob" and "chat_dk" in ss and "chat_key" not in ss and kem_ct is not None:
        ss["chat_key"] = ML_KEM_768.decaps(ss["chat_dk"], kem_ct)
    return epoch, ek, kem_ct, wire


def bob_make_keys():
    ss = st.session_state
    ek, dk = ML_KEM_768.keygen()
    epoch = get_room().publish_public_key(ek)
    ss["chat_dk"] = dk
    ss.pop("chat_key", None)
    ss["chat_epoch"] = epoch


def alice_make_shared_key():
    """Returns 'ok', 'no_public_key' or 'room_changed'."""
    ss = st.session_state
    room = get_room()
    epoch, ek, _, _ = room.snapshot()
    if ek is None:
        return "no_public_key"
    key, kem_ct = ML_KEM_768.encaps(ek)
    if not room.post_kem_ciphertext(epoch, kem_ct):
        return "room_changed"
    ss["chat_key"] = key
    ss["chat_epoch"] = epoch
    return "ok"


def send_message(role, text):
    ss = st.session_state
    key = ss.get("chat_key")
    if key is None:
        return False
    nonce, ct = encrypt_message(key, role, text)
    return get_room().post_message(ss["chat_epoch"], role, nonce, ct)


# ----------------------------------------------------------------------------- screen
def _live_view_body(role):
    """Status line and message list. Reruns by itself every 2 seconds."""
    ss = st.session_state
    epoch, ek, kem_ct, wire = _sync(role)
    key = ss.get("chat_key")
    if (key is not None) != ss.get("chat_ui_key_ready"):
        st.rerun()  # the key just appeared or vanished, so redraw the whole page

    if ek is None:
        st.info("Step 1: Bob presses **Make my keys**.")
    elif kem_ct is None:
        st.info("Step 2: Alice presses **Create shared key**.")
    else:
        st.success(f"Shared key agreed with ML-KEM. Public key {len(ek)} bytes, "
                   f"KEM ciphertext {len(kem_ct)} bytes. Everything below travels encrypted.")

    if role == "Eve":
        st.write("**What Eve captured from the wire**")
        if ek is not None:
            st.caption(f"Bob's public key ({len(ek)} bytes): {ek.hex()[:48]}...")
        if kem_ct is not None:
            st.caption(f"Alice's KEM ciphertext ({len(kem_ct)} bytes): {kem_ct.hex()[:48]}...")
        for m in wire:
            st.code(f"{m['sender']}: {m['ct'].hex()[:64]}...", language=None)
        if wire:
            st.warning("Eve has no key. To read these she would have to break ML-KEM.")
        return

    for m in wire:
        who = m["sender"]
        with st.chat_message("user" if who == "Alice" else "assistant"):
            text = decrypt_message(key, who, m["nonce"], m["ct"]) if key is not None else None
            if text is None:
                st.error(f"{who}: message rejected. It was altered on the way, or the key does not match.")
            else:
                st.write(f"**{who}:** {text}")
            st.caption(f"On the wire: {m['ct'].hex()[:40]}...")


_live_view = st.fragment(run_every=2)(_live_view_body) if hasattr(st, "fragment") else _live_view_body


def render_mlkem_chat(require_toggle=False):
    ss = st.session_state
    room = get_room()
    st.subheader("Live encrypted chat (ML-KEM)")
    st.caption("Open this page in two or three browser tabs (or on devices on the same Wi-Fi). "
               "Pick a different role in each: Bob, Alice and Eve.")
    if require_toggle and not st.toggle("Join the live chat (this page then refreshes every 2 seconds)",
                                        key="chat_on"):
        st.caption("Off by default so the rest of the app is never interrupted. Turn it on in each "
                   "browser tab or device that takes part in the chat.")
        return
    role = st.radio("I am", ["Bob", "Alice", "Eve"], horizontal=True, key="chat_role")
    _sync(role)

    if role == "Bob":
        if st.button("Make my keys (Bob)", key="chat_bob_keys"):
            bob_make_keys()
            st.rerun()
    elif role == "Alice":
        if st.button("Create shared key (Alice)", key="chat_alice_key"):
            result = alice_make_shared_key()
            if result == "no_public_key":
                st.warning("Bob has not made his keys yet. Ask Bob to press the button first.")
            elif result == "room_changed":
                st.warning("Bob changed his keys just now. Press the button again.")
            else:
                st.rerun()
    else:
        if st.button("Tamper with the newest message (Eve)", key="chat_eve_tamper"):
            if not room.tamper_last():
                st.warning("There is no message to tamper with yet.")

    key = ss.get("chat_key")
    ss["chat_ui_key_ready"] = key is not None
    if role in ("Alice", "Bob") and key is not None:
        with st.form("chat_form", clear_on_submit=True):
            text = st.text_input("Message", key="chat_text")
            sent = st.form_submit_button("Send")
        if sent and text.strip():
            if not send_message(role, text.strip()):
                st.warning("The room was reset. Start again from step 1.")

    _live_view(role)

    if st.button("Reset the room", key="chat_reset"):
        room.reset()
        for k in ("chat_dk", "chat_key"):
            ss.pop(k, None)
        st.rerun()
    with st.expander("Honest limits of this demo"):
        st.write("One Streamlit server relays every message and keeps each browser session's keys "
                 "in its memory, so this shows the protocol rather than a hardened product. "
                 "The room only ever holds public data and ciphertext. The ML-KEM library "
                 "(kyber-py) is educational, not audited.")