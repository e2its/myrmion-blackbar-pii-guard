"""
bb_crypto.py
============
Zero-dependency authenticated encryption for *reversible* PII tokens.

The default anonymization operators (replace / redact / mask / hash) are
one-way: once applied, the original value is gone. The `encrypt` operator is the
exception — it produces a self-describing token that can be turned back into the
original value later with the same key. This module implements that token.

Token format (the inner payload is base64url without padding), wrapped as:

    <ENC:ENTITY_TYPE:payload>

where the raw payload bytes are:

    MAGIC(1) | salt(16) | nonce(12) | ciphertext(N) | tag(16)

Construction (encrypt-then-MAC over an HMAC keystream — "AES-free" so it works
on stdlib alone):

    dk        = PBKDF2-HMAC-SHA256(key, salt, ITERATIONS, dklen=64)
    enc_key   = dk[:32]            # keystream key
    mac_key   = dk[32:]            # authentication key
    keystream = HMAC-SHA256(enc_key, nonce || be32(0)) || HMAC(..., be32(1)) ...
    ciphertext= plaintext XOR keystream
    tag       = HMAC-SHA256(mac_key, MAGIC || salt || nonce || ciphertext)[:16]

The exact same scheme is implemented in `desktop/server/index.js`, so a token
produced by Claude Code decrypts in Claude Desktop and vice-versa. The entity
type in the wrapper is a human-readable hint only; it is not authenticated and
is ignored on decrypt (the payload alone determines the plaintext).

Security notes
--------------
- The salt is shared across all tokens of a single `encrypt` call (one PBKDF2
  per call), but every token gets a fresh random nonce, so identical plaintexts
  never produce identical ciphertext and the keystream is never reused.
- Authentication is mandatory: a wrong key or a tampered token raises, rather
  than returning garbage.
- This is pseudonymization to keep PII out of the model, not a vault. Treat the
  key like a password and keep it out of prompts, logs, and the repo.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
from functools import lru_cache

MAGIC = b"\x01"
ITERATIONS = 200_000
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16

# <ENC:ENTITY_TYPE:base64url-payload>
TOKEN_RE = re.compile(r"<ENC:([A-Z0-9_]+):([A-Za-z0-9_\-]+)>")


# --------------------------------------------------------------------------- #
# base64url helpers (no padding, to keep tokens compact and URL/regex-safe)
# --------------------------------------------------------------------------- #
def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --------------------------------------------------------------------------- #
# Core primitives
# --------------------------------------------------------------------------- #
@lru_cache(maxsize=256)
def _derive(key: str, salt: bytes) -> tuple[bytes, bytes]:
    """Stretch the passphrase into (enc_key, mac_key). Cached per (key, salt)
    so a whole document encrypted/decrypted under one salt pays PBKDF2 once."""
    dk = hashlib.pbkdf2_hmac("sha256", key.encode("utf-8"), salt, ITERATIONS, dklen=64)
    return dk[:32], dk[32:]


def _keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hmac.new(
            enc_key, nonce + counter.to_bytes(4, "big"), hashlib.sha256
        ).digest()
        out += block
        counter += 1
    return bytes(out[:length])


def _xor(data: bytes, stream: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, stream))


def new_salt() -> bytes:
    """A fresh salt to share across one encrypt call's tokens."""
    return os.urandom(SALT_LEN)


# --------------------------------------------------------------------------- #
# Value-level encrypt / decrypt
# --------------------------------------------------------------------------- #
def encrypt_value(plaintext: str, key: str, *, salt: bytes | None = None) -> str:
    """Return the base64url payload (without the <ENC:...> wrapper)."""
    if not key:
        raise ValueError("encrypt requires a non-empty key")
    salt = salt if salt is not None else new_salt()
    nonce = os.urandom(NONCE_LEN)
    enc_key, mac_key = _derive(key, salt)
    pt = plaintext.encode("utf-8")
    ct = _xor(pt, _keystream(enc_key, nonce, len(pt)))
    tag = hmac.new(mac_key, MAGIC + salt + nonce + ct, hashlib.sha256).digest()[:TAG_LEN]
    return _b64encode(MAGIC + salt + nonce + ct + tag)


def decrypt_value(payload: str, key: str) -> str:
    """Reverse encrypt_value. Raises ValueError on a wrong key/corrupt token."""
    if not key:
        raise ValueError("decrypt requires a non-empty key")
    raw = _b64decode(payload)
    if len(raw) < 1 + SALT_LEN + NONCE_LEN + TAG_LEN or raw[:1] != MAGIC:
        raise ValueError("unrecognized token")
    salt = raw[1 : 1 + SALT_LEN]
    nonce = raw[1 + SALT_LEN : 1 + SALT_LEN + NONCE_LEN]
    tag = raw[-TAG_LEN:]
    ct = raw[1 + SALT_LEN + NONCE_LEN : -TAG_LEN]
    enc_key, mac_key = _derive(key, salt)
    expected = hmac.new(mac_key, MAGIC + salt + nonce + ct, hashlib.sha256).digest()[:TAG_LEN]
    if not hmac.compare_digest(tag, expected):
        raise ValueError("authentication failed (wrong key or corrupted token)")
    return _xor(ct, _keystream(enc_key, nonce, len(ct))).decode("utf-8")


def make_token(entity_type: str, plaintext: str, key: str, salt: bytes) -> str:
    return f"<ENC:{entity_type}:{encrypt_value(plaintext, key, salt=salt)}>"


# --------------------------------------------------------------------------- #
# Text-level: encrypt spans into tokens, and restore every token in a string
# --------------------------------------------------------------------------- #
def encrypt_spans(text: str, spans, key: str) -> str:
    """Replace each (start, end, entity_type) span with an <ENC:...> token.

    `spans` must be ordered so that substitutions apply right-to-left (largest
    start first), which keeps earlier offsets valid — the same contract the
    other operators rely on.
    """
    salt = new_salt()
    out = text
    for span in spans:
        original = out[span.start : span.end]
        token = make_token(span.entity_type, original, key, salt)
        out = out[: span.start] + token + out[span.end :]
    return out


def decrypt_text(text: str, key: str) -> tuple[str, int]:
    """Restore every <ENC:...> token in `text`. Returns (text, restored_count).

    Tokens that fail to decrypt (wrong key, corruption) are left untouched so a
    partial/mismatched key does not destroy data."""
    count = 0

    def _repl(match: "re.Match[str]") -> str:
        nonlocal count
        try:
            value = decrypt_value(match.group(2), key)
        except (ValueError, Exception):
            return match.group(0)
        count += 1
        return value

    return TOKEN_RE.sub(_repl, text), count


# --------------------------------------------------------------------------- #
# Self-test:  python3 bb_crypto.py "some secret text"
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    import sys

    sample = " ".join(sys.argv[1:]) or "Ada Lovelace, DNI 12345678Z"
    key = "correct horse battery staple"
    token = make_token("PERSON", sample, key, new_salt())
    wrapped = f"Name: {token} (end)"
    restored, n = decrypt_text(wrapped, key)
    bad, _ = decrypt_text(wrapped, "wrong key")
    print("plaintext :", sample)
    print("token     :", token)
    print("decrypt   :", restored, f"[restored {n}]")
    print("wrong key :", bad)
    assert restored == f"Name: {sample} (end)", "round-trip failed"
    assert token in bad, "wrong key should leave token intact"
    print("OK: round-trip verified")
