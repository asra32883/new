"""Hashcash-style proof of work for registration.

The server signs {random id, expiry, difficulty} with HMAC. The client finds a nonce such that
SHA-256("<challenge>:<nonce>") has at least `difficulty` leading zero bits. Challenges are single
use (the id is recorded by the caller) and expire. No IP address or third-party service is involved.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time

TTL_SECONDS = 600
_NONCE_RE = re.compile(r"^[A-Za-z0-9]{1,32}$")


class PowError(Exception):
    pass


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _sign(secret: bytes, body: str) -> str:
    return _b64(hmac.new(secret, body.encode(), hashlib.sha256).digest())


def issue(secret: bytes, bits: int, now: float | None = None) -> str:
    now = time.time() if now is None else now
    payload = {"r": secrets.token_hex(8), "e": int(now) + TTL_SECONDS, "d": bits}
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    return f"{body}.{_sign(secret, body)}"


def leading_zero_bits(digest: bytes) -> int:
    n = 0
    for byte in digest:
        if byte == 0:
            n += 8
            continue
        return n + 8 - byte.bit_length()
    return n


def verify(secret: bytes, challenge: str, nonce: str, now: float | None = None) -> tuple[str, int]:
    """Returns (challenge_id, expiry_unix). Raises PowError on any problem."""
    now = time.time() if now is None else now
    try:
        body, sig = challenge.split(".", 1)
    except ValueError:
        raise PowError("malformed") from None
    if not hmac.compare_digest(sig, _sign(secret, body)):
        raise PowError("bad signature")
    try:
        payload = json.loads(_unb64(body))
        cid, expiry, bits = str(payload["r"]), int(payload["e"]), int(payload["d"])
    except (ValueError, KeyError, TypeError):
        raise PowError("malformed") from None
    if now > expiry:
        raise PowError("expired")
    if not _NONCE_RE.match(nonce):
        raise PowError("bad nonce")
    digest = hashlib.sha256(f"{challenge}:{nonce}".encode()).digest()
    if leading_zero_bits(digest) < bits:
        raise PowError("insufficient work")
    return cid, expiry


def solve(challenge: str) -> str:
    """Reference solver (used by tests; the browser has an equivalent in JS)."""
    bits = json.loads(_unb64(challenge.split(".", 1)[0]))["d"]
    n = 0
    while True:
        nonce = format(n, "x")
        digest = hashlib.sha256(f"{challenge}:{nonce}".encode()).digest()
        if leading_zero_bits(digest) >= bits:
            return nonce
        n += 1
