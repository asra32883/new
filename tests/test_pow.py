import time

import pytest

from app.security import pow as powmod

K = b"s" * 32


def test_roundtrip():
    ch = powmod.issue(K, 10)
    cid, exp = powmod.verify(K, ch, powmod.solve(ch))
    assert cid and exp > time.time()


def _insufficient(ch, bits):
    import hashlib
    for i in range(1000):
        n = format(i, "x")
        if powmod.leading_zero_bits(hashlib.sha256(f"{ch}:{n}".encode()).digest()) < bits:
            return n
    raise AssertionError("no failing nonce found")


def test_wrong_nonce_tampered_expired_and_foreign_key():
    ch = powmod.issue(K, 12)
    good = powmod.solve(ch)
    with pytest.raises(powmod.PowError):
        powmod.verify(K, ch, _insufficient(ch, 12))
    body, sig = ch.split(".")
    with pytest.raises(powmod.PowError):
        powmod.verify(K, body + "x." + sig, good)
    with pytest.raises(powmod.PowError):
        powmod.verify(K, ch, good, now=time.time() + 10_000)
    with pytest.raises(powmod.PowError):
        powmod.verify(b"o" * 32, ch, good)
    with pytest.raises(powmod.PowError):
        powmod.verify(K, "garbage", good)
    with pytest.raises(powmod.PowError):
        powmod.verify(K, ch, "../../")


def test_difficulty_cannot_be_downgraded_by_client():
    ch = powmod.issue(K, 16)
    body, sig = ch.split(".")
    import base64, json
    forged = json.loads(base64.urlsafe_b64decode(body + "=="))
    forged["d"] = 0
    fbody = base64.urlsafe_b64encode(json.dumps(forged).encode()).rstrip(b"=").decode()
    with pytest.raises(powmod.PowError):
        powmod.verify(K, f"{fbody}.{sig}", "0")
