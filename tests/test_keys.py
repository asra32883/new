import hashlib
from pathlib import Path

import pytest
from sqlalchemy import select

from app.models import UserKey
from tests.conftest import PW, csrf, fake_pub, new_client, register, upload_key

ROOT = Path(__file__).resolve().parent.parent
PRIV = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nenc\n-----END PGP PRIVATE KEY BLOCK-----"


@pytest.fixture
def two(app):
    out = []
    for name in ("alice", "bobby"):
        c = new_client(app)
        out.append((c, csrf(register(c, name))))
    return out


def test_no_key_until_uploaded(two):
    (a, ah), _ = two
    assert a.get("/api/keys/me").status_code == 404
    r = upload_key(a, ah, "a1")
    assert r.status_code == 200 and r.json()["has_server_backup"] is False
    assert a.get("/api/keys/me").json()["public_key"] == fake_pub("a1")


def test_lookup_requires_auth_and_hides_everything_else(two, app):
    (a, ah), (b, bh) = two
    upload_key(a, ah, "a1")
    anon = new_client(app)
    assert anon.get("/api/users/alice/key").status_code == 401
    r = b.get("/api/users/ALICE/key")
    assert r.status_code == 200 and set(r.json()) == {"username", "public_key", "fingerprint"}
    assert b.get("/api/users/bobby/key").status_code == 404          # bobby has no key yet
    assert b.get("/api/users/nobody/key").status_code == 404
    assert b.get("/api/users/" + "a" * 100 + "/key").status_code == 404


@pytest.mark.parametrize("payload", [
    {"public_key": "plain", "fingerprint": "A" * 40},
    {"public_key": fake_pub().replace("PUBLIC", "PRIVATE"), "fingerprint": "A" * 40},
    {"public_key": fake_pub(), "fingerprint": "xyz"},
    {"public_key": fake_pub(), "fingerprint": "A" * 41},
    {"public_key": fake_pub(), "fingerprint": "A" * 40, "encrypted_private_key": "not armored"},
    {"public_key": fake_pub("x" * 40_000), "fingerprint": "A" * 40},
    {"public_key": fake_pub(), "fingerprint": "A" * 40, "extra": 1},
])
def test_key_validation(two, payload):
    (a, ah), _ = two
    # an oversized key is stopped by the body-size cap (413) before field validation (422); both reject it
    assert a.put("/api/keys/me", headers=ah, json=payload).status_code in (413, 422)
    assert a.get("/api/keys/me").status_code == 404


def test_key_endpoints_need_csrf(two):
    (a, ah), _ = two
    body = {"public_key": fake_pub(), "fingerprint": "A" * 40}
    assert a.put("/api/keys/me", json=body).status_code == 403
    upload_key(a, ah, "a1", backup=PRIV)
    assert a.delete("/api/keys/me/backup").status_code == 403


def test_rotation_keeps_one_active_key(two, db):
    (a, ah), (b, bh) = two
    upload_key(a, ah, "a1")
    upload_key(a, ah, "b2")
    rows = list(db.scalars(select(UserKey)))
    assert len(rows) == 2 and sum(k.is_active for k in rows) == 1
    assert b.get("/api/users/alice/key").json()["public_key"] == fake_pub("b2")
    upload_key(a, ah, "a1")                                           # re-activating an old key works
    db.expire_all()
    assert len(list(db.scalars(select(UserKey)))) == 2
    assert a.get("/api/keys/me").json()["public_key"] == fake_pub("a1")


def test_rotation_rate_limited(two):
    (a, ah), _ = two
    codes = [upload_key(a, ah, f"k{i}").status_code for i in range(12)]
    assert codes[:10] == [200] * 10 and codes[10:] == [429, 429]


def test_server_backup_is_opt_in_and_private_to_owner(two):
    (a, ah), (b, bh) = two
    upload_key(a, ah, "a1")
    assert a.get("/api/keys/me/backup").status_code == 404
    assert "encrypted_private_key" not in a.get("/api/keys/me").json()
    r = upload_key(a, ah, "a1", backup=PRIV)
    assert r.json()["has_server_backup"] is True
    assert a.get("/api/keys/me/backup").json() == {"encrypted_private_key": PRIV}
    # nobody else can reach it, and lookups of alice's key never include it
    upload_key(b, bh, "b1")
    assert b.get("/api/keys/me/backup").status_code == 404
    assert PRIV not in b.get("/api/users/alice/key").text
    assert a.delete("/api/keys/me/backup", headers=ah).status_code == 204
    assert a.get("/api/keys/me/backup").status_code == 404
    assert a.get("/api/keys/me").json()["has_server_backup"] is False


def test_reupload_without_backup_removes_server_copy(two):
    (a, ah), _ = two
    upload_key(a, ah, "a1", backup=PRIV)
    upload_key(a, ah, "a1")
    assert a.get("/api/keys/me/backup").status_code == 404


def test_sending_requires_keys_for_sender_and_recipients(two):
    (a, ah), (b, bh) = two
    msg = {"recipients": ["bobby"], "ciphertext": "-----BEGIN PGP MESSAGE-----\nx\n-----END PGP MESSAGE-----"}
    r = a.post("/api/messages", headers=ah, json=msg)
    assert r.status_code == 409 and "your encryption key" in r.json()["detail"]
    upload_key(a, ah, "a1")
    r = a.post("/api/messages", headers=ah, json=msg)
    assert r.status_code == 409 and "bobby" in r.json()["detail"]
    assert b.get("/api/mailbox/inbox").json()["items"] == []
    upload_key(b, bh, "b1")
    assert a.post("/api/messages", headers=ah, json=msg).status_code == 201


def test_account_deletion_removes_keys_and_backup(two, db):
    (a, ah), _ = two
    upload_key(a, ah, "a1", backup=PRIV)
    assert a.post("/api/account/delete", headers=ah, json={"password": PW}).status_code == 204
    assert db.scalar(select(UserKey)) is None


# ---- vendored crypto library integrity -----------------------------------------------------------------


def test_vendored_openpgp_matches_pinned_hash():
    vendor = ROOT / "app" / "static" / "vendor"
    for line in (vendor / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split()
        assert hashlib.sha256((vendor / name).read_bytes()).hexdigest() == digest, f"{name} was modified"
    assert b"OpenPGP.js v6.3.2" in (vendor / "openpgp.min.js").read_bytes()[:200]
