import logging
from datetime import timedelta

from sqlalchemy import select, text

from app.models import Folder, RateLimit, User, UserSession, utcnow
from tests.conftest import PW, csrf, new_client, register


def test_register_success_cookie_flags_and_storage(client, db):
    r = register(client)
    assert r.status_code == 201 and r.json()["username"] == "alice"
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "path=/" in cookie
    user = db.scalar(select(User))
    assert user.password_hash.startswith("$argon2id$") and PW not in user.password_hash
    assert {f.kind for f in db.scalars(select(Folder))} == {"inbox", "sent", "trash"}
    # raw token is never stored
    token = client.cookies.get("tm_session")
    assert token and all(token != s.token_hash for s in db.scalars(select(UserSession)))
    assert db.scalar(text("select count(*) from sessions where token_hash like :t"), {"t": f"%{token}%"}) == 0


def test_secure_cookie_uses_host_prefix(settings, tmp_path):
    from fastapi.testclient import TestClient
    from app.main import create_app
    from app.models import Base
    s = settings.model_copy(update={"cookie_secure": True})
    a = create_app(s)
    Base.metadata.drop_all(a.state.engine)
    Base.metadata.create_all(a.state.engine)
    c = TestClient(a, base_url="https://testserver")
    r = register(c)
    assert r.headers["set-cookie"].startswith("__Host-tm_session=") and "Secure" in r.headers["set-cookie"]


def test_username_case_insensitive_unique(client, app):
    assert register(client, "Alice").status_code == 201
    r = register(new_client(app), "alice")
    assert r.status_code == 409 and r.json()["detail"] == "Username unavailable"


def test_weak_password_rejected_and_not_echoed(client):
    r = register(client, "bob", "short")
    assert r.status_code == 422 and "short" not in r.text.replace("at least", "").replace("shortest", "")
    r = register(client, "bob", "password1234")
    assert r.status_code == 422 and "password1234" not in r.text


def test_registration_requires_valid_single_use_pow(client):
    body = {"username": "carol", "password": PW, "pow_challenge": "x.y", "pow_nonce": "0"}
    assert client.post("/api/auth/register", json=body).status_code == 400
    from app.security import pow as powmod
    ch = client.get("/api/auth/pow-challenge").json()["challenge"]
    good = {"username": "carol", "password": PW, "pow_challenge": ch, "pow_nonce": powmod.solve(ch)}
    assert client.post("/api/auth/register", json=good).status_code == 201
    replay = {**good, "username": "carol2"}
    assert client.post("/api/auth/register", json=replay).status_code == 400


def test_registration_global_cap(app, settings):
    app.state.settings = settings.model_copy(update={"register_global_per_hour": 2})
    for n in range(2):
        assert register(new_client(app), f"user{n}").status_code == 201
    r = register(new_client(app), "user9")
    assert r.status_code == 429 and "retry-after" in r.headers


def test_unknown_fields_rejected(client):
    assert client.post("/api/auth/login", json={"username": "a", "password": "b", "admin": True}).status_code == 422


def test_login_logout_and_session_invalidation(client, app):
    register(client)
    c2 = new_client(app)
    r = c2.post("/api/auth/login", json={"username": "ALICE", "password": PW})
    assert r.status_code == 200 and c2.get("/api/auth/me").json()["username"] == "alice"
    old_cookie = c2.cookies.get("tm_session")
    assert c2.post("/api/auth/logout").status_code == 403          # CSRF required
    assert c2.post("/api/auth/logout", headers=csrf(r)).status_code == 204
    c2.cookies.set("tm_session", old_cookie)                         # replay the old cookie
    assert c2.get("/api/auth/me").status_code == 401


def test_csrf_token_is_bound_to_session(client, app):
    r1 = register(client)
    c2 = new_client(app)
    r2 = c2.post("/api/auth/login", json={"username": "alice", "password": PW})
    assert r1.json()["csrf_token"] != r2.json()["csrf_token"]
    assert c2.post("/api/auth/logout", headers=csrf(r1)).status_code == 403
    assert c2.post("/api/auth/logout", headers={"X-CSRF-Token": ""}).status_code == 403


def test_login_errors_are_indistinguishable(client, app):
    register(client)
    c = new_client(app)
    a = c.post("/api/auth/login", json={"username": "alice", "password": "wrong-password-1"})
    b = c.post("/api/auth/login", json={"username": "nobody", "password": "wrong-password-1"})
    d = c.post("/api/auth/login", json={"username": "!!bad name!!", "password": "x"})
    assert a.status_code == b.status_code == d.status_code == 401
    assert a.json() == b.json() == d.json()


def test_bruteforce_lockout_applies_even_with_correct_password_then_resets(client, app, db):
    register(client)
    c = new_client(app)
    for _ in range(5):
        assert c.post("/api/auth/login", json={"username": "alice", "password": "nope-nope-nope"}).status_code == 401
    r = c.post("/api/auth/login", json={"username": "alice", "password": PW})
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
    # unknown users are throttled identically (no existence oracle)
    for _ in range(5):
        c.post("/api/auth/login", json={"username": "ghost", "password": "nope-nope-nope"})
    assert c.post("/api/auth/login", json={"username": "ghost", "password": "x"}).status_code == 429
    # lock is bounded: after it elapses the correct password works and the counter resets
    for row in db.scalars(select(RateLimit).where(RateLimit.key.like("loginfail:%"))):
        row.window_start = utcnow() - timedelta(minutes=30)
    db.commit()
    assert c.post("/api/auth/login", json={"username": "alice", "password": PW}).status_code == 200
    db.expire_all()
    # alice's failure counter is cleared by the success; only the unknown user's counter remains
    assert len(list(db.scalars(select(RateLimit).where(RateLimit.key.like("loginfail:%"))))) == 1


def test_rate_limit_keys_hold_no_usernames(client, app, db):
    register(client)
    new_client(app).post("/api/auth/login", json={"username": "alice", "password": "nope-nope-nope"})
    keys = [r.key for r in db.scalars(select(RateLimit))]
    assert keys and not any("alice" in k for k in keys)


def test_global_login_budget(app, settings):
    app.state.settings = settings.model_copy(update={"login_global_per_minute": 3})
    c = new_client(app)
    codes = [c.post("/api/auth/login", json={"username": f"u{i}", "password": "x"}).status_code for i in range(5)]
    assert codes[:3] == [401, 401, 401] and codes[3:] == [429, 429]


def test_idle_and_absolute_session_expiry(client, db):
    register(client)
    s = db.scalar(select(UserSession))
    s.last_seen_at = utcnow() - timedelta(minutes=31)
    db.commit()
    assert client.get("/api/auth/me").status_code == 401
    assert db.scalar(select(UserSession)) is None
    register_again = register(client, "alice2")
    assert register_again.status_code == 201
    s = db.scalar(select(UserSession))
    s.expires_at = utcnow() - timedelta(seconds=1)
    db.commit()
    assert client.get("/api/auth/me").status_code == 401


def test_session_activity_extends_idle_window(client, db):
    register(client)
    s = db.scalar(select(UserSession))
    s.last_seen_at = utcnow() - timedelta(minutes=10)
    db.commit()
    assert client.get("/api/auth/me").status_code == 200
    db.expire_all()
    assert utcnow() - db.scalar(select(UserSession)).last_seen_at < timedelta(minutes=1)


def test_login_replaces_presented_session_cookie(client):
    r = register(client)
    old = client.cookies.get("tm_session")
    client.post("/api/auth/login", json={"username": "alice", "password": PW})
    assert client.cookies.get("tm_session") != old
    client.cookies.set("tm_session", old)
    assert client.get("/api/auth/me").status_code == 401


def test_logout_all_and_session_listing(client, app):
    r1 = register(client)
    c2 = new_client(app)
    c2.post("/api/auth/login", json={"username": "alice", "password": PW})
    sessions = client.get("/api/account/sessions").json()
    assert len(sessions) == 2 and sum(s["current"] for s in sessions) == 1
    assert client.post("/api/auth/logout-all", headers=csrf(r1)).status_code == 204
    assert c2.get("/api/auth/me").status_code == 401


def test_cannot_list_or_revoke_other_users_sessions(client, app, db):
    register(client, "alice")
    other = new_client(app)
    ro = register(other, "bobby")
    alice_sid = client.get("/api/account/sessions").json()[0]["id"]
    assert [s["id"] for s in other.get("/api/account/sessions").json()] != [alice_sid]
    assert other.delete(f"/api/account/sessions/{alice_sid}", headers=csrf(ro)).status_code == 404
    assert client.get("/api/auth/me").status_code == 200


def test_password_change_revokes_other_sessions(client, app):
    r1 = register(client)
    c2 = new_client(app)
    c2.post("/api/auth/login", json={"username": "alice", "password": PW})
    new_pw = "another long passphrase 42"
    assert client.post("/api/account/password", headers=csrf(r1),
                       json={"current_password": "wrong-wrong-wrong", "new_password": new_pw}).status_code == 401
    assert client.post("/api/account/password", headers=csrf(r1),
                       json={"current_password": PW, "new_password": new_pw}).status_code == 204
    assert client.get("/api/auth/me").status_code == 200       # this session survives
    assert c2.get("/api/auth/me").status_code == 401           # others do not
    assert new_client(app).post("/api/auth/login", json={"username": "alice", "password": PW}).status_code == 401
    assert new_client(app).post("/api/auth/login", json={"username": "alice", "password": new_pw}).status_code == 200


def test_password_change_enforces_policy(client):
    r = register(client)
    resp = client.post("/api/account/password", headers=csrf(r),
                       json={"current_password": PW, "new_password": "short"})
    assert resp.status_code == 422


def test_account_deletion(client, app, db):
    r = register(client)
    assert client.post("/api/account/delete", headers=csrf(r), json={"password": "wrong-wrong-wrong"}).status_code == 401
    assert client.post("/api/account/delete", json={"password": PW}).status_code == 403
    assert client.post("/api/account/delete", headers=csrf(r), json={"password": PW}).status_code == 204
    assert db.scalar(select(User)) is None
    assert db.scalar(select(UserSession)) is None and db.scalar(select(Folder)) is None
    assert new_client(app).post("/api/auth/login", json={"username": "alice", "password": PW}).status_code == 401
    assert register(new_client(app), "alice").status_code == 201   # name is free again


def test_unauthenticated_access_denied(client):
    assert client.get("/api/auth/me").status_code == 401
    assert client.get("/api/account/sessions").status_code == 401
    assert client.post("/api/account/delete", json={"password": "x"}).status_code == 401


def test_logs_contain_no_secrets(client, app, caplog):
    caplog.set_level(logging.DEBUG)
    r = register(client, "loguser", "very secret passphrase 99")
    token = client.cookies.get("tm_session")
    new_client(app).post("/api/auth/login", json={"username": "loguser", "password": "wrong password here"})
    client.post("/api/auth/logout", headers=csrf(r))
    text_ = caplog.text
    for secret in ("loguser", "very secret passphrase 99", "wrong password here", token, r.json()["csrf_token"]):
        assert secret not in text_
