"""Phase 8: adversarial inputs and cross-cutting security properties."""
import pytest

from app.config import Settings
from app.main import create_app
from tests.conftest import PW, csrf, new_client, register, upload_key
from fastapi.testclient import TestClient

HOSTILE = ["' OR '1'='1", "alice'; DROP TABLE users;--", "<script>alert(1)</script>", "../../etc/passwd", "a\x00b", "%00", "ａｌｉｃｅ", "A" * 5000]


@pytest.mark.parametrize("name", HOSTILE)
def test_hostile_usernames_are_rejected_without_server_errors(client, name):
    r = register(client, name)
    assert r.status_code in (400, 413, 422)
    assert client.post("/api/auth/login", json={"username": name, "password": PW}).status_code in (401, 413, 422)
    assert client.get("/healthz").status_code == 200       # DB still intact


def test_sql_metacharacters_in_message_fields_are_inert(app):
    a, b = new_client(app), new_client(app)
    ha, hb = csrf(register(a, "alice")), csrf(register(b, "bobby"))
    upload_key(a, ha, "a"); upload_key(b, hb, "b")
    payload = "'; DROP TABLE messages;--"
    assert a.post("/api/messages", headers=ha, json={"recipients": ["bobby"], "ciphertext": "-----BEGIN PGP MESSAGE-----\n\n" + payload + "\n-----END PGP MESSAGE-----"}).status_code in (200, 201, 422)
    assert b.get("/api/mailbox/inbox").status_code == 200
    assert a.get("/api/users/" + payload.replace("/", "") + "/key").status_code in (404, 422)


def test_forged_and_tampered_cookies_are_rejected(app, client):
    register(client, "alice")
    name = next(iter(client.cookies.keys()))
    good = client.cookies[name]
    for bad in (good[:-2] + ("aa" if good[-2:] != "aa" else "bb"), "", "0" * len(good), "x" * 500):
        c = TestClient(app)
        c.cookies.set(name, bad)
        assert c.get("/api/auth/me").status_code == 401


def test_static_path_traversal_blocked(client):
    for p in ("/static/../config.py", "/static/%2e%2e/config.py", "/static/..%2fconfig.py", "/static//etc/passwd"):
        assert client.get(p).status_code in (400, 404)


def test_no_cors_headers_and_no_server_banner(client):
    r = client.get("/api/auth/me", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in {k.lower() for k in r.headers}
    assert "server" not in {k.lower() for k in r.headers}


def test_state_changing_endpoints_reject_get_and_missing_csrf(app, client):
    register(client, "alice")
    assert client.get("/api/auth/logout").status_code == 405
    assert client.post("/api/auth/logout").status_code in (401, 403)      # session cookie but no CSRF header
    assert client.post("/api/auth/logout", headers={"X-CSRF-Token": "wrong"}).status_code in (401, 403)


def test_production_hides_docs_and_openapi(tmp_path):
    s = Settings(_env_file=None, env="production", database_url="postgresql+psycopg://u:p@db/x", secret_key="k" * 40,
                 cookie_secure=True, bind_host="127.0.0.1")
    c = TestClient(create_app(s))
    for p in ("/docs", "/redoc", "/openapi.json"):
        assert c.get(p).status_code == 404


def test_errors_do_not_leak_internals(client):
    r = client.post("/api/auth/login", content=b"{not json", headers={"Content-Type": "application/json"})
    assert r.status_code == 422 and "Traceback" not in r.text and "sqlalchemy" not in r.text.lower()
    assert client.get("/api/nope").status_code == 404


def test_no_ip_or_user_agent_persisted(app, client, db):
    from sqlalchemy import inspect
    cols = {c["name"] for t in inspect(app.state.engine).get_table_names() for c in inspect(app.state.engine).get_columns(t)}
    assert not {c for c in cols if "ip" == c or c.startswith("ip_") or "user_agent" in c or "remote_addr" in c}


def test_key_lookup_and_registration_do_not_help_enumerate_via_status_codes(app):
    a = new_client(app); ha = csrf(register(a, "alice"))
    unknown = a.get("/api/users/ghost/key"); known_nokey = a.get("/api/users/alice/key")
    assert unknown.status_code == known_nokey.status_code == 404
    assert unknown.json() == known_nokey.json()


def test_nul_byte_in_any_username_field_never_errors(app):
    a = new_client(app); ha = csrf(register(a, "alice")); upload_key(a, ha, "a")
    assert a.get("/api/users/ali%00ce/key").status_code in (404, 422)
    r = a.post("/api/messages", headers=ha, json={"recipients": ["ali\u0000ce"], "ciphertext": "-----BEGIN PGP MESSAGE-----\n\nx\n-----END PGP MESSAGE-----"})
    assert r.status_code in (404, 422)
