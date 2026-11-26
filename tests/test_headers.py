def test_health_ok(client):
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_security_headers_present(client):
    h = client.get("/healthz").headers
    assert "script-src 'self'" in h["content-security-policy"]
    assert "frame-ancestors 'none'" in h["content-security-policy"]
    assert h["referrer-policy"] == "no-referrer"
    assert h["x-content-type-options"] == "nosniff"
    assert h["cache-control"] == "no-store"
    assert "server" not in {k.lower() for k in h}


def test_no_external_origins_in_csp(client):
    csp = client.get("/healthz").headers["content-security-policy"]
    assert "http" not in csp and "*" not in csp and "unsafe" not in csp


def test_oversize_body_rejected_by_header(client):
    r = client.post("/healthz", content=b"x" * 4096)
    assert r.status_code == 413


def test_docs_enabled_only_outside_production(settings):
    from fastapi.testclient import TestClient
    from app.config import Settings
    from app.main import create_app

    prod = Settings(
        _env_file=None, env="production", secret_key="k" * 40,
        database_url="postgresql://u:p@db/x",
    )
    c = TestClient(create_app(prod))
    assert c.get("/docs").status_code == 404
    assert c.get("/openapi.json").status_code == 404
