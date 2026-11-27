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
    assert "http" not in csp and "*" not in csp
    assert "'unsafe-eval'" not in csp and "'unsafe-inline'" not in csp
    # WebAssembly compilation is allowed (OpenPGP.js needs it for Argon2id); JS eval and inline script are not
    assert csp.count("unsafe") == 1 and "script-src 'self' 'wasm-unsafe-eval'" in csp


def test_oversize_body_rejected_by_header(client):
    r = client.post("/healthz", content=b"x" * 20000)
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


def test_static_assets_cache_by_content_hash_and_pages_never_cached(client):
    shell = client.get("/login")
    assert shell.headers["cache-control"] == "no-store"
    import re
    m = re.search(r'/static/js/app\.js\?v=([0-9a-f]{16})', shell.text)
    assert m, "asset URLs must carry a content hash"
    versioned = client.get(f"/static/js/app.js?v={m.group(1)}")
    assert "immutable" in versioned.headers["cache-control"]
    assert client.get("/static/js/app.js").headers["cache-control"] == "no-cache"


def test_gzip_only_for_static_files(client):
    big = client.get("/static/js/app.js", headers={"Accept-Encoding": "gzip"})
    assert big.headers.get("content-encoding") == "gzip"
    page = client.get("/login", headers={"Accept-Encoding": "gzip"})
    assert "content-encoding" not in page.headers          # BREACH: no compression next to secrets
    api = client.get("/api/auth/me", headers={"Accept-Encoding": "gzip"})
    assert "content-encoding" not in api.headers


def test_privacy_page_shows_configured_operator_contact(client, app):
    app.state.settings.operator_contact = "ops@example.onion"
    assert "ops@example.onion" in client.get("/privacy").text
