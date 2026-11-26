import os

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.models import Base
from app.security import pow as powmod

PW = "correct horse 7 battery"


@pytest.fixture
def settings(tmp_path):
    # Set TORMAIL_TEST_DATABASE_URL to run the whole suite against PostgreSQL instead of SQLite.
    url = os.environ.get("TORMAIL_TEST_DATABASE_URL") or f"sqlite:///{tmp_path}/t.db"
    return Settings(
        _env_file=None, env="test", database_url=url,
        max_request_bytes=8192, cookie_secure=False, secret_key="k" * 40,
        argon2_time_cost=1, argon2_memory_kib=64, argon2_parallelism=1, pow_difficulty_bits=8,
    )


@pytest.fixture
def app(settings):
    application = create_app(settings)
    Base.metadata.drop_all(application.state.engine)
    Base.metadata.create_all(application.state.engine)
    yield application
    application.state.engine.dispose()


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def db(app):
    s = app.state.session_factory()
    yield s
    s.close()


def register(client, username="alice", password=PW):
    ch = client.get("/api/auth/pow-challenge").json()["challenge"]
    return client.post("/api/auth/register", json={
        "username": username, "password": password,
        "pow_challenge": ch, "pow_nonce": powmod.solve(ch),
    })


def new_client(app):
    return TestClient(app)


def csrf(resp):
    return {"X-CSRF-Token": resp.json()["csrf_token"]}


def fake_pub(tag="x"):
    return f"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n{tag}\n-----END PGP PUBLIC KEY BLOCK-----"


def upload_key(client, headers, tag="x", fpr=None, backup=None):
    """Placeholder key for server-side tests; real keys are exercised in the browser tests."""
    body = {"public_key": fake_pub(tag), "fingerprint": fpr or (tag.encode().hex().upper() * 40)[:40]}
    if backup is not None:
        body["encrypted_private_key"] = backup
    return client.put("/api/keys/me", headers=headers, json=body)
