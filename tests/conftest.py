import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


@pytest.fixture
def settings():
    return Settings(_env_file=None, env="test", database_url="sqlite:///:memory:", max_request_bytes=2048)


@pytest.fixture
def client(settings):
    return TestClient(create_app(settings))
