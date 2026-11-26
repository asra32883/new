import pytest

from app.config import ConfigError, Settings

GOOD = dict(
    env="production",
    secret_key="x" * 40,
    database_url="postgresql+psycopg://u:p@db/tormail",
    cookie_secure=True,
)


def make(**over):
    return Settings(_env_file=None, **{**GOOD, **over})


def test_good_production_config_accepted():
    assert make().env == "production"


@pytest.mark.parametrize(
    "override, fragment",
    [
        ({"secret_key": ""}, "SECRET_KEY"),
        ({"secret_key": "short"}, "SECRET_KEY"),
        ({"secret_key": "change-me" + "x" * 40}, "SECRET_KEY"),
        ({"bind_host": "0.0.0.0"}, "BIND_HOST"),
        ({"cookie_secure": False}, "COOKIE_SECURE"),
        ({"database_url": "sqlite:///x.db"}, "SQLite"),
        ({"argon2_time_cost": 1}, "Argon2id"),
        ({"argon2_memory_kib": 1024}, "Argon2id"),
    ],
)
def test_unsafe_production_config_refused(override, fragment):
    with pytest.raises(Exception) as exc:
        make(**override)
    assert fragment in str(exc.value)


def test_internal_network_ack_allows_container_bind(monkeypatch):
    monkeypatch.setenv("TORMAIL_INTERNAL_NETWORK_ACK", "1")
    assert make(bind_host="0.0.0.0").bind_host == "0.0.0.0"


def test_development_allows_defaults():
    assert Settings(_env_file=None, env="development").cookie_secure is True
