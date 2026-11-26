"""Application configuration.

All settings come from environment variables (or a local .env file in dev).
In production mode the app refuses to start with insecure settings instead of
silently downgrading security.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ConfigError(RuntimeError):
    """Raised when production configuration is unsafe."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TORMAIL_", env_file=".env", extra="ignore")

    env: Literal["development", "test", "production"] = "development"
    database_url: str = "sqlite:///./dev.db"

    # Secret used to sign short-lived tokens (PoW challenges, CSRF). No default in prod.
    secret_key: str = ""

    # Network binding. Must stay on a local interface; Tor forwards to it.
    bind_host: str = "127.0.0.1"
    bind_port: int = 8000

    # Cookies
    cookie_secure: bool = True
    session_idle_minutes: int = Field(default=30, ge=1, le=1440)
    session_absolute_hours: int = Field(default=12, ge=1, le=168)

    # Password hashing (Argon2id)
    argon2_time_cost: int = Field(default=3, ge=1)
    argon2_memory_kib: int = Field(default=65536, ge=8)
    argon2_parallelism: int = Field(default=2, ge=1)

    # Abuse limits (no IP addresses are used or stored)
    pow_difficulty_bits: int = Field(default=20, ge=0, le=32)
    register_global_per_hour: int = Field(default=60, ge=1)
    login_global_per_minute: int = Field(default=300, ge=1)
    login_lock_threshold: int = Field(default=5, ge=1)
    max_message_bytes: int = Field(default=256 * 1024, ge=1024)
    max_request_bytes: int = Field(default=512 * 1024, ge=1024)

    # Data retention
    trash_purge_days: int = Field(default=30, ge=1)

    @model_validator(mode="after")
    def _validate_for_environment(self) -> "Settings":
        if self.env != "production":
            return self
        problems: list[str] = []
        if len(self.secret_key) < 32 or self.secret_key.startswith("change-me"):
            problems.append("TORMAIL_SECRET_KEY must be set to a random value of 32+ characters")
        if self.bind_host not in ("127.0.0.1", "::1"):
            # Docker deployments bind inside an isolated internal network; they must opt in explicitly.
            if not _internal_network_ack():
                problems.append(
                    "TORMAIL_BIND_HOST must be a loopback address (or set "
                    "TORMAIL_INTERNAL_NETWORK_ACK=1 when running on an isolated container network)"
                )
        if not self.cookie_secure:
            problems.append("TORMAIL_COOKIE_SECURE must not be disabled in production")
        if self.database_url.startswith("sqlite"):
            problems.append("SQLite is for development/testing only; use PostgreSQL in production")
        if self.argon2_time_cost < 2 or self.argon2_memory_kib < 19456:
            problems.append("Argon2id parameters are below the OWASP minimum (t>=2, m>=19456 KiB)")
        if problems:
            raise ConfigError("Unsafe production configuration:\n - " + "\n - ".join(problems))
        return self


def _internal_network_ack() -> bool:
    import os

    return os.environ.get("TORMAIL_INTERNAL_NETWORK_ACK") == "1"


@lru_cache
def get_settings() -> Settings:
    return Settings()
