from __future__ import annotations

import secrets

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.config import Settings


class PasswordService:
    """Argon2id hashing. verify() also runs a hash for unknown users so timing does not reveal existence."""

    def __init__(self, settings: Settings) -> None:
        self._ph = PasswordHasher(
            time_cost=settings.argon2_time_cost,
            memory_cost=settings.argon2_memory_kib,
            parallelism=settings.argon2_parallelism,
            type=Type.ID,
        )
        self._dummy = self._ph.hash(secrets.token_urlsafe(24))

    def hash(self, password: str) -> str:
        return self._ph.hash(password)

    def verify(self, stored_hash: str | None, password: str) -> bool:
        try:
            self._ph.verify(stored_hash or self._dummy, password)
            return stored_hash is not None
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def needs_rehash(self, stored_hash: str) -> bool:
        return self._ph.check_needs_rehash(stored_hash)
