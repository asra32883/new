"""Public-key storage.

The server stores armored public keys and, only if the user opts in, a passphrase-encrypted private key
blob. It cannot parse or verify OpenPGP material: structural checks here are guard rails, and clients
verify every key they fetch (fingerprint recomputed locally, expiry, revocation) before encrypting.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import User, UserKey, utcnow
from app.security import ratelimit

PUB_BEGIN, PUB_END = "-----BEGIN PGP PUBLIC KEY BLOCK-----", "-----END PGP PUBLIC KEY BLOCK-----"
PRIV_BEGIN, PRIV_END = "-----BEGIN PGP PRIVATE KEY BLOCK-----", "-----END PGP PRIVATE KEY BLOCK-----"
MAX_PUBLIC = 32 * 1024
MAX_PRIVATE = 64 * 1024
MAX_KEYS_PER_USER = 20
FPR_RE = re.compile(r"^(?:[0-9A-F]{40}|[0-9A-F]{64})$")


class KeyError_(Exception):
    pass


class InvalidKey(KeyError_):
    pass


class KeyLimited(KeyError_):
    pass


class NoKey(KeyError_):
    pass


def _armored(text: str, begin: str, end: str, limit: int, what: str) -> str:
    t = text.strip()
    if not (t.startswith(begin) and t.endswith(end)):
        raise InvalidKey(f"{what} must be an armored OpenPGP block")
    if len(t.encode()) > limit:
        raise InvalidKey(f"{what} is too large")
    return t


def validate(public_key: str, fingerprint: str, encrypted_private_key: str | None) -> tuple[str, str, str | None]:
    pub = _armored(public_key, PUB_BEGIN, PUB_END, MAX_PUBLIC, "Public key")
    if PRIV_BEGIN in pub:
        raise InvalidKey("Public key field contains a private key")
    fpr = fingerprint.strip().upper()
    if not FPR_RE.match(fpr):
        raise InvalidKey("Fingerprint must be 40 or 64 hex characters")
    priv = None
    if encrypted_private_key is not None:
        priv = _armored(encrypted_private_key, PRIV_BEGIN, PRIV_END, MAX_PRIVATE, "Private key backup")
    return pub, fpr, priv


def active_key(db: Session, user_id: uuid.UUID) -> UserKey | None:
    return db.scalar(select(UserKey).where(UserKey.user_id == user_id, UserKey.is_active.is_(True)))


def set_active_key(db: Session, settings: Settings, user: User, public_key: str, fingerprint: str,
                   encrypted_private_key: str | None, now: datetime | None = None) -> UserKey:
    """Make this the user's single active key. Older keys stay as inactive rows (history of fingerprints)."""
    now = now or utcnow()
    pub, fpr, priv = validate(public_key, fingerprint, encrypted_private_key)
    if not ratelimit.hit(db, f"keyset:{user.id}", 10, 86400, now):
        db.commit()
        raise KeyLimited
    existing = db.scalar(select(UserKey).where(UserKey.user_id == user.id, UserKey.fingerprint == fpr))
    if existing is None and db.scalar(select(func.count()).select_from(UserKey).where(UserKey.user_id == user.id)) >= MAX_KEYS_PER_USER:
        raise InvalidKey("Too many keys on this account")
    db.execute(update(UserKey).where(UserKey.user_id == user.id, UserKey.is_active.is_(True)).values(is_active=False))
    db.flush()
    if existing is None:
        existing = UserKey(user_id=user.id, public_key_armored=pub, fingerprint=fpr, created_at=now)
        db.add(existing)
    else:
        existing.public_key_armored = pub
    existing.is_active = True
    existing.encrypted_private_key = priv
    db.commit()
    return existing


def get_backup(db: Session, user_id: uuid.UUID) -> str:
    key = active_key(db, user_id)
    if key is None or key.encrypted_private_key is None:
        raise NoKey
    return key.encrypted_private_key


def delete_backup(db: Session, user_id: uuid.UUID) -> None:
    key = active_key(db, user_id)
    if key is None or key.encrypted_private_key is None:
        raise NoKey
    key.encrypted_private_key = None
    db.commit()


def public_for_username(db: Session, username: str) -> tuple[str, UserKey]:
    user = db.scalar(select(User).where(User.username == username.strip().lower()))
    key = active_key(db, user.id) if user else None
    if user is None or key is None:
        raise NoKey
    return user.username, key
