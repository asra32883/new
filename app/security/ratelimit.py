"""DB-backed counters. Keys are opaque; no IP addresses are used or stored."""
from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import RateLimit, utcnow

MAX_LOCK_SECONDS = 900
FAILURE_MEMORY = timedelta(hours=1)


def user_key(secret: bytes, scope: str, username: str) -> str:
    """Keyed hash so the table never holds attacker-chosen or real usernames in the clear."""
    return f"{scope}:" + hmac.new(secret, username.encode(), hashlib.sha256).hexdigest()[:32]


def hit(db: Session, key: str, limit: int, window_seconds: int, now: datetime | None = None) -> bool:
    """Fixed-window counter. Returns False once `limit` hits occurred in the current window."""
    now = now or utcnow()
    row = db.scalar(select(RateLimit).where(RateLimit.key == key).with_for_update())
    if row is None or now - row.window_start >= timedelta(seconds=window_seconds):
        if row is None:
            db.add(RateLimit(key=key, window_start=now, count=1))
        else:
            row.window_start, row.count = now, 1
        db.flush()
        return True
    if row.count >= limit:
        return False
    row.count += 1
    return True


def claim_once(db: Session, key: str, expires: datetime) -> bool:
    """Record a single-use value (e.g. a PoW challenge id). False if already used."""
    try:
        with db.begin_nested():
            db.add(RateLimit(key=key, window_start=expires, count=1))
            db.flush()
        return True
    except IntegrityError:
        return False


def lock_seconds(failures: int, threshold: int) -> int:
    if failures < threshold:
        return 0
    return min(5 * 2 ** (failures - threshold), MAX_LOCK_SECONDS)


def lock_remaining(db: Session, key: str, threshold: int, now: datetime | None = None) -> int:
    now = now or utcnow()
    row = db.get(RateLimit, key)
    if row is None or now - row.window_start > FAILURE_MEMORY:
        return 0
    unlock_at = row.window_start + timedelta(seconds=lock_seconds(row.count, threshold))
    return max(0, int((unlock_at - now).total_seconds()) + 1) if unlock_at > now else 0


def record_failure(db: Session, key: str, now: datetime | None = None) -> None:
    now = now or utcnow()
    row = db.scalar(select(RateLimit).where(RateLimit.key == key).with_for_update())
    if row is None:
        db.add(RateLimit(key=key, window_start=now, count=1))
    elif now - row.window_start > FAILURE_MEMORY:
        row.window_start, row.count = now, 1
    else:
        row.window_start, row.count = now, row.count + 1
    db.flush()


def reset(db: Session, key: str) -> None:
    db.execute(delete(RateLimit).where(RateLimit.key == key))


def purge_stale(db: Session, now: datetime | None = None) -> None:
    now = now or utcnow()
    db.execute(delete(RateLimit).where(RateLimit.window_start < now - timedelta(hours=2)))
