"""Authentication logic. No HTTP types here; routes translate the exceptions."""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import Folder, Message, MessageRecipient, User, UserSession, utcnow
from app.models.mail import FOLDER_KINDS
from app.security import policy, pow as powmod, ratelimit
from app.security.passwords import PasswordService

log = logging.getLogger("tormail.auth")
TOUCH_INTERVAL = timedelta(seconds=60)


class AuthError(Exception):
    pass


class UsernameTaken(AuthError):
    pass


class InvalidCredentials(AuthError):
    pass


class PowRejected(AuthError):
    pass


class RateLimited(AuthError):
    def __init__(self, retry_after: int) -> None:
        super().__init__("rate limited")
        self.retry_after = retry_after


# ---- tokens --------------------------------------------------------------------------------------


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def csrf_token(secret: bytes, session: UserSession) -> str:
    return hmac.new(secret, b"csrf:" + session.token_hash.encode(), hashlib.sha256).hexdigest()


# ---- registration --------------------------------------------------------------------------------


def register(
    db: Session, settings: Settings, secret: bytes, pw: PasswordService,
    username: str, password: str, challenge: str, nonce: str, now: datetime | None = None,
) -> User:
    now = now or utcnow()
    username = policy.validate_username(username)
    policy.validate_password(password, username)
    try:
        cid, expiry = powmod.verify(secret, challenge, nonce, now.replace(tzinfo=timezone.utc).timestamp())
    except powmod.PowError:
        raise PowRejected from None
    expires = datetime.fromtimestamp(expiry, timezone.utc).replace(tzinfo=None)
    if not ratelimit.claim_once(db, f"pow:{cid}", expires):
        raise PowRejected
    if not ratelimit.hit(db, "register:global", settings.register_global_per_hour, 3600, now):
        db.commit()
        raise RateLimited(600)
    ratelimit.purge_stale(db, now)

    user = User(username=username, password_hash=pw.hash(password), created_at=now)
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise UsernameTaken from None
    db.add_all(Folder(user_id=user.id, kind=k) for k in FOLDER_KINDS)
    db.flush()
    log.info("event=register_ok")
    return user


# ---- login ---------------------------------------------------------------------------------------


def verify_user_password(
    db: Session, settings: Settings, secret: bytes, pw: PasswordService,
    username: str, password: str, now: datetime | None = None,
) -> User:
    """Throttled password check shared by login, password change and account deletion."""
    now = now or utcnow()
    username = policy.normalize_username(username)
    key = ratelimit.user_key(secret, "loginfail", username)

    if not ratelimit.hit(db, "login:global", settings.login_global_per_minute, 60, now):
        db.commit()
        raise RateLimited(60)
    wait = ratelimit.lock_remaining(db, key, settings.login_lock_threshold, now)
    if wait:
        db.commit()
        raise RateLimited(wait)

    user = db.scalar(select(User).where(User.username == username))
    ok = pw.verify(user.password_hash if user else None, password)
    if user is None or not ok:
        ratelimit.record_failure(db, key, now)
        db.commit()
        log.info("event=login_failed")
        raise InvalidCredentials
    ratelimit.reset(db, key)
    if pw.needs_rehash(user.password_hash):
        user.password_hash = pw.hash(password)
    return user


def login(
    db: Session, settings: Settings, secret: bytes, pw: PasswordService,
    username: str, password: str, now: datetime | None = None,
) -> tuple[User, str, UserSession]:
    now = now or utcnow()
    user = verify_user_password(db, settings, secret, pw, username, password, now)
    user.last_login_at = now
    token, session = create_session(db, settings, user, now)
    db.commit()
    log.info("event=login_ok")
    return user, token, session


# ---- sessions ------------------------------------------------------------------------------------


def create_session(db: Session, settings: Settings, user: User, now: datetime | None = None) -> tuple[str, UserSession]:
    now = now or utcnow()
    token = secrets.token_urlsafe(32)
    session = UserSession(
        user_id=user.id, token_hash=hash_token(token), created_at=now, last_seen_at=now,
        expires_at=now + timedelta(hours=settings.session_absolute_hours),
    )
    db.add(session)
    db.flush()
    return token, session


def resolve_session(db: Session, settings: Settings, token: str, now: datetime | None = None) -> UserSession | None:
    now = now or utcnow()
    session = db.scalar(select(UserSession).where(UserSession.token_hash == hash_token(token)))
    if session is None:
        return None
    idle = timedelta(minutes=settings.session_idle_minutes)
    if now >= session.expires_at or now - session.last_seen_at > idle:
        db.delete(session)
        db.commit()
        return None
    if now - session.last_seen_at > TOUCH_INTERVAL:
        session.last_seen_at = now
        db.commit()
    return session


def revoke_token(db: Session, token: str) -> None:
    db.execute(delete(UserSession).where(UserSession.token_hash == hash_token(token)))
    db.commit()


def revoke_all(db: Session, user_id, except_session_id=None) -> None:
    stmt = delete(UserSession).where(UserSession.user_id == user_id)
    if except_session_id is not None:
        stmt = stmt.where(UserSession.id != except_session_id)
    db.execute(stmt)
    db.commit()


def purge_expired_sessions(db: Session, settings: Settings, now: datetime | None = None) -> None:
    now = now or utcnow()
    idle_cutoff = now - timedelta(minutes=settings.session_idle_minutes)
    db.execute(delete(UserSession).where((UserSession.expires_at <= now) | (UserSession.last_seen_at < idle_cutoff)))
    db.commit()


# ---- account -------------------------------------------------------------------------------------


def change_password(
    db: Session, settings: Settings, secret: bytes, pw: PasswordService,
    user: User, current_session: UserSession, current: str, new: str,
) -> None:
    verify_user_password(db, settings, secret, pw, user.username, current)
    policy.validate_password(new, user.username)
    user.password_hash = pw.hash(new)
    db.commit()
    revoke_all(db, user.id, except_session_id=current_session.id)
    log.info("event=password_changed")


def delete_account(
    db: Session, settings: Settings, secret: bytes, pw: PasswordService, user: User, password: str
) -> None:
    """Removes the user, keys, sessions, folders and mailbox rows.

    Messages they sent stay readable by their recipients (we cannot reach into other mailboxes) but lose the
    sender reference. Messages left with no sender and no recipients are deleted.
    """
    verify_user_password(db, settings, secret, pw, user.username, password)
    uid = user.id
    db.execute(delete(MessageRecipient).where(MessageRecipient.recipient_id == uid))
    db.execute(update(Message).where(Message.sender_id == uid).values(sender_id=None))
    orphans = ~select(MessageRecipient.message_id).where(MessageRecipient.message_id == Message.id).exists()
    db.execute(delete(Message).where(Message.sender_id.is_(None), orphans))
    db.execute(delete(User).where(User.id == uid))
    db.commit()
    log.info("event=account_deleted")
