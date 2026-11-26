"""Mailbox logic. Every query is scoped to the acting user; callers never pass another user's id.

The server handles opaque ciphertext only. Subjects and bodies live inside the OpenPGP message, so
there is no server-side content search (search runs in the browser over decrypted messages).
"""
from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import and_, delete, func, or_, select
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import Folder, Message, MessageRecipient, User, utcnow
from app.models import UserKey
from app.security import policy, ratelimit

ARMOR_BEGIN = "-----BEGIN PGP MESSAGE-----"
ARMOR_END = "-----END PGP MESSAGE-----"
FOLDERS = ("inbox", "sent", "trash")


class MailboxError(Exception):
    pass


class InvalidMessage(MailboxError):
    pass


class UnknownRecipients(MailboxError):
    pass


class SendLimited(MailboxError):
    def __init__(self, retry_after: int) -> None:
        super().__init__("send limit")
        self.retry_after = retry_after


class MissingKey(MailboxError):
    pass


class NotFound(MailboxError):
    pass


class BadCursor(MailboxError):
    pass


@dataclass
class Page:
    items: list[dict]
    next_cursor: str | None
    unread: int | None = None


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() + "Z" if dt else None


def _folder_id(db: Session, user_id: uuid.UUID, kind: str) -> uuid.UUID:
    fid = db.scalar(select(Folder.id).where(Folder.user_id == user_id, Folder.kind == kind))
    if fid is None:  # cannot happen for registered users; fail closed
        raise NotFound
    return fid


# ---- sending -------------------------------------------------------------------------------------


def validate_ciphertext(ciphertext: str, settings: Settings) -> bytes:
    """Structural check only: refuses obvious plaintext. It cannot prove the content is really encrypted."""
    data = ciphertext.strip()
    if not (data.startswith(ARMOR_BEGIN) and data.endswith(ARMOR_END)):
        raise InvalidMessage("Message must be an armored OpenPGP message")
    raw = data.encode()
    if len(raw) > settings.max_message_bytes:
        raise InvalidMessage("Message too large")
    return raw


def send(db: Session, settings: Settings, sender: User, recipients: list[str], ciphertext: str,
         now: datetime | None = None) -> list[str]:
    now = now or utcnow()
    raw = validate_ciphertext(ciphertext, settings)
    names = list(dict.fromkeys(policy.normalize_username(r) for r in recipients))  # de-duplicate, keep order
    if not names or len(names) > settings.max_recipients:
        raise InvalidMessage(f"Between 1 and {settings.max_recipients} recipients required")

    # Probing for usernames costs send budget exactly like a real send.
    uid = str(sender.id)
    if not ratelimit.hit(db, f"send:h:{uid}", settings.send_per_hour, 3600, now):
        db.commit()
        raise SendLimited(900)
    if not ratelimit.hit(db, f"send:d:{uid}", settings.send_per_day, 86400, now):
        db.commit()
        raise SendLimited(3600)

    users = {u.username: u for u in db.scalars(select(User).where(User.username.in_(names)))}
    missing = [n for n in names if n not in users]
    if missing:
        db.commit()
        raise UnknownRecipients(", ".join(missing))

    keyed = set(db.scalars(select(UserKey.user_id).where(
        UserKey.is_active.is_(True), UserKey.user_id.in_([u.id for u in users.values()] + [sender.id]))))
    if sender.id not in keyed:
        db.commit()
        raise MissingKey("You need to set up your encryption key before sending")
    nokey = [n for n in names if users[n].id not in keyed]
    if nokey:
        db.commit()
        raise MissingKey("No encryption key yet for: " + ", ".join(nokey))

    inbox = {
        f.user_id: f.id
        for f in db.scalars(select(Folder).where(Folder.kind == "inbox", Folder.user_id.in_([u.id for u in users.values()])))
    }
    msg = Message(sender_id=sender.id, ciphertext=raw, size_bytes=len(raw), created_at=now)
    db.add(msg)
    db.flush()
    for name in names:
        u = users[name]
        db.add(MessageRecipient(message_id=msg.id, recipient_id=u.id, folder_id=inbox[u.id], delivered_at=now))
    db.commit()
    return names


# ---- listing -------------------------------------------------------------------------------------


def encode_cursor(ts: datetime, mid: uuid.UUID) -> str:
    return base64.urlsafe_b64encode(f"{ts.isoformat()}|{mid}".encode()).decode().rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    try:
        text = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
        ts, mid = text.split("|", 1)
        return datetime.fromisoformat(ts), uuid.UUID(mid)
    except (ValueError, UnicodeDecodeError):
        raise BadCursor from None


def _recipient_item(row: MessageRecipient, msg: Message, sender_name: str | None, with_body: bool) -> dict:
    item = {
        "id": str(msg.id), "sender": sender_name, "created_at": _iso(msg.created_at),
        "delivered_at": _iso(row.delivered_at), "size_bytes": msg.size_bytes, "is_read": row.is_read,
        "deleted_at": _iso(row.deleted_at),
    }
    if with_body:
        item["ciphertext"] = msg.ciphertext.decode()
    return item


def list_folder(db: Session, settings: Settings, user: User, folder: str, cursor: str | None,
                limit: int | None) -> Page:
    if folder not in FOLDERS:
        raise NotFound
    limit = max(1, min(limit or settings.page_size_default, settings.page_size_max))
    after = decode_cursor(cursor) if cursor else None
    if folder == "sent":
        return _list_sent(db, user, after, limit)

    fid = _folder_id(db, user.id, folder)
    key = MessageRecipient.deleted_at if folder == "trash" else MessageRecipient.delivered_at
    q = (
        select(MessageRecipient, Message, User.username)
        .join(Message, Message.id == MessageRecipient.message_id)
        .outerjoin(User, User.id == Message.sender_id)
        .where(MessageRecipient.recipient_id == user.id, MessageRecipient.folder_id == fid)
    )
    if after:
        ts, mid = after
        q = q.where(or_(key < ts, and_(key == ts, MessageRecipient.message_id < mid)))
    rows = db.execute(q.order_by(key.desc(), MessageRecipient.message_id.desc()).limit(limit + 1)).all()
    more = len(rows) > limit
    rows = rows[:limit]
    items = [_recipient_item(r, m, name, True) for r, m, name in rows]
    nxt = None
    if more and rows:
        last_row = rows[-1][0]
        nxt = encode_cursor(getattr(last_row, key.key), last_row.message_id)
    unread = None
    if folder == "inbox":
        unread = db.scalar(
            select(func.count()).select_from(MessageRecipient).where(
                MessageRecipient.recipient_id == user.id, MessageRecipient.folder_id == fid,
                MessageRecipient.is_read.is_(False),
            )
        )
    return Page(items, nxt, unread)


def _list_sent(db: Session, user: User, after, limit: int) -> Page:
    q = select(Message).where(Message.sender_id == user.id, Message.sender_deleted_at.is_(None))
    if after:
        ts, mid = after
        q = q.where(or_(Message.created_at < ts, and_(Message.created_at == ts, Message.id < mid)))
    msgs = list(db.scalars(q.order_by(Message.created_at.desc(), Message.id.desc()).limit(limit + 1)))
    more = len(msgs) > limit
    msgs = msgs[:limit]
    names = _recipient_names(db, [m.id for m in msgs])
    items = [
        {"id": str(m.id), "recipients": names.get(m.id, []), "created_at": _iso(m.created_at),
         "size_bytes": m.size_bytes, "ciphertext": m.ciphertext.decode()}
        for m in msgs
    ]
    return Page(items, encode_cursor(msgs[-1].created_at, msgs[-1].id) if more and msgs else None)


def _recipient_names(db: Session, ids: list[uuid.UUID]) -> dict[uuid.UUID, list[str]]:
    out: dict[uuid.UUID, list[str]] = {}
    if not ids:
        return out
    rows = db.execute(
        select(MessageRecipient.message_id, User.username)
        .join(User, User.id == MessageRecipient.recipient_id)
        .where(MessageRecipient.message_id.in_(ids))
        .order_by(User.username)
    )
    for mid, name in rows:
        out.setdefault(mid, []).append(name)
    return out


# ---- single message ------------------------------------------------------------------------------


def _recipient_row(db: Session, user: User, folder: str, mid: uuid.UUID):
    if folder not in ("inbox", "trash"):
        return None
    fid = _folder_id(db, user.id, folder)
    return db.execute(
        select(MessageRecipient, Message, User.username)
        .join(Message, Message.id == MessageRecipient.message_id)
        .outerjoin(User, User.id == Message.sender_id)
        .where(MessageRecipient.message_id == mid, MessageRecipient.recipient_id == user.id,
               MessageRecipient.folder_id == fid)
    ).first()


def get_message(db: Session, user: User, folder: str, mid: uuid.UUID) -> dict:
    """Returns the item or raises NotFound. Other users' messages are indistinguishable from missing ones."""
    if folder == "sent":
        m = db.scalar(select(Message).where(Message.id == mid, Message.sender_id == user.id,
                                            Message.sender_deleted_at.is_(None)))
        if m is None:
            raise NotFound
        names = _recipient_names(db, [m.id]).get(m.id, [])
        return {"id": str(m.id), "recipients": names, "created_at": _iso(m.created_at),
                "size_bytes": m.size_bytes, "ciphertext": m.ciphertext.decode()}
    found = _recipient_row(db, user, folder, mid)
    if found is None:
        raise NotFound
    row, msg, sender = found
    return _recipient_item(row, msg, sender, True)


def set_read(db: Session, user: User, mid: uuid.UUID, is_read: bool) -> None:
    found = _recipient_row(db, user, "inbox", mid)
    if found is None:
        raise NotFound
    found[0].is_read = is_read
    db.commit()


def _collect_garbage(db: Session, mid: uuid.UUID) -> None:
    """Delete a message once nobody can reach it any more."""
    msg = db.get(Message, mid)
    if msg is None or (msg.sender_id is not None and msg.sender_deleted_at is None):
        return
    if db.scalar(select(func.count()).select_from(MessageRecipient).where(MessageRecipient.message_id == mid)) == 0:
        db.delete(msg)


def delete_message(db: Session, user: User, folder: str, mid: uuid.UUID, now: datetime | None = None) -> str:
    """inbox -> trash; trash -> gone; sent -> hidden from the sender (gone once no recipient has it)."""
    now = now or utcnow()
    if folder == "sent":
        m = db.scalar(select(Message).where(Message.id == mid, Message.sender_id == user.id,
                                            Message.sender_deleted_at.is_(None)))
        if m is None:
            raise NotFound
        m.sender_deleted_at = now
        db.flush()
        _collect_garbage(db, mid)
        db.commit()
        return "deleted"
    found = _recipient_row(db, user, folder, mid)
    if found is None:
        raise NotFound
    row = found[0]
    if folder == "inbox":
        row.folder_id, row.deleted_at = _folder_id(db, user.id, "trash"), now
        db.commit()
        return "trashed"
    db.delete(row)
    db.flush()
    _collect_garbage(db, mid)
    db.commit()
    return "deleted"


def restore(db: Session, user: User, mid: uuid.UUID) -> None:
    found = _recipient_row(db, user, "trash", mid)
    if found is None:
        raise NotFound
    found[0].folder_id, found[0].deleted_at = _folder_id(db, user.id, "inbox"), None
    db.commit()


# ---- retention -----------------------------------------------------------------------------------


def purge_trash(db: Session, settings: Settings, now: datetime | None = None) -> int:
    """Permanently remove messages that have sat in trash longer than the retention period."""
    now = now or utcnow()
    cutoff = now - timedelta(days=settings.trash_purge_days)
    old = db.execute(
        select(MessageRecipient.message_id, MessageRecipient.recipient_id)
        .join(Folder, Folder.id == MessageRecipient.folder_id)
        .where(Folder.kind == "trash", MessageRecipient.deleted_at < cutoff)
    ).all()
    for mid, rid in old:
        db.execute(delete(MessageRecipient).where(MessageRecipient.message_id == mid,
                                                  MessageRecipient.recipient_id == rid))
        db.flush()
        _collect_garbage(db, mid)
    db.commit()
    return len(old)
