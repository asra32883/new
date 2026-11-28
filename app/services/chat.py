"""Chat logic. Every query is scoped to the acting user's membership; callers never pass another user's id.

The server handles opaque ciphertext only. It enforces: membership, a membership-version check on every send (so a
message is never encrypted to a stale member list), disappearing-message expiry, and sender-only deletion.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import Chat, ChatBlob, ChatMember, ChatMessage, User, UserKey, utcnow
from app.security import policy, ratelimit

ARMOR_BEGIN = "-----BEGIN PGP MESSAGE-----"
ARMOR_END = "-----END PGP MESSAGE-----"
TTL_CHOICES = (30, 300, 3600, 86400, 604800)      # 30 s, 5 min, 1 h, 1 day, 1 week
PREVIEW_MAX_BYTES = 8 * 1024                      # larger last messages are not inlined in the chat list
SYNC_OVERLAP = timedelta(seconds=5)               # absorbs commit-order vs timestamp races in incremental sync
UNATTACHED_BLOB_TTL = timedelta(hours=1)
MAX_UNATTACHED_BLOBS = 5


class ChatError(Exception):
    pass


class NotFound(ChatError):
    pass


class Forbidden(ChatError):
    pass


class Invalid(ChatError):
    pass


class MissingKey(ChatError):
    pass


class UnknownUsers(ChatError):
    pass


class MembersChanged(ChatError):
    def __init__(self, current: int) -> None:
        super().__init__("members changed")
        self.current = current


class Limited(ChatError):
    def __init__(self, retry_after: int) -> None:
        super().__init__("limit")
        self.retry_after = retry_after


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() + "Z" if dt else None


def _armored(text: str, limit: int) -> bytes:
    data = text.strip()
    if not (data.startswith(ARMOR_BEGIN) and data.endswith(ARMOR_END)):
        raise Invalid("Must be an armored OpenPGP message")
    raw = data.encode()
    if len(raw) > limit:
        raise Invalid("Message too large")
    return raw


def _alive(now: datetime):
    return or_(ChatMessage.expires_at.is_(None), ChatMessage.expires_at > now)


def _membership(db: Session, user: User, chat_id: uuid.UUID, lock: bool = False) -> tuple[Chat, ChatMember]:
    """Returns (chat, my membership) or raises NotFound (also for chats you are not in: no existence oracle)."""
    stmt = select(Chat).where(Chat.id == chat_id)
    if lock:
        stmt = stmt.with_for_update()
    chat = db.scalar(stmt)
    me = db.get(ChatMember, (chat_id, user.id)) if chat else None
    if chat is None or me is None:
        raise NotFound
    return chat, me


def _touch(chat: Chat, now: datetime) -> None:
    chat.rev += 1
    chat.updated_at = now


def _check_keys(db: Session, users: list[User]) -> None:
    keyed = set(db.scalars(select(UserKey.user_id).where(UserKey.is_active.is_(True), UserKey.user_id.in_([u.id for u in users]))))
    missing = [u.username for u in users if u.id not in keyed]
    if missing:
        raise MissingKey("No encryption key yet for: " + ", ".join(missing))


def _lookup(db: Session, names: list[str]) -> list[User]:
    clean = list(dict.fromkeys(policy.normalize_username(n) for n in names))
    found = {u.username: u for u in db.scalars(select(User).where(User.username.in_(clean)))}
    missing = [n for n in clean if n not in found]
    if missing:
        raise UnknownUsers(", ".join(missing))
    return [found[n] for n in clean]


def _limit(db: Session, key: str, limit: int, window: int, now: datetime) -> None:
    if not ratelimit.hit(db, key, limit, window, now):
        db.commit()
        raise Limited(min(window, 900))


# ---- creating chats ------------------------------------------------------------------------------------


def create_direct(db: Session, settings: Settings, user: User, other: str, now: datetime | None = None) -> Chat:
    now = now or utcnow()
    _limit(db, f"chatnew:{user.id}", settings.chat_new_per_hour, 3600, now)   # probing names costs budget
    db.commit()                                                                # ...even when the lookup below fails
    (peer,) = _lookup(db, [other])
    if peer.id == user.id:
        raise Invalid("You cannot start a chat with yourself")
    _check_keys(db, [user, peer])
    low, high = sorted([str(user.id), str(peer.id)])
    key = f"{low}:{high}"
    chat = db.scalar(select(Chat).where(Chat.direct_key == key))
    if chat is not None:
        for uid in (user.id, peer.id):
            m = db.get(ChatMember, (chat.id, uid))
            if m is None:                       # a party left earlier (account deleted and recreated is a new id)
                db.add(ChatMember(chat_id=chat.id, user_id=uid, role="member", joined_seq=chat.last_seq))
                chat.members_version += 1
        mine = db.get(ChatMember, (chat.id, user.id))
        if mine is not None and mine.hidden:
            mine.hidden = False
        _touch(chat, now)
        db.commit()
        return chat
    chat = Chat(kind="direct", direct_key=key, created_at=now, updated_at=now)
    db.add(chat)
    db.flush()
    db.add_all([ChatMember(chat_id=chat.id, user_id=user.id, role="member"),
                ChatMember(chat_id=chat.id, user_id=peer.id, role="member", hidden=True)])  # hidden until first message
    db.commit()
    return chat


def create_group(db: Session, settings: Settings, user: User, names: list[str], meta_ciphertext: str,
                 now: datetime | None = None) -> Chat:
    now = now or utcnow()
    _limit(db, f"chatnew:{user.id}", settings.chat_new_per_hour, 3600, now)
    db.commit()
    others = [u for u in _lookup(db, names) if u.id != user.id]
    if not others:
        raise Invalid("Add at least one other member")
    if len(others) + 1 > settings.chat_max_members:
        raise Invalid(f"A group can have at most {settings.chat_max_members} members")
    _check_keys(db, [user, *others])
    meta = _armored(meta_ciphertext, settings.chat_max_message_bytes)
    chat = Chat(kind="group", created_at=now, updated_at=now, meta_ciphertext=meta)
    db.add(chat)
    db.flush()
    db.add(ChatMember(chat_id=chat.id, user_id=user.id, role="admin"))
    db.add_all([ChatMember(chat_id=chat.id, user_id=u.id, role="member") for u in others])
    db.commit()
    return chat


# ---- reading -------------------------------------------------------------------------------------------


def member_rows(db: Session, chat_ids: list[uuid.UUID]) -> dict[uuid.UUID, list[dict]]:
    out: dict[uuid.UUID, list[dict]] = {c: [] for c in chat_ids}
    if not chat_ids:
        return out
    rows = db.execute(select(ChatMember, User.username).join(User, User.id == ChatMember.user_id)
                      .where(ChatMember.chat_id.in_(chat_ids)).order_by(ChatMember.joined_at, User.username))
    for m, name in rows:
        out[m.chat_id].append({"username": name, "role": m.role, "last_read_seq": m.last_read_seq})
    return out


def chat_item(chat: Chat, me: ChatMember, members: list[dict], unread: int, last: dict | None) -> dict:
    return {
        "id": str(chat.id), "kind": chat.kind, "members": members, "members_version": chat.members_version,
        "rev": chat.rev, "updated_at": _iso(chat.updated_at), "ttl_seconds": chat.ttl_seconds, "last_seq": chat.last_seq,
        "my_role": me.role, "my_last_read_seq": me.last_read_seq, "my_joined_seq": me.joined_seq,
        "meta_ciphertext": chat.meta_ciphertext.decode() if chat.meta_ciphertext else None,
        "unread": unread, "last_message": last,
    }


def _msg_item(msg: ChatMessage, sender: str | None, blob_ids: list[uuid.UUID] | None = None) -> dict:
    return {
        "id": str(msg.id), "seq": msg.seq, "sender": sender, "created_at": _iso(msg.created_at),
        "expires_at": _iso(msg.expires_at), "size_bytes": msg.size_bytes, "deleted": msg.deleted_at is not None,
        "ciphertext": msg.ciphertext.decode() if msg.ciphertext is not None else None,
        "blobs": [str(b) for b in (blob_ids or [])],
    }


def list_chats(db: Session, user: User, after: datetime | None = None, now: datetime | None = None,
               overlap: bool = True) -> list[dict]:
    """My visible chats. With `after`, only chats changed since then (minus a small overlap for catch-up syncs)."""
    now = now or utcnow()
    stmt = (select(Chat, ChatMember).join(ChatMember, ChatMember.chat_id == Chat.id)
            .where(ChatMember.user_id == user.id, ChatMember.hidden.is_(False))
            .order_by(Chat.updated_at.desc()).limit(300))
    if after is not None:
        stmt = stmt.where(Chat.updated_at > (after - SYNC_OVERLAP if overlap else after))
    pairs = list(db.execute(stmt))
    ids = [c.id for c, _ in pairs]
    members = member_rows(db, ids)
    unread = dict(db.execute(
        select(ChatMessage.chat_id, func.count()).join(ChatMember, and_(ChatMember.chat_id == ChatMessage.chat_id, ChatMember.user_id == user.id))
        .where(ChatMessage.chat_id.in_(ids), ChatMessage.seq > ChatMember.last_read_seq, ChatMessage.seq > ChatMember.joined_seq,
               or_(ChatMessage.sender_id.is_(None), ChatMessage.sender_id != user.id), ChatMessage.deleted_at.is_(None), _alive(now))
        .group_by(ChatMessage.chat_id)).all()) if ids else {}
    out = []
    for chat, me in pairs:
        last_row = db.execute(
            select(ChatMessage, User.username).outerjoin(User, User.id == ChatMessage.sender_id)
            .where(ChatMessage.chat_id == chat.id, ChatMessage.seq > me.joined_seq, ChatMessage.deleted_at.is_(None), _alive(now))
            .order_by(ChatMessage.seq.desc()).limit(1)).first()
        last = None
        if last_row:
            m, sender = last_row
            last = _msg_item(m, sender)
            if m.size_bytes > PREVIEW_MAX_BYTES:
                last["ciphertext"] = None          # too big to inline; the client shows a generic preview
        out.append(chat_item(chat, me, members[chat.id], unread.get(chat.id, 0), last))
    return out


def get_chat(db: Session, user: User, chat_id: uuid.UUID) -> dict:
    chat, me = _membership(db, user, chat_id)
    return chat_item(chat, me, member_rows(db, [chat.id])[chat.id], 0, None)


def get_messages(db: Session, user: User, chat_id: uuid.UUID, after_seq: int | None, before_seq: int | None,
                 limit: int, now: datetime | None = None) -> dict:
    now = now or utcnow()
    chat, me = _membership(db, user, chat_id)
    stmt = (select(ChatMessage, User.username).outerjoin(User, User.id == ChatMessage.sender_id)
            .where(ChatMessage.chat_id == chat.id, ChatMessage.seq > me.joined_seq, ChatMessage.deleted_at.is_(None), _alive(now)))
    if after_seq is not None:
        stmt = stmt.where(ChatMessage.seq > after_seq).order_by(ChatMessage.seq.asc())
    else:
        if before_seq is not None:
            stmt = stmt.where(ChatMessage.seq < before_seq)
        stmt = stmt.order_by(ChatMessage.seq.desc())
    rows = list(db.execute(stmt.limit(limit + 1)))
    more = len(rows) > limit
    rows = rows[:limit]
    if after_seq is None:
        rows.reverse()
    blobs: dict[uuid.UUID, list[uuid.UUID]] = {}
    if rows:
        for mid, bid in db.execute(select(ChatBlob.message_id, ChatBlob.id).where(ChatBlob.message_id.in_([m.id for m, _ in rows]))):
            blobs.setdefault(mid, []).append(bid)
    deleted = list(db.scalars(select(ChatMessage.seq).where(
        ChatMessage.chat_id == chat.id, ChatMessage.seq > me.joined_seq, ChatMessage.deleted_at.is_not(None)).order_by(ChatMessage.seq).limit(2000)))
    return {"items": [_msg_item(m, s, blobs.get(m.id)) for m, s in rows], "has_more": more, "deleted_seqs": deleted}


# ---- sending, deleting, reading --------------------------------------------------------------------------


def send_message(db: Session, settings: Settings, user: User, chat_id: uuid.UUID, ciphertext: str, members_version: int,
                 blob_ids: list[uuid.UUID], now: datetime | None = None) -> dict:
    now = now or utcnow()
    raw = _armored(ciphertext, settings.chat_max_message_bytes)
    chat, me = _membership(db, user, chat_id, lock=True)
    if chat.members_version != members_version:
        raise MembersChanged(chat.members_version)
    _limit(db, f"chatmsg:m:{user.id}", settings.chat_send_per_minute, 60, now)
    others = db.scalar(select(func.count()).select_from(ChatMember).where(ChatMember.chat_id == chat.id, ChatMember.user_id != user.id))
    if not others:
        raise Invalid("There is nobody else in this chat")
    blob_ids = list(dict.fromkeys(blob_ids))
    blobs = list(db.scalars(select(ChatBlob).where(ChatBlob.id.in_(blob_ids)))) if blob_ids else []
    if len(blobs) != len(blob_ids) or any(b.chat_id != chat.id or b.uploader_id != user.id or b.message_id is not None for b in blobs):
        raise Invalid("Unknown attachment")
    chat.last_seq += 1
    msg = ChatMessage(chat_id=chat.id, seq=chat.last_seq, sender_id=user.id, ciphertext=raw, size_bytes=len(raw), created_at=now,
                      expires_at=now + timedelta(seconds=chat.ttl_seconds) if chat.ttl_seconds else None)
    db.add(msg)
    db.flush()
    for b in blobs:
        b.message_id = msg.id
    me.last_read_seq = chat.last_seq
    db.execute(update(ChatMember).where(ChatMember.chat_id == chat.id).values(hidden=False))
    _touch(chat, now)
    db.commit()
    return _msg_item(msg, user.username, [b.id for b in blobs])


def delete_message(db: Session, user: User, chat_id: uuid.UUID, seq: int, now: datetime | None = None) -> None:
    """The sender removes the stored ciphertext (and attachments) for everyone. Other people's copies already
    decrypted in their browsers cannot be recalled."""
    now = now or utcnow()
    chat, me = _membership(db, user, chat_id, lock=True)
    msg = db.scalar(select(ChatMessage).where(ChatMessage.chat_id == chat.id, ChatMessage.seq == seq))
    if msg is None or msg.sender_id != user.id or msg.seq <= me.joined_seq:
        raise NotFound
    db.execute(delete(ChatBlob).where(ChatBlob.message_id == msg.id))
    msg.ciphertext, msg.size_bytes, msg.deleted_at = None, 0, now
    _touch(chat, now)
    db.commit()


def mark_read(db: Session, user: User, chat_id: uuid.UUID, upto_seq: int, now: datetime | None = None) -> None:
    now = now or utcnow()
    chat, me = _membership(db, user, chat_id, lock=True)
    target = min(max(upto_seq, 0), chat.last_seq)
    if target > me.last_read_seq:
        me.last_read_seq = target
        _touch(chat, now)
        db.commit()


def set_ttl(db: Session, user: User, chat_id: uuid.UUID, ttl: int | None, now: datetime | None = None) -> None:
    now = now or utcnow()
    chat, me = _membership(db, user, chat_id, lock=True)
    if ttl is not None and ttl not in TTL_CHOICES:
        raise Invalid("Unsupported timer")
    if chat.kind == "group" and me.role != "admin":
        raise Forbidden("Only group admins can change the timer")
    chat.ttl_seconds = ttl
    _touch(chat, now)
    db.commit()


def hide_chat(db: Session, user: User, chat_id: uuid.UUID, now: datetime | None = None) -> None:
    """Direct chat: clear my history and hide it (the other person keeps theirs). Groups use remove_member (leave)."""
    now = now or utcnow()
    chat, me = _membership(db, user, chat_id, lock=True)
    if chat.kind != "direct":
        raise Invalid("Leave the group instead")
    me.hidden, me.joined_seq, me.last_read_seq = True, chat.last_seq, chat.last_seq
    db.commit()


# ---- group membership ------------------------------------------------------------------------------------


def add_members(db: Session, settings: Settings, user: User, chat_id: uuid.UUID, names: list[str], members_version: int,
                meta_ciphertext: str, now: datetime | None = None) -> None:
    now = now or utcnow()
    chat, me = _membership(db, user, chat_id, lock=True)
    if chat.kind != "group":
        raise Invalid("Only groups have members to add")
    if me.role != "admin":
        raise Forbidden("Only group admins can add members")
    if chat.members_version != members_version:
        raise MembersChanged(chat.members_version)
    existing = set(db.scalars(select(ChatMember.user_id).where(ChatMember.chat_id == chat.id)))
    new = [u for u in _lookup(db, names) if u.id not in existing]
    if not new:
        raise Invalid("Those people are already members")
    if len(existing) + len(new) > settings.chat_max_members:
        raise Invalid(f"A group can have at most {settings.chat_max_members} members")
    _check_keys(db, new)
    chat.meta_ciphertext = _armored(meta_ciphertext, settings.chat_max_message_bytes)   # re-encrypted so newcomers read the title
    db.add_all([ChatMember(chat_id=chat.id, user_id=u.id, role="member", joined_seq=chat.last_seq) for u in new])
    chat.members_version += 1
    _touch(chat, now)
    db.commit()


def remove_member(db: Session, user: User, chat_id: uuid.UUID, username: str, members_version: int | None,
                  now: datetime | None = None) -> None:
    """Admins remove others; anyone can remove themselves (leave)."""
    now = now or utcnow()
    chat, me = _membership(db, user, chat_id, lock=True)
    if chat.kind != "group":
        raise Invalid("Not a group")
    target_name = policy.normalize_username(username)
    leaving = target_name == user.username
    if not leaving:
        if me.role != "admin":
            raise Forbidden("Only group admins can remove members")
        if members_version is None or chat.members_version != members_version:
            raise MembersChanged(chat.members_version)
    target = db.scalar(select(ChatMember).join(User, User.id == ChatMember.user_id)
                       .where(ChatMember.chat_id == chat.id, User.username == target_name))
    if target is None:
        raise NotFound
    _drop_member(db, chat, target, now)
    db.commit()


def _drop_member(db: Session, chat: Chat, member: ChatMember, now: datetime) -> None:
    db.delete(member)
    db.flush()
    remaining = list(db.scalars(select(ChatMember).where(ChatMember.chat_id == chat.id).order_by(ChatMember.joined_at)))
    if not remaining:
        _delete_chat(db, chat)
        return
    if chat.kind == "group" and not any(m.role == "admin" for m in remaining):
        remaining[0].role = "admin"
    chat.members_version += 1
    _touch(chat, now)


def _delete_chat(db: Session, chat: Chat) -> None:
    db.execute(delete(ChatBlob).where(ChatBlob.chat_id == chat.id))
    db.execute(delete(ChatMessage).where(ChatMessage.chat_id == chat.id))
    db.delete(chat)


def on_account_deleted(db: Session, user_id: uuid.UUID, now: datetime | None = None) -> None:
    """Called inside delete_account's transaction. Remaining members get a new membership version, so nobody keeps
    encrypting to the deleted account's key."""
    now = now or utcnow()
    for chat in list(db.scalars(select(Chat).join(ChatMember, ChatMember.chat_id == Chat.id).where(ChatMember.user_id == user_id))):
        member = db.get(ChatMember, (chat.id, user_id))
        if member is not None:
            _drop_member(db, chat, member, now)
    db.execute(update(ChatMessage).where(ChatMessage.sender_id == user_id).values(sender_id=None))
    db.execute(update(ChatBlob).where(ChatBlob.uploader_id == user_id).values(uploader_id=None))


# ---- attachments -----------------------------------------------------------------------------------------


def upload_blob(db: Session, settings: Settings, user: User, chat_id: uuid.UUID, data: bytes, now: datetime | None = None) -> uuid.UUID:
    now = now or utcnow()
    chat, me = _membership(db, user, chat_id)
    if not data or len(data) > settings.chat_max_blob_bytes:
        raise Invalid("Attachment is empty or too large")
    if not data[0] & 0x80:                       # every OpenPGP packet starts with a byte whose top bit is set
        raise Invalid("Attachment must be an OpenPGP message")
    pending = db.scalar(select(func.count()).select_from(ChatBlob).where(
        ChatBlob.uploader_id == user.id, ChatBlob.message_id.is_(None), ChatBlob.created_at > now - UNATTACHED_BLOB_TTL))
    if pending >= MAX_UNATTACHED_BLOBS:
        raise Limited(300)
    _limit(db, f"chatblob:d:{user.id}", settings.chat_blobs_per_day, 86400, now)
    blob = ChatBlob(chat_id=chat.id, uploader_id=user.id, data=data, size_bytes=len(data), created_at=now)
    db.add(blob)
    db.commit()
    return blob.id


def get_blob(db: Session, user: User, chat_id: uuid.UUID, blob_id: uuid.UUID, now: datetime | None = None) -> bytes:
    now = now or utcnow()
    chat, me = _membership(db, user, chat_id)
    blob = db.get(ChatBlob, blob_id)
    if blob is None or blob.chat_id != chat.id:
        raise NotFound
    if blob.message_id is None:
        if blob.uploader_id != user.id:
            raise NotFound
        return blob.data
    msg = db.get(ChatMessage, blob.message_id)
    if msg is None or msg.seq <= me.joined_seq or (msg.expires_at is not None and msg.expires_at <= now):
        raise NotFound
    return blob.data


# ---- maintenance -----------------------------------------------------------------------------------------


def purge(db: Session, settings: Settings, now: datetime | None = None) -> dict:
    """Removes expired disappearing messages, old tombstones and abandoned uploads."""
    now = now or utcnow()
    expired = list(db.scalars(select(ChatMessage.id).where(ChatMessage.expires_at.is_not(None), ChatMessage.expires_at <= now)))
    old_tombs = list(db.scalars(select(ChatMessage.id).where(
        ChatMessage.deleted_at.is_not(None), ChatMessage.deleted_at < now - timedelta(days=settings.trash_purge_days))))
    ids = expired + old_tombs
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        db.execute(delete(ChatBlob).where(ChatBlob.message_id.in_(chunk)))
        db.execute(delete(ChatMessage).where(ChatMessage.id.in_(chunk)))
    orphans = db.execute(delete(ChatBlob).where(ChatBlob.message_id.is_(None), ChatBlob.created_at < now - UNATTACHED_BLOB_TTL)).rowcount
    db.commit()
    return {"messages": len(expired), "tombstones": len(old_tombs), "blobs": orphans or 0}
