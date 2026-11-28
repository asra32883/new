"""Chat tables. Like mail, the server holds opaque OpenPGP ciphertext; it never sees text, titles or file contents.

What the server *does* know (and the privacy policy says so): who is in which chat, who sent each message and when,
sizes, the disappearing-message timer, and each member's read position.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, LargeBinary, String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, utcnow


class Chat(Base):
    __tablename__ = "chats"
    __table_args__ = (CheckConstraint("kind in ('direct','group')", name="kind_valid"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    kind: Mapped[str] = mapped_column(String(8), nullable=False)
    direct_key: Mapped[str | None] = mapped_column(String(80), unique=True, nullable=True)  # "<low id>:<high id>"
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False, index=True)
    ttl_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)       # disappearing-message timer
    members_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)  # bumps on every membership change
    rev: Mapped[int] = mapped_column(Integer, default=0, nullable=False)              # bumps on any change (sync hint)
    last_seq: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    meta_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)  # group title, encrypted to members


class ChatMember(Base):
    __tablename__ = "chat_members"
    __table_args__ = (
        CheckConstraint("role in ('admin','member')", name="role_valid"),
        Index("ix_chat_members_user", "user_id", "hidden"),
    )

    chat_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("chats.id", ondelete="CASCADE"), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    role: Mapped[str] = mapped_column(String(8), default="member", nullable=False)
    joined_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    joined_seq: Mapped[int] = mapped_column(Integer, default=0, nullable=False)     # sees only messages with seq > this
    last_read_seq: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    hidden: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class ChatMessage(Base):
    __tablename__ = "chat_messages"
    __table_args__ = (
        UniqueConstraint("chat_id", "seq", name="uq_chat_messages_chat_seq"),
        CheckConstraint("size_bytes >= 0", name="size_nonnegative"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    chat_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("chats.id", ondelete="CASCADE"), nullable=False)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    sender_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)   # emptied when deleted
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ChatBlob(Base):
    """An encrypted attachment. Opaque bytes; attached to the message that references it when that is sent."""

    __tablename__ = "chat_blobs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    chat_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("chats.id", ondelete="CASCADE"), nullable=False, index=True)
    uploader_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    message_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("chat_messages.id", ondelete="CASCADE"), nullable=True, index=True)
    data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
