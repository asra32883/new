from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, utcnow

FOLDER_KINDS = ("inbox", "sent", "trash")


class Folder(Base):
    __tablename__ = "folders"
    __table_args__ = (
        UniqueConstraint("user_id", "kind", name="uq_folders_user_kind"),
        CheckConstraint("kind in ('inbox','sent','trash')", name="kind_valid"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)


class Message(Base):
    """One opaque OpenPGP message, encrypted in the browser to every recipient key and the sender's key.

    The server never sees subject or body. sender_id is NULLed when the sender deletes their account.
    """

    __tablename__ = "messages"
    __table_args__ = (CheckConstraint("size_bytes > 0", name="size_positive"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    sender_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False, index=True)
    sender_deleted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class MessageRecipient(Base):
    __tablename__ = "message_recipients"
    __table_args__ = (Index("ix_message_recipients_mailbox", "recipient_id", "folder_id", "delivered_at"),)

    message_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("messages.id", ondelete="CASCADE"), primary_key=True
    )
    recipient_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    folder_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("folders.id", ondelete="CASCADE"), nullable=False)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    delivered_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
