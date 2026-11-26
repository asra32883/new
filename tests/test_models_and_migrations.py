import uuid
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, select
from sqlalchemy.exc import IntegrityError

from app.database import make_engine
from app.models import Base, Folder, Message, MessageRecipient, User, UserKey, UserSession, utcnow

ROOT = Path(__file__).resolve().parent.parent


def alembic_cfg(url):
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def test_migrations_match_models_and_downgrade(tmp_path):
    url = f"sqlite:///{tmp_path}/m.db"
    command.upgrade(alembic_cfg(url), "head")
    engine = make_engine(url)
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == []
    command.downgrade(alembic_cfg(url), "base")
    assert set(inspect(make_engine(url)).get_table_names()) <= {"alembic_version"}


def mk(db, name):
    u = User(username=name, password_hash="x")
    db.add(u)
    db.flush()
    return u


def test_cascades_and_constraints(db):
    a, b = mk(db, "aaa"), mk(db, "bbb")
    folder = Folder(user_id=b.id, kind="inbox")
    db.add_all([folder, UserSession(user_id=a.id, token_hash="h", expires_at=utcnow()),
                UserKey(user_id=a.id, public_key_armored="k", fingerprint="f1")])
    msg = Message(sender_id=a.id, ciphertext=b"ct", size_bytes=2)
    db.add(msg)
    db.flush()
    db.add(MessageRecipient(message_id=msg.id, recipient_id=b.id, folder_id=folder.id))
    db.commit()

    db.delete(a)           # sender removed: keys/sessions cascade, message survives with NULL sender
    db.commit()
    db.expire_all()
    assert db.get(Message, msg.id).sender_id is None
    assert db.scalar(select(UserKey)) is None and db.scalar(select(UserSession)) is None

    db.delete(b)           # recipient removed: mailbox rows and folders cascade
    db.commit()
    assert db.scalar(select(MessageRecipient)) is None and db.scalar(select(Folder)) is None


def test_integrity_rules(db):
    a = mk(db, "aaa")
    db.commit()
    for bad in (
        lambda: db.add(User(username="UPPER", password_hash="x")),
        lambda: db.add(Folder(user_id=a.id, kind="bogus")),
        lambda: db.add(Message(sender_id=a.id, ciphertext=b"", size_bytes=0)),
        lambda: db.add(Message(sender_id=uuid.uuid4(), ciphertext=b"x", size_bytes=1)),   # dangling FK
    ):
        bad()
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
    db.add_all([UserKey(user_id=a.id, public_key_armored="k", fingerprint="f1"),
                UserKey(user_id=a.id, public_key_armored="k", fingerprint="f2")])  # two active keys
    with pytest.raises(IntegrityError):
        db.commit()
