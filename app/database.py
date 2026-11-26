from __future__ import annotations

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.pool import StaticPool


def make_engine(url: str) -> Engine:
    kwargs: dict = {"pool_pre_ping": True}
    is_sqlite = url.startswith("sqlite")
    if is_sqlite:
        kwargs = {"connect_args": {"check_same_thread": False}}
        if url in ("sqlite://", "sqlite:///:memory:"):
            kwargs["poolclass"] = StaticPool
    engine = create_engine(url, **kwargs)
    if is_sqlite:

        @event.listens_for(engine, "connect")
        def _fk_on(dbapi_conn, _record):  # SQLite ignores foreign keys unless asked
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

    return engine
