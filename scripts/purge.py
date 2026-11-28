"""Maintenance job: purge old trash, expired sessions and stale rate-limit rows.

Run daily (cron or systemd timer):  python -m scripts.purge
Logs only counts, never user data.
"""
from sqlalchemy.orm import sessionmaker

from app.config import get_settings
from app.database import make_engine
from app.security import ratelimit
from app.services import auth, chat, mailbox


def main() -> None:
    settings = get_settings()
    db = sessionmaker(make_engine(settings.database_url))()
    try:
        purged = mailbox.purge_trash(db, settings)
        gone = chat.purge(db, settings)
        auth.purge_expired_sessions(db, settings)
        ratelimit.purge_stale(db)
        db.commit()
        print(f"event=purge_done trash_purged={purged} chat_messages={gone['messages']} chat_tombstones={gone['tombstones']} chat_blobs={gone['blobs']}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
