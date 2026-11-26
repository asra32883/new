# Tor-Mail

A Tor-only, closed-system webmail with browser-side OpenPGP end-to-end encryption.

**Status: Phase 3 of 10 (schema, migrations, registration, login, sessions, account management).**
Mailbox and encryption are not implemented yet; there is no web UI yet, only the JSON API. See `ARCHITECTURE.md`
for the plan and `THREAT_MODEL.md` for what this system does and does not protect.

Addresses look like `username@<onion-host>.onion` but are **application-level only**:
they cannot exchange mail with Gmail or any other SMTP provider.
This is not "completely anonymous". Tor does not protect against a malicious operator
serving altered JavaScript, and metadata (who writes to whom, when, sizes) stays visible
to the operator.

## Run locally

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env
alembic upgrade head          # create the schema
python -m pytest              # add TORMAIL_TEST_DATABASE_URL=postgresql+psycopg://... to test on PostgreSQL
uvicorn app.main:factory --factory --host 127.0.0.1 --port 8000
```

Production mode (`TORMAIL_ENV=production`) refuses to start with a weak secret,
a non-loopback bind address, disabled secure cookies, SQLite, or weak Argon2id settings.

## Layout

See `ARCHITECTURE.md` section 5.1.
