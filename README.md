# Tor-Mail

A Tor-only, closed-system webmail with browser-side OpenPGP end-to-end encryption.

**Status: Phase 5 of 10 (adds browser-side OpenPGP encryption and the key-management page at `/keys`).**
The inbox/compose/login UI (Phase 7) is not built yet, so for now the JSON API plus `/keys` are the only interfaces.
The server can only check that a message *looks* like armored OpenPGP; it cannot prove it is encrypted. Encryption is enforced by the client code, which the server delivers (see ARCHITECTURE.md 4.3). See `ARCHITECTURE.md`
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

## Browser end-to-end tests

```bash
pip install playwright && playwright install chromium   # once
python -m pytest tests/e2e                                # real server + headless Chromium under the real CSP
```

## Maintenance

`python -m scripts.purge` removes trash older than `TORMAIL_TRASH_PURGE_DAYS` (30), expired sessions and stale rate-limit rows. Run it daily.

## Layout

See `ARCHITECTURE.md` section 5.1.
