# Tor-Mail

A Tor-only, closed-system webmail with browser-side OpenPGP end-to-end encryption.

**Status: Phase 2 of 10 (skeleton, configuration, security headers, test harness).**
Registration, mailbox and encryption are not implemented yet. See `ARCHITECTURE.md`
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
python -m pytest
uvicorn app.main:factory --factory --host 127.0.0.1 --port 8000
```

Production mode (`TORMAIL_ENV=production`) refuses to start with a weak secret,
a non-loopback bind address, disabled secure cookies, SQLite, or weak Argon2id settings.

## Layout

See `ARCHITECTURE.md` section 5.1.
