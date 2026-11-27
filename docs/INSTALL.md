# Installation and deployment guide

Status of this guide: the Python application, migrations and tests were run in a development sandbox (SQLite and
PostgreSQL 16). **The Docker images, the Compose stack and the Tor onion service could not be started there** (no Docker
daemon, no Tor network). Follow the "Verify" steps after every install and treat the first deployment as a test.

## 1. Local development (any Linux, no Tor)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env            # defaults are fine for development
alembic upgrade head
uvicorn app.main:factory --factory --host 127.0.0.1 --port 8000
```
Open http://127.0.0.1:8000. In development `TORMAIL_COOKIE_SECURE=false` is needed if you browse over plain HTTP
(the app logs a warning). Run the tests: `python -m pytest` (browser tests need `playwright install chromium`; the
accessibility audit needs `npm ci` in `tests/e2e/axe`).

## 2. Fedora (Docker/Podman stack with Tor)

Tested on: nothing — written for Fedora 40+ and unverified. Podman users: `podman compose` should work, but the
`group_add` and Unix-socket permission model (see `deployment/TOR.md`) must be checked on your setup.

```bash
sudo dnf install -y moby-engine docker-compose-plugin git      # or: sudo dnf install -y docker-ce ... from Docker's repo
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"   # log out and in. Note: docker group membership is root-equivalent.
```
SELinux stays **enforcing**. If a bind-mounted host path is ever added, label it with `:Z`; the shipped Compose file
uses named volumes only, which need no relabelling.

Firewall: nothing needs to be opened. The stack publishes **no ports**; Tor connects outbound only.
```bash
sudo firewall-cmd --list-all      # no tormail-related ports should appear
```

Configure and start:
```bash
git clone <your repository> tor-mail && cd tor-mail
cp .env.example .env
python3 -c "import secrets; print('TORMAIL_SECRET_KEY=' + secrets.token_urlsafe(48))"  # paste into .env
python3 -c "import secrets; print('POSTGRES_PASSWORD=' + secrets.token_hex(24))"        # paste into .env
chmod 600 .env
docker compose up -d --build
docker compose logs -f tor            # wait for "Bootstrapped 100%"
docker compose exec tor cat /var/lib/tor/tormail/hostname     # your .onion address
```
Set `TORMAIL_OPERATOR_CONTACT` in `.env` (shown on the privacy page), then `docker compose up -d`.

## 3. Bare-metal PostgreSQL (without Docker)

```bash
sudo dnf install -y postgresql-server && sudo postgresql-setup --initdb && sudo systemctl enable --now postgresql
sudo -u postgres psql -c "CREATE ROLE tormail LOGIN PASSWORD '<random hex>'"
sudo -u postgres psql -c "CREATE DATABASE tormail OWNER tormail"
export TORMAIL_DATABASE_URL='postgresql+psycopg://tormail:<password>@127.0.0.1:5432/tormail'
alembic upgrade head
```
Keep PostgreSQL listening on localhost only and use `scram-sha-256` in `pg_hba.conf`. For a production run without
Docker: `TORMAIL_ENV=production`, a 32+ character `TORMAIL_SECRET_KEY`, run uvicorn on a Unix socket
(`--uds`) and point a system `tor` at it with `HiddenServicePort 80 unix:/path/app.sock`
(the socket must be readable by the `tor` user only via group permissions). The app refuses to start in production with weak settings.

## 4. Verify (do this every time)

1. `docker compose ps` — all three services healthy.
2. `docker compose port app 8000` and `ss -ltnp` on the host show nothing published.
3. `scripts/check_exposure.sh` (see `deployment/TOR.md`) reports no leaks.
4. From Tor Browser, open the onion address: register, create a key, send yourself a message.
5. Visit `/.well-known/assets.json` and compare the hashes with the ones published from the release you built.
6. Check `docker compose logs app` contains event codes only (no usernames, no message content).

## 5. Routine maintenance

Daily purge of old trash, expired sessions and rate-limit rows (cron or a systemd timer on the host):
```bash
docker compose exec -T app python -m scripts.purge
```
Example `/etc/systemd/system/tormail-purge.service` + `.timer`:
```ini
[Service]
Type=oneshot
WorkingDirectory=/opt/tor-mail
ExecStart=/usr/bin/docker compose exec -T app python -m scripts.purge
```
```ini
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
```

## 6. Updating securely

```bash
git fetch && git log --oneline HEAD..origin/main      # read what changes
git verify-commit origin/main || true                  # if you sign releases
pip-audit -r requirements.txt                          # dependency advisories
docker compose build --pull && docker compose up -d   # migrations run on start (alembic upgrade head)
```
Take a database backup first (section 7). A bad migration can only be undone from a backup. The vendored
OpenPGP.js is pinned by hash (`app/static/vendor/SHA256SUMS`); upgrade it deliberately, verify the tarball against the
npm registry, and re-run the browser tests. After an update, users' cached JS refreshes by itself (content-hashed URLs).

## 7. Backup and restore

The database holds only ciphertext, public keys, password hashes and metadata, but metadata is sensitive: **encrypt backups**.
```bash
docker compose exec -T db pg_dump -U tormail -Fc tormail | age -r <recipient public key> > tormail-$(date +%F).dump.age
age -d -i key.txt tormail-2026-01-01.dump.age | docker compose exec -T db pg_restore -U tormail -d tormail --clean --if-exists
```
Also back up the onion identity (see `deployment/TOR.md`) and `.env`. Keep backups only as long as the privacy
policy says; deleted accounts and messages come back if an old backup is restored, so restore only into a fresh
instance and re-run the purge. **Backups cannot restore users' private keys**: those live in users' browsers (and optionally
as client-encrypted blobs in the DB). A lost passphrase is unrecoverable by design.

Test a restore into a scratch instance before you need it.

## 8. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `app` exits at start with "Unsafe production configuration" | read the listed problems; fix `.env` |
| `docker compose up` says a variable is not set | `TORMAIL_SECRET_KEY` / `POSTGRES_PASSWORD` missing in `.env` |
| Tor never reaches Bootstrapped 100% | host has no outbound internet or blocks Tor; try bridges (`deployment/TOR.md`) |
| Onion address loads but pages error 502/blank | Tor cannot read the app socket: check `docker compose logs tor` for permission errors and the `group_add: 10002` setting |
| Login works but you are signed out immediately | cookie `Secure` over plain HTTP outside Tor Browser; use Tor Browser or Firefox |
| "Unlock your key first" after every reload | by design: unlocked keys are memory-only |
| "No private key stored in this browser" | different browser/profile; import your backup file on the Keys page |
| Message list shows items but not subjects | key locked or you lost the key that a message was encrypted to |
| Registration is slow | proof-of-work puzzle; lower `TORMAIL_POW_DIFFICULTY_BITS` only if you accept more spam |
| Many "login locked" reports | per-username lock after 5 failures (max 15 min); an attacker can lock a known username (threat T19) |
| `alembic` errors on start | database unreachable or password changed after the volume was created (volume keeps the old password) |
