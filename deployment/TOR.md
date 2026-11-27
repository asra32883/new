# Tor onion service guide

How Tor-Mail is published, what to back up, and what can still go wrong. Nothing here makes the service
"completely anonymous". It hides the server's network location from visitors; it does not hide what
users do inside the service, and it does not protect against a malicious operator (see `THREAT_MODEL.md`).

## How the pieces connect

```
Tor Browser ==Tor circuit==> [tor container] --Unix socket (shared volume)--> [app container] --internal net--> [db]
                              |  egress network only                           backend network only
```

- The **tor** container is the only one with a route to the internet (outbound only). It publishes a **v3** onion service.
- The **app** container has **no TCP listener**. It serves HTTP on `/run/tormail/app.sock`; the socket directory is
  mode 0750, owned by the app, readable only by the shared group (gid 10002), which the tor container joins.
- The **db** is on an internal network shared only with the app.
- **No ports are published** on the host: there is nothing for a port scan of the server's IP address to find.

### Why a Unix socket and not `app:8000`

Tor Browser returns cookies marked `Secure` to plain-HTTP `.onion` connections. The Tor Project advises that
`HiddenServicePort` should point only at a local address, otherwise those cookies cross an unencrypted network hop
([advisory](https://onionservices.torproject.org/apps/web/onionspray/security/advisories/001-torbrowser/)).
A Unix socket keeps that hop entirely inside the host. Browsers accept `Secure` cookies from `.onion` sites
(Firefox 77+, Tor Browser; [Mozilla bug 1633015](https://bugzilla.mozilla.org/show_bug.cgi?id=1633015)), which is why
`TORMAIL_COOKIE_SECURE=true` stays on in production. **Do not put a reverse proxy, CDN or TLS terminator
between Tor and the app** unless it also talks over a local socket or `127.0.0.1`.

## First start

```bash
cp .env.example .env     # then set TORMAIL_SECRET_KEY and POSTGRES_PASSWORD (generation commands are in the file)
docker compose up -d --build
docker compose exec tor cat /var/lib/tor/tormail/hostname     # your address; may take a minute to appear
./scripts/check_exposure.sh                                    # verifies the properties listed above
```

Then open `http://<address>.onion/keys` in **Tor Browser**, register, and confirm you stay signed in after a reload.
Also check that Tor can actually talk to the app: `docker compose logs tor` must not show repeated connection errors to `/run/tormail/app.sock`, and the page must load.
Tor documents Unix-socket targets for `HiddenServicePort`, and the permission model here is tested with real unprivileged users, but this exact
Tor-to-socket connection has not been run in the build environment.

If you are signed out immediately after logging in, the browser rejected the `Secure` cookie: see Troubleshooting.

## What to back up (and protect)

| Item | Where | If lost | If leaked |
|---|---|---|---|
| Onion identity key `hs_ed25519_secret_key` | volume `tormail_torkeys`, `/var/lib/tor/tormail/` | the service gets a **new address**; everyone must be told | someone can **impersonate** the service |
| Database | volume `tormail_dbdata` | all accounts and (encrypted) messages | ciphertext + metadata exposed (see threat model T7) |
| `.env` | host | sessions/challenges signed with a new key are invalidated; DB password must match the volume | attacker can forge PoW challenges and CSRF tokens |

```bash
# Encrypted backup of the onion identity (example with age; any encryption you trust works)
docker compose cp tor:/var/lib/tor/tormail ./hs-backup
tar -C ./hs-backup -cf - . | age -p > onion-identity.tar.age && rm -rf ./hs-backup
```

Never commit these files; `.gitignore` and `.dockerignore` exclude them. Full backup/restore procedures for the
database are in the Phase 9 deployment guide.

## Hardening checklist for the host

The web application never reveals the server's IP address, but other things on the machine can:

- [ ] Run **nothing else** on the host that listens publicly (SSH on a non-default interface or behind a VPN, no mail server, no web server).
- [ ] Default-deny inbound firewall. An onion service needs **no inbound ports**. Docker bypasses `ufw` for *published* ports; this stack publishes none (check with `scripts/check_exposure.sh`).
- [ ] Keep Docker, the kernel and the images updated. Pin image digests in the Dockerfiles for production.
- [ ] Keep the clock accurate (NTP). Large clock skew breaks onion service descriptors and can aid correlation.
- [ ] Do not expose error pages, monitoring dashboards or admin tools on the same host's public IP.
- [ ] Your hosting provider knows the server exists and its IP. Choose it with that in mind.
- [ ] Consider the optional `vanguards` add-on for protection against guard discovery attacks (Tor 0.4.7+ includes a "vanguards-lite" default).
- [ ] For an **invite-only** service, use Tor *client authorization* so only holders of a key can even fetch the descriptor
      (see the Tor Project's onion services documentation; not configured or tested here).

## Troubleshooting

| Symptom | Likely cause and what to do |
|---|---|
| `hostname` file never appears | `docker compose logs tor`. Tor must bootstrap to 100%; the host needs outbound internet. Check the clock. |
| Onion address loads but shows 502/empty | App not healthy: `docker compose ps`, `docker compose logs app`. A `ConfigError` means production config validation refused to start (it names the bad setting). |
| `docker compose up` stops with "required variable ... missing" | Set `TORMAIL_SECRET_KEY` and `POSTGRES_PASSWORD` in `.env`. This is deliberate: there are no default secrets. |
| Signed out right after login | The browser rejected the `Secure` cookie (not Tor Browser or Firefox 77+?). Use Tor Browser. Do **not** disable `TORMAIL_COOKIE_SECURE`: production mode refuses to start without it. |
| Tor logs "permission denied" connecting to the socket | The tor container must have `group_add: ["10002"]`, and `/run/tormail` must be `0750` owned by uid 10001 gid 10002 (`docker compose exec app ls -ld /run/tormail`). |
| Log line about PoW defences unsupported | Your Tor build lacks onion-service PoW support. The service still works; remove `HiddenServicePoWDefensesEnabled` or use a newer build. |

## What was and was not tested for this phase

Tested automatically: the compose file, `torrc` and Dockerfiles are checked for the properties above (including
`docker compose config` resolution), and the Unix-socket access model is exercised with real unprivileged users
(group member allowed, other users denied, recovery after a crash). **Not tested** in the build environment: building
the images, running the containers, Tor bootstrapping, and reaching the onion address from Tor Browser. Run
`scripts/check_exposure.sh` and the first-start steps above on the real host before relying on it.
