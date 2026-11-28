# Tor-Mail: Architecture (Phase 1)

Status: design. No application code exists yet. Phases 2 to 10 implement this document.

## 1. What this system is, and is not

Tor-Mail is a **closed-system webmail** reachable only as a Tor v3 onion service. Users address each other as `username@<onion-host>.onion`. That is an **application-level address**. It is not an SMTP address, there is no MX record, and it cannot exchange mail with Gmail or any other provider. Messages move between rows in one database.

It is not "completely anonymous" and not "perfectly secure." Tor hides network location between client and server. It does not hide what a user does inside the service, and it does not stop an operator from serving malicious code (section 4.3).

## 2. Component overview

```
 User's Tor Browser
        |  (Tor circuit, 6 hops, end-to-end encrypted to the onion service)
        v
 [ Tor daemon ]  HiddenServiceDir /var/lib/tor/tormail/
        |  HiddenServicePort 80 -> app:8000   (internal network only)
        v
 [ FastAPI app (Uvicorn, 1 container, no published ports) ]
        |  internal network only
        v
 [ PostgreSQL ]   (SQLite for local dev/tests only)
```

- **Tor daemon**: terminates the onion protocol. The app never sees a client IP; every request arrives from the Tor container.
- **App**: FastAPI serves Jinja2 pages, static assets, and a JSON API. It listens on `127.0.0.1` (bare metal) or an internal Docker network (compose). No host port is published.
- **Database**: only the app can reach it.
- **No reverse proxy by default.** Tor already provides transport encryption and addressing. Adding nginx adds a component and config surface for no gain. Add one later only if needed (compression, static caching).
- **No TLS inside the onion.** Traffic is already end-to-end encrypted and authenticated by the onion address. Cookies therefore cannot rely on the `Secure` flag being meaningful over plain HTTP to the local hop. See 5.4 for how this is handled.

## 3. Technology decisions and justification

| Area | Choice | Why |
|---|---|---|
| Web framework | FastAPI + Uvicorn | As specified. Typed, testable, small. |
| ORM / migrations | SQLAlchemy 2.0 + Alembic | Mature; one model layer for SQLite and PostgreSQL; real migrations. |
| Templates | Jinja2, server-rendered | Pages work without JS where possible; autoescaping on. |
| Frontend | Vanilla JS, one CSS file | No build step, no npm supply chain, fast on Tor. |
| Crypto (client) | OpenPGP.js v5/v6, **vendored** into `static/vendor/` with pinned hash | Established OpenPGP implementation. Vendored because Tor users should not load scripts from a CDN. |
| Password hashing | `argon2-cffi`, Argon2id | As specified. Parameters set by config and tested. |
| Sessions | Server-side, random 256-bit tokens, only SHA-256 of token stored | DB leak does not yield usable sessions; instant revocation. |
| Tor | Official `tor` package, v3 onion service | Per Tor Project docs. |
| Tests | pytest, httpx TestClient | Includes authorization and crypto round-trip tests. |

Deviations from the brief: none so far.

## 4. End-to-end encryption design

### 4.1 Key model

- Each user has one OpenPGP key pair (Curve25519 / Ed25519 default in OpenPGP.js).
- **Key generation happens in the browser.** The private key never leaves the browser unprotected.
- The private key is protected by a **key passphrase**, which is distinct from the login password and is never sent to the server.
- The server stores:
  - the **public key** (armored), needed so senders can encrypt;
  - optionally, the **passphrase-encrypted private key blob**, only if the user opts in to "sync key to this server." The server cannot decrypt it. Its safety depends on passphrase strength, since anyone with database access can attempt offline guessing. The UI will say this plainly. Default is off; the user downloads a backup file instead.
- If the user loses both the key and the backup, **their messages are unrecoverable**. There is no escrow and no admin recovery. This is stated at key creation and again in settings.

### 4.2 Message format

What the browser encrypts (as one OpenPGP message, to the recipient's key **and** to the sender's own key so the Sent folder is readable):

```
{ "subject": "...", "body": "...", "client_ts": ..., "v": 1 }
```

Putting the subject **inside** the ciphertext means the server never sees it. Consequences:

- The inbox list needs decryption of each item's envelope to show a subject. The client decrypts and caches in memory for the session.
- **Server-side search over content is impossible.** Search is performed client-side over decrypted messages already loaded. Server-side filtering is limited to visible metadata (sender, date, read state). This is stated in the UI.

### 4.3 The webmail trust problem (the most important limitation)

In a webmail, **the server delivers the JavaScript that does the encryption.** A malicious or compromised operator could ship modified JS that exfiltrates the passphrase or plaintext. E2EE here protects against: database theft, backup theft, passive server-side snooping, and honest-but-curious operation. It does **not** protect against an operator who actively tampers with served code.

Mitigations planned (each partial):

1. All JS vendored and served from the same origin; strict CSP (`script-src 'self'`, no inline script) so injected scripts are blocked.
2. A published SHA-256 manifest of static assets (`/.well-known/assets.json`, also in the repo) so users or auditors can compare.
3. Later (out of scope for this build): a standalone client or signed browser extension, which removes the problem.

This will be in the privacy policy and the key-management page, not buried.

### 4.3.1 Implementation notes (Phase 5)

- **OpenPGP.js 6.3.2**, vendored and hash-pinned (`app/static/vendor/SHA256SUMS`, enforced by a test). 6.3.3 was only six days old at build time and its release notes were not yet published, so the older release with read notes was chosen. Upgrade procedure is in `vendor/README.md`.
- **Keys:** curve25519 (Ed25519 + X25519), generated in the browser; private key protected with **Argon2id** S2K (AEAD-protected). This needs WebAssembly, so the CSP includes `'wasm-unsafe-eval'` (compiles WASM only; JS `eval` and inline scripts remain blocked). Without it OpenPGP.js silently falls back to iterated SHA-256, which is much weaker against offline guessing of a stolen backup; a browser test fails if that fallback ever happens.
- **Sign-then-encrypt:** every message is signed by the sender's key inside the encryption. Readers verify against the sender's *current* public key and show `valid`, `invalid`, `unsigned` or `unverified`; the sender named in the signed contents must match the sender the server reports.
- **Key pinning (TOFU):** the first key seen for each contact is pinned in the browser. A later change blocks sending until the user accepts it, and is never applied silently when reading. A fingerprint is only called "verified" after the user marks it so.
- **Local storage:** only passphrase-protected private keys are stored (an unprotected key is refused at import and at save); unlocked keys exist in memory only.

### 4.4 Key authenticity

A sender fetches the recipient's public key from the server, so a malicious server could substitute a key (MITM). Mitigation: show a **key fingerprint** on the contact view and in key management so users can compare out of band. No fake "verified" badges: the UI shows "key fetched from server, not independently verified" until the user marks it verified locally.

## 5. Backend design

### 5.1 Layout

```
tor-mail/
  app/
    main.py            app factory, middleware, router wiring
    config.py          pydantic-settings, reads env only, refuses insecure prod config
    database.py        engine/session
    models/            SQLAlchemy models
    routes/            auth, mailbox, messages, keys, account, pages
    services/          mailbox logic, user logic (no HTTP types)
    security/          passwords, sessions, csrf, ratelimit, pow, headers
    templates/  static/ (static/vendor/openpgp.min.js)
  migrations/          Alembic
  tests/
  tor/torrc.example
  deployment/          compose, systemd units, Fedora notes
  scripts/             backup, restore, key checks
  SECURITY.md  ARCHITECTURE.md  THREAT_MODEL.md  README.md
```

### 5.2 Data model (summary; full DDL in Phase 3)

- `users(id UUID pk, username citext/unique lowercase, password_hash, created_at, last_login_at NULL)`
- `user_keys(id, user_id fk, public_key_armored, fingerprint, encrypted_private_key NULL, is_active, created_at)`
- `folders(id, user_id fk, kind enum[inbox,sent,trash], ...)`
- `messages(id UUID pk, sender_id fk NULL on delete SET NULL, ciphertext bytes, size_bytes, created_at, sender_deleted_at NULL)`: **one** OpenPGP message encrypted to all recipient keys and the sender's key (changed from the two-column design in Phase 1; simpler and avoids storing the same content twice).
- `message_recipients(message_id fk, recipient_id fk, folder_id fk, is_read, delivered_at, deleted_at NULL)`, PK `(message_id, recipient_id)`, index on `(recipient_id, folder_id, delivered_at)`
- `sessions(id, user_id fk, token_hash unique, created_at, last_seen_at, expires_at)` (no user-agent column: less data collected)
- `rate_limits(key pk, window_start, count)`: DB-backed, keys are keyed hashes, never IPs or raw usernames

Deletion rules (implemented in `services/auth.py::delete_account`, tested): deleting a user cascades keys, sessions, folders and their mailbox rows. Messages they sent stay readable by their recipients (we cannot reach into other mailboxes) but lose the sender reference; a message with no sender and no recipients left is deleted. Because the sender copy is the same ciphertext, deleting an account does not erase a sent message from recipients' mailboxes. This is a deliberate, documented trade-off and belongs in the retention policy.

### 5.3 Authentication

- Registration: username (3 to 32 chars, `[a-z0-9._-]`, reserved-name list), password (minimum length 12, no composition rules, checked against a small common-password list), **no email, no phone**.
- Login: Argon2id verify; constant-time-ish behavior for unknown users (verify against a dummy hash); generic error messages.
- Logout invalidates the server session. Password change invalidates all other sessions. "Log out everywhere" in settings.
- Sessions: idle timeout 30 min configurable, absolute 12 h. Cookie: `HttpOnly`, `SameSite=Strict`, `__Host-` prefix only when `Secure` is possible. See 5.4.
- Optional 2FA (TOTP) is deferred to a later version, as the brief says.

### 5.4 Cookies over HTTP-inside-Tor

Browsers treat `http://xyz.onion` specially: Tor Browser and Firefox treat `.onion` as a secure context, and the `Secure` cookie flag is accepted for onion origins in current Tor Browser, but this is not uniform across browsers. Decision: config flag `COOKIE_SECURE`, **default true**, and the app logs a startup warning (not silent) if it is turned off. Phase 6 verifies behavior in Tor Browser and documents it.

### 5.5 Abuse protection without IP addresses

Behind Tor every request comes from one internal address, so classic per-IP rate limiting is meaningless, and **we deliberately do not store client IPs.** Instead:

- **Registration:** a hashcash-style **proof-of-work** challenge (server issues a signed, expiring challenge; client finds a nonce) plus a global registration rate cap. No third-party CAPTCHA (it would leak/track).
- **Login:** throttling per **username** (exponential backoff after N failures) plus a global login-attempt budget. Note the DoS trade-off: an attacker can lock a victim's username temporarily. Mitigation: backoff is bounded and only delays, never permanently locks.
- **Sending:** per-user hourly/daily send limit and max message size.
- Tor also offers onion-service-level DoS defenses (PoW, introduction rate limits); documented in the Tor config.

### 5.6 Web hardening

CSP `default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `Permissions-Policy` denying everything, `Cache-Control: no-store` on authenticated pages, CSRF tokens (double submit via session-bound token) on all state-changing requests, strict input validation with Pydantic, request size caps, no `Server` header leakage, no external fonts/scripts/images.

### 5.6 Logging

Access logging off by default. Application logs contain event codes and no usernames, tokens, bodies, or IPs. Errors scrubbed. A test asserts that secrets are not emitted in log output during auth flows.

## 6. Tor integration

Implemented in Phase 6: `tor/torrc`, `tor/Dockerfile`, `Dockerfile`, `docker-compose.yml`, `deployment/TOR.md`.

```
Tor Browser ==Tor==> [tor] --Unix socket (shared volume, mode 0750 dir)--> [app] --backend (internal net)--> [db]
                      egress only                                            no TCP listener
```

- **Changed from the Phase 1 sketch:** Tor forwards to a **Unix socket**, not `app:8000`. Tor Browser returns `Secure` cookies over plain-HTTP onion connections, and the Tor Project's advisory says `HiddenServicePort` should target only a local address, otherwise those cookies cross an unencrypted network hop. A socket keeps that hop off the network entirely, and lets the app sit on an internal network with no other neighbour than its database.
- **Isolation:** `backend` is an internal Docker network (no internet route) holding app and db; only `tor` has an egress network. No service publishes a port. All containers: read-only filesystem, `cap_drop: ALL`, `no-new-privileges`, non-root users, pid and memory limits.
- **Socket access control:** uvicorn creates the socket world-writable, so the directory is the lock: `/run/tormail` is `0750`, owner uid 10001, group 10002; the tor container joins group 10002 and mounts it read-only. Verified with real unprivileged users in `tests/test_socket_permissions.py`.
- **`torrc`:** v3 service; `SocksPort 0`, no control port, `ClientOnly 1`, `ExitRelay 0`; intro-point DoS defences, stream limits, and PoW defences (needs a Tor build with PoW support).
- The hidden-service directory holds the **onion identity secret key** (volume `torkeys`): back it up encrypted, never commit it. Loss means a new address; theft means impersonation.
- No reverse proxy: if one is ever added it must also use a local socket or `127.0.0.1`.
- Host-level leak vectors (other services, DNS, hosting provider, clock) are in the checklist in `deployment/TOR.md`.
- **Untested in the build environment:** building and running the containers and reaching the onion address. `scripts/check_exposure.sh` verifies the running stack on the real host.

## 7. Phase plan and acceptance gates

| Phase | Deliverable | Gate |
|---|---|---|
| 1 | This document and THREAT_MODEL.md | Reviewed |
| 2 | Skeleton, config, headers, health check, test harness | `pytest` green; prod config validation refuses unsafe settings |
| 3 | DB schema, migrations, registration/login/sessions | Auth tests incl. brute-force, session expiry |
| 4 | Mailbox: inbox, compose, sent, delete, pagination (opaque ciphertext) | Cross-user access tests |
| 5 | Browser E2EE with OpenPGP.js, key mgmt UI | Round-trip test; server-side test proving no plaintext stored |
| 6 | Tor + compose + hardening | Onion reachable; no host ports published |
| 7 | Responsive UI polish, accessibility pass | Works without external requests |
| 8 | Security test suite complete, dependency audit | pip-audit clean or justified |
| 9 | Deployment/backup/restore/troubleshooting docs (Fedora included) | Fresh-VM walkthrough |
| 10 | Final review against threat model | Residual risk list signed off |

Browser-side crypto is tested with a headless-browser or Node harness using the same OpenPGP.js build; Python tests cover everything server-side.

## 8. Open questions for you

1. **Invite-only or open registration?** Open registration plus Tor means spam and abuse are the main operational risk. I default to open with PoW, with an optional invite-code mode.
2. **Server-synced encrypted private key:** off by default (my recommendation) or on?
3. **Trash/retention:** auto-purge deleted messages after 30 days acceptable?
4. **Docker-first or systemd-first** as the primary deployment path?


## Phase 7: web UI

- Single-page app served from one shell (`app.html`) for every UI route; views are inert `<template>` elements cloned by `app.js`, filled with `textContent` only (no `innerHTML`, no inline script/style, so the strict CSP holds).
- Client-side routing (History API) keeps the unlocked private key in memory across navigation; a full reload locks it again by design.
- Search is client-side over decrypted messages already loaded; the server cannot search ciphertext.
- Trust indicators on each message: decryption, signature (valid/invalid/unsigned/unverified), whether the sender's key changed since first use, and whether you verified the fingerprint. Nothing is shown as "secure" that was not checked.
- Static files: gzip and content-hash URLs (`?v=`, immutable). Pages and API responses are never compressed or cached (BREACH, secrets).
- Usability: show-password toggle, current-page highlight in the nav, card layout, auto-lock of the key after 15 idle minutes (the view is rebuilt so decrypted text leaves the page).
- Speed: scripts load with `defer`; static files are gzip + immutable-cached.
- Accessibility: skip link, labelled forms, live status region, 44px targets, light/dark themes, no animation; axe-core WCAG 2.1 AA audit in `tests/e2e` (`npm ci` in `tests/e2e/axe` to enable).
- `TORMAIL_OPERATOR_CONTACT` is shown on the privacy page.


## Chat
- Tables: `chats`, `chat_members` (role, joined_seq, last_read_seq, hidden), `chat_messages` (per-chat seq, ciphertext, expires_at, tombstone), `chat_blobs`.
- Events inside the encrypted payload: `msg`, `edit`, `react` (group names in a `meta` payload). The server never parses them.
- Group keys: each message is one OpenPGP ciphertext encrypted to every current member plus the sender. `members_version` guards against stale member lists.
- Live sync: `GET /api/chats?wait=25&after=<cursor>`; wake-ups in process, 5 s re-check for multi-worker setups, no DB session while waiting.
- Attachments: `files.js` strips metadata, `chat.js` encrypts and uploads raw bytes (`POST /api/chats/{id}/blobs`, own body limit), recipients download and decrypt in the browser; previews use `blob:` images (the only CSP relaxation).
