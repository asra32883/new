# Final security review (Phase 10)

Scope: this repository at the commit that contains this file, reviewed against `THREAT_MODEL.md`.
Reviewer: the author (self-review, not independent). **No external audit has been done; get one before relying on this for people at risk.**

## Verified by automated tests (147+ tests, SQLite and PostgreSQL 16, real Chromium)
- Argon2id hashing, generic login errors, per-username lockout, global budget, session expiry, rotation at login, revocation, CSRF binding (T2, T4, T5, T17, T19).
- Every mailbox/key/session endpoint is user-scoped; cross-user access denied (T1). Mutation testing showed these tests fail when scoping is removed.
- Server stores only ciphertext; browser test greps the whole DB for plaintext (T8). Signatures: valid / invalid / unverified are distinguished; key changes are surfaced (T10).
- Hostile inputs (SQL metacharacters, traversal, NULs, huge values), forged cookies, no CORS, no server banner, docs off in production, errors without internals.
- CSP enforced in the browser tests; no inline script/style; no `innerHTML`/`eval` in app code (T6). axe-core WCAG 2.1 AA: no violations on tested pages.
- No IP/user-agent columns; logs carry event codes only (T15). `pip-audit` on the lock file: no known vulnerabilities on 2026-11-27.
- PostgreSQL run of the whole non-browser suite found and fixed a NUL-byte-in-username 500 error (now normalised so it never reaches the DB).
- Config validation refuses unsafe production settings. Unix-socket permissions tested with real unprivileged users (T21).

## Not verified (could not be tested in the development sandbox)
- Docker images build/run, the Compose network isolation, and `check_exposure.sh` behaviour on a real host.
- A real Tor onion service end to end, including Secure-cookie behaviour in Tor Browser and onion DoS behaviour.
- Argon2/OpenPGP.js behaviour in Tor Browser's *Safest* mode (JavaScript is disabled there: the site **cannot work** at that level).
- Performance and abuse resistance under real load; PoW difficulty tuning.
- Restore procedure in `docs/INSTALL.md`; Fedora/Podman instructions.

## Corrections made during this review
- T16 claimed hash-pinned Python dependencies; only versions were pinned. Fixed: `requirements.lock` with hashes is now what the image installs.

## Chat review (added later)
Verified by tests (SQLite and PostgreSQL for the API, real Chromium for the UI): non-member isolation on every endpoint (404, no existence oracle); CSRF and auth; stale membership versions refused; history hidden from people who join later; sender-only deletion that removes ciphertext and attachments; disappearing-message expiry and purge; attachment ownership, size and lifecycle limits; probing for usernames is rate limited; account deletion bumps membership versions; long-poll wake-up and removal notices; plaintext never reaches the database; image metadata removal on real JPEG/PNG/WebP/GIF files; axe-core WCAG audit of every chat screen in light and dark; phone layout.
Not verified: behaviour with many members or very large histories, multi-worker deployments (wake-ups then arrive within 5 s instead of immediately), long polls through a real Tor circuit, Tor Browser's handling of `blob:` image URLs and downloads, voice or video (not implemented).
Not implemented on purpose: typing indicators, online/last-seen status, bots, public channels, cloud-searchable history, calls. They would add metadata or need the server to read content.
Not implemented yet: renaming a group, promoting a second admin, per-message disappearing timers, forward secrecy.

## Residual risks (accepted, stated to users)
1. **Malicious or compromised server delivers malicious JavaScript (T9).** Inherent to webmail. Published asset hashes help only users/auditors who actually compare them. A native client or a signed browser extension would be the mitigation.
2. **Public-key substitution (T10)** for users who never verify fingerprints. TOFU pinning only detects later changes.
3. **Metadata is visible to the operator** (who wrote to whom, when, size, last login). No padding or mixing. A database leak exposes the social graph (T7, T18).
4. **Traffic correlation and endpoint compromise (T12)** are outside what the software can address. Tor does not guarantee anonymity.
5. **Targeted lockout (T19):** anyone who knows a username can lock it for up to 15 minutes per burst.
6. **`'wasm-unsafe-eval'` in CSP (T20)** is required for Argon2id key protection; it is weaker than a CSP without it.
7. **Browser storage:** private keys sit passphrase-encrypted in localStorage. Weak passphrases can be brute-forced offline by anyone who copies the profile; Argon2id raises the cost but does not remove it. An XSS or a malicious extension in the same profile could capture the passphrase.
8. **No forward secrecy and no deniability:** one long-lived key decrypts all past messages; signatures prove authorship.
9. **Lost key or passphrase = lost mail**, by design.
10. **Registration reveals whether a username exists**, unavoidable for any account system.
11. **Resource exhaustion** is possible despite limits; no external rate limiting layer exists beyond Tor.
12. **Operator can add logging** or alter the deployment; this cannot be prevented technically.
13. `.onion` addresses are application-level only; this is not SMTP and cannot exchange mail with other providers.

## Recommended before real use
Independent code and cryptographic-usage review; a real-Tor deployment test following `docs/INSTALL.md` section 4; a staged restore test; decide on and publish a retention/backup policy; consider adding subresource-style asset hash checking in a separate tool users can run.
