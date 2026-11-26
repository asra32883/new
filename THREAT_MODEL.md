# Tor-Mail: Threat Model (Phase 1)

## 1. Assets

| Asset | Why it matters |
|---|---|
| Message plaintext (subject, body) | Core user secret |
| User private keys and key passphrases | Anyone holding them can read that user's mail |
| Login credentials and sessions | Account takeover, impersonation |
| Social graph (who messages whom, when) | Sensitive even without content |
| Server's real network location | Operator safety and service availability |
| Onion identity key (`hs_ed25519_secret_key`) | Service identity; theft allows impersonation |
| Database and backups | Everything at rest |

## 2. Adversaries

| ID | Adversary | Capability |
|---|---|---|
| A1 | Remote unauthenticated attacker | Reaches the onion site, can script requests |
| A2 | Malicious registered user | Valid account, probes authorization, spams |
| A3 | Database/backup thief | Reads DB dump or backup, no live access |
| A4 | Honest-but-curious operator | Has shell and DB access, runs unmodified code |
| A5 | Malicious or compromised operator | Can alter served JS and code |
| A6 | Network observer (ISP, local) | Sees the server's Tor traffic and timing |
| A7 | Global passive adversary | Can correlate traffic at both ends of Tor |
| A8 | Client-side attacker | Malware or XSS in the user's browser |

## 3. Threats and mitigations

| # | Threat | Adversary | Mitigation | Residual risk |
|---|---|---|---|---|
| T1 | Reading another user's mailbox via IDOR | A2 | Every query scoped by authenticated user id; ownership checks in the service layer; dedicated tests per endpoint | Logic bugs; covered by tests, not eliminated |
| T2 | Password guessing | A1 | Argon2id, per-username backoff, global budget, long-password policy | Targeted temporary lockout (DoS) |
| T3 | Credential stuffing/account farming | A1 | Registration proof-of-work, global caps | Determined attackers with compute |
| T4 | Session theft or fixation | A1, A8 | Random tokens, hashed at rest, HttpOnly, SameSite=Strict, rotation at login, server-side revocation | XSS in a vulnerable page; strict CSP reduces |
| T5 | CSRF | A1 | Session-bound CSRF tokens, SameSite=Strict, no GET state changes | Low |
| T6 | XSS | A1, A2 | Autoescaping, no inline scripts, CSP, message content rendered as **plain text** only (no HTML mail, no remote content) | Low; a vendored-library vulnerability is the main path |
| T7 | DB or backup theft | A3 | Message content is ciphertext; passwords Argon2id; sessions hashed; backups encrypted (documented) | **Metadata exposed**: usernames, sender/recipient, timestamps, sizes, public keys |
| T8 | Operator reads mail | A4 | Server only holds ciphertext | Operator sees metadata and can see key/ciphertext structure |
| T9 | **Operator ships malicious JS** | A5 | CSP, vendored code, published asset hashes | **Not solved.** This is inherent to webmail. A standalone client is the real fix |
| T10 | Public-key substitution by server | A5 | Fingerprint display, user-marked verification | Users who do not verify are exposed |
| T11 | Server IP leak | A6 | Onion service only, no inbound ports, no outbound calls from app, no external assets, hardening checklist | Host misconfiguration (other services, DNS, mail), hosting provider knowledge |
| T12 | Traffic correlation | A7 | Out of scope; Tor's limits apply | Accepted and stated |
| T13 | Spam/abuse and DoS | A1, A2 | Send limits, PoW, size caps, Tor onion DoS defenses | Resource exhaustion remains possible |
| T14 | Lost keys | User | Backup flow, honest warnings | Permanent message loss by design |
| T15 | Log leakage | A4 | Access logs off, scrubbed app logs, tests | Operator can add logging; cannot be technically prevented |
| T16 | Supply chain (Python/JS deps) | All | Pinned versions with hashes, `pip-audit`, vendored JS hash check | Zero-days |
| T17 | Timing side channels on login/username existence | A1 | Dummy-hash verification, generic errors | Registration necessarily reveals if a username is taken |
| T19 | Login-budget exhaustion: an attacker spends the global login budget (default 300/min) so legitimate logins get 429 | A1 | Budget is configurable; Tor onion-service PoW defenses throttle floods upstream | **Accepted:** global limits cannot distinguish users when IPs are unavailable; availability is traded for brute-force protection |
| T20 | Weakened CSP: `'wasm-unsafe-eval'` allows WebAssembly compilation | A8 | Needed for Argon2id key protection; JS `eval` and inline script stay blocked; all scripts same-origin and hash-published | Injected script from the same origin could run WASM; it could already run JS in that case |
| T18 | Message-size/timing metadata analysis | A4, A3 | Optional padding of ciphertext to size buckets | Padding is future work; sizes visible in v1 |

## 4. What administrators can and cannot access

**Can access:** usernames; creation and last-login times; public keys and fingerprints; which user sent a message to which user; timestamps; ciphertext sizes; read/unread and folder state; session records; (if the user opted in) the passphrase-protected private key blob.

**Cannot access (assuming unmodified code and a non-trivial key passphrase):** subjects, bodies, private keys, key passphrases, login passwords (only hashes).

**Can access if malicious (T9):** anything a user types or decrypts in a modified page.

## 5. Out of scope

- Delivery to or from SMTP/external providers.
- Defense against a global passive adversary or Tor protocol breaks.
- Compromised user devices or browsers.
- Legal compulsion of the operator or hosting provider.
- Forward secrecy for stored messages: OpenPGP encrypts to a long-lived key, so a stolen private key plus stored ciphertext reveals history. Key rotation will be supported, but past ciphertext is not re-encrypted automatically.

## 6. Security properties we claim, and do not claim

We claim: ciphertext-only storage of message content; no password or private key exposure to the server in normal operation; no client IP storage; no third-party requests.

We do **not** claim: anonymity against capable adversaries; metadata privacy; protection from a malicious operator; resistance to endpoint compromise.

## 7. Assumptions

1. Users use Tor Browser, current version.
2. The operator runs the published code and keeps the host patched.
3. Cryptographic libraries (OpenPGP.js, argon2-cffi, Tor) are correct.
4. Users choose a strong key passphrase.
