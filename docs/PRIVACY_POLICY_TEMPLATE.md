# Privacy policy — template for operators

This is a **template, not legal advice**. The in-app page at `/privacy` describes what the software does. Operators
must add their own facts, check local law (data protection, lawful-access, logging obligations), and keep the policy true.

## Operator
Name or pseudonym: ____  Contact (also set `TORMAIL_OPERATOR_CONTACT`): ____  Jurisdiction of the server: ____

## What the software stores
Username; Argon2id hash of the login password; public encryption key and fingerprint; optionally a passphrase-encrypted
private key blob (opt-in); messages as ciphertext; metadata: sender account, recipient accounts, timestamps, size, read
state, folder; session token hashes with created/last-used/expiry times; keyed-hash abuse counters.

## What the software does not store
Email address, phone number, real name, IP addresses, user-agent strings, analytics, third-party requests.

## What the operator can and cannot see
Can: usernames, account creation and last-login times, public keys, who wrote to whom and when, message sizes.
Cannot (unmodified software, strong key passphrase): subjects, bodies, recipients inside messages, private keys, passwords.
Limit: a web app delivers its own code; an operator, or an attacker who controls the server, could serve altered code.

## Retention
Trash purged after __ days (default 30). Sessions expire after 30 min idle / 12 h. Counters expire within hours.
Backups: kept for ____ days, encrypted, stored at ____. Deleted data may persist in backups until they rotate out.

## Account deletion
Settings → Delete account. Removes login, keys, sessions and mailbox. Sent copies stay in recipients' mailboxes without a link to you.

## Disclosure
Describe how you handle legal requests. State plainly what you could hand over (the metadata above and ciphertext)
and what you cannot (plaintext, private keys). Do not promise what you cannot guarantee.

## Limits you should know about
Tor reduces but does not eliminate the ways you can be identified. Writing style, timing, account links across
services, malware on your device, or a compromised Tor Browser can all identify you. Lost key = lost messages.
