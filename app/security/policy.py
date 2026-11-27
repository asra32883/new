"""Username and password policy. No composition rules: length plus a deny-list (NIST SP 800-63B style)."""
from __future__ import annotations

import re

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")
RESERVED = frozenset(
    "admin administrator root postmaster abuse security support help info mail webmaster "
    "system noreply no-reply tor onion tormail staff moderator null undefined api static".split()
)
MIN_PASSWORD = 12
MAX_PASSWORD = 256
COMMON_PASSWORDS = frozenset(
    p.lower()
    for p in (
        "password1234", "passwordpassword", "123456789012", "1234567890123", "qwertyuiop12",
        "qwertyqwerty", "iloveyou1234", "letmein12345", "administrator", "welcome12345",
        "password12345", "changeme1234", "abcdefghijkl", "111111111111", "000000000000",
        "correcthorsebatterystaple", "trustno1trustno1", "monkeymonkey12", "dragondragon12",
    )
)


def normalize_username(username: str) -> str:
    # NUL cannot be stored or queried in PostgreSQL text; map it to a character no valid username contains,
    # so such input simply fails to match instead of raising a database error.
    return username.replace("\x00", "\ufffd").strip().lower()


def validate_username(username: str) -> str:
    u = normalize_username(username)
    if not USERNAME_RE.match(u):
        raise ValueError("Username must be 3-32 characters: letters, digits, '.', '_' or '-', starting with a letter or digit")
    if u in RESERVED:
        raise ValueError("That username is reserved")
    return u


def validate_password(password: str, username: str = "") -> None:
    if len(password) < MIN_PASSWORD:
        raise ValueError(f"Password must be at least {MIN_PASSWORD} characters")
    if len(password) > MAX_PASSWORD:
        raise ValueError(f"Password must be at most {MAX_PASSWORD} characters")
    low = password.lower()
    if low in COMMON_PASSWORDS:
        raise ValueError("That password is too common")
    if username and normalize_username(username) in low:
        raise ValueError("Password must not contain your username")
    if len(set(password)) < 5:
        raise ValueError("Password is too repetitive")
