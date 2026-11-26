import pytest

from app.config import Settings
from app.security import policy
from app.security.passwords import PasswordService

S = Settings(_env_file=None, env="test", argon2_time_cost=1, argon2_memory_kib=64, argon2_parallelism=1)


def test_hash_is_argon2id_and_salted():
    pw = PasswordService(S)
    h1, h2 = pw.hash("correct horse 7 battery"), pw.hash("correct horse 7 battery")
    assert h1.startswith("$argon2id$") and h1 != h2
    assert "correct horse" not in h1


def test_verify_and_unknown_user():
    pw = PasswordService(S)
    h = pw.hash("correct horse 7 battery")
    assert pw.verify(h, "correct horse 7 battery")
    assert not pw.verify(h, "wrong")
    assert not pw.verify(None, "anything")  # dummy-hash path never succeeds


def test_needs_rehash_when_params_weaker():
    old = PasswordService(S).hash("correct horse 7 battery")
    stronger = Settings(_env_file=None, env="test", argon2_time_cost=2, argon2_memory_kib=128, argon2_parallelism=1)
    assert PasswordService(stronger).needs_rehash(old)


@pytest.mark.parametrize("bad", ["short", "a" * 300, "password1234", "aaaaaaaaaaaaaaa", "xx-alice-xxxxxxx-1"])
def test_bad_passwords(bad):
    with pytest.raises(ValueError):
        policy.validate_password(bad, "alice")


@pytest.mark.parametrize("bad", ["ab", "A b", "-abc", "admin", "a" * 33, "bob/../x", "ünïcode"])
def test_bad_usernames(bad):
    with pytest.raises(ValueError):
        policy.validate_username(bad)


def test_username_normalised():
    assert policy.validate_username("  Alice.B ") == "alice.b"
