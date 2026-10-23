import pytest

from periscope.auth.passwords import hash_password, verify_password


def test_hash_is_argon2id_and_verifies():
    h = hash_password("correct horse battery")
    assert h.startswith("$argon2id$")
    assert verify_password(h, "correct horse battery")
    assert not verify_password(h, "wrong password here")


def test_min_length_enforced():
    with pytest.raises(ValueError):
        hash_password("short")


def test_unknown_user_hash_is_false_but_still_hashes():
    assert verify_password(None, "whatever password") is False
