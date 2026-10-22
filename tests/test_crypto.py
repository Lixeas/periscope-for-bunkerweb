import pytest
from cryptography.fernet import InvalidToken

from mc.crypto import decrypt, encrypt


def test_roundtrip_and_not_plaintext():
    token = encrypt("s3cr3t-token")
    assert token != "s3cr3t-token"
    assert "s3cr3t" not in token
    assert decrypt(token) == "s3cr3t-token"


def test_tampered_ciphertext_rejected():
    token = encrypt("x")
    with pytest.raises(InvalidToken):
        decrypt(token[:-4] + "AAAA")
