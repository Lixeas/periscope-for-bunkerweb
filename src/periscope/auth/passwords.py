import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from periscope.i18n import N_, LocalizedError

MIN_LENGTH = 12
_ph = PasswordHasher()  # argon2id by default
_DUMMY = _ph.hash(secrets.token_urlsafe(32))  # random secret: no password can match it


def hash_password(password: str) -> str:
    if len(password) < MIN_LENGTH:
        raise LocalizedError(N_("Password too short ({min} characters minimum)"), min=MIN_LENGTH)
    return _ph.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    """Unknown user (None): verify a dummy hash to equalize timing, then reject."""
    if not password_hash:
        try:
            _ph.verify(_DUMMY, password)
        except (VerificationError, InvalidHashError):
            pass
        return False
    try:
        return _ph.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False
