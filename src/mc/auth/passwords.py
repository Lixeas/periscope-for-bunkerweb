from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

MIN_LENGTH = 12
_ph = PasswordHasher()  # argon2id par défaut
_DUMMY = _ph.hash("dummy-password-for-timing")


def hash_password(password: str) -> str:
    if len(password) < MIN_LENGTH:
        raise ValueError(f"mot de passe trop court ({MIN_LENGTH} caractères minimum)")
    return _ph.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    """Utilisateur inconnu (None) : on vérifie quand même un faux hash pour égaliser le temps."""
    try:
        _ph.verify(password_hash or _DUMMY, password)
    except (VerifyMismatchError, InvalidHashError):
        return False
    return password_hash is not None
