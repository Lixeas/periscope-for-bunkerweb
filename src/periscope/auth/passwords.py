import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

MIN_LENGTH = 12
_ph = PasswordHasher()  # argon2id par défaut
_DUMMY = _ph.hash(secrets.token_urlsafe(32))  # secret aléatoire : aucun mot de passe ne peut le valider


def hash_password(password: str) -> str:
    if len(password) < MIN_LENGTH:
        raise ValueError(f"mot de passe trop court ({MIN_LENGTH} caractères minimum)")
    return _ph.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    """Utilisateur inconnu (None) : on vérifie un faux hash pour égaliser le temps, puis on refuse."""
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
