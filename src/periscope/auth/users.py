import re

from sqlalchemy.orm import Session

from periscope.auth.passwords import hash_password
from periscope.models import User


def create_user(db: Session, username: str, password: str, role: str = "reader") -> User:
    username = username.strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,64}", username):
        raise ValueError("nom d'utilisateur invalide (3-64 caractères : lettres, chiffres, . _ -)")
    if role not in ("admin", "reader"):
        raise ValueError("rôle invalide")
    if db.query(User).filter_by(username=username).first():
        raise ValueError("utilisateur déjà existant")
    user = User(username=username, password_hash=hash_password(password), role=role)
    db.add(user)
    db.flush()
    return user
