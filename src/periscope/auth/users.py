import re

from sqlalchemy.orm import Session

from periscope.auth.passwords import hash_password
from periscope.i18n import N_, LocalizedError
from periscope.models import User


def create_user(db: Session, username: str, password: str, role: str = "reader") -> User:
    username = username.strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,64}", username):
        raise LocalizedError(N_("Invalid username (3-64 characters: letters, digits, . _ -)"))
    if role not in ("admin", "reader"):
        raise LocalizedError(N_("Invalid role"))
    if db.query(User).filter_by(username=username).first():
        raise LocalizedError(N_("User already exists"))
    user = User(username=username, password_hash=hash_password(password), role=role)
    db.add(user)
    db.flush()
    return user
