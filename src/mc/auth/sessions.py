import hashlib
import secrets
from datetime import datetime, timedelta

from sqlalchemy.orm import Session as DB

from mc.models import Session, User

COOKIE = "mc_session"
PENDING_IDLE = 300  # session « mot de passe OK, 2FA en attente »
PENDING_MAX = 900


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create(db: DB, user: User, mfa_ok: bool, now: datetime) -> tuple[str, Session]:
    db.query(Session).filter(Session.last_seen < now - timedelta(days=1)).delete()  # purge
    token = secrets.token_urlsafe(32)
    row = Session(id=_hash(token), user_id=user.id, csrf=secrets.token_urlsafe(24),
                  mfa_ok=mfa_ok, created_at=now, last_seen=now)
    db.add(row)
    db.flush()
    return token, row


def lookup(db: DB, token: str, now: datetime, idle: int, max_age: int) -> Session | None:
    row = db.get(Session, _hash(token))
    if row is None:
        return None
    idle_limit, max_limit = (idle, max_age) if row.mfa_ok else (PENDING_IDLE, PENDING_MAX)
    if (now - row.last_seen > timedelta(seconds=idle_limit)
            or now - row.created_at > timedelta(seconds=max_limit)):
        db.delete(row)
        return None
    row.last_seen = now
    return row


def destroy(db: DB, token: str) -> None:
    row = db.get(Session, _hash(token))
    if row:
        db.delete(row)


def promote(db: DB, row: Session, user: User, now: datetime) -> str:
    """Après validation du 2FA : nouvelle session pleine, nouveau jeton (anti fixation)."""
    db.delete(row)
    token, _ = create(db, user, True, now)
    return token
