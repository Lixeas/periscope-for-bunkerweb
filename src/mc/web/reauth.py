from fastapi import Request

from mc.auth import ratelimit
from mc.auth.audit import audit
from mc.auth.passwords import verify_password
from mc.clock import utcnow
from mc.models import Session, User

ERRORS = {
    "pwd_bad": "Mot de passe actuel incorrect.",
    "locked": "Trop d'échecs : compte temporairement verrouillé.",
}


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


def reauth(request: Request, db, user: User, password: str) -> str | None:
    """Ré-authentification par mot de passe, avec le même verrouillage que la connexion.
    Retourne un code de message d'erreur, ou None si le mot de passe est correct."""
    now = utcnow()
    if ratelimit.is_locked(user, now):
        return "locked"
    if verify_password(user.password_hash, password):
        return None
    ratelimit.register_failure(user, now)
    audit(db, "reauth_failed", user.username, ip=_ip(request))
    db.commit()
    return "pwd_bad"


def revoke_other_sessions(request: Request, db, user: User, reason: str) -> None:
    """Après un changement de second facteur : ferme toutes les autres sessions (non committé)."""
    db.query(Session).filter(Session.user_id == user.id, Session.id != request.state.session.id).delete()
    audit(db, "sessions_revoked", user.username, detail=reason, ip=_ip(request))
