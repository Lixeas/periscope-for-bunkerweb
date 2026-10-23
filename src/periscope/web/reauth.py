from fastapi import Request

from periscope.auth import ratelimit
from periscope.auth.audit import audit
from periscope.auth.passwords import verify_password
from periscope.clock import utcnow
from periscope.i18n import N_
from periscope.models import Session, User

ERRORS = {
    "pwd_bad": N_("Current password is incorrect."),
    "locked": N_("Too many failures: account temporarily locked."),
}


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


def reauth(request: Request, db, user: User, password: str) -> str | None:
    """Password re-authentication, with the same lockout as login.
    Returns an error message code, or None if the password is correct."""
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
    """After a second-factor change: close all other sessions (not committed)."""
    db.query(Session).filter(Session.user_id == user.id, Session.id != request.state.session.id).delete()
    audit(db, "sessions_revoked", user.username, detail=reason, ip=_ip(request))
