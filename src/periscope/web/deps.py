import hmac

from fastapi import Depends, HTTPException, Request

from periscope.auth import sessions
from periscope.clock import utcnow
from periscope.config import get_settings
from periscope.db import get_db
from periscope.i18n import tr
from periscope.models import Session, User


class Redirect(Exception):
    def __init__(self, url: str):
        self.url = url


def session_row(request: Request, db) -> Session | None:
    token = request.cookies.get(sessions.COOKIE)
    if not token:
        return None
    cfg = get_settings()
    return sessions.lookup(db, token, utcnow(), cfg.session_idle_seconds, cfg.session_max_seconds)


async def _check_csrf(request: Request, row: Session) -> None:
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    sent = request.headers.get("x-csrf-token")
    if sent is None:
        form = await request.form()
        sent = form.get("csrf")
    if not isinstance(sent, str) or not hmac.compare_digest(sent, row.csrf):
        raise HTTPException(403, tr(request, "Invalid CSRF token"))


async def _user_for(request: Request, db, *, full: bool) -> User:
    row = session_row(request, db)
    if row is None or row.mfa_ok != full:
        raise Redirect("/login")
    user = db.get(User, row.user_id)
    if user is None:
        raise Redirect("/login")
    request.state.lang_pref = user.lang  # the saved preference wins over cookie and header
    await _check_csrf(request, row)
    request.state.session = row
    return user


async def pending_user(request: Request, db=Depends(get_db)) -> User:
    """Password validated, second factor pending."""
    return await _user_for(request, db, full=False)


async def current_user(request: Request, db=Depends(get_db)) -> User:
    return await _user_for(request, db, full=True)


async def require_admin(request: Request, user: User = Depends(current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(403, tr(request, "Administrators only"))
    return user
