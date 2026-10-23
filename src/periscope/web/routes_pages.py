import hmac

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse

from periscope import i18n
from periscope.config import get_settings
from periscope.db import get_db
from periscope.models import User
from periscope.web.deps import session_row
from periscope.web.routes_auth import LOGIN_CSRF

router = APIRouter()


@router.get("/")
async def index():
    return RedirectResponse("/dashboard", 303)


def _csrf_ok(sent, tokens: list[str]) -> bool:
    return isinstance(sent, str) and any(hmac.compare_digest(sent.encode(), t.encode()) for t in tokens if t)


@router.post("/lang")
async def set_language(request: Request, db=Depends(get_db)):
    """Language switch. CSRF: the session token when logged in (also while the second factor is
    pending), or the pre-login double-submit cookie (login page). Sets the cookie and, when a user
    session exists, saves the preference on the account."""
    form = await request.form()
    row = session_row(request, db)
    tokens = [row.csrf if row else "", request.cookies.get(LOGIN_CSRF, "")]
    if not _csrf_ok(form.get("csrf"), tokens):
        raise HTTPException(403, i18n.tr(request, "Invalid CSRF token"))
    lang = i18n.normalize(form.get("lang"))
    if lang is None:
        raise HTTPException(400, i18n.tr(request, "Unsupported language"))
    if row and (user := db.get(User, row.user_id)):
        user.lang = lang
        db.commit()
    resp = RedirectResponse(i18n.safe_next(form.get("next")), 303)
    resp.set_cookie(i18n.COOKIE, lang, max_age=i18n.COOKIE_MAX_AGE, httponly=True, samesite="lax",
                    secure=get_settings().cookie_secure, path="/")
    return resp
