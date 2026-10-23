import hmac
import logging
import re
import secrets

import segno
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from webauthn.helpers import base64url_to_bytes

from periscope.auth import mfa, ratelimit, sessions
from periscope.auth import webauthn_ as wa
from periscope.auth.audit import audit
from periscope.auth.passwords import verify_password
from periscope.clock import utcnow
from periscope.config import get_settings
from periscope.db import get_db
from periscope.i18n import N_, tr
from periscope.models import Credential, User
from periscope.web.deps import current_user, pending_user, session_row
from periscope.web.reauth import ERRORS, reauth, revoke_other_sessions
from periscope.web.render import render

log = logging.getLogger("periscope.auth")
router = APIRouter()
limiter = ratelimit.IPLimiter()
login_failures = ratelimit.LoginFailures()
GENERIC = N_("Invalid credentials or account temporarily locked.")


def ip_of(request: Request) -> str:
    return request.client.host if request.client else ""


THROTTLED = N_("Too many attempts, please try again later.")


def throttle(request: Request, family: str) -> int:
    """Count an attempt for (endpoint family, IP); return the blocking seconds (0 = OK)."""
    key = f"{family}:{ip_of(request)}"
    return 0 if limiter.hit(key) else max(1, limiter.retry_after(key))


def retry_after(resp, secs: int):
    resp.headers["Retry-After"] = str(secs)
    return resp


def set_cookie(resp, token: str, *, final: bool):
    cfg = get_settings()
    resp.set_cookie(sessions.COOKIE, token, httponly=True, secure=cfg.cookie_secure,
                    samesite="strict", path="/", max_age=cfg.session_max_seconds if final else None)
    return resp


def finish_login(request: Request, db, user: User, method: str) -> str:
    """Promote the session to a full session; return the new token."""
    ratelimit.register_success(user)
    login_failures.clear(user.username, ip_of(request))
    token = sessions.promote(db, request.state.session, user, utcnow())
    audit(db, "login", user.username, detail=method, ip=ip_of(request))
    db.commit()
    return token


def fail_2fa(request: Request, db, user: User, event: str = "login_2fa_failed") -> None:
    ratelimit.register_failure(user, utcnow())
    audit(db, event, user.username, ip=ip_of(request))
    db.commit()


def twofa_page(request: Request, user: User, error: str | None = None, status: int = 200):
    return render(request, "login_2fa.html", status=status, error=error,
                  has_totp=user.totp_confirmed, has_passkey=bool(user.credentials))


# --- password ---------------------------------------------------------

LOGIN_CSRF = "periscope_login_csrf"


def login_form(request: Request, status: int = 200, error: str | None = None):
    """Login form with pre-session CSRF (identical cookie + hidden field)."""
    token = request.cookies.get(LOGIN_CSRF) or secrets.token_urlsafe(24)
    resp = render(request, "login.html", status=status, error=error, login_csrf=token)
    resp.set_cookie(LOGIN_CSRF, token, httponly=True, secure=get_settings().cookie_secure,
                    samesite="strict", path="/")
    return resp


@router.get("/login")
async def login_page(request: Request, db=Depends(get_db)):
    row = session_row(request, db)
    if row and row.mfa_ok:
        return RedirectResponse("/", 303)
    return login_form(request)


@router.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...),
                csrf: str = Form(""), db=Depends(get_db)):
    ip, now = ip_of(request), utcnow()
    cookie = request.cookies.get(LOGIN_CSRF, "")
    if not cookie or not hmac.compare_digest(csrf.encode(), cookie.encode()):
        raise HTTPException(403, tr(request, "Invalid CSRF token"))
    if wait := throttle(request, "login"):
        audit(db, "login_throttled", username, ip=ip)
        db.commit()
        return retry_after(login_form(request, 429, tr(request, THROTTLED)), wait)
    # Password lock by (username, IP) only: never on the real account (anti-DoS).
    user = db.query(User).filter_by(username=username).one_or_none()
    locked = bool(login_failures.retry_after(username, ip))
    if locked or not verify_password(user.password_hash if user else None, password):
        if not locked:
            login_failures.register_failure(username, ip)
        audit(db, "login_locked" if locked else "login_failed", username, ip=ip)
        db.commit()
        return login_form(request, 401, tr(request, GENERIC))
    token, _ = sessions.create(db, user, False, now)
    audit(db, "password_ok", username, ip=ip)
    db.commit()
    dest = "/login/2fa" if mfa.has_second_factor(user) else "/enroll"
    return set_cookie(RedirectResponse(dest, 303), token, final=False)


# --- second factor -------------------------------------------------------

@router.get("/login/2fa")
async def twofa_get(request: Request, user: User = Depends(pending_user)):
    if not mfa.has_second_factor(user):
        return RedirectResponse("/enroll", 303)
    return twofa_page(request, user)


@router.post("/login/2fa")
async def twofa_post(request: Request, code: str = Form(...), user: User = Depends(pending_user),
                     db=Depends(get_db)):
    if wait := throttle(request, "2fa"):
        audit(db, "login_throttled", user.username, detail="2fa", ip=ip_of(request))
        db.commit()
        return retry_after(twofa_page(request, user, tr(request, THROTTLED), 429), wait)
    if ratelimit.is_locked(user, utcnow()):
        audit(db, "login_locked", user.username, ip=ip_of(request))
        db.commit()
        return twofa_page(request, user, tr(request, "Account temporarily locked."), 429)
    method = None
    if user.totp_confirmed and re.fullmatch(r"\d{6}", code.strip().replace(" ", "")):
        step = mfa.verify_totp(user.totp_secret_enc, code, user.totp_last_step)
        if step:
            user.totp_last_step, method = step, "totp"
    if method is None and mfa.consume_backup(user, code):
        method = "backup_code"
    if method is None:
        fail_2fa(request, db, user)
        return twofa_page(request, user, tr(request, "Invalid code."), 401)
    token = finish_login(request, db, user, method)
    return set_cookie(RedirectResponse("/", 303), token, final=True)


@router.post("/webauthn/auth/options")
async def passkey_auth_options(request: Request, user: User = Depends(pending_user), db=Depends(get_db)):
    opts, challenge = wa.authentication_options(user)
    request.state.session.challenge = challenge
    db.commit()
    return opts


@router.post("/webauthn/auth/verify")
async def passkey_auth_verify(request: Request, user: User = Depends(pending_user), db=Depends(get_db)):
    if wait := throttle(request, "2fa"):
        audit(db, "login_throttled", user.username, detail="passkey", ip=ip_of(request))
        db.commit()
        return JSONResponse({"error": tr(request, THROTTLED)}, status_code=429, headers={"Retry-After": str(wait)})
    if ratelimit.is_locked(user, utcnow()):
        audit(db, "login_locked", user.username, ip=ip_of(request))
        db.commit()
        return JSONResponse({"error": tr(request, "Account temporarily locked.")}, status_code=429)
    row = request.state.session
    body = await request.json()
    challenge, row.challenge = row.challenge, None
    try:
        stored = db.query(Credential).filter_by(
            user_id=user.id, credential_id=base64url_to_bytes(body["id"])).one()
        stored.sign_count = wa.verify_authentication(body, challenge, stored)
    except Exception:
        log.info("passkey verification failed for %s", user.username, exc_info=True)
        fail_2fa(request, db, user, "login_passkey_failed")
        return JSONResponse({"error": tr(request, "Passkey verification failed")}, status_code=401)
    token = finish_login(request, db, user, "passkey")
    return set_cookie(JSONResponse({"ok": True, "redirect": "/"}), token, final=True)


# --- initial enrollment (TOTP) -------------------------------------------

def enroll_page(request: Request, db, user: User, error: str | None = None, status: int = 200):
    if not user.totp_secret_enc:
        user.totp_secret_enc = mfa.new_secret_enc()
        db.commit()
    uri = mfa.provisioning_uri(user.totp_secret_enc, user.username, get_settings().rp_name)
    return render(request, "enroll.html", status=status, error=error,
                  qr=segno.make(uri).png_data_uri(scale=5), secret=mfa.secret_plain(user.totp_secret_enc))


@router.get("/enroll")
async def enroll_get(request: Request, user: User = Depends(pending_user), db=Depends(get_db)):
    if mfa.has_second_factor(user):
        return RedirectResponse("/login/2fa", 303)
    return enroll_page(request, db, user)


@router.post("/enroll")
async def enroll_post(request: Request, code: str = Form(...), user: User = Depends(pending_user),
                      db=Depends(get_db)):
    if mfa.has_second_factor(user):
        return RedirectResponse("/login/2fa", 303)
    if wait := throttle(request, "enroll"):
        audit(db, "login_throttled", user.username, detail="enroll", ip=ip_of(request))
        db.commit()
        return retry_after(enroll_page(request, db, user, tr(request, THROTTLED), 429), wait)
    step = mfa.verify_totp(user.totp_secret_enc, code, 0) if user.totp_secret_enc else None
    if not step:
        fail_2fa(request, db, user, "enroll_failed")
        return enroll_page(request, db, user, tr(request, "Invalid code."), 401)
    user.totp_confirmed, user.totp_last_step = True, step
    codes = mfa.reset_backup_codes(db, user)
    audit(db, "totp_enrolled", user.username, ip=ip_of(request))
    token = finish_login(request, db, user, "enroll")
    request.state.session = None  # the old session no longer exists
    return set_cookie(render(request, "backup_codes.html", codes=codes), token, final=True)


def _enroll_denied(request: Request, db, user: User, detail: str):
    """JSON error response if passkey enrollment is not allowed, otherwise None."""
    if mfa.has_second_factor(user):
        return JSONResponse({"error": tr(request, "A second factor is already configured.")}, status_code=403)
    if wait := throttle(request, "enroll"):
        audit(db, "login_throttled", user.username, detail=detail, ip=ip_of(request))
        db.commit()
        return JSONResponse({"error": tr(request, THROTTLED)}, status_code=429, headers={"Retry-After": str(wait)})
    return None


@router.post("/webauthn/enroll/options")
async def passkey_enroll_options(request: Request, user: User = Depends(pending_user), db=Depends(get_db)):
    if denied := _enroll_denied(request, db, user, "passkey_enroll"):
        return denied
    opts, challenge = wa.registration_options(user)
    request.state.session.challenge = challenge
    db.commit()
    return opts


@router.post("/webauthn/enroll/verify")
async def passkey_enroll_verify(request: Request, user: User = Depends(pending_user), db=Depends(get_db)):
    if denied := _enroll_denied(request, db, user, "passkey_enroll"):
        return denied
    row = request.state.session
    body = await request.json()
    challenge, row.challenge = row.challenge, None
    try:
        cid, pub, count = wa.verify_registration(body, challenge)
    except Exception:
        log.info("passkey enrollment failed for %s", user.username, exc_info=True)
        fail_2fa(request, db, user, "enroll_failed")
        return JSONResponse({"error": tr(request, "Passkey registration failed")}, status_code=400)
    db.add(Credential(user_id=user.id, credential_id=cid, public_key=pub, sign_count=count, name="Passkey 1"))
    audit(db, "passkey_enrolled", user.username, ip=ip_of(request))
    token = finish_login(request, db, user, "enroll_passkey")
    return set_cookie(JSONResponse({"ok": True, "redirect": "/account?m=codes_hint"}), token, final=True)


# --- logout ----------------------------------------------------------

@router.post("/logout")
async def logout(request: Request, user: User = Depends(current_user), db=Depends(get_db)):
    sessions.destroy(db, request.cookies.get(sessions.COOKIE, ""))
    audit(db, "logout", user.username, ip=ip_of(request))
    db.commit()
    resp = RedirectResponse("/login", 303)
    resp.delete_cookie(sessions.COOKIE, path="/")
    return resp


# --- passkey registration (logged-in user) --------------------

@router.post("/webauthn/register/options")
async def passkey_register_options(request: Request, user: User = Depends(current_user), db=Depends(get_db)):
    try:
        body = await request.json()
    except ValueError:
        body = {}
    password = body.get("password") if isinstance(body, dict) else None
    if err := reauth(request, db, user, password if isinstance(password, str) else ""):
        return JSONResponse({"error": tr(request, ERRORS[err])}, status_code=403)
    opts, challenge = wa.registration_options(user)
    request.state.session.challenge = challenge
    db.commit()
    return opts


@router.post("/webauthn/register/verify")
async def passkey_register_verify(request: Request, user: User = Depends(current_user), db=Depends(get_db)):
    row = request.state.session
    body = await request.json()
    challenge, row.challenge = row.challenge, None
    try:
        cid, pub, count = wa.verify_registration(body, challenge)
    except Exception:
        log.info("passkey registration failed for %s", user.username, exc_info=True)
        db.commit()
        return JSONResponse({"error": tr(request, "Passkey registration failed")}, status_code=400)
    db.add(Credential(user_id=user.id, credential_id=cid, public_key=pub, sign_count=count,
                      name=f"Passkey {len(user.credentials) + 1}"))
    audit(db, "passkey_added", user.username, ip=ip_of(request))
    revoke_other_sessions(request, db, user, "passkey_added")
    db.commit()
    return {"ok": True}
