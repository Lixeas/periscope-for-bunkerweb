import hmac
import logging
import re
import secrets

import segno
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from webauthn.helpers import base64url_to_bytes

from mc.auth import mfa, ratelimit, sessions
from mc.auth import webauthn_ as wa
from mc.auth.audit import audit
from mc.auth.passwords import verify_password
from mc.clock import utcnow
from mc.config import get_settings
from mc.db import get_db
from mc.models import Credential, User
from mc.web.deps import current_user, pending_user, session_row
from mc.web.render import render

log = logging.getLogger("mc.auth")
router = APIRouter()
limiter = ratelimit.IPLimiter()
GENERIC = "Identifiants invalides ou compte temporairement verrouillé."


def ip_of(request: Request) -> str:
    return request.client.host if request.client else ""


def set_cookie(resp, token: str, *, final: bool):
    cfg = get_settings()
    resp.set_cookie(sessions.COOKIE, token, httponly=True, secure=cfg.cookie_secure,
                    samesite="strict", path="/", max_age=cfg.session_max_seconds if final else None)
    return resp


def finish_login(request: Request, db, user: User, method: str) -> str:
    """Promeut la session en session pleine ; retourne le nouveau jeton."""
    ratelimit.register_success(user)
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


# --- mot de passe ---------------------------------------------------------

LOGIN_CSRF = "mc_login_csrf"


def login_form(request: Request, status: int = 200, error: str | None = None):
    """Formulaire de connexion avec CSRF pré-session (cookie + champ caché identiques)."""
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
        raise HTTPException(403, "CSRF invalide")
    if not limiter.hit(ip):
        audit(db, "login_throttled", username, ip=ip)
        db.commit()
        return login_form(request, 429, "Trop de tentatives, réessayez plus tard.")
    user = db.query(User).filter_by(username=username).one_or_none()
    locked = bool(user and ratelimit.is_locked(user, now))
    if not (verify_password(user.password_hash if user else None, password) and not locked):
        if user and not locked:
            ratelimit.register_failure(user, now)
        audit(db, "login_locked" if locked else "login_failed", username, ip=ip)
        db.commit()
        return login_form(request, 401, GENERIC)
    token, _ = sessions.create(db, user, False, now)
    audit(db, "password_ok", username, ip=ip)
    db.commit()
    dest = "/login/2fa" if mfa.has_second_factor(user) else "/enroll"
    return set_cookie(RedirectResponse(dest, 303), token, final=False)


# --- second facteur -------------------------------------------------------

@router.get("/login/2fa")
async def twofa_get(request: Request, user: User = Depends(pending_user)):
    if not mfa.has_second_factor(user):
        return RedirectResponse("/enroll", 303)
    return twofa_page(request, user)


@router.post("/login/2fa")
async def twofa_post(request: Request, code: str = Form(...), user: User = Depends(pending_user),
                     db=Depends(get_db)):
    if ratelimit.is_locked(user, utcnow()):
        audit(db, "login_locked", user.username, ip=ip_of(request))
        db.commit()
        return twofa_page(request, user, "Compte temporairement verrouillé.", 429)
    method = None
    if user.totp_confirmed and re.fullmatch(r"\d{6}", code.strip().replace(" ", "")):
        step = mfa.verify_totp(user.totp_secret_enc, code, user.totp_last_step)
        if step:
            user.totp_last_step, method = step, "totp"
    if method is None and mfa.consume_backup(user, code):
        method = "backup_code"
    if method is None:
        fail_2fa(request, db, user)
        return twofa_page(request, user, "Code invalide.", 401)
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
    if ratelimit.is_locked(user, utcnow()):
        audit(db, "login_locked", user.username, ip=ip_of(request))
        db.commit()
        return JSONResponse({"error": "Compte temporairement verrouillé."}, status_code=429)
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
        return JSONResponse({"error": "Vérification de la passkey échouée"}, status_code=401)
    token = finish_login(request, db, user, "passkey")
    return set_cookie(JSONResponse({"ok": True, "redirect": "/"}), token, final=True)


# --- enrôlement initial (TOTP) -------------------------------------------

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
    step = mfa.verify_totp(user.totp_secret_enc, code, 0) if user.totp_secret_enc else None
    if not step:
        fail_2fa(request, db, user, "enroll_failed")
        return enroll_page(request, db, user, "Code invalide.", 401)
    user.totp_confirmed, user.totp_last_step = True, step
    codes = mfa.reset_backup_codes(db, user)
    audit(db, "totp_enrolled", user.username, ip=ip_of(request))
    token = finish_login(request, db, user, "enroll")
    request.state.session = None  # l'ancienne session n'existe plus
    return set_cookie(render(request, "backup_codes.html", codes=codes), token, final=True)


# --- déconnexion ----------------------------------------------------------

@router.post("/logout")
async def logout(request: Request, user: User = Depends(current_user), db=Depends(get_db)):
    sessions.destroy(db, request.cookies.get(sessions.COOKIE, ""))
    audit(db, "logout", user.username, ip=ip_of(request))
    db.commit()
    resp = RedirectResponse("/login", 303)
    resp.delete_cookie(sessions.COOKIE, path="/")
    return resp


# --- enregistrement de passkey (utilisateur connecté) --------------------

@router.post("/webauthn/register/options")
async def passkey_register_options(request: Request, user: User = Depends(current_user), db=Depends(get_db)):
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
        return JSONResponse({"error": "Enregistrement de la passkey échoué"}, status_code=400)
    db.add(Credential(user_id=user.id, credential_id=cid, public_key=pub, sign_count=count,
                      name=f"Passkey {len(user.credentials) + 1}"))
    audit(db, "passkey_added", user.username, ip=ip_of(request))
    db.commit()
    return {"ok": True}
