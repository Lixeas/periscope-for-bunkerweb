from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from periscope.auth import mfa
from periscope.auth.audit import audit
from periscope.auth.passwords import MIN_LENGTH, hash_password
from periscope.db import get_db
from periscope.i18n import N_, tr
from periscope.models import Credential, User
from periscope.web.deps import current_user
from periscope.web.reauth import ERRORS, reauth, revoke_other_sessions
from periscope.web.render import render
from periscope.web.routes_auth import ip_of

router = APIRouter(prefix="/account")

MESSAGES = {
    "pwd_ok": N_("Password changed; the other sessions have been closed."),
    **ERRORS,
    "pwd_short": N_("Password too short ({min} characters minimum)."),
    "pwd_mismatch": N_("The confirmation does not match."),
    "last_factor": N_("Not possible: this is your last second factor."),
    "totp_removed": N_("TOTP disabled."),
    "pk_deleted": N_("Passkey deleted."),
    "codes_hint": N_("Passkey registered. Remember to generate your backup codes."),
    "lang_saved": N_("Language preference saved."),
}


def back(code: str) -> RedirectResponse:
    return RedirectResponse(f"/account?m={code}", 303)


def factor_count(user: User) -> int:
    return int(user.totp_confirmed) + len(user.credentials)


@router.get("")
async def account(request: Request, user: User = Depends(current_user)):
    code = MESSAGES.get(request.query_params.get("m"))
    return render(request, "account.html", user=user,
                  msg=tr(request, code, min=MIN_LENGTH) if code else None,
                  backup_left=sum(not b.used for b in user.backup_codes))


@router.post("/password")
async def change_password(request: Request, current: str = Form(...), new: str = Form(...),
                          confirm: str = Form(...), user: User = Depends(current_user), db=Depends(get_db)):
    if err := reauth(request, db, user, current):
        return back(err)
    if len(new) < MIN_LENGTH:
        return back("pwd_short")
    if new != confirm:
        return back("pwd_mismatch")
    user.password_hash = hash_password(new)
    audit(db, "password_changed", user.username, ip=ip_of(request))
    revoke_other_sessions(request, db, user, "password_changed")
    db.commit()
    return back("pwd_ok")


@router.post("/backup-codes")
async def regenerate_codes(request: Request, password: str = Form(...), user: User = Depends(current_user),
                           db=Depends(get_db)):
    if err := reauth(request, db, user, password):
        return back(err)
    codes = mfa.reset_backup_codes(db, user)
    audit(db, "backup_codes_regenerated", user.username, ip=ip_of(request))
    revoke_other_sessions(request, db, user, "backup_codes")
    db.commit()
    return render(request, "backup_codes.html", user=user, codes=codes)


@router.post("/totp/remove")
async def remove_totp(request: Request, password: str = Form(...), user: User = Depends(current_user),
                      db=Depends(get_db)):
    if err := reauth(request, db, user, password):
        return back(err)
    if not user.credentials:
        return back("last_factor")
    user.totp_confirmed, user.totp_secret_enc = False, None
    audit(db, "totp_removed", user.username, ip=ip_of(request))
    revoke_other_sessions(request, db, user, "totp_removed")
    db.commit()
    return back("totp_removed")


@router.post("/passkeys/{cred_id}/delete")
async def delete_passkey(request: Request, cred_id: int, password: str = Form(...),
                         user: User = Depends(current_user), db=Depends(get_db)):
    if err := reauth(request, db, user, password):
        return back(err)
    cred = db.query(Credential).filter_by(id=cred_id, user_id=user.id).one_or_none()
    if cred is None:
        return back("pk_deleted")
    if factor_count(user) <= 1:
        return back("last_factor")
    user.credentials.remove(cred)
    audit(db, "passkey_deleted", user.username, ip=ip_of(request))
    revoke_other_sessions(request, db, user, "passkey_deleted")
    db.commit()
    return back("pk_deleted")
