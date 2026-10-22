from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from mc.auth import mfa
from mc.auth.audit import audit
from mc.auth.passwords import MIN_LENGTH, hash_password, verify_password
from mc.db import get_db
from mc.models import Credential, Session, User
from mc.web.deps import current_user
from mc.web.render import render
from mc.web.routes_auth import ip_of

router = APIRouter(prefix="/account")

MESSAGES = {
    "pwd_ok": "Mot de passe modifié ; les autres sessions ont été fermées.",
    "pwd_bad": "Mot de passe actuel incorrect.",
    "pwd_short": f"Mot de passe trop court ({MIN_LENGTH} caractères minimum).",
    "pwd_mismatch": "La confirmation ne correspond pas.",
    "last_factor": "Impossible : c'est votre dernier second facteur.",
    "totp_removed": "TOTP désactivé.",
    "pk_deleted": "Passkey supprimée.",
}


def back(code: str) -> RedirectResponse:
    return RedirectResponse(f"/account?m={code}", 303)


def factor_count(user: User) -> int:
    return int(user.totp_confirmed) + len(user.credentials)


@router.get("")
async def account(request: Request, user: User = Depends(current_user)):
    return render(request, "account.html", user=user, msg=MESSAGES.get(request.query_params.get("m")),
                  backup_left=sum(not b.used for b in user.backup_codes))


@router.post("/password")
async def change_password(request: Request, current: str = Form(...), new: str = Form(...),
                          confirm: str = Form(...), user: User = Depends(current_user), db=Depends(get_db)):
    if not verify_password(user.password_hash, current):
        return back("pwd_bad")
    if len(new) < MIN_LENGTH:
        return back("pwd_short")
    if new != confirm:
        return back("pwd_mismatch")
    user.password_hash = hash_password(new)
    db.query(Session).filter(Session.user_id == user.id, Session.id != request.state.session.id).delete()
    audit(db, "password_changed", user.username, ip=ip_of(request))
    db.commit()
    return back("pwd_ok")


@router.post("/backup-codes")
async def regenerate_codes(request: Request, password: str = Form(...), user: User = Depends(current_user),
                           db=Depends(get_db)):
    if not verify_password(user.password_hash, password):
        return back("pwd_bad")
    codes = mfa.reset_backup_codes(db, user)
    audit(db, "backup_codes_regenerated", user.username, ip=ip_of(request))
    db.commit()
    return render(request, "backup_codes.html", user=user, codes=codes)


@router.post("/totp/remove")
async def remove_totp(request: Request, password: str = Form(...), user: User = Depends(current_user),
                      db=Depends(get_db)):
    if not verify_password(user.password_hash, password):
        return back("pwd_bad")
    if not user.credentials:
        return back("last_factor")
    user.totp_confirmed, user.totp_secret_enc = False, None
    audit(db, "totp_removed", user.username, ip=ip_of(request))
    db.commit()
    return back("totp_removed")


@router.post("/passkeys/{cred_id}/delete")
async def delete_passkey(request: Request, cred_id: int, user: User = Depends(current_user), db=Depends(get_db)):
    cred = db.query(Credential).filter_by(id=cred_id, user_id=user.id).one_or_none()
    if cred is None:
        return back("pk_deleted")
    if factor_count(user) <= 1:
        return back("last_factor")
    user.credentials.remove(cred)
    audit(db, "passkey_deleted", user.username, ip=ip_of(request))
    db.commit()
    return back("pk_deleted")
