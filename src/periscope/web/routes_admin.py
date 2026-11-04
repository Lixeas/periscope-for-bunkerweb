import re
import secrets
from datetime import timedelta
from urllib.parse import urlparse

from fastapi import APIRouter, BackgroundTasks, Depends, Form, Request
from fastapi.responses import RedirectResponse

from periscope import collector, pki, queries
from periscope.agent import make_bundle
from periscope.agent_server import enroll_token_hash
from periscope.auth.audit import audit
from periscope.auth.passwords import MIN_LENGTH, hash_password
from periscope.auth.users import create_user
from periscope.bw_client import BWClient, BWError
from periscope.clock import utcnow
from periscope.config import get_settings
from periscope.crypto import encrypt
from periscope.db import get_db
from periscope.i18n import N_, LocalizedError, lang_for, localize, tr, translate
from periscope.models import AuditLog, Instance, Session, User
from periscope.tags import assign as assign_tags
from periscope.tags import parse as tag_list
from periscope.tags import prune as prune_tags
from periscope.web.deps import require_admin
from periscope.web.render import render
from periscope.web.routes_auth import ip_of

router = APIRouter(prefix="/admin")

CONNECTIONS = ("direct", "agent")
MESSAGES = {
    "added": N_("Instance added; first collection in progress."),
    "saved": N_("Instance saved."),
    "deleted": N_("Instance deleted."),
    "revoked": N_("Agent revoked: its certificate is no longer accepted."),
}
KIND_LABEL = {"network": N_("Instance unreachable"),
              "auth": N_("Authentication refused (credentials or insufficient permissions)"),
              "http": N_("Unexpected HTTP response"),
              "data": N_("Response is not JSON (is this really the BunkerWeb API?)")}


async def check_instance(base_url: str, verify_tls: bool, credentials: tuple[str, str]) -> BWError | None:
    """Connection test: ping + one authenticated call (exercises POST /auth).
    Returns the error (displayed translated by the caller) or None."""
    client = BWClient(base_url, credentials, timeout=get_settings().http_timeout, verify=verify_tls)
    try:
        await client.ping()
        await client.bans()
    except BWError as e:
        return e
    finally:
        await client.aclose()
    return None


def clean_url(raw: str) -> str:
    raw = raw.strip()
    try:
        u = urlparse(raw)
        ok = u.scheme in ("http", "https") and u.hostname and not u.username and not u.password
        _ = u.port  # raises ValueError if the port is invalid
    except ValueError:
        ok = False
    if not ok:
        raise LocalizedError(N_("Invalid URL (expected: http(s)://host[:port], without credentials)"))
    return raw.rstrip("/")


def validate_name(db, name: str, exclude_id: int | None = None) -> str:
    name = name.strip()
    if not re.fullmatch(r"[A-Za-z0-9._ -]{1,64}", name):
        raise LocalizedError(N_("Invalid name (1-64 characters: letters, digits, space, . _ -)"))
    clash = db.query(Instance).filter(Instance.name == name)
    if exclude_id:
        clash = clash.filter(Instance.id != exclude_id)
    if clash.first():
        raise LocalizedError(N_("An instance with this name already exists"))
    return name


def validate_fields(db, name: str, base_url: str, tls_port: int, exclude_id: int | None = None) -> tuple[str, str]:
    name = validate_name(db, name, exclude_id)
    if not 1 <= tls_port <= 65535:
        raise LocalizedError(N_("Invalid TLS port"))
    return name, clean_url(base_url)


def instances_page(request: Request, db, user: User, error=None, form=None, status=200):
    code = MESSAGES.get(request.query_params.get("m"))
    q = db.query(Instance).order_by(Instance.name)
    ids = queries.scope(db, request.query_params.get("tag", ""))
    if ids is not None:
        q = q.filter(Instance.id.in_(ids))
    return render(request, "admin_instances.html", status=status, user=user, error=error, form=form or {},
                  msg=tr(request, code) if code else None, instances=q.all(),
                  agents_enabled=bool(get_settings().agent_public_url))


def new_enroll_token(inst: Instance) -> str:
    """Single-use enrollment token (only its hash is kept), valid PERISCOPE_AGENT_ENROLL_TTL seconds."""
    token = secrets.token_urlsafe(32)
    inst.agent_enroll_hash = enroll_token_hash(token)
    inst.agent_enroll_expires = utcnow() + timedelta(seconds=get_settings().agent_enroll_ttl)
    return token


def enroll_page(request: Request, db, user: User, inst: Instance, token: str):
    """Shown once: the token is not stored in clear and cannot be displayed again."""
    cfg = get_settings()
    bundle = make_bundle(cfg.agent_public_url, token, pki.ca_fingerprint(db))
    db.commit()
    return render(request, "admin_agent_enroll.html", user=user, inst=inst, bundle=bundle,
                  ca_fp=pki.ca_fingerprint(db), console_url=cfg.agent_public_url)


@router.get("/instances")
def instances_get(request: Request, user: User = Depends(require_admin), db=Depends(get_db)):
    return instances_page(request, db, user)


@router.post("/instances")
async def instances_add(request: Request, background: BackgroundTasks,
                        name: str = Form(""), connection: str = Form("direct"), tags: str = Form(""),
                        base_url: str = Form(""), api_username: str = Form(""), api_password: str = Form(""),
                        probe_host: str = Form(""), tls_port: int = Form(443),
                        verify_tls: bool = Form(False), force: bool = Form(False),
                        user: User = Depends(require_admin), db=Depends(get_db)):
    form = {"name": name, "base_url": base_url, "probe_host": probe_host, "tls_port": tls_port,
            "verify_tls": verify_tls, "connection": connection, "api_username": api_username, "tags": tags}
    api_username = api_username.strip()
    lang = lang_for(request)
    try:
        if connection not in CONNECTIONS:
            raise LocalizedError(N_("Invalid connection mode"))
        tag_names = tag_list(tags)
        if connection == "agent":
            name = validate_name(db, name)
            if not get_settings().agent_public_url:
                raise LocalizedError(N_("The agent mode needs PERISCOPE_AGENT_PUBLIC_URL on the console"))
        else:
            name, base_url = validate_fields(db, name, base_url, tls_port)
            if not (api_username and api_password):
                raise LocalizedError(N_("API username and password required"))
    except ValueError as e:
        return instances_page(request, db, user, localize(lang, e), form, 400)
    if connection == "agent":
        inst = Instance(name=name, connection="agent", status="unknown")
        db.add(inst)
        db.flush()
        assign_tags(db, inst, tag_names)
        token = new_enroll_token(inst)
        audit(db, "instance_added", user.username, detail=f"{name} (agent)", ip=ip_of(request))
        audit(db, "agent_enroll_token", user.username, detail=name, ip=ip_of(request))
        return enroll_page(request, db, user, inst, token)
    if not force:
        db.commit()  # releases the SQLite write lock during the network call
        err = await check_instance(base_url, verify_tls, (api_username, api_password))
        if err:
            detail = f"{translate(lang, KIND_LABEL[err.kind])} — {err.localize(lang)}"
            return instances_page(request, db, user, translate(lang, N_("Connection test failed: {error}"), error=detail),
                                  {**form, "failed": True}, 400)
    inst = Instance(name=name, base_url=base_url, verify_tls=verify_tls, connection="direct",
                    probe_host=probe_host.strip(), tls_port=tls_port,
                    api_username=api_username, api_password_enc=encrypt(api_password))
    db.add(inst)
    db.flush()
    assign_tags(db, inst, tag_names)
    audit(db, "instance_added", user.username, detail=f"{name} (direct)", ip=ip_of(request))
    db.commit()
    background.add_task(collector.refresh_instance, inst.id)
    return RedirectResponse("/admin/instances?m=added", 303)


def edit_page(request: Request, inst: Instance, user: User, error=None, status=200):
    return render(request, "admin_instance_edit.html", status=status, user=user, inst=inst, error=error,
                  tags_value=", ".join(t.name for t in inst.tags), now=utcnow())


@router.get("/instances/{inst_id}")
def instance_edit_get(request: Request, inst_id: int, user: User = Depends(require_admin), db=Depends(get_db)):
    inst = db.get(Instance, inst_id)
    if inst is None:
        return RedirectResponse("/admin/instances", 303)
    return edit_page(request, inst, user)


@router.post("/instances/{inst_id}")
async def instance_edit_post(request: Request, inst_id: int, background: BackgroundTasks,
                             name: str = Form(""), tags: str = Form(""), base_url: str = Form(""),
                             api_username: str = Form(""), api_password: str = Form(""),
                             probe_host: str = Form(""), tls_port: int = Form(443),
                             verify_tls: bool = Form(False), enabled: bool = Form(False),
                             user: User = Depends(require_admin), db=Depends(get_db)):
    inst = db.get(Instance, inst_id)
    if inst is None:
        return RedirectResponse("/admin/instances", 303)

    def fail(msg: str):
        return edit_page(request, inst, user, msg, 400)

    lang = lang_for(request)
    try:
        tag_names = tag_list(tags)
        if inst.is_agent:
            name = validate_name(db, name, exclude_id=inst_id)
        else:
            name, base_url = validate_fields(db, name, base_url, tls_port, exclude_id=inst_id)
    except ValueError as e:
        return fail(localize(lang, e))
    if not inst.is_agent:
        username = api_username.strip() or inst.api_username
        if not username:
            return fail(tr(request, N_("API username required")))
        if (base_url != inst.base_url or username != inst.api_username or not inst.api_password_enc) \
                and not api_password:
            return fail(tr(request, N_("Changing the URL or the user requires re-entering the API password")))
        inst.base_url, inst.probe_host, inst.tls_port, inst.verify_tls = base_url, probe_host.strip(), tls_port, verify_tls
        inst.api_username = username
        if api_password:
            inst.api_password_enc = encrypt(api_password)
            inst.last_error = ""  # e.g. the message left by the removal of the static token mode
    inst.name, inst.enabled = name, enabled
    assign_tags(db, inst, tag_names)
    audit(db, "instance_edited", user.username, detail=f"{name} ({inst.connection})", ip=ip_of(request))
    db.commit()
    if inst.enabled and not inst.is_agent:
        background.add_task(collector.refresh_instance, inst.id)
    return RedirectResponse("/admin/instances?m=saved", 303)


@router.post("/instances/{inst_id}/agent-token")
def instance_agent_token(request: Request, inst_id: int, user: User = Depends(require_admin), db=Depends(get_db)):
    """New single-use enrollment token (re-enrollment: the current certificate stays valid until it is used)."""
    inst = db.get(Instance, inst_id)
    if inst is None or not inst.is_agent:
        return RedirectResponse("/admin/instances", 303)
    if not get_settings().agent_public_url:
        return edit_page(request, inst, user,
                         tr(request, N_("The agent mode needs PERISCOPE_AGENT_PUBLIC_URL on the console")), 400)
    token = new_enroll_token(inst)
    audit(db, "agent_enroll_token", user.username, detail=inst.name, ip=ip_of(request))
    return enroll_page(request, db, user, inst, token)


@router.post("/instances/{inst_id}/agent-revoke")
def instance_agent_revoke(request: Request, inst_id: int, user: User = Depends(require_admin), db=Depends(get_db)):
    inst = db.get(Instance, inst_id)
    if inst is None or not inst.is_agent:
        return RedirectResponse("/admin/instances", 303)
    inst.agent_cert_fp = inst.agent_next_cert_fp = inst.agent_enroll_hash = ""
    inst.agent_cert_not_after = inst.agent_enroll_expires = None
    inst.status, inst.last_attempt_at = "unknown", None
    audit(db, "agent_revoked", user.username, detail=inst.name, ip=ip_of(request))
    db.commit()
    return RedirectResponse("/admin/instances?m=revoked", 303)


SILENCE_HOURS = (1, 4, 24)


@router.post("/instances/{inst_id}/silence")
def instance_silence(request: Request, inst_id: int, hours: str = Form(""), user: User = Depends(require_admin),
                     db=Depends(get_db)):
    """Mute the alerts of one instance for 1, 4 or 24 hours (maintenance); 0 clears the silence."""
    inst = db.get(Instance, inst_id)
    if inst is None:
        return RedirectResponse("/admin/instances", 303)
    if hours == "0":
        inst.silenced_until = None
        audit(db, "instance_unsilenced", user.username, detail=inst.name, ip=ip_of(request))
    elif hours.isdigit() and int(hours) in SILENCE_HOURS:
        inst.silenced_until = utcnow() + timedelta(hours=int(hours))
        audit(db, "instance_silenced", user.username, detail=inst.name, ip=ip_of(request))
    db.commit()
    return RedirectResponse(f"/admin/instances/{inst_id}", 303)


@router.post("/instances/{inst_id}/delete")
def instance_delete(request: Request, inst_id: int, user: User = Depends(require_admin), db=Depends(get_db)):
    inst = db.get(Instance, inst_id)
    if inst:
        audit(db, "instance_deleted", user.username, detail=inst.name, ip=ip_of(request))
        db.delete(inst)
        db.flush()
        prune_tags(db)
        db.commit()
    return RedirectResponse("/admin/instances?m=deleted", 303)


# --- users ----------------------------------------------------------

USER_MESSAGES = {
    "created": N_("User created. They will have to enroll a second factor at first login."),
    "deleted": N_("User deleted."),
    "role_ok": N_("Role changed."),
    "reset_ok": N_("Second factor reset: re-enrollment required at next login."),
    "pwd_ok": N_("Password reset; account unlocked, sessions closed."),
    "pwd_short": N_("Password too short ({min} characters minimum)."),
    "self": N_("Action not possible on your own account (use the Account page)."),
    "last_admin": N_("At least one administrator must remain."),
}


def users_back(code: str) -> RedirectResponse:
    return RedirectResponse(f"/admin/users?m={code}", 303)


def users_page(request: Request, db, user: User, error=None, status=200):
    code = USER_MESSAGES.get(request.query_params.get("m"))
    return render(request, "admin_users.html", status=status, user=user, error=error,
                  msg=tr(request, code, min=MIN_LENGTH) if code else None,
                  users=db.query(User).order_by(User.username).all())


def admin_count(db) -> int:
    return db.query(User).filter_by(role="admin").count()


@router.get("/users")
async def users_get(request: Request, user: User = Depends(require_admin), db=Depends(get_db)):
    return users_page(request, db, user)


@router.post("/users")
async def users_create(request: Request, username: str = Form(""), role: str = Form("reader"),
                       password: str = Form(""), user: User = Depends(require_admin), db=Depends(get_db)):
    try:
        create_user(db, username, password, role)
    except ValueError as e:
        return users_page(request, db, user, localize(lang_for(request), e), 400)
    audit(db, "user_created", user.username, detail=f"{username} ({role})", ip=ip_of(request))
    db.commit()
    return users_back("created")


@router.post("/users/{uid}/role")
async def users_role(request: Request, uid: int, role: str = Form(...),
                     user: User = Depends(require_admin), db=Depends(get_db)):
    target = db.get(User, uid)
    if target is None or role not in ("admin", "reader"):
        return users_back("self")
    if target.role == "admin" and role != "admin" and admin_count(db) <= 1:
        return users_back("last_admin")
    target.role = role
    audit(db, "user_role_changed", user.username, detail=f"{target.username} -> {role}", ip=ip_of(request))
    db.commit()
    return users_back("role_ok")


@router.post("/users/{uid}/delete")
async def users_delete(request: Request, uid: int, user: User = Depends(require_admin), db=Depends(get_db)):
    target = db.get(User, uid)
    if target is None:
        return users_back("deleted")
    if target.id == user.id:
        return users_back("self")
    if target.role == "admin" and admin_count(db) <= 1:
        return users_back("last_admin")
    db.query(Session).filter_by(user_id=target.id).delete()
    audit(db, "user_deleted", user.username, detail=target.username, ip=ip_of(request))
    db.delete(target)
    db.commit()
    return users_back("deleted")


@router.post("/users/{uid}/reset-2fa")
async def users_reset_2fa(request: Request, uid: int, user: User = Depends(require_admin), db=Depends(get_db)):
    target = db.get(User, uid)
    if target is None or target.id == user.id:
        return users_back("self")
    target.totp_confirmed, target.totp_secret_enc, target.totp_last_step = False, None, 0
    target.credentials.clear()
    target.backup_codes.clear()
    db.query(Session).filter_by(user_id=target.id).delete()
    audit(db, "user_2fa_reset", user.username, detail=target.username, ip=ip_of(request))
    db.commit()
    return users_back("reset_ok")


@router.post("/users/{uid}/password")
async def users_password(request: Request, uid: int, password: str = Form(...),
                         user: User = Depends(require_admin), db=Depends(get_db)):
    target = db.get(User, uid)
    if target is None or target.id == user.id:
        return users_back("self")
    try:
        target.password_hash = hash_password(password)
    except ValueError:
        return users_back("pwd_short")
    target.failed_attempts, target.locked_until = 0, None
    db.query(Session).filter_by(user_id=target.id).delete()
    audit(db, "user_password_reset", user.username, detail=target.username, ip=ip_of(request))
    db.commit()
    return users_back("pwd_ok")


# --- audit -----------------------------------------------------------------

# Stored event codes (stable, English) -> description translated at display time; unknown codes
# (legacy rows) are shown as stored.
EVENT_LABELS = {
    "login": N_("Login"),
    "login_failed": N_("Failed login"),
    "login_locked": N_("Login blocked (lockout)"),
    "login_throttled": N_("Login throttled (too many attempts)"),
    "login_2fa_failed": N_("Second factor rejected"),
    "login_passkey_failed": N_("Passkey login failed"),
    "password_ok": N_("Password accepted"),
    "logout": N_("Logout"),
    "enroll_failed": N_("Enrollment failed"),
    "totp_enrolled": N_("TOTP enrolled"),
    "passkey_enrolled": N_("Passkey enrolled"),
    "passkey_added": N_("Passkey added"),
    "passkey_deleted": N_("Passkey deleted"),
    "password_changed": N_("Password changed"),
    "backup_codes_regenerated": N_("Backup codes regenerated"),
    "totp_removed": N_("TOTP disabled"),
    "sessions_revoked": N_("Sessions revoked"),
    "reauth_failed": N_("Re-authentication failed"),
    "instance_added": N_("Instance added"),
    "instance_edited": N_("Instance edited"),
    "instance_deleted": N_("Instance deleted"),
    "agent_enroll_token": N_("Agent enrollment token created"),
    "agent_enrolled": N_("Agent enrolled"),
    "agent_enroll_failed": N_("Agent enrollment refused"),
    "agent_cert_renewed": N_("Agent certificate renewed"),
    "agent_revoked": N_("Agent revoked"),
    "user_created": N_("User created"),
    "user_deleted": N_("User deleted"),
    "user_role_changed": N_("User role changed"),
    "user_2fa_reset": N_("User second factor reset"),
    "user_password_reset": N_("User password reset"),
    "instance_silenced": N_("Instance alerts silenced"),
    "instance_unsilenced": N_("Instance alerts resumed"),
    "alert_channel_created": N_("Alert created"),
    "alert_channel_edited": N_("Alert edited"),
    "alert_channel_deleted": N_("Alert deleted"),
    "alert_smtp_updated": N_("SMTP server updated"),
    "alert_test_sent": N_("Alert test sent"),
}


@router.get("/audit")
async def audit_get(request: Request, user: User = Depends(require_admin), db=Depends(get_db)):
    rows = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(200).all()
    labels = {e.event: tr(request, EVENT_LABELS[e.event]) for e in rows if e.event in EVENT_LABELS}
    return render(request, "admin_audit.html", user=user, rows=rows, labels=labels)
