"""Admin page of the outgoing alerts: SMTP server, channels (e-mail lists / webhooks), send log."""
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from periscope import alert_config, alert_send, i18n
from periscope.auth.audit import audit
from periscope.crypto import encrypt
from periscope.db import get_db
from periscope.i18n import N_, LocalizedError, localize, tr
from periscope.models import AlertChannel, AlertLog, User
from periscope.tags import parse as tag_list
from periscope.tags import prune as prune_tags
from periscope.tags import resolve as resolve_tags
from periscope.web.deps import require_admin
from periscope.web.render import render
from periscope.web.routes_auth import ip_of

router = APIRouter(prefix="/admin/alerts")

MESSAGES = {
    "created": N_("Alert created."),
    "saved": N_("Alert saved."),
    "deleted": N_("Alert deleted."),
    "smtp_saved": N_("SMTP server saved."),
}
KINDS = ("email", "webhook")
LOG_SHOWN = 50


def _display(ch: AlertChannel) -> str:
    """What identifies the destination in the list: recipients, or the webhook host (never the URL
    path or query, which often carry a token)."""
    if ch.kind == "email":
        return ", ".join(r for r in ch.recipients.splitlines() if r.strip())
    try:
        return urlparse(ch.webhook_url).hostname or ""
    except ValueError:
        return ""


def page(request: Request, db, user: User, error=None, notice=None, status=200, form=None):
    code = MESSAGES.get(request.query_params.get("m"))
    channels = db.query(AlertChannel).order_by(AlertChannel.name).all()
    last = {}
    for row in db.query(AlertLog).filter(AlertLog.channel_id.is_not(None)).order_by(AlertLog.id):
        last[row.channel_id] = row
    return render(request, "admin_alerts.html", status=status, user=user, error=error, form=form or {},
                  notice=notice or (tr(request, code) if code else None), smtp=alert_config.smtp_public(db),
                  securities=alert_config.SECURITIES, channels=channels, last=last, display=_display,
                  log=db.query(AlertLog).order_by(AlertLog.id.desc()).limit(LOG_SHOWN).all())


def form_page(request: Request, user: User, kind: str, ch: AlertChannel | None = None, error=None, form=None,
              status=200):
    if form is None:
        form = ({"name": ch.name, "lang": ch.lang, "events": ch.events.split(","), "enabled": ch.enabled,
                 "tags": ", ".join(t.name for t in ch.tags), "recipients": ch.recipients,
                 "webhook_url": ""} if ch else
                {"name": "", "lang": "en", "events": alert_config.DEFAULT_EVENTS.split(","), "enabled": True,
                 "tags": "", "recipients": "", "webhook_url": ""})
    return render(request, "admin_alert_form.html", status=status, user=user, kind=kind, ch=ch, error=error,
                  form=form, events=alert_config.EVENTS,
                  has_secret=bool(ch and ch.webhook_secret_enc))


def _validate(db, request: Request, kind: str, name: str, lang: str, events: list[str], tags: str,
              recipients: str, webhook_url: str, exclude_id: int | None = None) -> dict:
    """Clean values for an AlertChannel; raises LocalizedError."""
    name = " ".join(name.split())
    if not name or len(name) > 64:
        raise LocalizedError(N_("Name required (64 characters at most)"))
    for other in db.query(AlertChannel):
        if other.id != exclude_id and other.name.casefold() == name.casefold():
            raise LocalizedError(N_("An alert with this name already exists"))
    if lang not in i18n.SUPPORTED:
        raise LocalizedError(N_("Unsupported language"))
    out = {"name": name, "lang": lang, "events": alert_config.parse_events(events), "tag_names": tag_list(tags)}
    if kind == "email":
        out["recipients"] = "\n".join(alert_config.parse_recipients(recipients))
    else:
        out["webhook_url"] = alert_config.clean_webhook_url(webhook_url)
    return out


def _form_values(name, lang, events, tags, recipients, webhook_url, enabled) -> dict:
    return {"name": name, "lang": lang, "events": events, "tags": tags, "recipients": recipients,
            "webhook_url": webhook_url, "enabled": enabled}


@router.get("")
def alerts_get(request: Request, user: User = Depends(require_admin), db=Depends(get_db)):
    return page(request, db, user)


@router.post("/smtp")
async def smtp_save(request: Request, host: str = Form(""), port: str = Form("587"), security: str = Form("starttls"),
                    username: str = Form(""), password: str = Form(""), sender: str = Form(""),
                    user: User = Depends(require_admin), db=Depends(get_db)):
    try:
        try:
            port_n = int(port)
        except ValueError:
            raise LocalizedError(N_("Invalid SMTP port (1-65535)")) from None
        alert_config.save_smtp(db, host=host, port=port_n, security=security, username=username,
                               password=password, sender=sender)
    except ValueError as e:
        db.rollback()
        return page(request, db, user, error=localize(i18n.lang_for(request), e), status=400)
    audit(db, "alert_smtp_updated", user.username, ip=ip_of(request))
    db.commit()
    return RedirectResponse("/admin/alerts?m=smtp_saved", 303)


@router.post("/smtp/test")
async def smtp_test(request: Request, to: str = Form(""), user: User = Depends(require_admin), db=Depends(get_db)):
    ok, error = await alert_send.send_smtp_test(to)
    audit(db, "alert_test_sent", user.username, detail="SMTP", ip=ip_of(request))
    db.commit()
    if ok:
        return page(request, db, user, notice=tr(request, N_("Test e-mail sent.")))
    return page(request, db, user, error=tr(request, N_("Test e-mail failed: {error}"), error=error))


@router.get("/new")
def new_get(request: Request, kind: str = "", user: User = Depends(require_admin)):
    if kind not in KINDS:
        return RedirectResponse("/admin/alerts", 303)
    return form_page(request, user, kind)


@router.post("")
async def create(request: Request, kind: str = Form(""), name: str = Form(""), lang: str = Form("en"),
                 events: list[str] = Form([]), tags: str = Form(""), recipients: str = Form(""),
                 webhook_url: str = Form(""), webhook_secret: str = Form(""), enabled: bool = Form(False),
                 user: User = Depends(require_admin), db=Depends(get_db)):
    if kind not in KINDS:
        return RedirectResponse("/admin/alerts", 303)
    form = _form_values(name, lang, events, tags, recipients, "", enabled)
    try:
        v = _validate(db, request, kind, name, lang, events, tags, recipients, webhook_url)
    except ValueError as e:
        return form_page(request, user, kind, error=localize(i18n.lang_for(request), e), form=form, status=400)
    ch = AlertChannel(name=v["name"], kind=kind, lang=v["lang"], events=v["events"], enabled=enabled,
                      recipients=v.get("recipients", ""), webhook_url=v.get("webhook_url", ""),
                      webhook_secret_enc=encrypt(webhook_secret) if kind == "webhook" and webhook_secret else "")
    db.add(ch)
    ch.tags = resolve_tags(db, v["tag_names"])
    audit(db, "alert_channel_created", user.username, detail=ch.name, ip=ip_of(request))
    db.commit()
    return RedirectResponse("/admin/alerts?m=created", 303)


@router.get("/{channel_id}")
def edit_get(request: Request, channel_id: int, user: User = Depends(require_admin), db=Depends(get_db)):
    ch = db.get(AlertChannel, channel_id)
    if ch is None:
        return RedirectResponse("/admin/alerts", 303)
    return form_page(request, user, ch.kind, ch)


@router.post("/{channel_id}")
async def edit_post(request: Request, channel_id: int, name: str = Form(""), lang: str = Form("en"),
                    events: list[str] = Form([]), tags: str = Form(""), recipients: str = Form(""),
                    webhook_url: str = Form(""), webhook_secret: str = Form(""), enabled: bool = Form(False),
                    user: User = Depends(require_admin), db=Depends(get_db)):
    ch = db.get(AlertChannel, channel_id)
    if ch is None:
        return RedirectResponse("/admin/alerts", 303)
    form = _form_values(name, lang, events, tags, recipients, "", enabled)
    try:
        v = _validate(db, request, ch.kind, name, lang, events, tags, recipients,
                      webhook_url.strip() or ch.webhook_url, exclude_id=ch.id)  # blank keeps the stored URL
    except ValueError as e:
        return form_page(request, user, ch.kind, ch, error=localize(i18n.lang_for(request), e), form=form,
                         status=400)
    ch.name, ch.lang, ch.events, ch.enabled = v["name"], v["lang"], v["events"], enabled
    if ch.kind == "email":
        ch.recipients = v["recipients"]
    else:
        ch.webhook_url = v["webhook_url"]
        if webhook_secret:  # blank keeps the stored secret
            ch.webhook_secret_enc = encrypt(webhook_secret)
    ch.tags = resolve_tags(db, v["tag_names"])
    db.flush()
    prune_tags(db)
    audit(db, "alert_channel_edited", user.username, detail=ch.name, ip=ip_of(request))
    db.commit()
    return RedirectResponse("/admin/alerts?m=saved", 303)


@router.post("/{channel_id}/delete")
def delete(request: Request, channel_id: int, user: User = Depends(require_admin), db=Depends(get_db)):
    ch = db.get(AlertChannel, channel_id)
    if ch:
        audit(db, "alert_channel_deleted", user.username, detail=ch.name, ip=ip_of(request))
        db.delete(ch)
        db.flush()
        prune_tags(db)
        db.commit()
    return RedirectResponse("/admin/alerts?m=deleted", 303)


@router.post("/{channel_id}/test")
async def test_channel(request: Request, channel_id: int, user: User = Depends(require_admin), db=Depends(get_db)):
    ch = db.get(AlertChannel, channel_id)
    if ch is None:
        return RedirectResponse("/admin/alerts", 303)
    name = ch.name
    ok, error = await alert_send.send_test(channel_id)
    audit(db, "alert_test_sent", user.username, detail=name, ip=ip_of(request))
    db.commit()
    if ok:
        return page(request, db, user, notice=tr(request, N_("Test message sent to {name}."), name=name))
    return page(request, db, user, error=tr(request, N_("Test to {name} failed: {error}"), name=name, error=error))
