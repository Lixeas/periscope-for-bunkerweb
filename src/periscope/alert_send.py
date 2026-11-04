"""Alert delivery: routing to channels, message rendering (in the channel's language), senders."""
import asyncio
import hashlib
import hmac
import json
import logging
import smtplib
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta
from email.message import EmailMessage

import httpx

from periscope import __version__, alert_config
from periscope.alert_engine import Notification
from periscope.clock import utcnow
from periscope.crypto import decrypt
from periscope.db import session_scope
from periscope.i18n import N_, translate
from periscope.i18n import render as render_stored
from periscope.models import AlertChannel, AlertLog

log = logging.getLogger("periscope.alerts")

# --- routing ----------------------------------------------------------------------------------


def matches(channel: AlertChannel, n: Notification) -> bool:
    """Enabled, event switched on and, when the channel has tags, a common tag; a test always passes."""
    if not channel.enabled:
        return False
    if n.event == "test":
        return True
    if not channel.has_event(n.event):
        return False
    wanted = {t.name for t in channel.tags}
    return not wanted or bool(wanted & set(n.tags))


# --- rendering --------------------------------------------------------------------------------

LINES = {
    "instance_down": N_("{instance} is down"),
    "instance_degraded": N_("{instance} is degraded"),
    "instance_resolved": N_("{instance} is back to normal"),
    "instance_reminder_down": N_("{instance} is still down"),
    "instance_reminder_degraded": N_("{instance} is still degraded"),
    "cert_orange": N_("{instance}: the certificate of {domain} expires in {days} days (on {date})"),
    "cert_red": N_("{instance}: URGENT, the certificate of {domain} expires in {days} days (on {date})"),
    "cert_expired": N_("{instance}: the certificate of {domain} has expired (on {date})"),
    "cert_error": N_("{instance}: the TLS probe of {domain} failed"),
    "cert_resolved": N_("{instance}: the certificate of {domain} is valid again"),
    "instance_version_changed": N_("{instance} now runs BunkerWeb {version}"),
    "test": N_("Test message from Periscope: this channel works"),
}
# (heading, notification types) in display order
SECTIONS = (
    (N_("Down"), ("instance_down",)),
    (N_("Degraded"), ("instance_degraded",)),
    (N_("Still failing"), ("instance_reminder",)),
    (N_("Certificates"), ("cert_expired", "cert_red", "cert_orange", "cert_error")),
    (N_("Back to normal"), ("instance_resolved", "cert_resolved")),
    (N_("BunkerWeb version"), ("instance_version_changed",)),
    (N_("Test"), ("test",)),
)
SUMMARY = N_("{count} event(s): {names}")
SUBJECT = N_("[Periscope] {summary}")
HEADER = N_("Periscope report of {date}")
MAX_NAMES = 3


def _date(d: datetime | None, lang: str) -> str:
    if d is None:
        return ""
    return d.strftime("%d/%m/%Y" if lang == "fr" else "%Y-%m-%d")


def _iso(d: datetime | None) -> str | None:
    return d.strftime("%Y-%m-%dT%H:%M:%SZ") if d else None


def _line(lang: str, n: Notification) -> str:
    key = f"instance_reminder_{n.status}" if n.type == "instance_reminder" else n.type
    return translate(lang, LINES[key], instance=n.instance, domain=n.domain, days=n.days_left,
                     date=_date(n.not_after, lang), version=n.version)


def _summary(lang: str, notifications: list[Notification]) -> str:
    names = list(dict.fromkeys(n.instance for n in notifications))
    shown = ", ".join(names[:MAX_NAMES]) + (", ..." if len(names) > MAX_NAMES else "")
    return translate(lang, SUMMARY, count=len(notifications), names=shown)


def render_email(lang: str, notifications: list[Notification], now: datetime) -> tuple[str, str]:
    """(subject, plain-text body)."""
    subject = translate(lang, SUBJECT, summary=_summary(lang, notifications))
    out = [translate(lang, HEADER, date=_date(now, lang) + now.strftime(" %H:%M UTC")), ""]
    for heading, types in SECTIONS:
        group = [n for n in notifications if n.type in types]
        if not group:
            continue
        out.append(translate(lang, heading))
        for n in group:
            out.append("- " + _line(lang, n))
            detail = render_stored(lang, n.message)
            if detail:
                out.append("    " + detail)
        out.append("")
    return subject, "\n".join(out).rstrip() + "\n"


def render_webhook(lang: str, notifications: list[Notification], now: datetime) -> bytes:
    """JSON payload v1 (field names are a contract, see docs/alerts.md)."""
    payload = {
        "version": 1, "sent_at": _iso(now), "lang": lang, "summary": _summary(lang, notifications),
        "events": [{"type": n.type, "instance": n.instance, "tags": list(n.tags), "status": n.status,
                    "message": render_stored(lang, n.message), "domain": n.domain, "not_after": _iso(n.not_after),
                    "days_left": n.days_left, "since": _iso(n.since)} for n in notifications],
    }
    return json.dumps(payload, ensure_ascii=False).encode()


def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


# --- senders ----------------------------------------------------------------------------------

ATTEMPTS = 3
BACKOFF = (1.0, 5.0)  # seconds before attempt 2 and 3
TIMEOUT = 10.0
LOG_DAYS, LOG_ROWS = 30, 1000


class DeliveryError(Exception):
    """A failed send; the message is always free of secrets (never built from a library's text)."""


def _send_email_sync(smtp: alert_config.SmtpSettings, recipients: list[str], subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["From"], msg["To"] = smtp.sender, ", ".join(recipients)
    msg["Subject"] = " ".join(subject.split())  # no line break can survive into a header
    msg.set_content(body)
    ctx = ssl.create_default_context()
    if smtp.security == "ssl":
        client = smtplib.SMTP_SSL(smtp.host, smtp.port, timeout=TIMEOUT, context=ctx)
    else:
        client = smtplib.SMTP(smtp.host, smtp.port, timeout=TIMEOUT)
    with client:
        if smtp.security == "starttls":
            client.starttls(context=ctx)
        if smtp.username:
            client.login(smtp.username, smtp.password)
        client.send_message(msg)


async def send_email(smtp: alert_config.SmtpSettings, recipients: list[str], subject: str, body: str) -> None:
    try:
        await asyncio.to_thread(_send_email_sync, smtp, recipients, subject, body)
    except smtplib.SMTPAuthenticationError as e:
        raise DeliveryError("SMTP authentication failed") from e
    except smtplib.SMTPRecipientsRefused as e:
        raise DeliveryError("recipients refused by the SMTP server") from e
    except smtplib.SMTPException as e:
        raise DeliveryError(f"SMTP error ({type(e).__name__})") from e
    except (OSError, ssl.SSLError) as e:
        raise DeliveryError(f"SMTP connection failed ({type(e).__name__})") from e
    except Exception as e:
        raise DeliveryError(f"e-mail could not be sent ({type(e).__name__})") from e


async def send_webhook(url: str, secret: str, body: bytes, transport: httpx.AsyncBaseTransport | None = None) -> None:
    headers = {"Content-Type": "application/json", "User-Agent": f"Periscope/{__version__}"}
    if secret:
        headers["X-Periscope-Signature"] = sign(secret, body)
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False, transport=transport) as client:
            r = await client.post(url, content=body, headers=headers)
    except httpx.TimeoutException as e:
        raise DeliveryError("webhook timed out") from e
    except Exception as e:  # never str(e): httpx messages may hold the URL, whose query can be a token
        raise DeliveryError(f"webhook could not be reached ({type(e).__name__})") from e
    if not 200 <= r.status_code < 300:
        raise DeliveryError(f"webhook answered HTTP {r.status_code}")


# --- dispatch ---------------------------------------------------------------------------------

@dataclass
class Job:
    channel_id: int | None
    name: str
    kind: str  # email | webhook | smtp-test
    lang: str
    recipients: list[str]
    url: str
    secret: str
    batch: list[Notification]


def _job(ch: AlertChannel, batch: list[Notification]) -> Job:
    secret = decrypt(ch.webhook_secret_enc) if ch.webhook_secret_enc else ""
    recipients = [r.strip() for r in ch.recipients.splitlines() if r.strip()]
    return Job(ch.id, ch.name, ch.kind, ch.lang, recipients, ch.webhook_url, secret, batch)


def _plan(notifications: list[Notification]) -> list[Job]:
    with session_scope() as s:
        jobs = []
        for ch in s.query(AlertChannel).filter_by(enabled=True).order_by(AlertChannel.id):
            batch = [n for n in notifications if matches(ch, n)]
            if batch:
                jobs.append(_job(ch, batch))
        return jobs


def _smtp() -> alert_config.SmtpSettings | None:
    with session_scope() as s:
        return alert_config.load_smtp(s)


async def _deliver(job: Job, now: datetime) -> tuple[bool, str]:
    """(ok, error). Retries transient failures; a missing SMTP configuration is not retried."""
    try:
        if job.kind == "webhook":
            payload = render_webhook(job.lang, job.batch, now)

            async def call():
                await send_webhook(job.url, job.secret, payload)
        else:
            smtp = await asyncio.to_thread(_smtp)
            if smtp is None:
                return False, "SMTP not configured"
            subject, body = render_email(job.lang, job.batch, now)

            async def call():
                await send_email(smtp, job.recipients, subject, body)
    except Exception as e:  # noqa: BLE001  rendering / decrypting problem: logged, never raised
        log.warning("alert %s could not be prepared: %s", job.name, type(e).__name__)
        return False, f"message could not be prepared ({type(e).__name__})"
    error = ""
    for attempt in range(ATTEMPTS):
        try:
            await call()
            return True, ""
        except DeliveryError as e:
            error = str(e)
        except Exception as e:  # noqa: BLE001  a sender bug must not stop the other channels
            error = f"unexpected error ({type(e).__name__})"
        if attempt < ATTEMPTS - 1:
            await asyncio.sleep(BACKOFF[min(attempt, len(BACKOFF) - 1)])
    return False, error


def _write_log(results: list[tuple[Job, bool, str]], now: datetime) -> None:
    with session_scope() as s:
        for job, ok, error in results:
            types = ",".join(dict.fromkeys(n.type for n in job.batch))
            names = ",".join(dict.fromkeys(n.instance for n in job.batch))
            s.add(AlertLog(at=now, channel_id=job.channel_id, channel_name=job.name[:64], events=types[:255],
                           instances=names[:255], ok=ok, error=error[:512]))
        s.flush()
        s.query(AlertLog).filter(AlertLog.at < now - timedelta(days=LOG_DAYS)).delete()
        edge = s.query(AlertLog.id).order_by(AlertLog.id.desc()).offset(LOG_ROWS).first()
        if edge:
            s.query(AlertLog).filter(AlertLog.id <= edge[0]).delete()


async def dispatch(notifications: list[Notification], now: datetime | None = None) -> None:
    """Send each matching channel one grouped message. Never raises: failures go to the send log."""
    if not notifications:
        return
    now = now or utcnow()
    try:
        jobs = await asyncio.to_thread(_plan, notifications)
        results = []
        for job in jobs:
            ok, error = await _deliver(job, now)
            results.append((job, ok, error))
        if results:
            await asyncio.to_thread(_write_log, results, now)
    except Exception:
        log.exception("alert dispatch failed")


def _test_note() -> Notification:
    return Notification("test", "test", 0, "Periscope", ())


async def send_test(channel_id: int) -> tuple[bool, str]:
    """Test message through the real path (no routing, no state). Returns (ok, error)."""
    def load():
        with session_scope() as s:
            ch = s.get(AlertChannel, channel_id)
            return _job(ch, [_test_note()]) if ch else None

    job = await asyncio.to_thread(load)
    if job is None:
        return False, "Channel not found"
    now = utcnow()
    ok, error = await _deliver(job, now)
    await asyncio.to_thread(_write_log, [(job, ok, error)], now)
    return ok, error


async def send_smtp_test(to: str) -> tuple[bool, str]:
    """Test e-mail to one address with the saved SMTP settings."""
    to = (to or "").strip()
    if not alert_config.is_address(to):
        return False, "Invalid e-mail address"
    job = Job(None, "SMTP test", "smtp-test", "en", [to], "", "", [_test_note()])
    now = utcnow()
    ok, error = await _deliver(job, now)
    await asyncio.to_thread(_write_log, [(job, ok, error)], now)
    return ok, error
