"""Alert delivery: routing to channels, message rendering (in the channel's language), senders."""
import hashlib
import hmac
import json
from datetime import datetime

from periscope.alert_engine import Notification
from periscope.i18n import N_, translate
from periscope.i18n import render as render_stored
from periscope.models import AlertChannel

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
