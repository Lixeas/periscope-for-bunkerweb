"""Alert configuration: SMTP server settings (stored in the `settings` table, password encrypted)
and validation of what the admin types for channels (recipients, webhook URL, events)."""
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from periscope.crypto import decrypt, encrypt
from periscope.i18n import N_, LocalizedError
from periscope.models import Setting

EVENTS = ("down", "degraded", "certificate", "version")
DEFAULT_EVENTS = "down,degraded,certificate"
SECURITIES = ("starttls", "ssl", "none")
MAX_RECIPIENTS = 20
_PREFIX = "alert_smtp_"
_HOST_RE = re.compile(r"[A-Za-z0-9._-]{1,253}")
# characters never allowed in an address: whitespace / control characters (header injection) and the ones that
# separate or quote addresses
_FORBIDDEN = frozenset('<>,;:"\\')
MAX_ADDRESS, MAX_LOCAL = 254, 64


@dataclass(frozen=True)
class SmtpSettings:
    host: str
    port: int
    security: str
    username: str
    password: str
    sender: str


def is_address(value: str) -> bool:
    """Practical check, linear in the length (no backtracking): one "@", a dotted domain without empty labels,
    no whitespace, control or separator characters, bounded lengths."""
    if not value or len(value) > MAX_ADDRESS or value.count("@") != 1:
        return False
    if any(c in _FORBIDDEN or c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
        return False
    local, domain = value.split("@")
    if not local or len(local) > MAX_LOCAL or "." not in domain:
        return False
    return all(domain.split("."))  # no empty label: ".example", "b.", "b..example"


def _get(db, key: str, default: str = "") -> str:
    row = db.get(Setting, _PREFIX + key)
    return row.value if row else default


def _set(db, key: str, value: str) -> None:
    db.merge(Setting(key=_PREFIX + key, value=value))


def load_smtp(db) -> SmtpSettings | None:
    """None unless a host and a sender address are configured."""
    host, sender = _get(db, "host"), _get(db, "sender")
    if not host or not sender:
        return None
    token = _get(db, "password")
    return SmtpSettings(host, int(_get(db, "port", "587")), _get(db, "security", "starttls"),
                        _get(db, "username"), decrypt(token) if token else "", sender)


def smtp_public(db) -> dict:
    """What the page may show: never the password."""
    return {"host": _get(db, "host"), "port": int(_get(db, "port", "587")),
            "security": _get(db, "security", "starttls"), "username": _get(db, "username"),
            "sender": _get(db, "sender"), "has_password": bool(_get(db, "password"))}


def save_smtp(db, *, host: str, port: int, security: str, username: str, password: str, sender: str) -> None:
    """An empty password keeps the stored one."""
    host, username, sender = host.strip(), username.strip(), sender.strip()
    if host and not _HOST_RE.fullmatch(host):
        raise LocalizedError(N_("Invalid SMTP host"))
    if not 1 <= port <= 65535:
        raise LocalizedError(N_("Invalid SMTP port (1-65535)"))
    if security not in SECURITIES:
        raise LocalizedError(N_("Invalid connection security (starttls, ssl or none)"))
    if sender and not is_address(sender):
        raise LocalizedError(N_("Invalid sender address"))
    if any(c in username for c in "\r\n\x00"):
        raise LocalizedError(N_("Invalid SMTP username"))
    _set(db, "host", host)
    _set(db, "port", str(port))
    _set(db, "security", security)
    _set(db, "username", username)
    _set(db, "sender", sender)
    if password:
        _set(db, "password", encrypt(password))


def parse_recipients(raw: str) -> list[str]:
    """Addresses separated by commas, semicolons or new lines; unique (case-insensitive), 1 to 20."""
    out: list[str] = []
    for part in re.split(r"[,;\n]", raw or ""):
        addr = part.strip()
        if not addr:
            continue
        if not is_address(addr):
            raise LocalizedError(N_("Invalid e-mail address: {address}"), address=addr[:80])
        if addr.casefold() not in {a.casefold() for a in out}:
            out.append(addr)
    if not out:
        raise LocalizedError(N_("At least one recipient is required"))
    if len(out) > MAX_RECIPIENTS:
        raise LocalizedError(N_("At most {max} recipients"), max=MAX_RECIPIENTS)
    return out


def clean_webhook_url(raw: str) -> str:
    url = (raw or "").strip()
    try:
        parsed = urlparse(url)
        scheme, host = parsed.scheme.lower(), parsed.hostname
    except ValueError:
        scheme, host = "", None
    if scheme not in ("http", "https") or not host or len(url) > 512 or re.search(r"[\s\x00-\x1f\x7f]", url):
        raise LocalizedError(N_("The webhook URL must start with http:// or https:// and contain a host"))
    return url


def parse_events(selected: list[str]) -> str:
    chosen = set(selected)
    if not chosen:
        raise LocalizedError(N_("Choose at least one event"))
    if not chosen <= set(EVENTS):
        raise LocalizedError(N_("Unknown event"))
    return ",".join(e for e in EVENTS if e in chosen)
