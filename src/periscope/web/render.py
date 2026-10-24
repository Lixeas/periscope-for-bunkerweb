import math
from datetime import UTC, datetime
from pathlib import Path

from fastapi import Request
from fastapi.templating import Jinja2Templates
from jinja2 import pass_context

from periscope import i18n
from periscope.auth.passwords import MIN_LENGTH
from periscope.clock import utcnow
from periscope.i18n import N_

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _dt(d: datetime | None, lang: str = i18n.DEFAULT) -> str:
    if not d:
        return "—"
    return d.strftime("%d/%m/%Y %H:%M UTC" if lang == "fr" else "%Y-%m-%d %H:%M UTC")


def _date(d: datetime | None, lang: str = i18n.DEFAULT) -> str:
    if not d:
        return "—"
    return d.strftime("%d/%m/%Y" if lang == "fr" else "%Y-%m-%d")


def _ago(d: datetime | None, lang: str = i18n.DEFAULT) -> str:
    if d is None:
        return i18n.translate(lang, N_("never"))
    s = int((utcnow() - d).total_seconds())
    if s < 60:
        return i18n.translate(lang, N_("{n} s ago"), n=s)
    if s < 3600:
        return i18n.translate(lang, N_("{n} min ago"), n=s // 60)
    if s < 86400:
        return i18n.translate(lang, N_("{n} h ago"), n=s // 3600)
    return i18n.translate(lang, N_("{n} d ago"), n=s // 86400)


def _finite(v) -> bool:
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return True  # math.isfinite raises OverflowError beyond ~1e308
    return isinstance(v, float) and math.isfinite(v)


def _epoch(v, lang: str = i18n.DEFAULT) -> str:
    """Epoch (seconds) -> readable date; "—" if missing (0/None), non-numeric or out of range."""
    if not _finite(v) or v <= 0:
        return "—"
    try:
        return _dt(datetime.fromtimestamp(v, UTC), lang)
    except (OverflowError, OSError, ValueError):
        return "—"


def _duration(v, lang: str = i18n.DEFAULT) -> str:
    """Remaining seconds -> "45 s", "12 min", "3 h 20", "2 d 4 h" (French: "2 j 4 h"); "—" if invalid."""
    if not _finite(v) or v < 0:
        return "—"
    s = int(v)
    if s < 60:
        return f"{s} s"
    if s < 3600:
        return f"{s // 60} min"
    if s < 86400:
        h, m = divmod(s // 60, 60)
        return f"{h} h {m:02d}" if m else f"{h} h"
    d, h = divmod(s // 3600, 24)
    if h:
        return i18n.translate(lang, N_("{d} d {h} h"), d=d, h=h)
    return i18n.translate(lang, N_("{d} d"), d=d)


def _lang_of(ctx) -> str:
    return i18n.normalize(ctx.get("lang")) or i18n.DEFAULT


def _bind(fn):
    """Template filter reading the request language from the template context."""
    @pass_context
    def wrapper(ctx, value):
        return fn(value, _lang_of(ctx))
    return wrapper


@pass_context
def _gettext(ctx, msgid: str, **params):
    return i18n.translate_html(_lang_of(ctx), msgid, **params)


@pass_context
def _stored(ctx, value):
    """Display a message persisted language-neutral (see i18n.pack); legacy plain text is shown as is."""
    return i18n.render(_lang_of(ctx), value)


templates.env.filters["dt"] = _bind(_dt)
templates.env.filters["date"] = _bind(_date)
templates.env.filters["epoch"] = _bind(_epoch)
templates.env.filters["duration"] = _bind(_duration)
templates.env.filters["ago"] = _bind(_ago)
templates.env.filters["stored"] = _stored
templates.env.globals["_"] = _gettext
templates.env.globals["MIN_PASSWORD"] = MIN_LENGTH
_STATIC = Path(__file__).parent / "static"
# cache-busting suffix for app.css / app.js: changes whenever either file does
templates.env.globals["ASSET_V"] = int(max((_STATIC / n).stat().st_mtime for n in ("app.css", "app.js")))
templates.env.globals["LANGUAGES"] = (("en", "English"), ("fr", "Français"))


def render(request: Request, name: str, status: int = 200, **ctx):
    row = getattr(request.state, "session", None)
    ctx.setdefault("user", None)
    ctx["csrf"] = row.csrf if row else ""
    ctx["lang"] = i18n.lang_for(request)
    # Where the language switcher returns to: a GET page only (never a POST-only URL).
    ctx["next_url"] = i18n.safe_next(
        request.url.path + ("?" + request.url.query if request.url.query else "")
        if request.method in ("GET", "HEAD") else "/")
    return templates.TemplateResponse(request, name, ctx, status_code=status)
