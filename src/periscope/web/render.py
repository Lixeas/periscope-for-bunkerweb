import math
from datetime import UTC, datetime
from pathlib import Path

from fastapi import Request
from fastapi.templating import Jinja2Templates

from periscope.clock import utcnow

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _dt(d: datetime | None) -> str:
    return d.strftime("%d/%m/%Y %H:%M UTC") if d else "—"


def _ago(d: datetime | None) -> str:
    if d is None:
        return "jamais"
    s = int((utcnow() - d).total_seconds())
    if s < 60:
        return f"il y a {s} s"
    if s < 3600:
        return f"il y a {s // 60} min"
    if s < 86400:
        return f"il y a {s // 3600} h"
    return f"il y a {s // 86400} j"


def _finite(v) -> bool:
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return True  # math.isfinite raises OverflowError beyond ~1e308
    return isinstance(v, float) and math.isfinite(v)


def _epoch(v) -> str:
    """Epoch (seconds) -> readable date; "—" if missing (0/None), non-numeric or out of range."""
    if not _finite(v) or v <= 0:
        return "—"
    try:
        return _dt(datetime.fromtimestamp(v, UTC))
    except (OverflowError, OSError, ValueError):
        return "—"


def _duration(v) -> str:
    """Remaining seconds -> "45 s", "12 min", "3 h 20", "2 j 4 h"; "—" if invalid."""
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
    return f"{d} j {h} h" if h else f"{d} j"


templates.env.filters["dt"] = _dt
templates.env.filters["epoch"] = _epoch
templates.env.filters["duration"] = _duration
templates.env.filters["ago"] = _ago


def render(request: Request, name: str, status: int = 200, **ctx):
    row = getattr(request.state, "session", None)
    ctx.setdefault("user", None)
    ctx["csrf"] = row.csrf if row else ""
    return templates.TemplateResponse(request, name, ctx, status_code=status)
