from datetime import datetime
from pathlib import Path

from fastapi import Request
from fastapi.templating import Jinja2Templates

from mc.clock import utcnow

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


templates.env.filters["dt"] = _dt
templates.env.filters["ago"] = _ago


def render(request: Request, name: str, status: int = 200, **ctx):
    row = getattr(request.state, "session", None)
    ctx.setdefault("user", None)
    ctx["csrf"] = row.csrf if row else ""
    return templates.TemplateResponse(request, name, ctx, status_code=status)
