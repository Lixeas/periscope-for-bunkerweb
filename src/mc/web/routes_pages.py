from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse

from mc.models import User
from mc.web.deps import current_user
from mc.web.render import render

router = APIRouter()


@router.get("/")
async def index():
    return RedirectResponse("/dashboard", 303)


@router.get("/dashboard")
async def dashboard(request: Request, user: User = Depends(current_user)):
    return render(request, "dashboard.html", user=user)
