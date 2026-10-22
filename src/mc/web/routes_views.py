from fastapi import APIRouter, Depends, Request

from mc import queries
from mc.clock import utcnow
from mc.db import get_db
from mc.models import User
from mc.web.deps import current_user
from mc.web.render import render

router = APIRouter()


@router.get("/dashboard")
async def dashboard(request: Request, user: User = Depends(current_user), db=Depends(get_db)):
    now = utcnow()
    return render(request, "dashboard.html", user=user,
                  cards=queries.instance_cards(db, now), s=queries.summary(db, now))


@router.get("/api/summary")
async def api_summary(user: User = Depends(current_user), db=Depends(get_db)):
    return queries.summary(db, utcnow())


@router.get("/services")
async def services(request: Request, instance: str = "", mode: str = "",
                   user: User = Depends(current_user), db=Depends(get_db)):
    rows, names = queries.services(db, instance, mode)
    return render(request, "services.html", user=user, rows=rows, names=names, instance=instance, mode=mode)


@router.get("/bans")
async def bans(request: Request, q: str = "", user: User = Depends(current_user), db=Depends(get_db)):
    return render(request, "bans.html", user=user, rows=queries.bans(db, q), q=q)


@router.get("/jobs")
async def jobs(request: Request, user: User = Depends(current_user), db=Depends(get_db)):
    names, matrix = queries.plugins(db)
    return render(request, "jobs.html", user=user, jobs=queries.jobs(db), names=names, matrix=matrix)


@router.get("/certificates")
async def certificates(request: Request, user: User = Depends(current_user), db=Depends(get_db)):
    return render(request, "certificates.html", user=user, rows=queries.certs(db, utcnow()))
