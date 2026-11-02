from fastapi import APIRouter, Depends, Request

from periscope import queries
from periscope.clock import utcnow
from periscope.db import get_db
from periscope.models import User
from periscope.web.deps import current_user
from periscope.web.render import render

router = APIRouter()


# `tag` (query string) scopes every view to the instances carrying that tag (one customer).

@router.get("/dashboard")
def dashboard(request: Request, tag: str = "", user: User = Depends(current_user), db=Depends(get_db)):
    now, ids = utcnow(), queries.scope(db, tag)
    cards = queries.instance_cards(db, now, ids)
    return render(request, "dashboard.html", user=user, cards=cards, s=queries.summary(db, now, ids, cards))


@router.get("/api/summary")
def api_summary(tag: str = "", user: User = Depends(current_user), db=Depends(get_db)):
    return queries.summary(db, utcnow(), queries.scope(db, tag))


@router.get("/services")
def services(request: Request, instance: str = "", mode: str = "", diff: str = "", tag: str = "",
             user: User = Depends(current_user), db=Depends(get_db)):
    rows, names = queries.services(db, instance, mode, bool(diff), queries.scope(db, tag))
    return render(request, "services.html", user=user, rows=rows, names=names, instance=instance, mode=mode, diff=bool(diff))


@router.get("/bans")
def bans(request: Request, q: str = "", tag: str = "", user: User = Depends(current_user), db=Depends(get_db)):
    return render(request, "bans.html", user=user, rows=queries.bans(db, q, queries.scope(db, tag)), q=q)


@router.get("/jobs")
def jobs(request: Request, tag: str = "", user: User = Depends(current_user), db=Depends(get_db)):
    ids = queries.scope(db, tag)
    names, matrix = queries.plugins(db, ids)
    return render(request, "jobs.html", user=user, jobs=queries.jobs(db, ids), now=utcnow(), names=names, matrix=matrix)


@router.get("/certificates")
def certificates(request: Request, tag: str = "", user: User = Depends(current_user), db=Depends(get_db)):
    return render(request, "certificates.html", user=user, rows=queries.certs(db, utcnow(), queries.scope(db, tag)))
