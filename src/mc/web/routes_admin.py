import re
from urllib.parse import urlparse

from fastapi import APIRouter, BackgroundTasks, Depends, Form, Request
from fastapi.responses import RedirectResponse

from mc import collector
from mc.auth.audit import audit
from mc.bw_client import BWClient, BWError
from mc.config import get_settings
from mc.crypto import encrypt
from mc.db import get_db
from mc.models import Instance, User
from mc.web.deps import require_admin
from mc.web.render import render
from mc.web.routes_auth import ip_of

router = APIRouter(prefix="/admin")

MESSAGES = {
    "added": "Instance ajoutée ; première collecte en cours.",
    "saved": "Instance enregistrée.",
    "deleted": "Instance supprimée.",
}
KIND_LABEL = {"network": "Instance injoignable", "auth": "Authentification refusée (token ou droits insuffisants)",
              "http": "Réponse HTTP inattendue", "data": "Réponse non JSON (est-ce bien l'API BunkerWeb ?)"}


async def check_instance(base_url: str, token: str, verify_tls: bool) -> str | None:
    """Test de connexion : ping + un appel authentifié. Retourne un message d'erreur ou None."""
    client = BWClient(base_url, token, timeout=get_settings().http_timeout, verify=verify_tls)
    try:
        await client.ping()
        await client.bans()
    except BWError as e:
        return f"{KIND_LABEL[e.kind]} — {e}"
    finally:
        await client.aclose()
    return None


def clean_url(raw: str) -> str:
    raw = raw.strip()
    try:
        u = urlparse(raw)
        ok = u.scheme in ("http", "https") and u.hostname and not u.username and not u.password
        _ = u.port  # lève ValueError si le port est invalide
    except ValueError:
        ok = False
    if not ok:
        raise ValueError("URL invalide (attendu : http(s)://hôte[:port], sans identifiants)")
    return raw.rstrip("/")


def validate_fields(db, name: str, base_url: str, tls_port: int, exclude_id: int | None = None) -> tuple[str, str]:
    name = name.strip()
    if not re.fullmatch(r"[A-Za-z0-9._ -]{1,64}", name):
        raise ValueError("Nom invalide (1-64 caractères : lettres, chiffres, espace, . _ -)")
    clash = db.query(Instance).filter(Instance.name == name)
    if exclude_id:
        clash = clash.filter(Instance.id != exclude_id)
    if clash.first():
        raise ValueError("Une instance de ce nom existe déjà")
    if not 1 <= tls_port <= 65535:
        raise ValueError("Port TLS invalide")
    return name, clean_url(base_url)


def instances_page(request: Request, db, user: User, error=None, form=None, status=200):
    return render(request, "admin_instances.html", status=status, user=user, error=error, form=form or {},
                  msg=MESSAGES.get(request.query_params.get("m")),
                  instances=db.query(Instance).order_by(Instance.name).all())


@router.get("/instances")
async def instances_get(request: Request, user: User = Depends(require_admin), db=Depends(get_db)):
    return instances_page(request, db, user)


@router.post("/instances")
async def instances_add(request: Request, background: BackgroundTasks,
                        name: str = Form(""), base_url: str = Form(""), token: str = Form(""),
                        probe_host: str = Form(""), tls_port: int = Form(443),
                        verify_tls: bool = Form(False), force: bool = Form(False),
                        user: User = Depends(require_admin), db=Depends(get_db)):
    form = {"name": name, "base_url": base_url, "probe_host": probe_host, "tls_port": tls_port,
            "verify_tls": verify_tls}
    try:
        name, base_url = validate_fields(db, name, base_url, tls_port)
        if not token.strip():
            raise ValueError("Token requis")
    except ValueError as e:
        return instances_page(request, db, user, str(e), form, 400)
    if not force:
        err = await check_instance(base_url, token.strip(), verify_tls)
        if err:
            return instances_page(request, db, user, f"Test de connexion échoué : {err}", {**form, "failed": True}, 400)
    inst = Instance(name=name, base_url=base_url, token_enc=encrypt(token.strip()), verify_tls=verify_tls,
                    probe_host=probe_host.strip(), tls_port=tls_port)
    db.add(inst)
    db.flush()
    audit(db, "instance_added", user.username, detail=name, ip=ip_of(request))
    db.commit()
    background.add_task(collector.refresh_instance, inst.id)
    return RedirectResponse("/admin/instances?m=added", 303)


@router.get("/instances/{inst_id}")
async def instance_edit_get(request: Request, inst_id: int, user: User = Depends(require_admin), db=Depends(get_db)):
    inst = db.get(Instance, inst_id)
    if inst is None:
        return RedirectResponse("/admin/instances", 303)
    return render(request, "admin_instance_edit.html", user=user, inst=inst, error=None)


@router.post("/instances/{inst_id}")
async def instance_edit_post(request: Request, inst_id: int, background: BackgroundTasks,
                             name: str = Form(""), base_url: str = Form(""), token: str = Form(""),
                             probe_host: str = Form(""), tls_port: int = Form(443),
                             verify_tls: bool = Form(False), enabled: bool = Form(False),
                             user: User = Depends(require_admin), db=Depends(get_db)):
    inst = db.get(Instance, inst_id)
    if inst is None:
        return RedirectResponse("/admin/instances", 303)
    try:
        name, base_url = validate_fields(db, name, base_url, tls_port, exclude_id=inst_id)
    except ValueError as e:
        return render(request, "admin_instance_edit.html", status=400, user=user, inst=inst, error=str(e))
    inst.name, inst.base_url, inst.probe_host = name, base_url, probe_host.strip()
    inst.tls_port, inst.verify_tls, inst.enabled = tls_port, verify_tls, enabled
    if token.strip():
        inst.token_enc = encrypt(token.strip())
    audit(db, "instance_edited", user.username, detail=name, ip=ip_of(request))
    db.commit()
    if inst.enabled:
        background.add_task(collector.refresh_instance, inst.id)
    return RedirectResponse("/admin/instances?m=saved", 303)


@router.post("/instances/{inst_id}/delete")
async def instance_delete(request: Request, inst_id: int, user: User = Depends(require_admin), db=Depends(get_db)):
    inst = db.get(Instance, inst_id)
    if inst:
        audit(db, "instance_deleted", user.username, detail=inst.name, ip=ip_of(request))
        db.delete(inst)
        db.commit()
    return RedirectResponse("/admin/instances?m=deleted", 303)
