import asyncio
import hashlib
import logging
from datetime import datetime, timedelta

from periscope.bw_client import BWClient, BWError
from periscope.clock import utcnow
from periscope.config import get_settings
from periscope.crypto import decrypt
from periscope.db import session_scope
from periscope.models import CertProbe, Instance, Snapshot
from periscope.tlsprobe import probe

log = logging.getLogger("periscope.collector")
KINDS = ("services", "bans", "jobs", "plugins", "instances")


# Jetons Biscuit en mémoire (processus unique) : (id instance, empreinte des identifiants) -> jeton.
# Changer identifiant ou mot de passe change l'empreinte, donc invalide l'entrée.
_TOKEN_CACHE: dict[tuple[int, str], str] = {}


# Dernière recherche de version (OpenAPI) par instance : évite une requête par cycle.
_VERSION_CHECKED: dict[int, datetime] = {}
VERSION_RECHECK = timedelta(hours=1)


def _cache_key(inst: Instance) -> tuple[int, str]:
    fp = hashlib.sha256(f"{inst.api_username}\0{inst.api_password_enc}".encode()).hexdigest()
    return inst.id, fp


def remember_token(inst: Instance, client) -> None:
    if inst.auth_mode != "user":
        return
    key = _cache_key(inst)
    # purge les entrées périmées de cette instance (anciens identifiants)
    for k in [k for k in _TOKEN_CACHE if k[0] == inst.id and k != key]:
        del _TOKEN_CACHE[k]
    tok = getattr(client, "token", None)
    if tok:
        _TOKEN_CACHE[key] = tok
    else:
        _TOKEN_CACHE.pop(key, None)


def default_client(inst: Instance) -> BWClient:
    kw = {"timeout": get_settings().http_timeout, "verify": inst.verify_tls}
    if inst.auth_mode == "user":
        return BWClient(inst.base_url, token=_TOKEN_CACHE.get(_cache_key(inst)),
                        credentials=(inst.api_username, decrypt(inst.api_password_enc)), **kw)
    return BWClient(inst.base_url, decrypt(inst.token_enc), **kw)


def _node_problems(nodes: list[dict]) -> str:
    """Message d'erreur pour les nœuds en défaut ('loading' n'en est pas un) ; '' si tout va bien."""
    parts = []
    for status, label in (("down", "hors ligne"), ("failover", "en failover")):
        names = [str(n.get("hostname") or n.get("name") or "?") for n in nodes if n.get("status") == status]
        if names:
            parts.append(f"{len(names)} {'nœud' if len(names) == 1 else 'nœuds'} {label} : {', '.join(names)}")
    return "; ".join(parts)


def _save_snapshot(s, inst_id: int, kind: str, payload: list, now) -> None:
    row = s.query(Snapshot).filter_by(instance_id=inst_id, kind=kind).one_or_none()
    if row:
        row.payload, row.collected_at = payload, now
    else:
        s.add(Snapshot(instance_id=inst_id, kind=kind, payload=payload, collected_at=now))


def _finish(inst_id, now, status, error, latency, version, results) -> None:
    with session_scope() as s:
        inst = s.get(Instance, inst_id)
        if inst is None:  # supprimée pendant le cycle
            return
        inst.status, inst.last_attempt_at, inst.last_error = status, now, error[:1024]
        if status != "down":
            inst.last_ok_at, inst.latency_ms = now, latency
            inst.version = version[:32] if version else inst.version
        for kind, payload in results.items():
            _save_snapshot(s, inst_id, kind, payload, now)


async def collect_one(inst_id: int, client_factory=default_client) -> None:
    # ponytail: accès DB synchrones dans la boucle async ; OK pour SQLite et <= 10 instances.
    with session_scope() as s:
        inst = s.get(Instance, inst_id)
        if inst is None or not inst.enabled:
            return
    now = utcnow()
    client = client_factory(inst)
    results, errors = {}, []
    try:
        try:
            latency, version = await client.ping()
        except BWError as e:
            _finish(inst_id, now, "down", f"{e.kind}: {e}", None, None, {})
            return
        if not version and (not inst.version
                            or now - _VERSION_CHECKED.get(inst_id, datetime.min) > VERSION_RECHECK):
            _VERSION_CHECKED[inst_id] = now
            try:
                version = await client.version()  # ne lève pas ; None = on garde la valeur connue
            except Exception:  # noqa: BLE001 - la version ne doit jamais affecter la collecte
                version = None
        for kind in KINDS:
            try:
                results[kind] = await getattr(client, kind)()
            except BWError as e:
                errors.append(f"{kind}: {e.kind}: {e}")
    finally:
        remember_token(inst, client)  # réutilisé au cycle suivant (évite un POST /auth par cycle)
        await client.aclose()
    if problem := _node_problems(results.get("instances") or []):
        errors.append(problem)
    _finish(inst_id, now, "degraded" if errors else "ok", "; ".join(errors), latency, version, results)


async def probe_one(inst_id: int, probe_fn=probe) -> None:
    with session_scope() as s:
        inst = s.get(Instance, inst_id)
        if inst is None or not inst.enabled:
            return
        snap = s.query(Snapshot).filter_by(instance_id=inst_id, kind="services").one_or_none()
        domains = sorted({x["name"].split()[0] for x in (snap.payload if snap else [])
                          if not x.get("draft") and x["name"].strip()})
        target, port = inst.probe_target, inst.tls_port
    timeout = get_settings().http_timeout
    infos = dict(zip(domains, await asyncio.gather(*[probe_fn(target, port, d, timeout) for d in domains])))
    now = utcnow()
    with session_scope() as s:
        if s.get(Instance, inst_id) is None:  # supprimée pendant la sonde
            return
        for row in s.query(CertProbe).filter_by(instance_id=inst_id).all():
            if row.domain not in infos:
                s.delete(row)
        for domain, i in infos.items():
            row = (s.query(CertProbe).filter_by(instance_id=inst_id, domain=domain).one_or_none()
                   or CertProbe(instance_id=inst_id, domain=domain))
            row.present, row.issuer, row.not_after = i.present, i.issuer, i.not_after
            row.error, row.probed_at = i.error[:512], now
            s.add(row)


async def refresh_instance(inst_id: int) -> None:
    """Collecte puis sonde immédiatement une instance (après ajout ou modification)."""
    await collect_one(inst_id)
    await probe_one(inst_id)


def _enabled_ids() -> list[int]:
    with session_scope() as s:
        return [i for (i,) in s.query(Instance.id).filter_by(enabled=True)]


async def _gather_logged(coros) -> None:
    for r in await asyncio.gather(*coros, return_exceptions=True):
        if isinstance(r, Exception):
            log.error("cycle task failed: %r", r)


async def collect_all() -> None:
    await _gather_logged([collect_one(i) for i in _enabled_ids()])


async def probe_all() -> None:
    await _gather_logged([probe_one(i) for i in _enabled_ids()])


async def _every(fn, seconds: float, first_delay: float = 0) -> None:
    await asyncio.sleep(first_delay)
    while True:
        try:
            await fn()
        except Exception:
            log.exception("cycle failed")
        await asyncio.sleep(seconds)


async def run_forever() -> None:
    cfg = get_settings()
    await asyncio.gather(
        _every(collect_all, cfg.poll_interval),
        _every(probe_all, cfg.probe_interval, first_delay=15),  # laisse la 1re collecte remplir les services
    )
