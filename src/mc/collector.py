import asyncio
import logging

from mc.bw_client import BWClient, BWError
from mc.clock import utcnow
from mc.config import get_settings
from mc.crypto import decrypt
from mc.db import session_scope
from mc.models import CertProbe, Instance, Snapshot
from mc.tlsprobe import probe

log = logging.getLogger("mc.collector")
KINDS = ("services", "bans", "jobs", "plugins")


def default_client(inst: Instance) -> BWClient:
    return BWClient(inst.base_url, decrypt(inst.token_enc),
                    timeout=get_settings().http_timeout, verify=inst.verify_tls)


def _save_snapshot(s, inst_id: int, kind: str, payload: list, now) -> None:
    row = s.query(Snapshot).filter_by(instance_id=inst_id, kind=kind).one_or_none()
    if row:
        row.payload, row.collected_at = payload, now
    else:
        s.add(Snapshot(instance_id=inst_id, kind=kind, payload=payload, collected_at=now))


def _finish(inst_id, now, status, error, latency, version, results) -> None:
    with session_scope() as s:
        inst = s.get(Instance, inst_id)
        inst.status, inst.last_attempt_at, inst.last_error = status, now, error[:1024]
        if status != "down":
            inst.last_ok_at, inst.latency_ms = now, latency
            inst.version = version or inst.version
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
        for kind in KINDS:
            try:
                results[kind] = await getattr(client, kind)()
            except BWError as e:
                errors.append(f"{kind}: {e.kind}: {e}")
    finally:
        await client.aclose()
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
        for row in s.query(CertProbe).filter_by(instance_id=inst_id).all():
            if row.domain not in infos:
                s.delete(row)
        for domain, i in infos.items():
            row = (s.query(CertProbe).filter_by(instance_id=inst_id, domain=domain).one_or_none()
                   or CertProbe(instance_id=inst_id, domain=domain))
            row.present, row.issuer, row.not_after = i.present, i.issuer, i.not_after
            row.error, row.probed_at = i.error[:512], now
            s.add(row)


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
