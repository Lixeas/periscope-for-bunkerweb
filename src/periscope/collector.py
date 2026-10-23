import asyncio
import hashlib
import logging
from datetime import datetime, timedelta

from periscope.bw_client import BWClient, BWError
from periscope.clock import utcnow
from periscope.config import get_settings
from periscope.crypto import decrypt
from periscope.db import session_scope
from periscope.i18n import N_, pack, pack_data, pack_many, render
from periscope.models import CertProbe, Instance, Snapshot
from periscope.tlsprobe import probe

log = logging.getLogger("periscope.collector")
KINDS = ("services", "bans", "jobs", "plugins", "instances")


# Biscuit tokens in memory (single process): (instance id, credentials fingerprint) -> token.
# Changing the username or password changes the fingerprint, hence invalidates the entry.
_TOKEN_CACHE: dict[tuple[int, str], str] = {}


# Last version lookup (OpenAPI) per instance: avoids one request per cycle.
_VERSION_CHECKED: dict[int, datetime] = {}
VERSION_RECHECK = timedelta(hours=1)


def _cache_key(inst: Instance) -> tuple[int, str]:
    fp = hashlib.sha256(f"{inst.api_username}\0{inst.api_password_enc}".encode()).hexdigest()
    return inst.id, fp


def remember_token(inst: Instance, client) -> None:
    if inst.auth_mode != "user":
        return
    key = _cache_key(inst)
    # purge stale entries of this instance (old credentials)
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


def _node_problems(nodes: list[dict]) -> list[str]:
    """Packed (language-neutral) messages for faulty nodes ('loading' is not one); [] if all is well."""
    problems = []
    for status, one, many in (
            ("down", N_("{count} node offline: {names}"), N_("{count} nodes offline: {names}")),
            ("failover", N_("{count} node in failover: {names}"), N_("{count} nodes in failover: {names}"))):
        names = [str(n.get("hostname") or n.get("name") or "?") for n in nodes if n.get("status") == status]
        if names:
            problems.append(pack(one if len(names) == 1 else many, count=len(names), names=", ".join(names)))
    return problems


def _save_snapshot(s, inst_id: int, kind: str, payload: list, now) -> None:
    row = s.query(Snapshot).filter_by(instance_id=inst_id, kind=kind).one_or_none()
    if row:
        row.payload, row.collected_at = payload, now
    else:
        s.add(Snapshot(instance_id=inst_id, kind=kind, payload=payload, collected_at=now))


def _bw_problem(resource: str | None, e: BWError) -> str:
    """Packed message for one BunkerWeb API failure ("kind: detail", prefixed by the resource if any)."""
    detail = pack_data(e.msgid, **e.params)
    if resource is None:
        return pack(N_("{kind}: {detail}"), kind=e.kind, detail=detail)
    return pack(N_("{resource}: {kind}: {detail}"), resource=resource, kind=e.kind, detail=detail)


def _stored_error(errors: list[str]) -> str:
    """Language-neutral stored form of the cycle's problems ('' if none), shown translated at display time."""
    if not errors:
        return ""
    packed = pack_many(errors)
    return packed if len(packed) <= 1024 else render("en", packed)[:1024]  # column size: keep readable text


def _finish(inst_id, now, status, error, latency, version, results) -> None:
    with session_scope() as s:
        inst = s.get(Instance, inst_id)
        if inst is None:  # deleted during the cycle
            return
        inst.status, inst.last_attempt_at, inst.last_error = status, now, error
        if status != "down":
            inst.last_ok_at, inst.latency_ms = now, latency
            inst.version = version[:32] if version else inst.version
        for kind, payload in results.items():
            _save_snapshot(s, inst_id, kind, payload, now)


async def collect_one(inst_id: int, client_factory=default_client) -> None:
    # ponytail: synchronous DB access in the async loop; fine for SQLite and <= 10 instances.
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
            _finish(inst_id, now, "down", _stored_error([_bw_problem(None, e)]), None, None, {})
            return
        if not version and (not inst.version
                            or now - _VERSION_CHECKED.get(inst_id, datetime.min) > VERSION_RECHECK):
            _VERSION_CHECKED[inst_id] = now
            try:
                version = await client.version()  # does not raise; None = keep the known value
            except Exception:  # noqa: BLE001 - the version must never affect collection
                version = None
        for kind in KINDS:
            try:
                results[kind] = await getattr(client, kind)()
            except BWError as e:
                errors.append(_bw_problem(kind, e))
    finally:
        remember_token(inst, client)  # reused on the next cycle (avoids one POST /auth per cycle)
        await client.aclose()
    if problem := _node_problems(results.get("instances") or []):
        errors.extend(problem)
    _finish(inst_id, now, "degraded" if errors else "ok", _stored_error(errors), latency, version, results)


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
        if s.get(Instance, inst_id) is None:  # deleted during the probe
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
    """Immediately collect then probe an instance (after addition or modification)."""
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
        _every(probe_all, cfg.probe_interval, first_delay=15),  # lets the 1st collection fill in the services
    )
