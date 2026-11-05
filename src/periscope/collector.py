import asyncio
import hashlib
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from periscope import alert_engine
from periscope.bw_client import BWClient, BWError
from periscope.clock import utcnow
from periscope.config import get_settings
from periscope.crypto import decrypt
from periscope.db import session_scope
from periscope.i18n import N_, pack, pack_data, pack_many, render
from periscope.models import CertProbe, Instance, Snapshot
from periscope.tlsprobe import CertInfo, probe

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
    return BWClient(inst.base_url, (inst.api_username, decrypt(inst.api_password_enc)),
                    token=_TOKEN_CACHE.get(_cache_key(inst)),
                    timeout=get_settings().http_timeout, verify=inst.verify_tls)


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


@dataclass
class Collected:
    """Result of one collection cycle, independent of where it ran (console or agent)."""
    status: str  # ok | degraded | down
    errors: list[str] = field(default_factory=list)  # packed messages
    latency: float | None = None
    version: str | None = None
    results: dict[str, list] = field(default_factory=dict)  # kind -> normalized payload


async def gather(client, want_version: Callable[[], bool] = lambda: True) -> Collected:
    """Query one BunkerWeb API (network only, no database). `want_version()` is asked only when /ping
    carries no version, to decide whether the (rate-limited) version lookup runs this cycle."""
    try:
        latency, version = await client.ping()
    except BWError as e:
        return Collected("down", [_bw_problem(None, e)])
    if not version and want_version():
        try:
            version = await client.version()  # does not raise; None = keep the known value
        except Exception:  # noqa: BLE001 - the version must never affect collection
            version = None
    results, errors = {}, []
    for kind in KINDS:
        try:
            results[kind] = await getattr(client, kind)()
        except BWError as e:
            errors.append(_bw_problem(kind, e))
    errors.extend(_node_problems(results.get("instances") or []))
    return Collected("degraded" if errors else "ok", errors, latency, version, results)


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


def store(inst_id: int, now: datetime, c: Collected) -> None:
    _finish(inst_id, now, c.status, _stored_error(c.errors), c.latency, c.version, c.results)


def _load_direct(inst_id: int) -> Instance | None:
    with session_scope() as s:
        inst = s.get(Instance, inst_id)
        return inst if inst is not None and inst.enabled and not inst.is_agent else None


async def collect_one(inst_id: int, client_factory=default_client) -> None:
    """Poll one `direct` instance and store the result (database access runs in a worker thread so
    that many instances do not block the event loop shared with the web UI)."""
    inst = await asyncio.to_thread(_load_direct, inst_id)
    if inst is None:
        return
    now = utcnow()

    def want_version() -> bool:
        last = _VERSION_CHECKED.get(inst_id)
        if inst.version and last is not None and now - last <= VERSION_RECHECK:
            return False
        _VERSION_CHECKED[inst_id] = now
        return True

    client = client_factory(inst)
    try:
        result = await gather(client, want_version)
    finally:
        remember_token(inst, client)  # reused on the next cycle (avoids one POST /auth per cycle)
        await client.aclose()
    await asyncio.to_thread(store, inst_id, now, result)


def service_domains(services_payload) -> list[str]:
    """Domains to probe: the first server name of each non-draft service."""
    return sorted({str(x["name"]).split()[0] for x in (services_payload or [])
                   if isinstance(x, dict) and not x.get("draft") and str(x.get("name", "")).strip()})


async def probe_domains(target: str, port: int, domains: list[str], timeout: float, probe_fn=probe,
                        limit: asyncio.Semaphore | None = None) -> dict[str, CertInfo]:
    async def one(d):
        if limit is None:
            return await probe_fn(target, port, d, timeout)
        async with limit:
            return await probe_fn(target, port, d, timeout)
    return dict(zip(domains, await asyncio.gather(*[one(d) for d in domains]), strict=True))


def store_probes(inst_id: int, infos: dict[str, CertInfo], now: datetime) -> None:
    with session_scope() as s:
        if s.get(Instance, inst_id) is None:  # deleted during the probe
            return
        for row in s.query(CertProbe).filter_by(instance_id=inst_id).all():
            if row.domain not in infos:
                s.delete(row)
        for domain, i in infos.items():
            row = (s.query(CertProbe).filter_by(instance_id=inst_id, domain=domain).one_or_none()
                   or CertProbe(instance_id=inst_id, domain=domain))
            row.present, row.issuer, row.not_after = i.present, (i.issuer or "")[:255], i.not_after
            row.error, row.probed_at = (i.error or "")[:512], now
            s.add(row)


def _probe_plan(inst_id: int) -> tuple[str, int, list[str]] | None:
    with session_scope() as s:
        inst = s.get(Instance, inst_id)
        if inst is None or not inst.enabled or inst.is_agent:
            return None
        snap = s.query(Snapshot).filter_by(instance_id=inst_id, kind="services").one_or_none()
        return inst.probe_target, inst.tls_port, service_domains(snap.payload if snap else [])


async def probe_one(inst_id: int, probe_fn=probe, limit: asyncio.Semaphore | None = None) -> None:
    plan = await asyncio.to_thread(_probe_plan, inst_id)
    if plan is None:
        return
    target, port, domains = plan
    infos = await probe_domains(target, port, domains, get_settings().http_timeout, probe_fn, limit)
    await asyncio.to_thread(store_probes, inst_id, infos, utcnow())


async def refresh_instance(inst_id: int) -> None:
    """Immediately collect then probe an instance (after addition or modification)."""
    await collect_one(inst_id)
    await probe_one(inst_id)


def _enabled_ids(connection: str = "direct") -> list[int]:
    with session_scope() as s:
        return [i for (i,) in s.query(Instance.id).filter_by(enabled=True, connection=connection)]


def agent_silence_limit() -> timedelta:
    cfg = get_settings()
    return timedelta(seconds=max(cfg.stale_cycles * cfg.poll_interval, 60))


def check_agents(now: datetime | None = None) -> None:
    """Agent instances report on their own: mark `down` those that went silent, and say which ones
    still wait for enrollment or their first report (the stored message is language-neutral)."""
    now = now or utcnow()
    limit = agent_silence_limit()
    with session_scope() as s:
        for inst in s.query(Instance).filter_by(enabled=True, connection="agent"):
            if not inst.agent_cert_fp:
                inst.status, inst.last_error = "unknown", pack(N_("Agent not enrolled yet"))
            elif inst.last_attempt_at is None:
                inst.status, inst.last_error = "unknown", pack(N_("Waiting for the first agent report"))
            elif now - inst.last_attempt_at > limit and inst.status != "down":
                inst.status = "down"
                inst.last_error = pack(N_("No report from the agent for more than {seconds} s"),
                                       seconds=int(limit.total_seconds()))


async def _gather_logged(coros) -> None:
    for r in await asyncio.gather(*coros, return_exceptions=True):
        if isinstance(r, Exception):
            log.error("cycle task failed: %r", r)


async def _bounded(limit: asyncio.Semaphore, coro):
    async with limit:
        return await coro


async def collect_all() -> None:
    limit = asyncio.Semaphore(get_settings().max_parallel)
    ids = await asyncio.to_thread(_enabled_ids)
    await _gather_logged([_bounded(limit, collect_one(i)) for i in ids])
    await asyncio.to_thread(check_agents)
    await alert_engine.run_status()


async def probe_all() -> None:
    cfg = get_settings()
    limit, handshakes = asyncio.Semaphore(cfg.max_parallel), asyncio.Semaphore(cfg.max_parallel_probes)
    ids = await asyncio.to_thread(_enabled_ids)
    await _gather_logged([_bounded(limit, probe_one(i, limit=handshakes)) for i in ids])
    await alert_engine.run_certs()


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
