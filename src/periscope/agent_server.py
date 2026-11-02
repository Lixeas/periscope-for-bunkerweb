"""Console side of the agent mode: the HTTPS listener the agents report to (mutual TLS).

Separate from the web UI (own port, own FastAPI app without cookies, sessions or HTML), started in the
web app's lifespan when PERISCOPE_AGENT_PUBLIC_URL is set:

- TLS server certificate signed by the Periscope agent CA (`pki.py`), regenerated at each start;
- client certificates verified by TLS against that CA (`CERT_OPTIONAL`: only /v1/ca and /v1/enroll
  work without one, every other route requires it), then mapped to ONE instance by the SHA-256 of
  their DER: an agent can only write the data of its own instance, and forgetting the fingerprint
  revokes it at once;
- reports are untrusted input: size-capped, strictly shaped, stored like a direct collection.

Routes: GET /v1/ca (CA certificate, public), POST /v1/enroll (single-use token + CSR -> certificate),
POST /v1/report (mTLS), POST /v1/renew (mTLS, CSR -> new certificate, promoted at its first use).
"""
import asyncio
import contextlib
import hashlib
import json
import logging
import math
import shutil
import ssl
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

from cryptography import x509
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import or_

from periscope import collector, pki
from periscope.auth.audit import audit
from periscope.auth.ratelimit import IPLimiter
from periscope.clock import utcnow
from periscope.collector import KINDS, Collected
from periscope.config import get_settings
from periscope.db import session_scope
from periscope.models import Instance
from periscope.tlsprobe import CertInfo

log = logging.getLogger("periscope.agents")
CERT_EXT = "periscope.client_cert"  # ASGI scope extension set by MTLSProtocol: client cert DER or None
PROTOCOL = 1
MIN_REPORT_GAP = timedelta(seconds=5)
MAX_ITEMS = 100_000  # per snapshot kind
MAX_PROBES = 10_000
MAX_ERRORS = 50
MAX_STR = 2048
enroll_limiter = IPLimiter(max_events=10, window=600)


class ReportError(ValueError):
    pass


@dataclass
class Report:
    collected: Collected
    probes: dict[str, CertInfo] | None
    agent_version: str


def _text(v, limit: int = MAX_STR, *, optional: bool = False) -> str | None:
    if v is None and optional:
        return None
    if not isinstance(v, str) or len(v) > limit:
        raise ReportError("bad string")
    return v


def _number(v) -> float | None:
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, int | float) or not math.isfinite(v) or v < 0:
        raise ReportError("bad number")
    return float(v)


def _date(v) -> datetime | None:
    if v is None:
        return None
    try:
        d = datetime.fromisoformat(_text(v, 64))
    except ValueError as e:
        raise ReportError("bad date") from e
    return d.astimezone(UTC).replace(tzinfo=None) if d.tzinfo else d


def parse_report(body) -> Report:
    """Strict validation of an agent report (an agent's machine may be compromised: never trust it)."""
    if not isinstance(body, dict) or body.get("protocol") != PROTOCOL:
        raise ReportError("unsupported protocol")
    status = body.get("status")
    if status not in ("ok", "degraded", "down"):
        raise ReportError("bad status")
    errors = body.get("errors") or []
    if not isinstance(errors, list) or len(errors) > MAX_ERRORS:
        raise ReportError("bad errors")
    snapshots = body.get("snapshots") or {}
    if not isinstance(snapshots, dict) or not set(snapshots) <= set(KINDS):
        raise ReportError("bad snapshots")
    results = {}
    for kind, items in snapshots.items():
        if not isinstance(items, list) or len(items) > MAX_ITEMS or not all(isinstance(i, dict) for i in items):
            raise ReportError(f"bad {kind}")
        results[kind] = items
    probes = body.get("probes")
    infos = None
    if probes is not None:
        if not isinstance(probes, list) or len(probes) > MAX_PROBES:
            raise ReportError("bad probes")
        infos = {}
        for p in probes:
            if not isinstance(p, dict):
                raise ReportError("bad probe")
            infos[_text(p.get("domain"), 255)] = CertInfo(
                bool(p.get("present")), _text(p.get("issuer") or "", 255), _date(p.get("not_after")),
                _text(p.get("error") or "", 512))
    version = _text(body.get("version"), 64, optional=True)
    return Report(Collected(status, [_text(e) for e in errors], _number(body.get("latency_ms")),
                            version[:32] if version else None, results),
                  infos, (_text(body.get("agent_version") or "", 64) or "")[:32])


def _peer_der(request: Request) -> bytes | None:
    return (request.scope.get("extensions") or {}).get(CERT_EXT) or None


def authenticate(db, der: bytes | None) -> Instance | None:
    """The agent instance owning this client certificate (TLS already checked it was signed by the CA).
    A renewed certificate becomes the current one at its first use."""
    if not der:
        return None
    fp = pki.fingerprint(der)
    inst = (db.query(Instance).filter(Instance.connection == "agent")
            .filter(or_(Instance.agent_cert_fp == fp, Instance.agent_next_cert_fp == fp)).one_or_none())
    if inst is not None and inst.agent_next_cert_fp == fp:
        inst.agent_cert_fp, inst.agent_next_cert_fp = fp, ""
        inst.agent_cert_not_after = x509.load_der_x509_certificate(der).not_valid_after_utc.replace(tzinfo=None)
        audit(db, "agent_cert_renewed", detail=inst.name)
    return inst


async def _json_body(request: Request, limit: int):
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise ReportError("too large")
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            raise ReportError("too large")
    try:
        return json.loads(bytes(body))
    except (ValueError, RecursionError) as e:
        raise ReportError("invalid JSON") from e


def _err(status: int, message: str) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


def _intervals(inst: Instance, now: datetime) -> dict:
    cfg = get_settings()
    renew = inst.agent_cert_not_after is None or inst.agent_cert_not_after - now < pki.AGENT_RENEW_BEFORE
    return {"poll_interval": cfg.poll_interval, "probe_interval": cfg.probe_interval,
            "renew": bool(renew and not inst.agent_next_cert_fp)}


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


def enroll_token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_agent_app() -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        return resp

    @app.get("/v1/ca")
    async def ca():
        def load():
            with session_scope() as s:
                return pki.ca_pem(s)
        return PlainTextResponse(await asyncio.to_thread(load), media_type="application/x-pem-file")

    @app.post("/v1/enroll")
    async def enroll(request: Request):
        ip = _ip(request)
        if not enroll_limiter.hit(ip):
            return _err(429, "too many attempts")
        try:
            body = await _json_body(request, 16 * 1024)
            token, csr = _text(body.get("token"), 256), _text(body.get("csr"), pki.MAX_CSR_BYTES)
        except (ReportError, AttributeError):
            return _err(400, "invalid request")

        def do():
            now = utcnow()
            with session_scope() as s:
                inst = (s.query(Instance).filter_by(connection="agent", agent_enroll_hash=enroll_token_hash(token))
                        .one_or_none())
                if inst is None or not inst.agent_enroll_expires or inst.agent_enroll_expires < now:
                    audit(s, "agent_enroll_failed", ip=ip)
                    return None
                try:
                    pem, fp, not_after = pki.issue_agent_cert(s, csr, inst.id)
                except ValueError:
                    return "csr"
                inst.agent_enroll_hash, inst.agent_enroll_expires = "", None  # single use
                inst.agent_cert_fp, inst.agent_next_cert_fp, inst.agent_cert_not_after = fp, "", not_after
                inst.agent_ip, inst.last_attempt_at, inst.status = ip[:64], None, "unknown"
                audit(s, "agent_enrolled", detail=inst.name, ip=ip)
                return {"certificate": pem, "ca": pki.ca_pem(s).decode(), "instance": inst.name,
                        **_intervals(inst, now)}
        out = await asyncio.to_thread(do)
        if out is None:
            return _err(403, "invalid or expired enrollment token")
        if out == "csr":
            return _err(400, "invalid certificate request")
        return JSONResponse(out)

    @app.post("/v1/report")
    async def report(request: Request):
        der = _peer_der(request)
        if der is None:
            return _err(401, "client certificate required")
        try:
            rep = parse_report(await _json_body(request, get_settings().agent_max_report_bytes))
        except ReportError as e:
            # the reason goes to the console's log only: never echo exception text to the client
            log.warning("invalid agent report from %s: %s", _ip(request), e)
            return _err(400, "invalid report")
        ip = _ip(request)

        def do():
            now = utcnow()
            with session_scope() as s:
                inst = authenticate(s, der)
                if inst is None:
                    return None
                answer = _intervals(inst, now)
                if not inst.enabled:
                    return {**answer, "accepted": False}
                if inst.last_attempt_at and now - inst.last_attempt_at < MIN_REPORT_GAP:
                    return "early"
                inst.agent_ip, inst.agent_version = ip[:64], rep.agent_version
                inst_id = inst.id
            collector.store(inst_id, now, rep.collected)
            if rep.probes is not None:
                collector.store_probes(inst_id, rep.probes, now)
            return {**answer, "accepted": True}
        out = await asyncio.to_thread(do)
        if out is None:
            return _err(403, "unknown or revoked agent certificate")
        if out == "early":
            return _err(429, "reports too frequent")
        return JSONResponse(out)

    @app.post("/v1/renew")
    async def renew(request: Request):
        der = _peer_der(request)
        if der is None:
            return _err(401, "client certificate required")
        try:
            csr = _text((await _json_body(request, 16 * 1024)).get("csr"), pki.MAX_CSR_BYTES)
        except (ReportError, AttributeError):
            return _err(400, "invalid request")

        def do():
            with session_scope() as s:
                inst = authenticate(s, der)
                if inst is None:
                    return None
                try:
                    pem, fp, _ = pki.issue_agent_cert(s, csr, inst.id)
                except ValueError:
                    return "csr"
                inst.agent_next_cert_fp = fp
                return {"certificate": pem}
        out = await asyncio.to_thread(do)
        if out is None:
            return _err(403, "unknown or revoked agent certificate")
        if out == "csr":
            return _err(400, "invalid certificate request")
        return JSONResponse(out)

    return app


# --- listener --------------------------------------------------------------------------------

def _mtls_protocol():
    from uvicorn.protocols.http.h11_impl import H11Protocol

    class MTLSProtocol(H11Protocol):
        """Passes the verified client certificate (DER) to the app through a scope extension: it can only
        come from the TLS layer, never from a request header."""

        def connection_made(self, transport):
            super().connection_made(transport)
            ssl_obj = transport.get_extra_info("ssl_object")
            der = ssl_obj.getpeercert(binary_form=True) if ssl_obj is not None else None
            inner = self.app

            async def app(scope, receive, send):
                if scope["type"] == "http":
                    scope = {**scope, "extensions": {**(scope.get("extensions") or {}), CERT_EXT: der}}
                await inner(scope, receive, send)
            self.app = app

    return MTLSProtocol


def public_host(url: str) -> str:
    u = urlparse(url)
    if u.scheme != "https" or not u.hostname:
        raise ValueError("PERISCOPE_AGENT_PUBLIC_URL must be https://host[:port]")
    return u.hostname


class AgentListener:
    """The mTLS listener, run as a task of the web app's lifespan."""

    def __init__(self, host: str | None = None, port: int | None = None):
        cfg = get_settings()
        self.host = host or cfg.agent_listen_host
        self.port = cfg.agent_listen_port if port is None else port
        self.server = None
        self._dir: Path | None = None

    def _config(self):
        import uvicorn

        with session_scope() as s:
            ca = pki.ca_pem(s)
            cert, key = pki.issue_server_cert(s, public_host(get_settings().agent_public_url))
        self._dir = Path(tempfile.mkdtemp(prefix="periscope-agent-tls-"))
        for name, data in (("ca.crt", ca), ("server.crt", cert), ("server.key", key)):
            p = self._dir / name
            p.touch(mode=0o600)
            p.write_bytes(data)
        config = uvicorn.Config(create_agent_app(), host=self.host, port=self.port, lifespan="off",
                                ssl_certfile=str(self._dir / "server.crt"), ssl_keyfile=str(self._dir / "server.key"),
                                ssl_ca_certs=str(self._dir / "ca.crt"), ssl_cert_reqs=ssl.CERT_OPTIONAL,
                                http=_mtls_protocol(), proxy_headers=False, server_header=False,
                                log_config=None, timeout_keep_alive=30)
        config.load()
        config.ssl.minimum_version = ssl.TLSVersion.TLSv1_2
        return config

    async def serve(self) -> None:
        import uvicorn

        class _Server(uvicorn.Server):
            @contextlib.contextmanager
            def capture_signals(self):  # the main server owns the signals
                yield

            def install_signal_handlers(self):  # older uvicorn
                pass

        try:
            self.server = _Server(await asyncio.to_thread(self._config))
            log.info("agent listener on %s:%s", self.host, self.port)
            await self.server.serve()
        finally:
            if self._dir:
                shutil.rmtree(self._dir, ignore_errors=True)

    def stop(self) -> None:
        if self.server is not None:
            self.server.should_exit = True
