"""Periscope agent: runs next to a BunkerWeb instance (same network), collects it with the same code as
the console's direct mode, and pushes the result to the console over mutual TLS.

Nothing listens on the agent side: the only connections are outbound (to the local BunkerWeb API,
to the TLS ports of its services, and to the console). The BunkerWeb API user's password stays on the
agent's machine; the console never holds it.

  periscope agent enroll <bundle>   # once: bundle shown by the console when the instance is created
  periscope agent run               # the loop (container entrypoint)

Configuration: environment variables PERISCOPE_AGENT_* (see AgentSettings). Files (directory
PERISCOPE_AGENT_DIR): agent.key (private key, 0600, generated here and never sent), agent.crt, ca.crt
(the console's agent CA, pinned by fingerprint at enrollment) and console.json.
"""
import asyncio
import base64
import binascii
import hmac
import json
import logging
import os
import ssl
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from cryptography import x509
from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from periscope import __version__, collector, pki
from periscope.bw_client import BWClient

log = logging.getLogger("periscope.agent")
BUNDLE_PREFIX = "psc1."
PROTOCOL = 1


class AgentError(Exception):
    pass


class AgentSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PERISCOPE_AGENT_", env_file=".env", extra="ignore")

    dir: Path = Path("./data/agent")
    bw_url: str = ""  # local BunkerWeb API, e.g. http://bw-api:8888 (root prefix included)
    bw_username: str = ""
    bw_password: SecretStr = SecretStr("")
    bw_password_file: Path | None = None  # alternative to bw_password (Docker secret)
    bw_verify_tls: bool = True
    probe_host: str = ""  # empty = host of bw_url
    tls_port: int = 443
    http_timeout: float = 5.0
    max_parallel_probes: int = 20

    def password(self) -> str:
        if self.bw_password_file:
            return self.bw_password_file.read_text(encoding="utf-8").strip()
        return self.bw_password.get_secret_value()


# --- enrollment bundle ---------------------------------------------------------------------------

def make_bundle(url: str, token: str, ca_fp: str) -> str:
    raw = json.dumps({"u": url, "t": token, "f": ca_fp}, separators=(",", ":")).encode()
    return BUNDLE_PREFIX + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def parse_bundle(bundle: str) -> tuple[str, str, str]:
    b = bundle.strip()
    if not b.startswith(BUNDLE_PREFIX):
        raise AgentError("not a Periscope enrollment bundle")
    b = b[len(BUNDLE_PREFIX):]
    try:
        data = json.loads(base64.urlsafe_b64decode(b + "=" * (-len(b) % 4)))
        url, token, fp = data["u"], data["t"], data["f"]
    except (ValueError, KeyError, TypeError, binascii.Error) as e:
        raise AgentError("corrupted enrollment bundle") from e
    if not all(isinstance(v, str) and v for v in (url, token, fp)) or not url.startswith("https://"):
        raise AgentError("corrupted enrollment bundle")
    return url.rstrip("/"), token, fp.lower()


# --- files -----------------------------------------------------------------------------------------

def _write(path: Path, data: bytes, private: bool = False) -> None:
    """Atomic write (temporary file + rename); private files are created 0600."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.unlink(missing_ok=True)  # O_EXCL below: a leftover (or planted) file never keeps its own mode
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600 if private else 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def _files(d: Path) -> dict[str, Path]:
    return {k: d / n for k, n in (("key", "agent.key"), ("cert", "agent.crt"), ("ca", "ca.crt"),
                                  ("console", "console.json"), ("health", "health.json"))}


def write_health(d: Path, poll: int) -> None:
    """Called after each report the console accepted: `periscope agent health` reads it."""
    _write(_files(d)["health"], json.dumps({"t": time.time(), "poll": poll}).encode())


def healthy(d: Path, now: float | None = None) -> bool:
    """True if the console accepted a report within 3 poll intervals (+ 30 s)."""
    try:
        h = json.loads(_files(d)["health"].read_text())
        return (now or time.time()) - float(h["t"]) <= 3 * int(h["poll"]) + 30
    except (OSError, ValueError, KeyError, TypeError):
        return False


def client_context(d: Path, identity: bool = True, ca: Path | None = None) -> ssl.SSLContext:
    """TLS context to the console: only the pinned agent CA is trusted, our certificate is presented.
    Enrollment passes identity=False (the token authenticates it, and an old or expired certificate left on
    the volume must not break the handshake) and the CA it is still verifying (`ca`)."""
    f = _files(d)
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca or f["ca"]))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if identity and f["cert"].exists():
        ctx.load_cert_chain(str(f["cert"]), str(f["key"]))
    return ctx


def cert_not_after(d: Path) -> datetime:
    cert = x509.load_pem_x509_certificate(_files(d)["cert"].read_bytes())
    return cert.not_valid_after_utc.replace(tzinfo=None)


async def enroll(bundle: str, d: Path, transport=None) -> str:
    """Pin the console's CA, generate the key locally, have the CSR signed; return the instance name."""
    url, token, fp = parse_bundle(bundle)
    d.mkdir(parents=True, exist_ok=True)
    d.chmod(0o700)  # holds the agent's private key
    f = _files(d)
    # 1. CA fetched without verification, then accepted ONLY if its fingerprint is the one in the bundle
    async with httpx.AsyncClient(base_url=url, verify=False, timeout=10, transport=transport) as c:
        try:
            r = await c.get("/v1/ca")
        except httpx.HTTPError as e:
            raise AgentError(f"console unreachable: {type(e).__name__}") from e
    if r.status_code != 200:
        raise AgentError(f"console answered HTTP {r.status_code} on /v1/ca")
    try:
        ca = x509.load_pem_x509_certificate(r.content)
    except ValueError as e:
        raise AgentError("the console did not return a certificate") from e
    from cryptography.hazmat.primitives.serialization import Encoding
    if not hmac.compare_digest(pki.fingerprint(ca.public_bytes(Encoding.DER)), fp):
        raise AgentError("CA fingerprint mismatch: wrong console URL or interception, enrollment aborted")
    # the verified CA waits next to the real one: an identity already on the volume (re-enrollment) stays
    # intact until the console has accepted the new one
    pending_ca = d / "ca.crt.new"
    _write(pending_ca, r.content)
    try:
        # 2. the private key is generated here and never leaves this machine
        key, csr = pki.new_key_and_csr()
        async with httpx.AsyncClient(base_url=url, verify=client_context(d, identity=False, ca=pending_ca),
                                     timeout=10, transport=transport) as c:
            try:
                r = await c.post("/v1/enroll", json={"token": token, "csr": csr.decode()})
            except httpx.HTTPError as e:
                raise AgentError(f"enrollment failed: {type(e).__name__}") from e
        if r.status_code != 200:
            raise AgentError(f"enrollment refused (HTTP {r.status_code}): {_error_of(r)}")
        body = r.json()
        os.replace(pending_ca, f["ca"])
    finally:
        pending_ca.unlink(missing_ok=True)
    _write(f["key"], key, private=True)
    _write(f["cert"], body["certificate"].encode())
    _write(f["console"], json.dumps({"url": url, "instance": body.get("instance", "")}).encode())
    return str(body.get("instance", ""))


def _error_of(r: httpx.Response) -> str:
    try:
        return str(r.json().get("error", ""))[:200]
    except ValueError:
        return ""


# --- loop ----------------------------------------------------------------------------------------

def _probe_rows(infos) -> list[dict]:
    return [{"domain": d, "present": i.present, "issuer": i.issuer, "error": i.error,
             "not_after": i.not_after.replace(tzinfo=UTC).isoformat() if i.not_after else None}
            for d, i in infos.items()]


def build_report(result: collector.Collected, probes=None) -> dict:
    return {"protocol": PROTOCOL, "agent_version": __version__, "status": result.status,
            "errors": result.errors, "latency_ms": result.latency, "version": result.version,
            "snapshots": result.results, "probes": None if probes is None else _probe_rows(probes)}


class Agent:
    def __init__(self, cfg: AgentSettings, transport=None, bw_transport=None, probe_fn=None):
        self.cfg, self.dir = cfg, cfg.dir
        f = _files(self.dir)
        if not (f["cert"].exists() and f["key"].exists() and f["console"].exists()):
            raise AgentError(f"not enrolled: run `periscope agent enroll <bundle>` (directory {self.dir})")
        if not (cfg.bw_url and cfg.bw_username and cfg.password()):
            raise AgentError("PERISCOPE_AGENT_BW_URL, _BW_USERNAME and _BW_PASSWORD(_FILE) are required")
        self.url = json.loads(f["console"].read_text())["url"]
        self.transport, self.probe_fn = transport, probe_fn
        self.poll, self.probe_every = 30, 900
        self.next_probe = 0.0
        self.version_checked: datetime | None = None
        self.version: str | None = None
        self.services: list = []
        self.bw = BWClient(cfg.bw_url, (cfg.bw_username, cfg.password()), timeout=cfg.http_timeout,
                           verify=cfg.bw_verify_tls, transport=bw_transport)
        self.console = self._console()

    def _console(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(base_url=self.url, verify=client_context(self.dir), timeout=30,
                                 transport=self.transport)

    def _want_version(self) -> bool:
        now = datetime.now(UTC).replace(tzinfo=None)
        if self.version and self.version_checked and now - self.version_checked <= collector.VERSION_RECHECK:
            return False
        self.version_checked = now
        return True

    async def collect(self) -> dict:
        result = await collector.gather(self.bw, self._want_version)
        if result.version:
            self.version = result.version
        if "services" in result.results:
            self.services = result.results["services"]
        probes = None
        if time.monotonic() >= self.next_probe and self.services:
            from periscope.tlsprobe import probe
            target = self.cfg.probe_host or httpx.URL(self.cfg.bw_url).host
            probes = await collector.probe_domains(target, self.cfg.tls_port, collector.service_domains(self.services),
                                                   self.cfg.http_timeout, self.probe_fn or probe,
                                                   asyncio.Semaphore(self.cfg.max_parallel_probes))
            self.next_probe = time.monotonic() + self.probe_every
        return build_report(result, probes)

    async def send(self, report: dict) -> dict:
        r = await self.console.post("/v1/report", json=report)
        if r.status_code in (401, 403):
            raise AgentError(f"console refused this agent (HTTP {r.status_code}): {_error_of(r)}; "
                             "re-enroll it from the console if it was revoked")
        if r.status_code != 200:
            raise AgentError(f"console answered HTTP {r.status_code}: {_error_of(r)}")
        body = r.json()
        self.poll = max(5, int(body.get("poll_interval") or self.poll))
        self.probe_every = max(60, int(body.get("probe_interval") or self.probe_every))
        write_health(self.dir, self.poll)
        return body

    async def renew(self) -> None:
        """New key + certificate; the console keeps accepting the old one until the new one is used."""
        key, csr = pki.new_key_and_csr()
        r = await self.console.post("/v1/renew", json={"csr": csr.decode()})
        if r.status_code != 200:
            raise AgentError(f"certificate renewal refused (HTTP {r.status_code}): {_error_of(r)}")
        f = _files(self.dir)
        _write(f["key"], key, private=True)
        _write(f["cert"], r.json()["certificate"].encode())
        await self.console.aclose()
        self.console = self._console()
        log.info("agent certificate renewed (valid until %s)", cert_not_after(self.dir).isoformat())

    async def cycle(self) -> None:
        body = await self.send(await self.collect())
        if body.get("renew") or cert_not_after(self.dir) - datetime.now(UTC).replace(tzinfo=None) < timedelta(days=30):
            try:
                await self.renew()
            except (AgentError, httpx.HTTPError, OSError, ValueError) as e:  # retried next cycle
                log.warning("certificate renewal failed (%s): %s", type(e).__name__, e)

    async def run_forever(self) -> None:
        failures = 0
        log.info("Periscope agent %s reporting to %s", __version__, self.url)
        try:
            while True:
                started = time.monotonic()
                try:
                    await self.cycle()
                    failures = 0
                except (AgentError, httpx.HTTPError, ssl.SSLError, OSError, ValueError) as e:
                    failures += 1
                    log.warning("report failed (%s): %s", type(e).__name__, e)
                delay = self.poll if not failures else min(self.poll * 2 ** min(failures - 1, 4), 300)
                await asyncio.sleep(max(1.0, delay - (time.monotonic() - started)))
        finally:
            await self.bw.aclose()
            await self.console.aclose()
