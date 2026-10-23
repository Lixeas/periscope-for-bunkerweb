"""Fake BunkerWeb for the demo. Start two instances:

  FAKE_DAYS=15 FAKE_TLS_PORT=9443 uvicorn --app-dir dev fake_bunkerweb:app --port 9001
  FAKE_DAYS=60 FAKE_TLS_PORT=9444 FAKE_EXTRA=1 uvicorn --app-dir dev fake_bunkerweb:app --port 9002

In Periscope: URL http://127.0.0.1:9001 (any token), empty probe host, TLS port 9443.

The responses reproduce the REAL shapes of the BunkerWeb v1.6.17 API, derived from reading the source
(not captured from a live instance): /ping without version, /services with security_mode,
/services/{id}?full=true with `config`, /bans aggregated per nginx instance (2 simulated nginx instances that
report the same ban; `exp` = remaining seconds, 0 = permanent), /jobs as a dict indexed by name with
plugin_id and history sorted by descending end_date, /plugins with the extra keys, /instances
with the scheduler's nodes (2 nodes; with FAKE_EXTRA=1 the second is `down`, to demonstrate the degraded state).

Authentication (optional): POST /auth (HTTP Basic, or `username` + `password` fields/JSON; user
`periscope`, password FAKE_PASSWORD, default `secret`) returns {"token":...}. With FAKE_AUTH=1, all
data endpoints require a valid Bearer (401 otherwise); the token expires after FAKE_TTL seconds
(default 3600). /ping and /health stay public. The returned token imitates a Biscuit token: a protobuf message
(Biscuit{authority=2: SignedBlock{block=1: Block{symbols=1}}}) in URL-safe base64 whose symbols are
the user, 127.0.0.1, localhost:PORT, the fake version 1.6.17-fake, api_user and a random identifier.
/openapi.json returns HTTP 500 {"status":"error","message":"internal error"}, like the real 1.6.17 instance
observed, except with FAKE_OPENAPI=1 (public document with info.version): the version is then read from the token.
  FAKE_AUTH=1 FAKE_TTL=8 uvicorn --app-dir dev fake_bunkerweb:app --port 9001
"""
import asyncio
import base64
import hmac
import os
import secrets
import ssl
import tempfile
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

DAYS = int(os.environ.get("FAKE_DAYS", "30"))
TLS_PORT = int(os.environ.get("FAKE_TLS_PORT", "0"))
EXTRA = os.environ.get("FAKE_EXTRA") == "1"
AUTH = os.environ.get("FAKE_AUTH") == "1"
PASSWORD = os.environ.get("FAKE_PASSWORD", "secret")
TTL = float(os.environ.get("FAKE_TTL", "3600"))
OPENAPI = os.environ.get("FAKE_OPENAPI") == "1"
VERSION = "1.6.17-fake"
TOKENS: dict[str, float] = {}  # jeton -> expiration (time.monotonic)

SERVICES = {"www.example.test": "block", "api.example.test": "detect"}
if EXTRA:
    SERVICES["blog.example.test"] = "block"


def _write_cert(directory: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Let's Encrypt"),
                      x509.NameAttribute(NameOID.COMMON_NAME, "R11")])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=DAYS)).sign(key, hashes.SHA256()))
    cf, kf = directory / "cert.pem", directory / "key.pem"
    cf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kf.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    return cf, kf


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _ld(num: int, data: bytes) -> bytes:
    return _varint(num << 3 | 2) + _varint(len(data)) + data


def _biscuit_like(user: str, token_id: str, port: str) -> str:
    symbols = [user, "127.0.0.1", f"localhost:{port}", VERSION, "api_user", token_id]
    block = b"".join(_ld(1, x.encode()) for x in symbols)
    return base64.urlsafe_b64encode(_ld(2, _ld(1, block) + _ld(2, b"\0" * 64))).decode().rstrip("=")


@asynccontextmanager
async def lifespan(_: FastAPI):
    server = None
    if TLS_PORT:
        cf, kf = _write_cert(Path(tempfile.mkdtemp()))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cf, kf)

        async def handle(_r, w):
            w.close()

        server = await asyncio.start_server(handle, "127.0.0.1", TLS_PORT, ssl=ctx)
    yield
    if server:
        server.close()


app = FastAPI(lifespan=lifespan, openapi_url=None)  # /openapi.json below (public, like the real one)


def require_token(request: Request) -> None:
    if not AUTH:
        return
    scheme, _, tok = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or TOKENS.get(tok, 0) <= time.monotonic():
        raise HTTPException(401, "invalid or expired token")


@app.post("/auth")
async def auth(request: Request):
    scheme, _, b64 = request.headers.get("authorization", "").partition(" ")
    user, pwd = "", ""
    if scheme.lower() == "basic":
        try:
            user, _, pwd = base64.b64decode(b64).decode().partition(":")
        except ValueError:
            pass
    else:
        try:
            body = await request.json()
        except ValueError:
            body = (await request.form()) if "form" in request.headers.get("content-type", "") else {}
        if isinstance(body, dict) or hasattr(body, "get"):
            user, pwd = str(body.get("username") or ""), str(body.get("password") or "")
    if not (hmac.compare_digest(user, "periscope") and hmac.compare_digest(pwd, PASSWORD)):
        raise HTTPException(401, "Invalid credentials")
    token = _biscuit_like(user, secrets.token_hex(8), str(request.url.port or 80))
    TOKENS[token] = time.monotonic() + TTL
    return {"token": token}


@app.get("/openapi.json")
def openapi_doc():
    # Public (outside the auth guard). 500 by default like the real 1.6.17 instance; FAKE_OPENAPI=1: valid document.
    if not OPENAPI:
        return JSONResponse({"status": "error", "message": "internal error"}, status_code=500)
    return {"openapi": "3.1.0", "info": {"title": "BunkerWeb API", "version": VERSION}, "paths": {}}


@app.get("/ping")
def ping():
    return {"status": "ok", "message": "pong"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/services", dependencies=[Depends(require_token)])
def services():
    return {"status": "success", "services": [
        {"id": s, "method": "ui", "is_draft": False, "creation_date": "2026-01-01T00:00:00+00:00",
         "last_update": "2026-01-02T00:00:00+00:00", "template": None, "security_mode": m}
        for s, m in SERVICES.items()]}


@app.get("/services/{service}", dependencies=[Depends(require_token)])
def service(service: str, full: bool = False):
    return {"status": "success", "service": service, "config": {
        "SECURITY_MODE": {"value": SERVICES.get(service, "detect"), "global": False, "method": "ui",
                          "default": "detect", "template": None}}}


def _ban(ip, reason, service, exp, kind="ban", scope="service", country="FR"):
    return {"ip": ip, "reason": reason, "service": service, "date": int(time.time()) - 120, "country": country,
            "ban_scope": scope, "exp": exp, "permanent": exp == 0, "kind": kind, "reason_data": {}}


@app.get("/bans", dependencies=[Depends(require_token)])
def bans():
    """Aggregate per nginx instance; the same ban is reported once per instance (slightly different exp)."""
    shared = _ban("203.0.113.7", "antibot", "www.example.test", 3600)
    nginx2 = [{**shared, "exp": 3590}]
    nginx1 = [shared]
    if EXTRA:
        nginx1.append(_ban("198.51.100.9", "crowdsec", "global", 0, kind="crowdsec_lease", scope="global"))
    return {"fake-nginx-1": {"status": "success", "msg": "success", "data": nginx1},
            "fake-nginx-2": {"status": "success", "msg": "success", "data": nginx2}}


@app.get("/jobs", dependencies=[Depends(require_token)])
def jobs():
    def hist(*runs):  # most recent first (descending end_date)
        return [{"start_date": e, "end_date": e, "success": ok} for e, ok in runs]
    return {"status": "success", "jobs": {
        "certbot-renew": {"plugin_id": "letsencrypt", "every": "day", "reload": True, "async": False,
                          "history": hist(("2026-10-22T03:00:05+00:00", True), ("2026-10-21T03:00:05+00:00", True)),
                          "cache": []},
        "blacklist-download": {"plugin_id": "blacklist", "every": "hour", "reload": True, "async": True,
                               "history": hist(("2026-10-22T10:00:05+00:00", not EXTRA),
                                               ("2026-10-22T09:00:05+00:00", True)),
                               "cache": []}}}


@app.get("/plugins", dependencies=[Depends(require_token)])
def plugins():
    return {"status": "success", "plugins": [
        {"id": "antibot", "stream": "partial", "name": "Antibot", "description": "Antibot", "version": "1.9" if EXTRA else "1.8",
         "type": "core", "method": "manual", "page": False, "settings": {}, "checksum": "a"},
        {"id": "letsencrypt", "stream": "no", "name": "Let's Encrypt", "description": "LE", "version": "1.8",
         "type": "core", "method": "manual", "page": True, "settings": {}, "checksum": "b"}]}


@app.get("/instances", dependencies=[Depends(require_token)])
def instances():
    """Nginx nodes managed by this scheduler (real shape); the 2nd is `down` with FAKE_EXTRA=1."""
    seen = datetime.now(UTC) - timedelta(seconds=5)

    def node(host, name, status, last_seen):
        return {"hostname": host, "name": name, "port": 5000, "listen_https": False, "https_port": 5443,
                "server_name": "bwapi", "type": "static", "status": status, "method": "scheduler",
                "creation_date": "2026-01-01T00:00:00+00:00",
                "last_seen": last_seen.isoformat() if last_seen else None}
    return {"status": "success", "instances": [
        node("bunkerweb", "local nginx", "up", seen),
        node("bw-worker-vm2", "worker vm2", "down" if EXTRA else "up",
             seen - timedelta(minutes=10) if EXTRA else seen)]}
