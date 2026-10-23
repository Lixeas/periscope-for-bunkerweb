"""Faux BunkerWeb pour la démo. Lancer deux instances :

  FAKE_DAYS=15 FAKE_TLS_PORT=9443 uvicorn --app-dir dev fake_bunkerweb:app --port 9001
  FAKE_DAYS=60 FAKE_TLS_PORT=9444 FAKE_EXTRA=1 uvicorn --app-dir dev fake_bunkerweb:app --port 9002

Dans Periscope : URL http://127.0.0.1:9001 (token quelconque), hôte sonde vide, port TLS 9443.

Les réponses reprennent les formes RÉELLES de l'API BunkerWeb v1.6.17, dérivées de la lecture du source
(pas capturées sur une instance vivante) : /ping sans version, /services avec security_mode,
/services/{id}?full=true avec `config`, /bans agrégé par instance nginx (2 instances nginx simulées qui
rapportent le même ban ; `exp` = secondes restantes, 0 = permanent), /jobs en dict indexé par nom avec
plugin_id et history triée par end_date décroissante, /plugins avec les clés supplémentaires.

Authentification (optionnelle) : POST /auth (HTTP Basic, ou champs/JSON `username` + `password` ; utilisateur
`periscope`, mot de passe FAKE_PASSWORD, défaut `secret`) renvoie {"token":...}. Avec FAKE_AUTH=1, tous les
endpoints de données exigent un Bearer valide (401 sinon) ; le jeton expire après FAKE_TTL secondes
(défaut 3600). /ping, /health et /openapi.json restent publics.
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

DAYS = int(os.environ.get("FAKE_DAYS", "30"))
TLS_PORT = int(os.environ.get("FAKE_TLS_PORT", "0"))
EXTRA = os.environ.get("FAKE_EXTRA") == "1"
AUTH = os.environ.get("FAKE_AUTH") == "1"
PASSWORD = os.environ.get("FAKE_PASSWORD", "secret")
TTL = float(os.environ.get("FAKE_TTL", "3600"))
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


app = FastAPI(lifespan=lifespan, openapi_url=None)  # /openapi.json ci-dessous (public, comme le vrai)


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
    token = secrets.token_urlsafe(24)
    TOKENS[token] = time.monotonic() + TTL
    return {"token": token}


@app.get("/openapi.json")
def openapi_doc():
    # Public (hors garde d'auth), comme l'API réelle : la version vit dans info.version.
    return {"openapi": "3.1.0", "info": {"title": "BunkerWeb API", "version": "1.6.17-fake"}, "paths": {}}


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
    """Agrégat par instance nginx ; le même ban remonte une fois par instance (exp légèrement différent)."""
    shared = _ban("203.0.113.7", "antibot", "www.example.test", 3600)
    nginx2 = [{**shared, "exp": 3590}]
    nginx1 = [shared]
    if EXTRA:
        nginx1.append(_ban("198.51.100.9", "crowdsec", "global", 0, kind="crowdsec_lease", scope="global"))
    return {"fake-nginx-1": {"status": "success", "msg": "success", "data": nginx1},
            "fake-nginx-2": {"status": "success", "msg": "success", "data": nginx2}}


@app.get("/jobs", dependencies=[Depends(require_token)])
def jobs():
    def hist(*runs):  # plus récent d'abord (end_date décroissante)
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
