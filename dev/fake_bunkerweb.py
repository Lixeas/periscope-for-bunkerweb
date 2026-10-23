"""Faux BunkerWeb pour la démo. Lancer deux instances :

  FAKE_DAYS=15 FAKE_TLS_PORT=9443 uvicorn --app-dir dev fake_bunkerweb:app --port 9001
  FAKE_DAYS=60 FAKE_TLS_PORT=9444 FAKE_EXTRA=1 uvicorn --app-dir dev fake_bunkerweb:app --port 9002

Dans Periscope : URL http://127.0.0.1:9001 (token quelconque), hôte sonde vide, port TLS 9443.

Authentification (optionnelle) : POST /auth en HTTP Basic (utilisateur `periscope`, mot de passe FAKE_PASSWORD,
défaut `secret`) renvoie {"status":"success","token":...}. Avec FAKE_AUTH=1, tous les endpoints de données
exigent un Bearer valide (401 sinon) ; le jeton expire après FAKE_TTL secondes (défaut 3600). /ping reste public.
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


app = FastAPI(lifespan=lifespan)


def require_token(request: Request) -> None:
    if not AUTH:
        return
    scheme, _, tok = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or TOKENS.get(tok, 0) <= time.monotonic():
        raise HTTPException(401, "invalid or expired token")


@app.post("/auth")
def auth(request: Request):
    scheme, _, b64 = request.headers.get("authorization", "").partition(" ")
    try:
        user, _, pwd = base64.b64decode(b64).decode().partition(":")
    except ValueError:
        user, pwd = "", ""
    ok = scheme.lower() == "basic" and hmac.compare_digest(user, "periscope") and hmac.compare_digest(pwd, PASSWORD)
    if not ok:
        raise HTTPException(401, "bad credentials")
    token = secrets.token_urlsafe(24)
    TOKENS[token] = time.monotonic() + TTL
    return {"status": "success", "token": token}


@app.get("/ping")
def ping():
    return {"status": "success", "message": "pong", "version": "1.6.0-fake"}


@app.get("/services", dependencies=[Depends(require_token)])
def services():
    return {"status": "success", "services": [{"id": s, "is_draft": False} for s in SERVICES]}


@app.get("/services/{service}", dependencies=[Depends(require_token)])
def service(service: str, full: bool = False):
    return {f"{service}_SECURITY_MODE": SERVICES.get(service, "detect")}


@app.get("/bans", dependencies=[Depends(require_token)])
def bans():
    out = [{"ip": "203.0.113.7", "reason": "antibot", "service": "www.example.test", "exp": 3600, "date": 1}]
    if EXTRA:
        out.append({"ip": "198.51.100.9", "reason": "modsecurity", "service": "global", "exp": 600, "date": 2})
    return {"status": "success", "bans": out}


@app.get("/jobs", dependencies=[Depends(require_token)])
def jobs():
    return {"status": "success", "jobs": {
        "certbot-renew": {"plugin": "letsencrypt", "every": "day",
                          "history": [{"success": True, "end_date": "2026-10-22 03:00:00"}]},
        "blacklist-download": {"plugin": "blacklist", "every": "hour",
                               "history": [{"success": not EXTRA, "end_date": "2026-10-22 10:00:00"}]}}}


@app.get("/plugins", dependencies=[Depends(require_token)])
def plugins():
    return {"status": "success", "plugins": [
        {"id": "antibot", "name": "Antibot", "version": "1.9" if EXTRA else "1.8", "type": "core"},
        {"id": "letsencrypt", "name": "Let's Encrypt", "version": "1.8", "type": "core"}]}
