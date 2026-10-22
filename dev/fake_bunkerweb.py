"""Faux BunkerWeb pour la démo. Lancer deux instances :

  FAKE_DAYS=15 FAKE_TLS_PORT=9443 uvicorn --app-dir dev fake_bunkerweb:app --port 9001
  FAKE_DAYS=60 FAKE_TLS_PORT=9444 FAKE_EXTRA=1 uvicorn --app-dir dev fake_bunkerweb:app --port 9002

Dans Mission Control : URL http://127.0.0.1:9001 (token quelconque), hôte sonde vide, port TLS 9443.
"""
import asyncio
import os
import ssl
import tempfile
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import FastAPI

DAYS = int(os.environ.get("FAKE_DAYS", "30"))
TLS_PORT = int(os.environ.get("FAKE_TLS_PORT", "0"))
EXTRA = os.environ.get("FAKE_EXTRA") == "1"

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


@app.get("/ping")
def ping():
    return {"status": "success", "message": "pong", "version": "1.6.0-fake"}


@app.get("/services")
def services():
    return {"status": "success", "services": [{"id": s, "is_draft": False} for s in SERVICES]}


@app.get("/services/{service}")
def service(service: str, full: bool = False):
    return {f"{service}_SECURITY_MODE": SERVICES.get(service, "detect")}


@app.get("/bans")
def bans():
    out = [{"ip": "203.0.113.7", "reason": "antibot", "service": "www.example.test", "exp": 3600, "date": 1}]
    if EXTRA:
        out.append({"ip": "198.51.100.9", "reason": "modsecurity", "service": "global", "exp": 600, "date": 2})
    return {"status": "success", "bans": out}


@app.get("/jobs")
def jobs():
    return {"status": "success", "jobs": {
        "certbot-renew": {"plugin": "letsencrypt", "every": "day",
                          "history": [{"success": True, "end_date": "2026-10-22 03:00:00"}]},
        "blacklist-download": {"plugin": "blacklist", "every": "hour",
                               "history": [{"success": not EXTRA, "end_date": "2026-10-22 10:00:00"}]}}}


@app.get("/plugins")
def plugins():
    return {"status": "success", "plugins": [
        {"id": "antibot", "name": "Antibot", "version": "1.9" if EXTRA else "1.8", "type": "core"},
        {"id": "letsencrypt", "name": "Let's Encrypt", "version": "1.8", "type": "core"}]}
