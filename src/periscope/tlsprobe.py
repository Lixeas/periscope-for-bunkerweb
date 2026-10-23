import asyncio
import ssl
from dataclasses import dataclass
from datetime import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID


@dataclass
class CertInfo:
    present: bool
    issuer: str = ""
    not_after: datetime | None = None  # naive UTC
    error: str = ""


def _label(name: x509.Name) -> str:
    for oid in (NameOID.ORGANIZATION_NAME, NameOID.COMMON_NAME):
        attrs = name.get_attributes_for_oid(oid)
        if attrs:
            return str(attrs[0].value)
    return ""


async def probe(host: str, port: int, domain: str, timeout: float = 5.0) -> CertInfo:
    """TLS handshake to host:port with SNI=domain; reads the served certificate without validating it."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=domain), timeout)
    except (OSError, ssl.SSLError, ValueError) as e:
        return CertInfo(False, error=f"{type(e).__name__}: {e}")
    try:
        der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001, S110
            pass
    if not der:
        return CertInfo(False, error="no certificate")
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError as e:
        return CertInfo(False, error=f"invalid certificate: {e}")
    return CertInfo(True, _label(cert.issuer), cert.not_valid_after_utc.replace(tzinfo=None))
