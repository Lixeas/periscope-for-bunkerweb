import asyncio
import ssl
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from mc.tlsprobe import probe


def make_cert(tmp_path, org: str, days: int):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                      x509.NameAttribute(NameOID.COMMON_NAME, "t.example")])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=days))
            .sign(key, hashes.SHA256()))
    cf, kf = tmp_path / "c.pem", tmp_path / "k.pem"
    cf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kf.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    return cf, kf


async def serve(cf, kf):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cf, kf)

    async def handle(reader, writer):
        writer.close()

    srv = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ctx)
    return srv, srv.sockets[0].getsockname()[1]


async def test_probe_reads_issuer_and_expiry(tmp_path):
    srv, port = await serve(*make_cert(tmp_path, "Let's Encrypt", 30))
    async with srv:
        info = await probe("127.0.0.1", port, "t.example")
    assert info.present and info.issuer == "Let's Encrypt"
    days = (info.not_after - datetime.now(UTC).replace(tzinfo=None)).days
    assert 28 <= days <= 30
    assert info.not_after.tzinfo is None


async def test_probe_closed_port_reports_error(tmp_path):
    srv, port = await serve(*make_cert(tmp_path, "X", 5))
    srv.close()
    await srv.wait_closed()
    info = await probe("127.0.0.1", port, "t.example", timeout=2)
    assert not info.present and info.error


async def test_probe_invalid_der_reports_error(monkeypatch):
    class SSLObj:
        def getpeercert(self, binary_form=False):
            return b"not a certificate"

    class Writer:
        def get_extra_info(self, name):
            return SSLObj()

        def close(self):
            pass

        async def wait_closed(self):
            pass

    async def fake_open(*a, **k):
        return None, Writer()

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    info = await probe("127.0.0.1", 1, "t.example")
    assert not info.present and "invalid certificate" in info.error
