"""Private certificate authority of the agents (mutual TLS).

The console holds one CA (EC P-256, key encrypted with PERISCOPE_SECRET_KEY in the `settings` table).
It signs:
- the agents' client certificates (from a CSR: the agent's private key never leaves its machine);
- the server certificate of the agent listener, regenerated at each start for the host of
  PERISCOPE_AGENT_PUBLIC_URL.
Agents trust only this CA (pinned by its SHA-256 fingerprint at enrollment), the listener accepts only
client certificates it signed, and the console maps each certificate to one instance by fingerprint
(revocation = forgetting the fingerprint, effective immediately).
"""
import hashlib
import ipaddress
import secrets
from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from periscope.clock import utcnow
from periscope.crypto import decrypt, encrypt
from periscope.i18n import N_, LocalizedError
from periscope.models import Setting

CA_CERT = "agent_ca_cert"
CA_KEY = "agent_ca_key_enc"
CA_DAYS = 3650
AGENT_CERT_DAYS = 90
AGENT_RENEW_BEFORE = timedelta(days=30)  # the agent renews its certificate when less remains
SERVER_CERT_DAYS = 397
MAX_CSR_BYTES = 8192


def fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def _naive(dt):
    return dt.replace(tzinfo=None)


def _get(db, key: str) -> str | None:
    row = db.get(Setting, key)
    return row.value if row else None


def ensure_ca(db) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """Load the CA, creating it on first use (the caller commits)."""
    cert_pem, key_enc = _get(db, CA_CERT), _get(db, CA_KEY)
    if cert_pem and key_enc:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        key = serialization.load_pem_private_key(decrypt(key_enc).encode(), password=None)
        return cert, key
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Periscope"),
                      x509.NameAttribute(NameOID.COMMON_NAME, f"Periscope agent CA {secrets.token_hex(4)}")])
    now = utcnow()
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=CA_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False, key_agreement=False,
                                         key_cert_sign=True, crl_sign=True, encipher_only=False,
                                         decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
    db.merge(Setting(key=CA_CERT, value=cert.public_bytes(serialization.Encoding.PEM).decode()))
    db.merge(Setting(key=CA_KEY, value=encrypt(key_pem)))
    db.flush()
    return cert, key


def ca_pem(db) -> bytes:
    return ensure_ca(db)[0].public_bytes(serialization.Encoding.PEM)


def ca_fingerprint(db) -> str:
    return fingerprint(ensure_ca(db)[0].public_bytes(serialization.Encoding.DER))


def load_csr(pem: str | bytes) -> x509.CertificateSigningRequest:
    """Parse and check a CSR (valid signature, EC P-256/P-384 or RSA >= 2048 key)."""
    raw = pem.encode() if isinstance(pem, str) else pem
    if not raw or len(raw) > MAX_CSR_BYTES:
        raise LocalizedError(N_("Invalid certificate request"))
    try:
        csr = x509.load_pem_x509_csr(raw)
        ok = csr.is_signature_valid
    except ValueError:
        ok = False
    if not ok:
        raise LocalizedError(N_("Invalid certificate request"))
    pub = csr.public_key()
    if isinstance(pub, ec.EllipticCurvePublicKey):
        ok = isinstance(pub.curve, ec.SECP256R1 | ec.SECP384R1)
    elif isinstance(pub, rsa.RSAPublicKey):
        ok = pub.key_size >= 2048
    else:
        ok = False
    if not ok:
        raise LocalizedError(N_("Invalid certificate request"))
    return csr


def _leaf(db, subject: x509.Name, public_key, days: int, usage, san=None) -> x509.Certificate:
    ca, ca_key = ensure_ca(db)
    now = utcnow()
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca.subject).public_key(public_key)
         .serial_number(x509.random_serial_number())
         .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                      data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                      crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False))
    if san:
        b = b.add_extension(x509.SubjectAlternativeName(san), critical=False)
    return b.sign(ca_key, hashes.SHA256())


def issue_agent_cert(db, csr_pem: str | bytes, instance_id: int) -> tuple[str, str, object]:
    """Sign an agent CSR for one instance: (certificate PEM, fingerprint, not_after naive UTC).
    The subject is chosen by the console, only the public key comes from the CSR."""
    csr = load_csr(csr_pem)
    subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Periscope"),
                         x509.NameAttribute(NameOID.COMMON_NAME, f"periscope-agent-{instance_id}")])
    cert = _leaf(db, subject, csr.public_key(), AGENT_CERT_DAYS, ExtendedKeyUsageOID.CLIENT_AUTH,
                 [x509.UniformResourceIdentifier(f"urn:periscope:agent:{instance_id}")])
    return (cert.public_bytes(serialization.Encoding.PEM).decode(),
            fingerprint(cert.public_bytes(serialization.Encoding.DER)),
            _naive(cert.not_valid_after_utc))


def issue_server_cert(db, host: str) -> tuple[bytes, bytes]:
    """Certificate + key (PEM) of the agent listener, valid for `host` (DNS name or IP)."""
    key = ec.generate_private_key(ec.SECP256R1())
    try:
        san = [x509.IPAddress(ipaddress.ip_address(host))]
    except ValueError:
        san = [x509.DNSName(host)]
    subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Periscope"),
                         x509.NameAttribute(NameOID.COMMON_NAME, host[:64])])
    cert = _leaf(db, subject, key.public_key(), SERVER_CERT_DAYS, ExtendedKeyUsageOID.SERVER_AUTH, san)
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))


def new_key_and_csr() -> tuple[bytes, bytes]:
    """Agent side: a fresh EC P-256 key and its CSR (PEM)."""
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "periscope-agent")]))
           .sign(key, hashes.SHA256()))
    return (key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()),
            csr.public_bytes(serialization.Encoding.PEM))
