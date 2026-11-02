"""Agent mode: PKI, report validation, the listener's routes, the agent loop, and one real mutual-TLS run."""
import asyncio
import json
import socket
import ssl
from datetime import datetime, timedelta

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from periscope import agent as agent_mod
from periscope import agent_server, collector, i18n, pki
from periscope.agent import (
    Agent,
    AgentError,
    AgentSettings,
    build_report,
    enroll,
    make_bundle,
    parse_bundle,
)
from periscope.agent_server import CERT_EXT, AgentListener, create_agent_app, parse_report
from periscope.clock import utcnow
from periscope.config import get_settings
from periscope.db import session_scope
from periscope.models import AuditLog, CertProbe, Instance, Snapshot
from periscope.tlsprobe import CertInfo
from periscope.web.routes_admin import new_enroll_token
from tests.test_collector import Fake


@pytest.fixture(autouse=True)
def _reset_limiter():
    agent_server.enroll_limiter.__init__(max_events=10, window=600)


def agent_instance(enabled=True) -> tuple[int, str]:
    with session_scope() as s:
        inst = Instance(name="remote", connection="agent", enabled=enabled)
        s.add(inst)
        s.flush()
        return inst.id, new_enroll_token(inst)


def der_of(pem: str) -> bytes:
    return x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)


def with_cert(app, der):
    """What MTLSProtocol does after a verified handshake: the DER goes in a scope extension."""
    async def wrapped(scope, receive, send):
        if scope["type"] == "http":
            scope = {**scope, "extensions": {CERT_EXT: der}}
        await app(scope, receive, send)
    return wrapped


def report(**over):
    base = {"protocol": 1, "agent_version": "0.1.0", "status": "ok", "errors": [], "latency_ms": 3.5,
            "version": "1.6.17", "snapshots": {"services": [{"name": "a.example", "draft": False, "mode": "block"}],
                                               "bans": [{"ip": "1.1.1.1"}]},
            "probes": [{"domain": "a.example", "present": True, "issuer": "R3", "error": "",
                        "not_after": "2030-01-01T00:00:00+00:00"}]}
    return {**base, **over}


# --- PKI -------------------------------------------------------------------------------------------

def test_ca_created_once_key_encrypted_and_agent_cert_bound_to_instance(fresh_db):
    with session_scope() as s:
        fp1 = pki.ca_fingerprint(s)
    with session_scope() as s:
        assert pki.ca_fingerprint(s) == fp1  # persisted, not regenerated
        from periscope.models import Setting
        assert "PRIVATE KEY" not in s.get(Setting, pki.CA_KEY).value
        _, csr = pki.new_key_and_csr()
        pem, fp, not_after = pki.issue_agent_cert(s, csr, 7)
        ca = x509.load_pem_x509_certificate(pki.ca_pem(s))
    cert = x509.load_pem_x509_certificate(pem.encode())
    cert.verify_directly_issued_by(ca)
    assert fp == pki.fingerprint(der_of(pem)) and 89 <= (not_after - utcnow()).days <= 90
    assert "periscope-agent-7" in cert.subject.rfc4514_string()
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]


@pytest.mark.parametrize("csr", [b"", b"garbage", b"x" * 9000])
def test_bad_csr_rejected(fresh_db, csr):
    with session_scope() as s, pytest.raises(ValueError):
        pki.issue_agent_cert(s, csr, 1)


def test_weak_rsa_csr_rejected(fresh_db):
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(65537, 1024)
    csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([]))
           .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
    with session_scope() as s, pytest.raises(ValueError):
        pki.issue_agent_cert(s, csr, 1)


# --- bundle ----------------------------------------------------------------------------------------

def test_bundle_round_trip_and_garbage():
    b = make_bundle("https://c.example:8443/", "tok", "AB" * 32)
    assert parse_bundle(b) == ("https://c.example:8443", "tok", "ab" * 32)
    for bad in ("", "psc1.", "psc1.!!!", "nope", make_bundle("http://plain", "t", "f")):
        with pytest.raises(AgentError):
            parse_bundle(bad)


# --- report validation -----------------------------------------------------------------------------

def test_parse_report_ok():
    rep = parse_report(report())
    assert rep.collected.status == "ok" and rep.collected.version == "1.6.17"
    assert rep.collected.results["bans"] == [{"ip": "1.1.1.1"}]
    assert rep.probes["a.example"].not_after == datetime(2030, 1, 1) and rep.agent_version == "0.1.0"


@pytest.mark.parametrize("over", [
    {"protocol": 2}, {"status": "great"}, {"errors": "x"}, {"errors": [1]}, {"errors": ["x"] * 51},
    {"snapshots": {"evil": []}}, {"snapshots": {"bans": "x"}}, {"snapshots": {"bans": [1]}},
    {"probes": [{"domain": 1}]}, {"probes": [{"domain": "a", "not_after": "yesterday"}]},
    {"latency_ms": -1}, {"latency_ms": float("nan")}, {"latency_ms": True}, {"version": 5},
])
def test_parse_report_rejects_bad_shapes(over):
    with pytest.raises(agent_server.ReportError):
        parse_report(report(**over))


# --- listener routes (certificate injected as after a verified handshake) ----------------------------

def enrolled(client_app=None) -> tuple[int, bytes, TestClient]:
    iid, token = agent_instance()
    _, csr = pki.new_key_and_csr()
    c = TestClient(create_agent_app())
    r = c.post("/v1/enroll", json={"token": token, "csr": csr.decode()})
    assert r.status_code == 200
    return iid, der_of(r.json()["certificate"]), c


def test_enroll_is_single_use_and_audited(fresh_db):
    iid, token = agent_instance()
    c = TestClient(create_agent_app())
    _, csr = pki.new_key_and_csr()
    r = c.post("/v1/enroll", json={"token": token, "csr": csr.decode()})
    body = r.json()
    assert r.status_code == 200 and body["instance"] == "remote" and "BEGIN CERTIFICATE" in body["ca"]
    with session_scope() as s:
        inst = s.get(Instance, iid)
        assert inst.agent_cert_fp == pki.fingerprint(der_of(body["certificate"]))
        assert inst.agent_enroll_hash == "" and inst.agent_cert_not_after is not None
    assert c.post("/v1/enroll", json={"token": token, "csr": csr.decode()}).status_code == 403
    with session_scope() as s:
        assert [e.event for e in s.query(AuditLog)] == ["agent_enrolled", "agent_enroll_failed"]


def test_enroll_rejects_expired_token_bad_csr_and_throttles(fresh_db):
    iid, token = agent_instance()
    c = TestClient(create_agent_app())
    assert c.post("/v1/enroll", json={"token": token, "csr": "garbage"}).status_code == 400
    with session_scope() as s:
        s.get(Instance, iid).agent_enroll_expires = utcnow() - timedelta(seconds=1)
    _, csr = pki.new_key_and_csr()
    assert c.post("/v1/enroll", json={"token": token, "csr": csr.decode()}).status_code == 403
    assert c.post("/v1/enroll", content=b"not json").status_code == 400
    codes = [c.post("/v1/enroll", json={"token": "x", "csr": csr.decode()}).status_code for _ in range(10)]
    assert codes[-1] == 429


def test_report_requires_known_certificate_and_stores(fresh_db):
    iid, der, _ = enrolled()
    assert TestClient(create_agent_app()).post("/v1/report", json=report()).status_code == 401  # no cert
    with session_scope() as s:
        _, csr = pki.new_key_and_csr()
        stranger = der_of(pki.issue_agent_cert(s, csr, 999)[0])  # signed by the CA but unknown
    assert TestClient(with_cert(create_agent_app(), stranger)).post("/v1/report", json=report()).status_code == 403
    c = TestClient(with_cert(create_agent_app(), der))
    r = c.post("/v1/report", json=report())
    assert r.status_code == 200 and r.json() == {"poll_interval": 30, "probe_interval": 900, "renew": False,
                                                  "accepted": True}
    with session_scope() as s:
        inst = s.get(Instance, iid)
        assert (inst.status, inst.version, inst.latency_ms, inst.agent_version) == ("ok", "1.6.17", 3.5, "0.1.0")
        assert s.query(Snapshot).filter_by(instance_id=iid, kind="bans").one().payload == [{"ip": "1.1.1.1"}]
        assert [(p.domain, p.issuer) for p in s.query(CertProbe)] == [("a.example", "R3")]
    assert c.post("/v1/report", json=report()).status_code == 429  # too early
    with session_scope() as s:
        s.get(Instance, iid).last_attempt_at = utcnow() - timedelta(minutes=1)
    r = c.post("/v1/report", json=report(status="down", snapshots={}, probes=None,
                                         errors=[i18n.pack("{kind}: {detail}", kind="network", detail="x")]))
    assert r.status_code == 200
    with session_scope() as s:
        inst = s.get(Instance, iid)
        assert inst.status == "down" and i18n.render("en", inst.last_error) == "network: x"
        assert s.query(Snapshot).filter_by(instance_id=iid, kind="bans").one().payload == [{"ip": "1.1.1.1"}]
        assert s.query(CertProbe).count() == 1  # no probes in this report: kept


def test_report_cannot_touch_another_instance_and_is_size_capped(fresh_db, monkeypatch):
    iid, der, _ = enrolled()
    with session_scope() as s:
        other = Instance(name="other", base_url="http://x:8888", api_username="u")
        s.add(other)
        s.flush()
        oid = other.id
    c = TestClient(with_cert(create_agent_app(), der))
    assert c.post("/v1/report", json={**report(), "instance_id": oid}).status_code == 200
    with session_scope() as s:
        assert s.query(Snapshot).filter_by(instance_id=oid).count() == 0
        s.get(Instance, iid).last_attempt_at = None
    monkeypatch.setattr(get_settings(), "agent_max_report_bytes", 100)
    assert c.post("/v1/report", json=report()).status_code == 400


def test_disabled_instance_report_not_stored_and_revocation(fresh_db):
    iid, der, _ = enrolled()
    with session_scope() as s:
        s.get(Instance, iid).enabled = False
    c = TestClient(with_cert(create_agent_app(), der))
    r = c.post("/v1/report", json=report())
    assert r.status_code == 200 and r.json()["accepted"] is False
    with session_scope() as s:
        assert s.query(Snapshot).count() == 0
        inst = s.get(Instance, iid)
        inst.enabled, inst.agent_cert_fp = True, ""  # what "Revoke the agent" does
    assert c.post("/v1/report", json=report()).status_code == 403


def test_renewal_promotes_new_certificate_at_first_use(fresh_db):
    iid, der, _ = enrolled()
    old = TestClient(with_cert(create_agent_app(), der))
    _, csr = pki.new_key_and_csr()
    r = old.post("/v1/renew", json={"csr": csr.decode()})
    new_der = der_of(r.json()["certificate"])
    with session_scope() as s:
        inst = s.get(Instance, iid)
        assert inst.agent_cert_fp == pki.fingerprint(der) and inst.agent_next_cert_fp == pki.fingerprint(new_der)
    assert old.post("/v1/report", json=report()).json()["renew"] is False  # old still accepted, renewal pending
    with session_scope() as s:
        s.get(Instance, iid).last_attempt_at = None
    assert TestClient(with_cert(create_agent_app(), new_der)).post("/v1/report", json=report()).status_code == 200
    with session_scope() as s:
        inst = s.get(Instance, iid)
        assert inst.agent_cert_fp == pki.fingerprint(new_der) and inst.agent_next_cert_fp == ""
        s.get(Instance, iid).last_attempt_at = None
    assert old.post("/v1/report", json=report()).status_code == 403  # the old one is gone


def test_renew_flag_when_certificate_expires_soon(fresh_db):
    iid, der, _ = enrolled()
    with session_scope() as s:
        s.get(Instance, iid).agent_cert_not_after = utcnow() + timedelta(days=10)
    assert TestClient(with_cert(create_agent_app(), der)).post("/v1/report", json=report()).json()["renew"] is True


# --- silence detection -----------------------------------------------------------------------------

def test_check_agents_states(fresh_db):
    iid, _ = agent_instance()
    now = utcnow()
    collector.check_agents(now)
    with session_scope() as s:
        inst = s.get(Instance, iid)
        assert inst.status == "unknown" and i18n.render("en", inst.last_error) == "Agent not enrolled yet"
        inst.agent_cert_fp = "f" * 64
    collector.check_agents(now)
    with session_scope() as s:
        inst = s.get(Instance, iid)
        assert i18n.render("en", inst.last_error) == "Waiting for the first agent report"
        inst.status, inst.last_attempt_at, inst.last_error = "ok", now - timedelta(seconds=30), ""
    collector.check_agents(now)
    with session_scope() as s:
        assert s.get(Instance, iid).status == "ok"
        s.get(Instance, iid).last_attempt_at = now - timedelta(seconds=200)
    collector.check_agents(now)
    with session_scope() as s:
        inst = s.get(Instance, iid)
        assert inst.status == "down" and "No report from the agent for more than 90 s" == i18n.render("en", inst.last_error)
        assert "Aucun rapport" in i18n.render("fr", inst.last_error)


async def test_collect_all_skips_agent_instances(fresh_db, monkeypatch):
    agent_instance()
    called = []

    async def fake_collect(i, *a, **k):
        called.append(i)

    monkeypatch.setattr(collector, "collect_one", fake_collect)
    await collector.collect_all()
    assert called == []


# --- agent loop (fake BunkerWeb client, console app in-process) ----------------------------------------

def test_build_report_is_accepted_by_parse_report():
    c = collector.Collected("degraded", [i18n.pack("x")], 1.0, "1.6", {"bans": []})
    rep = build_report(c, {"a.example": CertInfo(True, "R3", datetime(2030, 1, 1))})
    parsed = parse_report(json.loads(json.dumps(rep)))
    assert parsed.collected.status == "degraded" and parsed.probes["a.example"].not_after == datetime(2030, 1, 1)


def test_agent_refuses_to_start_unenrolled_or_without_credentials(tmp_path):
    with pytest.raises(AgentError, match="not enrolled"):
        Agent(AgentSettings(dir=tmp_path, bw_url="http://bw", bw_username="u", bw_password="p"))
    for name in ("agent.crt", "agent.key", "console.json"):
        (tmp_path / name).write_text("{}")
    with pytest.raises(AgentError, match="required"):
        Agent(AgentSettings(dir=tmp_path))


def test_password_file(tmp_path):
    f = tmp_path / "pw"
    f.write_text("from-file\n")
    assert AgentSettings(bw_password_file=f, bw_password="ignored").password() == "from-file"


# --- end to end: real listener, real mutual TLS ----------------------------------------------------

def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def listener(fresh_db, monkeypatch):
    port = free_port()
    monkeypatch.setattr(get_settings(), "agent_public_url", f"https://localhost:{port}")
    srv = AgentListener("127.0.0.1", port)
    task = asyncio.create_task(srv.serve())
    for _ in range(200):
        if srv.server is not None and srv.server.started:
            break
        await asyncio.sleep(0.02)
    assert srv.server.started
    yield f"https://localhost:{port}"
    srv.stop()
    await asyncio.wait_for(task, 5)


async def test_end_to_end_mutual_tls(listener, tmp_path):
    url = listener
    iid, token = agent_instance()
    with session_scope() as s:
        fp = pki.ca_fingerprint(s)
    # a bundle with the wrong CA fingerprint is refused before anything is sent
    with pytest.raises(AgentError, match="fingerprint mismatch"):
        await enroll(make_bundle(url, token, "0" * 64), tmp_path / "bad")
    assert await enroll(make_bundle(url, token, fp), tmp_path) == "remote"
    assert oct((tmp_path / "agent.key").stat().st_mode & 0o777) == "0o600"

    # without a client certificate: TLS is fine (CERT_OPTIONAL) but the report route refuses
    anon = ssl.create_default_context(cafile=str(tmp_path / "ca.crt"))
    async with httpx.AsyncClient(base_url=url, verify=anon) as c:
        assert (await c.post("/v1/report", json=report())).status_code == 401

    # a certificate from another CA is rejected by the TLS handshake itself
    rogue = tmp_path / "rogue"
    rogue.mkdir()
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "rogue")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(utcnow() - timedelta(days=1))
            .not_valid_after(utcnow() + timedelta(days=1)).sign(key, hashes.SHA256()))
    (rogue / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (rogue / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                    serialization.NoEncryption()))
    ctx = ssl.create_default_context(cafile=str(tmp_path / "ca.crt"))
    ctx.load_cert_chain(str(rogue / "c.pem"), str(rogue / "k.pem"))
    with pytest.raises((httpx.HTTPError, ssl.SSLError, OSError)):
        async with httpx.AsyncClient(base_url=url, verify=ctx) as c:
            await c.post("/v1/report", json=report())

    # the agent's loop: collect (fake BunkerWeb) -> report over mTLS -> stored on the console
    probed = []

    async def fake_probe(host, port, domain, timeout):
        probed.append((host, port, domain))
        return CertInfo(True, "Let's Encrypt", datetime(2031, 1, 1))

    cfg = AgentSettings(dir=tmp_path, bw_url="http://10.1.2.3:8888", bw_username="periscope", bw_password="pw")
    a = Agent(cfg, probe_fn=fake_probe)
    await a.bw.aclose()
    a.bw = Fake()
    await a.cycle()
    await a.console.aclose()
    assert probed == [("10.1.2.3", 443, "a.example")]
    with session_scope() as s:
        inst = s.get(Instance, iid)
        assert (inst.status, inst.version, inst.agent_ip) == ("ok", "1.6.0", "127.0.0.1")
        assert s.query(Snapshot).filter_by(instance_id=iid, kind="services").count() == 1
        assert [(p.domain, p.issuer) for p in s.query(CertProbe)] == [("a.example", "Let's Encrypt")]

    # renewal over mTLS, then the new certificate is used
    with session_scope() as s:
        s.get(Instance, iid).last_attempt_at = None
    a = Agent(cfg, probe_fn=fake_probe)
    await a.bw.aclose()
    a.bw = Fake()
    old_fp = pki.fingerprint(der_of((tmp_path / "agent.crt").read_text()))
    await a.renew()
    await a.send(await a.collect())
    await a.console.aclose()
    with session_scope() as s:
        inst = s.get(Instance, iid)
        assert inst.agent_cert_fp != old_fp and inst.agent_cert_fp == pki.fingerprint(
            der_of((tmp_path / "agent.crt").read_text()))

    # revoked: the console refuses the agent
    with session_scope() as s:
        inst = s.get(Instance, iid)
        inst.agent_cert_fp, inst.last_attempt_at = "", None
    a = Agent(cfg)
    a.bw = Fake()
    with pytest.raises(AgentError, match="refused this agent"):
        await a.send(await a.collect())
    await a.console.aclose()


def test_agent_module_never_needs_the_console_secret(monkeypatch, tmp_path):
    """The agent runs without PERISCOPE_SECRET_KEY (it holds no console secret)."""
    assert "secret_key" not in AgentSettings.model_fields
    key, csr = agent_mod.pki.new_key_and_csr()
    assert b"PRIVATE KEY" in key and b"CERTIFICATE REQUEST" in csr
