import re

import pytest

from periscope import collector
from periscope.agent import parse_bundle
from periscope.agent_server import enroll_token_hash
from periscope.bw_client import BWError
from periscope.config import get_settings
from periscope.crypto import decrypt
from periscope.db import session_scope
from periscope.models import AuditLog, CertProbe, Instance, Snapshot, Tag
from periscope.web import routes_admin
from tests.helpers import login_as, make_client

FORM = {"name": "bwu", "base_url": "http://10.0.0.5:8888/", "connection": "direct", "api_username": "periscope",
        "api_password": "pw-secret", "tls_port": "443", "verify_tls": "on"}
AGENT_URL = "https://agents.example.test:8443"


@pytest.fixture
def client(fresh_db):
    with make_client() as c:
        yield c


@pytest.fixture
def admin(client, monkeypatch):
    calls = []
    state = {"error": None, "checks": []}

    async def check(base_url, verify_tls, credentials):
        state["checks"].append({"url": base_url, "credentials": credentials})
        return state["error"]

    async def refresh(inst_id):
        calls.append(inst_id)

    monkeypatch.setattr(routes_admin, "check_instance", check)
    monkeypatch.setattr(collector, "refresh_instance", refresh)
    csrf = login_as(client)
    return csrf, calls, state


@pytest.fixture
def agents_on(monkeypatch):
    monkeypatch.setattr(get_settings(), "agent_public_url", AGENT_URL)


def post(client, csrf, path="/admin/instances", **data):
    return client.post(path, data={"csrf": csrf, **data}, follow_redirects=False)


def only_instance():
    with session_scope() as s:
        return s.query(Instance).one().id


# --- direct mode ---------------------------------------------------------------------------------

def test_add_direct_encrypts_password_tests_with_credentials_and_refreshes(client, admin):
    csrf, calls, state = admin
    r = post(client, csrf, **FORM)
    assert r.status_code == 303 and r.headers["location"] == "/admin/instances?m=added"
    assert state["checks"] == [{"url": "http://10.0.0.5:8888", "credentials": ("periscope", "pw-secret")}]
    with session_scope() as s:
        i = s.query(Instance).one()
        assert (i.connection, i.base_url, i.api_username, i.verify_tls) == ("direct", "http://10.0.0.5:8888", "periscope", True)
        assert i.api_password_enc != "pw-secret" and decrypt(i.api_password_enc) == "pw-secret"
        assert [e.event for e in s.query(AuditLog)][-1] == "instance_added"
        assert calls == [i.id]
    page = client.get("/admin/instances").text
    assert "pw-secret" not in page and "API user" in page and "Direct API" in page


def test_direct_requires_username_and_password(client, admin):
    csrf, _, _ = admin
    for override in ({"api_username": ""}, {"api_password": ""}):
        r = client.post("/admin/instances", data={"csrf": csrf, **FORM, **override})
        assert r.status_code == 400 and "required" in r.text
    r = client.post("/admin/instances", data={"csrf": csrf, **FORM, "connection": "token"})
    assert r.status_code == 400 and "Invalid connection mode" in r.text
    with session_scope() as s:
        assert s.query(Instance).count() == 0


def test_connection_failure_blocks_unless_forced(client, admin):
    csrf, _calls, state = admin
    state["error"] = BWError("network", "timeout on {path}", path="/ping")
    r = client.post("/admin/instances", data={"csrf": csrf, **FORM})
    assert r.status_code == 400 and "Instance unreachable" in r.text
    with session_scope() as s:
        assert s.query(Instance).count() == 0
    assert post(client, csrf, force="on", **FORM).status_code == 303
    with session_scope() as s:
        assert s.query(Instance).count() == 1


def test_wrong_password_reports_auth_message(client, admin):
    csrf, _, state = admin
    state["error"] = BWError("auth", "HTTP {status} on {path}", status=401, path="/auth")
    r = client.post("/admin/instances", data={"csrf": csrf, **FORM})
    assert r.status_code == 400 and "Authentication refused" in r.text and "HTTP 401 on /auth" in r.text
    assert "pw-secret" not in r.text


@pytest.mark.parametrize("override,fragment", [
    ({"base_url": "ftp://x"}, "Invalid URL"),
    ({"base_url": "http://user:pw@x:8888"}, "Invalid URL"),
    ({"base_url": "http://x:99999"}, "Invalid URL"),
    ({"name": ""}, "Invalid name"),
    ({"tls_port": "70000"}, "Invalid TLS port"),
    ({"tags": "ok, bad;tag"}, "Invalid tag"),
    ({"tags": ",".join(f"t{i}" for i in range(11))}, "At most 10 tags"),
])
def test_validation_errors(client, admin, override, fragment):
    csrf, _, _ = admin
    r = client.post("/admin/instances", data={"csrf": csrf, **FORM, **override})
    assert r.status_code == 400 and fragment in r.text
    with session_scope() as s:
        assert s.query(Instance).count() == 0


def test_duplicate_name_rejected(client, admin):
    csrf, _, _ = admin
    post(client, csrf, **FORM)
    r = client.post("/admin/instances", data={"csrf": csrf, **FORM})
    assert r.status_code == 400 and "already exists" in r.text


def test_edit_blank_password_keeps_and_new_replaces(client, admin):
    csrf, _, _ = admin
    post(client, csrf, **FORM)
    iid = only_instance()
    data = {"name": "bwu-renamed", "base_url": "http://10.0.0.5:8888", "api_username": "periscope",
            "api_password": "", "tls_port": "8443", "probe_host": "10.0.0.7", "enabled": "on"}
    assert post(client, csrf, f"/admin/instances/{iid}", **data).status_code == 303
    with session_scope() as s:
        i = s.get(Instance, iid)
        assert (i.name, i.tls_port, i.probe_host, i.verify_tls) == ("bwu-renamed", 8443, "10.0.0.7", False)
        assert decrypt(i.api_password_enc) == "pw-secret"
    post(client, csrf, f"/admin/instances/{iid}", **{**data, "api_password": "new-pw"})
    with session_scope() as s:
        assert decrypt(s.get(Instance, iid).api_password_enc) == "new-pw"
    page = client.get(f"/admin/instances/{iid}").text
    assert "new-pw" not in page and 'value="periscope"' in page
    post(client, csrf, f"/admin/instances/{iid}", **{k: v for k, v in data.items() if k != "enabled"})
    with session_scope() as s:
        assert s.get(Instance, iid).enabled is False


def test_edit_url_or_username_change_requires_password(client, admin):
    csrf, _, _ = admin
    post(client, csrf, **FORM)
    iid = only_instance()
    base = {"name": "bwu", "base_url": "http://10.0.0.5:8888", "api_username": "periscope",
            "api_password": "", "tls_port": "443", "enabled": "on"}
    for override in ({"base_url": "http://evil:8888"}, {"api_username": "other"}):
        r = client.post(f"/admin/instances/{iid}", data={"csrf": csrf, **base, **override})
        assert r.status_code == 400 and "re-entering the API password" in r.text
    with session_scope() as s:
        assert s.get(Instance, iid).base_url == "http://10.0.0.5:8888"
    r = post(client, csrf, f"/admin/instances/{iid}", **{**base, "base_url": "http://ok:8888", "api_password": "x"})
    assert r.status_code == 303


def test_instance_migrated_from_token_needs_user_and_password(client, admin):
    """What migration 0004 leaves for a former static-token instance: disabled, no API user."""
    csrf, _, _ = admin
    with session_scope() as s:
        s.add(Instance(name="old", base_url="http://10.0.0.9:8888", enabled=False, last_error='{"m":"x"}'))
    iid = only_instance()
    base = {"name": "old", "base_url": "http://10.0.0.9:8888", "tls_port": "443", "enabled": "on"}
    r = client.post(f"/admin/instances/{iid}", data={"csrf": csrf, **base})
    assert r.status_code == 400 and "API username required" in r.text
    r = client.post(f"/admin/instances/{iid}", data={"csrf": csrf, **base, "api_username": "periscope"})
    assert r.status_code == 400 and "re-entering the API password" in r.text
    assert post(client, csrf, f"/admin/instances/{iid}", **base, api_username="periscope", api_password="pw").status_code == 303
    with session_scope() as s:
        i = s.get(Instance, iid)
        assert i.enabled and i.last_error == "" and decrypt(i.api_password_enc) == "pw"


def test_delete_cascades(client, admin):
    csrf, _, _ = admin
    post(client, csrf, **FORM, tags="acme")
    with session_scope() as s:
        i = s.query(Instance).one()
        i.snapshots.append(Snapshot(kind="bans", payload=[]))
        i.probes.append(CertProbe(domain="a.example"))
        iid = i.id
    assert post(client, csrf, f"/admin/instances/{iid}/delete").status_code == 303
    with session_scope() as s:
        assert (s.query(Instance).count(), s.query(Snapshot).count(), s.query(CertProbe).count()) == (0, 0, 0)
        assert s.query(Tag).count() == 0  # unused tags are dropped


def test_reader_forbidden_and_csrf_required(client, admin):
    assert client.post("/admin/instances", data=FORM).status_code == 403  # without CSRF
    with make_client() as c2:
        login_as(c2, "bob", "reader")
        assert c2.get("/admin/instances").status_code == 403
        assert c2.post("/admin/instances/1/agent-token", data={}).status_code == 403


def test_check_instance_exercises_auth():
    import asyncio

    import respx
    from httpx import Response
    with respx.mock:
        auth = respx.post("http://bw:8888/auth").mock(return_value=Response(401))
        respx.get("http://bw:8888/ping").respond(json={})
        err = asyncio.run(routes_admin.check_instance("http://bw:8888", True, ("periscope", "bad")))
    assert auth.called and err.kind == "auth" and "bad" not in str(err)


# --- tags ------------------------------------------------------------------------------------------

def test_tags_created_reused_case_insensitively_and_pruned(client, admin):
    csrf, _, _ = admin
    post(client, csrf, **FORM, tags=" Acme ,  prod  ,acme")
    post(client, csrf, **{**FORM, "name": "bw2"}, tags="ACME")
    with session_scope() as s:
        assert sorted(t.name for t in s.query(Tag)) == ["Acme", "prod"]
        a, b = (s.query(Instance).filter_by(name=n).one() for n in ("bwu", "bw2"))
        assert [t.name for t in a.tags] == ["Acme", "prod"] and [t.name for t in b.tags] == ["Acme"]
        aid = a.id
    data = {"name": "bwu", "base_url": "http://10.0.0.5:8888", "api_username": "periscope", "tls_port": "443",
            "enabled": "on", "tags": "other"}
    assert post(client, csrf, f"/admin/instances/{aid}", **data).status_code == 303
    with session_scope() as s:
        assert sorted(t.name for t in s.query(Tag)) == ["Acme", "other"]  # "prod" no longer used
    page = client.get("/admin/instances?tag=other").text
    assert ">bwu<" in page and ">bw2<" not in page
    assert 'id="tag-scope"' in page and '<option value="other" selected>' in page


# --- agent mode ------------------------------------------------------------------------------------

def add_agent(client, csrf, **extra):
    return client.post("/admin/instances", data={"csrf": csrf, "name": "remote", "connection": "agent", **extra})


def bundle_of(html: str) -> str:
    return re.search(r'<code class="bundle mb-2" id="bundle">([^<]+)</code>', html).group(1)


def test_agent_mode_needs_public_url(client, admin):
    csrf, _, _ = admin
    r = add_agent(client, csrf)
    assert r.status_code == 400 and "PERISCOPE_AGENT_PUBLIC_URL" in r.text
    assert "disabled" in client.get("/admin/instances").text


def test_add_agent_shows_bundle_once_and_stores_only_hash(client, admin, agents_on):
    csrf, calls, state = admin
    r = add_agent(client, csrf, tags="acme", base_url="ignored", api_password="ignored")
    assert r.status_code == 200 and "shown only once" in r.text
    url, token, fp = parse_bundle(bundle_of(r.text))
    assert url == AGENT_URL and len(fp) == 64 and fp in r.text
    with session_scope() as s:
        i = s.query(Instance).one()
        assert (i.connection, i.base_url, i.api_password_enc, i.status) == ("agent", "", "", "unknown")
        assert i.agent_enroll_hash == enroll_token_hash(token) and i.agent_enroll_expires is not None
        assert [t.name for t in i.tags] == ["acme"]
        assert [e.event for e in s.query(AuditLog)][-2:] == ["instance_added", "agent_enroll_token"]
        iid = i.id
    assert state["checks"] == [] and calls == []  # nothing to test or collect from the console
    listing, edit = client.get("/admin/instances").text, client.get(f"/admin/instances/{iid}").text
    assert token not in listing and token not in edit
    assert "Not enrolled" in listing and "Token pending until" in edit
    # a new bundle replaces the token
    r = client.post(f"/admin/instances/{iid}/agent-token", data={"csrf": csrf})
    _, token2, _ = parse_bundle(bundle_of(r.text))
    with session_scope() as s:
        assert token2 != token and s.get(Instance, iid).agent_enroll_hash == enroll_token_hash(token2)


def test_edit_agent_keeps_connection_and_revoke_clears_certificate(client, admin, agents_on):
    csrf, calls, _ = admin
    add_agent(client, csrf)
    iid = only_instance()
    with session_scope() as s:
        s.get(Instance, iid).agent_cert_fp = "ab" * 32
    r = post(client, csrf, f"/admin/instances/{iid}", name="remote2", tags="x", enabled="on",
             base_url="http://evil:8888", api_username="u", api_password="p")
    assert r.status_code == 303 and calls == []
    with session_scope() as s:
        i = s.get(Instance, iid)
        assert (i.name, i.connection, i.base_url, i.api_username, i.api_password_enc) == ("remote2", "agent", "", "", "")
    page = client.get(f"/admin/instances/{iid}").text
    assert "Revoke the agent" in page and "abababababababab" in page
    assert post(client, csrf, f"/admin/instances/{iid}/agent-revoke").headers["location"] == "/admin/instances?m=revoked"
    with session_scope() as s:
        i = s.get(Instance, iid)
        assert (i.agent_cert_fp, i.agent_enroll_hash, i.status) == ("", "", "unknown")
        assert [e.event for e in s.query(AuditLog)][-1] == "agent_revoked"


def test_agent_routes_ignore_direct_instances(client, admin, agents_on):
    csrf, _, _ = admin
    post(client, csrf, **FORM)
    iid = only_instance()
    for action in ("agent-token", "agent-revoke"):
        assert post(client, csrf, f"/admin/instances/{iid}/{action}").headers["location"] == "/admin/instances"
    with session_scope() as s:
        assert s.get(Instance, iid).agent_enroll_hash == ""


# --- alert silence -------------------------------------------------------------------------------

def make_instance(name="bw1") -> int:
    with session_scope() as s:
        inst = Instance(name=name, base_url="http://h:8888")
        s.add(inst)
        s.flush()
        return inst.id


def test_silence_sets_and_clears(client, admin):
    from datetime import timedelta

    from periscope.clock import utcnow
    csrf, *_ = admin
    iid = make_instance()
    r = post(client, csrf, f"/admin/instances/{iid}/silence", hours="4")
    assert r.status_code == 303 and r.headers["location"] == f"/admin/instances/{iid}"
    with session_scope() as s:
        until = s.get(Instance, iid).silenced_until
    assert timedelta(hours=3, minutes=59) < until - utcnow() <= timedelta(hours=4)
    post(client, csrf, f"/admin/instances/{iid}/silence", hours="0")
    with session_scope() as s:
        assert s.get(Instance, iid).silenced_until is None
        events = [(e.event, e.detail) for e in s.query(AuditLog)]
    assert ("instance_silenced", "bw1") in events and ("instance_unsilenced", "bw1") in events


def test_silence_rejects_other_values_and_unknown_instance(client, admin):
    csrf, *_ = admin
    iid = make_instance()
    for bad in ("999", "-1", "abc", ""):
        r = post(client, csrf, f"/admin/instances/{iid}/silence", hours=bad)
        assert r.status_code in (303, 400, 422)
        with session_scope() as s:
            assert s.get(Instance, iid).silenced_until is None
    r = post(client, csrf, "/admin/instances/999/silence", hours="1")
    assert r.status_code == 303 and r.headers["location"] == "/admin/instances"


def test_silence_requires_csrf_and_admin(client, admin):
    iid = make_instance()
    r = client.post(f"/admin/instances/{iid}/silence", data={"hours": "1"}, follow_redirects=False)
    assert r.status_code == 403  # logged in, no CSRF token
    with session_scope() as s:
        assert s.get(Instance, iid).silenced_until is None
    reader = make_client()
    rcsrf = login_as(reader, "bob", role="reader")
    r = reader.post(f"/admin/instances/{iid}/silence", data={"hours": "1", "csrf": rcsrf}, follow_redirects=False)
    assert r.status_code == 403
    with session_scope() as s:
        assert s.get(Instance, iid).silenced_until is None


def test_edit_page_shows_active_silence(client, admin):
    csrf, *_ = admin
    iid = make_instance()
    page = client.get(f"/admin/instances/{iid}").text
    assert f"/admin/instances/{iid}/silence" in page and 'name="hours"' in page
    post(client, csrf, f"/admin/instances/{iid}/silence", hours="24")
    assert "silenced" in client.get(f"/admin/instances/{iid}").text.lower()
