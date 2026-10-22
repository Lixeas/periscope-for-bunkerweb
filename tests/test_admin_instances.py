import pytest

from mc import collector
from mc.crypto import decrypt
from mc.db import session_scope
from mc.models import AuditLog, CertProbe, Instance, Snapshot
from mc.web import routes_admin
from tests.helpers import login_as, make_client

FORM = {"name": "bw1", "base_url": "http://10.0.0.5:8888/", "token": "tok123", "tls_port": "443", "verify_tls": "on"}


@pytest.fixture
def client(fresh_db):
    with make_client() as c:
        yield c


@pytest.fixture
def admin(client, monkeypatch):
    calls = []
    state = {"error": None}

    async def check(base_url, token, verify_tls):
        return state["error"]

    async def refresh(inst_id):
        calls.append(inst_id)

    monkeypatch.setattr(routes_admin, "check_instance", check)
    monkeypatch.setattr(collector, "refresh_instance", refresh)
    csrf = login_as(client)
    return csrf, calls, state


def post(client, csrf, path="/admin/instances", **data):
    return client.post(path, data={"csrf": csrf, **data}, follow_redirects=False)


def test_add_instance_encrypts_token_and_triggers_refresh(client, admin):
    csrf, calls, _ = admin
    r = post(client, csrf, **FORM)
    assert r.status_code == 303 and r.headers["location"] == "/admin/instances?m=added"
    with session_scope() as s:
        i = s.query(Instance).one()
        assert i.base_url == "http://10.0.0.5:8888" and i.verify_tls is True
        assert i.token_enc != "tok123" and decrypt(i.token_enc) == "tok123"
        assert [e.event for e in s.query(AuditLog)][-1] == "instance_added"
        assert calls == [i.id]


def test_token_never_rendered(client, admin):
    csrf, _, _ = admin
    post(client, csrf, **FORM)
    assert "tok123" not in client.get("/admin/instances").text


def test_connection_failure_blocks_unless_forced(client, admin):
    csrf, _calls, state = admin
    state["error"] = "Instance injoignable"
    r = post(client, csrf, **FORM)
    assert r.status_code == 400 and "injoignable" in client.post(
        "/admin/instances", data={"csrf": csrf, **FORM}).text
    with session_scope() as s:
        assert s.query(Instance).count() == 0
    r = post(client, csrf, force="on", **FORM)
    assert r.status_code == 303
    with session_scope() as s:
        assert s.query(Instance).count() == 1


@pytest.mark.parametrize("override,fragment", [
    ({"base_url": "ftp://x"}, "URL invalide"),
    ({"base_url": "http://user:pw@x:8888"}, "URL invalide"),
    ({"base_url": "http://x:99999"}, "URL invalide"),
    ({"name": ""}, "Nom invalide"),
    ({"tls_port": "70000"}, "Port TLS invalide"),
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
    assert r.status_code == 400 and "existe déjà" in r.text


def test_edit_keeps_token_when_blank_and_replaces_when_given(client, admin):
    csrf, _calls, _ = admin
    post(client, csrf, **FORM)
    with session_scope() as s:
        iid = s.query(Instance).one().id
    data = {"name": "bw1-renamed", "base_url": "http://10.0.0.5:8888", "token": "", "tls_port": "8443",
            "probe_host": "10.0.0.7", "enabled": "on"}
    r = post(client, csrf, f"/admin/instances/{iid}", **data)
    assert r.status_code == 303
    with session_scope() as s:
        i = s.get(Instance, iid)
        assert (i.name, i.base_url, i.tls_port, i.probe_host) == ("bw1-renamed", "http://10.0.0.5:8888", 8443, "10.0.0.7")
        assert decrypt(i.token_enc) == "tok123" and i.verify_tls is False
    post(client, csrf, f"/admin/instances/{iid}", **{**data, "token": "newtok"})
    with session_scope() as s:
        assert decrypt(s.get(Instance, iid).token_enc) == "newtok"
    post(client, csrf, f"/admin/instances/{iid}", **{k: v for k, v in data.items() if k != "enabled"})
    with session_scope() as s:
        assert s.get(Instance, iid).enabled is False


def test_delete_cascades(client, admin):
    csrf, _, _ = admin
    post(client, csrf, **FORM)
    with session_scope() as s:
        i = s.query(Instance).one()
        i.snapshots.append(Snapshot(kind="bans", payload=[]))
        i.probes.append(CertProbe(domain="a.example"))
        iid = i.id
    assert post(client, csrf, f"/admin/instances/{iid}/delete").status_code == 303
    with session_scope() as s:
        assert (s.query(Instance).count(), s.query(Snapshot).count(), s.query(CertProbe).count()) == (0, 0, 0)


def test_reader_forbidden_and_csrf_required(client, admin):
    _csrf, _, _ = admin
    assert client.post("/admin/instances", data=FORM).status_code == 403  # sans CSRF
    with make_client() as c2:
        login_as(c2, "bob", "reader")
        assert c2.get("/admin/instances").status_code == 403


def test_edit_url_change_requires_token(client, admin):
    csrf, _, _ = admin
    post(client, csrf, **FORM)
    with session_scope() as s:
        iid = s.query(Instance).one().id
    data = {"name": "bw1", "base_url": "http://evil.example:8888", "token": "", "tls_port": "443", "enabled": "on"}
    r = client.post(f"/admin/instances/{iid}", data={"csrf": csrf, **data})
    assert r.status_code == 400 and "ressaisir le token" in r.text.replace("&#39;", "'")
    with session_scope() as s:
        assert s.get(Instance, iid).base_url == "http://10.0.0.5:8888"
    r = post(client, csrf, f"/admin/instances/{iid}", **{**data, "token": "newtok"})
    assert r.status_code == 303
