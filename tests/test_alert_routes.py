import re

import pytest

from periscope import alert_config, alert_send
from periscope.crypto import decrypt
from periscope.db import session_scope
from periscope.models import AlertChannel, AlertLog, AuditLog, Setting
from tests.helpers import login_as, make_client

SMTP = {"host": "smtp.example", "port": "587", "security": "starttls", "username": "u", "password": "S3cret!",
        "sender": "periscope@example.com"}


@pytest.fixture
def client(fresh_db):
    with make_client() as c:
        yield c


@pytest.fixture
def admin(client):
    return login_as(client)


def post(client, csrf, path, **data):
    return client.post(path, data={"csrf": csrf, **data}, follow_redirects=False)


def channels():
    with session_scope() as s:
        return s.query(AlertChannel).order_by(AlertChannel.id).all()


def audit_events():
    with session_scope() as s:
        return [(e.event, e.detail) for e in s.query(AuditLog).order_by(AuditLog.id)]


def email_form(**kw):
    return {"kind": "email", "name": "MSP", "lang": "en", "events": ["down", "certificate"], "tags": "",
            "recipients": "ops@example.com\nb@example.com", "enabled": "on", **kw}


def hook_form(**kw):
    return {"kind": "webhook", "name": "hook", "lang": "fr", "events": ["down"], "tags": "customer-a",
            "webhook_url": "https://hooks.example/x?token=T0K", "webhook_secret": "HookSecret", "enabled": "on", **kw}


# --- access -------------------------------------------------------------------------------------

def test_alerts_page_admin_only(client):
    assert client.get("/admin/alerts", follow_redirects=False).status_code == 303  # anonymous -> login
    login_as(client, "bob", role="reader")
    assert client.get("/admin/alerts", follow_redirects=False).status_code == 403
    assert client.post("/admin/alerts/smtp", data={"csrf": "x"}, follow_redirects=False).status_code in (403, 400)


def test_sidebar_link_below_instances(client):
    csrf = login_as(client)
    html = client.get("/dashboard").text
    assert html.index('href="/admin/instances') < html.index('href="/admin/alerts')
    assert csrf


def test_sidebar_link_hidden_for_readers(client):
    login_as(client, "bob", role="reader")
    assert 'href="/admin/alerts' not in client.get("/dashboard").text


# --- channels -----------------------------------------------------------------------------------

def test_create_email_channel_and_list(client, admin):
    r = post(client, admin, "/admin/alerts", **email_form(tags="customer-a, prod"))
    assert r.status_code == 303 and r.headers["location"] == "/admin/alerts?m=created"
    (ch,) = channels()
    assert (ch.name, ch.kind, ch.lang, ch.events, ch.enabled) == ("MSP", "email", "en", "down,certificate", True)
    assert ch.recipients == "ops@example.com\nb@example.com" and sorted(t.name for t in ch.tags) == ["customer-a", "prod"]
    page = client.get("/admin/alerts?m=created").text
    assert "MSP" in page and "ops@example.com" in page and "customer-a" in page


def test_new_channel_form_prechecks_the_default_events(client, admin):
    page = client.get("/admin/alerts/new?kind=email").text
    for ev in ("down", "degraded", "certificate"):
        assert re.search(rf'value="{ev}"[^>]*checked', page), ev
    assert not re.search(r'value="version"[^>]*checked', page)


def test_channel_tags_survive_pruning_and_are_pruned_with_the_channel(client, admin):
    from periscope import tags as tagmod
    from periscope.models import Tag
    post(client, admin, "/admin/alerts", **email_form(tags="customer-a"))
    with session_scope() as s:  # an instance edit elsewhere prunes unused tags
        tagmod.prune(s)
    with session_scope() as s:
        assert [t.name for t in s.query(Tag)] == ["customer-a"]
    post(client, admin, f"/admin/alerts/{channels()[0].id}/delete")
    with session_scope() as s:
        assert s.query(Tag).count() == 0


def test_create_webhook_channel_secret_encrypted_and_never_shown(client, admin):
    assert post(client, admin, "/admin/alerts", **hook_form()).status_code == 303
    (ch,) = channels()
    assert ch.lang == "fr" and ch.webhook_url == "https://hooks.example/x?token=T0K"
    assert ch.webhook_secret_enc != "HookSecret" and decrypt(ch.webhook_secret_enc) == "HookSecret"
    listing, edit = client.get("/admin/alerts").text, client.get(f"/admin/alerts/{ch.id}").text
    assert "hooks.example" in listing and "/x?token" not in listing  # host only
    for page in (listing, edit):
        assert "HookSecret" not in page and "T0K" not in page
    # blank secret keeps it, a new one replaces it
    cid = ch.id
    data = hook_form(webhook_secret="")
    assert post(client, admin, f"/admin/alerts/{cid}", **data).status_code == 303
    assert decrypt(channels()[0].webhook_secret_enc) == "HookSecret"
    assert post(client, admin, f"/admin/alerts/{cid}", **hook_form(webhook_secret="New")).status_code == 303
    assert decrypt(channels()[0].webhook_secret_enc) == "New"
    # the URL is kept when the field is blank, replaced (and validated) when given
    assert post(client, admin, f"/admin/alerts/{cid}", **hook_form(webhook_url="")).status_code == 303
    assert channels()[0].webhook_url == "https://hooks.example/x?token=T0K"
    assert post(client, admin, f"/admin/alerts/{cid}", **hook_form(webhook_url="file:///x")).status_code == 400
    assert post(client, admin, f"/admin/alerts/{cid}", **hook_form(webhook_url="https://new.example/y")).status_code == 303
    assert channels()[0].webhook_url == "https://new.example/y"


@pytest.mark.parametrize("form", [
    email_form(recipients="a@b.example\r\nBcc: x@y.example"),
    email_form(recipients="not-an-address"),
    email_form(recipients=""),
    email_form(name=""),
    email_form(events=[]),
    email_form(events=["nope"]),
    email_form(lang="de"),
    hook_form(webhook_url="file:///etc/passwd"),
    hook_form(webhook_url="javascript:alert(1)"),
    hook_form(webhook_url="https://"),
    hook_form(tags="bad/tag"),
])
def test_invalid_input_rejected_with_message(client, admin, form):
    data = dict(form)
    if data.get("events") == []:
        del data["events"]
    r = post(client, admin, "/admin/alerts", **data)
    assert r.status_code == 400 and 'role="alert"' in r.text
    assert channels() == []


def test_duplicate_name_rejected(client, admin):
    assert post(client, admin, "/admin/alerts", **email_form()).status_code == 303
    assert post(client, admin, "/admin/alerts", **email_form(name="msp")).status_code == 400
    assert len(channels()) == 1


def test_edit_and_delete_channel_audited_without_secrets(client, admin):
    post(client, admin, "/admin/alerts", **hook_form())
    cid = channels()[0].id
    r = post(client, admin, f"/admin/alerts/{cid}", **hook_form(name="hook2", events=["down", "version"], tags=""))
    assert r.status_code == 303 and r.headers["location"] == "/admin/alerts?m=saved"
    ch = channels()[0]
    assert (ch.name, ch.events, list(ch.tags)) == ("hook2", "down,version", [])
    r = post(client, admin, f"/admin/alerts/{cid}", **hook_form(enabled=""))  # unchecked box is absent
    data = hook_form()
    del data["enabled"]
    post(client, admin, f"/admin/alerts/{cid}", **data)
    assert channels()[0].enabled is False
    assert post(client, admin, f"/admin/alerts/{cid}/delete").headers["location"] == "/admin/alerts?m=deleted"
    assert channels() == []
    events = audit_events()
    assert [e for e, _ in events if e.startswith("alert_")][:2] == ["alert_channel_created", "alert_channel_edited"]
    assert ("alert_channel_deleted", "hook") in events
    blob = str(events)
    assert "HookSecret" not in blob and "T0K" not in blob and "hooks.example" not in blob


def test_unknown_channel_redirects(client, admin):
    assert client.get("/admin/alerts/999", follow_redirects=False).headers["location"] == "/admin/alerts"
    assert post(client, admin, "/admin/alerts/999", **email_form()).headers["location"] == "/admin/alerts"
    assert post(client, admin, "/admin/alerts/999/delete").headers["location"] == "/admin/alerts?m=deleted"


def test_new_form_pages(client, admin):
    assert "recipients" in client.get("/admin/alerts/new?kind=email").text
    assert "webhook_url" in client.get("/admin/alerts/new?kind=webhook").text
    assert client.get("/admin/alerts/new?kind=nope", follow_redirects=False).status_code == 303


def test_csrf_required_on_every_post(client, admin):
    post(client, admin, "/admin/alerts", **email_form())
    cid = channels()[0].id
    for path in ("/admin/alerts", f"/admin/alerts/{cid}", f"/admin/alerts/{cid}/delete", f"/admin/alerts/{cid}/test",
                 "/admin/alerts/smtp", "/admin/alerts/smtp/test"):
        r = client.post(path, data={"name": "x"}, follow_redirects=False)
        assert r.status_code == 403, path
    assert len(channels()) == 1


# --- SMTP ---------------------------------------------------------------------------------------

def test_smtp_form_saves_without_echoing_password(client, admin):
    r = post(client, admin, "/admin/alerts/smtp", **SMTP)
    assert r.status_code == 303 and r.headers["location"] == "/admin/alerts?m=smtp_saved"
    with session_scope() as s:
        loaded = alert_config.load_smtp(s)
        assert (loaded.host, loaded.password) == ("smtp.example", "S3cret!")
        assert "S3cret!" not in "".join(r.value for r in s.query(Setting))
    page = client.get("/admin/alerts?m=smtp_saved").text
    assert "S3cret!" not in page and "smtp.example" in page
    r = post(client, admin, "/admin/alerts/smtp", **{**SMTP, "password": "", "host": "other.example"})
    assert r.status_code == 303
    with session_scope() as s:
        loaded = alert_config.load_smtp(s)
        assert (loaded.host, loaded.password) == ("other.example", "S3cret!")
    assert ("alert_smtp_updated", "") in audit_events()
    assert "S3cret!" not in str(audit_events())


def test_smtp_form_rejects_bad_values(client, admin):
    r = post(client, admin, "/admin/alerts/smtp", **{**SMTP, "port": "0"})
    assert r.status_code == 400 and 'role="alert"' in r.text
    r = post(client, admin, "/admin/alerts/smtp", **{**SMTP, "sender": "nope"})
    assert r.status_code == 400


# --- tests buttons ------------------------------------------------------------------------------

def test_send_test_buttons_show_the_result(client, admin, monkeypatch):
    post(client, admin, "/admin/alerts", **email_form())
    cid = channels()[0].id
    results = iter([(False, "boom"), (True, "")])

    async def fake_test(channel_id):
        assert channel_id == cid
        return next(results)

    async def fake_smtp(to):
        assert to == "ops@example.com"
        return next(results)

    monkeypatch.setattr(alert_send, "send_test", fake_test)
    monkeypatch.setattr(alert_send, "send_smtp_test", fake_smtp)
    r = post(client, admin, f"/admin/alerts/{cid}/test")
    assert r.status_code == 200 and "boom" in r.text and 'role="alert"' in r.text
    r = post(client, admin, "/admin/alerts/smtp/test", to="ops@example.com")
    assert r.status_code == 200 and 'role="status"' in r.text
    assert ("alert_test_sent", "MSP") in audit_events()


# --- send log -----------------------------------------------------------------------------------

def test_page_shows_the_send_log_and_last_result(client, admin):
    post(client, admin, "/admin/alerts", **email_form())
    with session_scope() as s:
        cid = s.query(AlertChannel.id).scalar()
        s.add(AlertLog(channel_id=cid, channel_name="MSP", events="instance_down", instances="bw1", ok=False,
                       error="SMTP not configured"))
    page = client.get("/admin/alerts").text
    assert "SMTP not configured" in page and "bw1" in page and "instance_down" in page


def test_page_renders_in_french(client, admin):
    page = client.get("/admin/alerts", headers={"accept-language": "fr"}).text
    assert "Alertes" in page
