import hashlib
import hmac
import json
import re
import smtplib
from datetime import datetime, timedelta
from typing import ClassVar

import httpx
import pytest

from periscope import alert_config
from periscope import alert_send as send
from periscope.alert_engine import Notification
from periscope.clock import utcnow
from periscope.crypto import encrypt
from periscope.db import session_scope
from periscope.i18n import pack
from periscope.models import AlertChannel, AlertLog, Tag

NOW = datetime(2026, 11, 4, 12, 0, 0)


def note(type="instance_down", event="down", instance="bw1", tags=("a",), **kw) -> Notification:
    return Notification(type, event, 1, instance, tags, **kw)


def channel(events="down,degraded,certificate", tags=(), enabled=True, lang="en", kind="email") -> AlertChannel:
    ch = AlertChannel(name="c", kind=kind, events=events, enabled=enabled, lang=lang)
    ch.tags = [Tag(name=t) for t in tags]
    return ch


# --- routing ----------------------------------------------------------------------------------

def test_matches_by_tag_and_event():
    assert send.matches(channel(), note())  # no tag: everything
    assert send.matches(channel(tags=("a", "b")), note(tags=("b",)))
    assert not send.matches(channel(tags=("x",)), note(tags=("a",)))
    assert not send.matches(channel(tags=("x",)), note(tags=()))
    assert not send.matches(channel(events="down"), note("cert_red", "certificate"))
    assert send.matches(channel(events="certificate"), note("cert_red", "certificate"))
    assert not send.matches(channel(events="down"), note("instance_degraded", "degraded"))
    assert send.matches(channel(events="down"), note("instance_resolved", "down"))  # follows what it resolves
    assert not send.matches(channel(events="down,certificate"), note("instance_version_changed", "version"))
    assert send.matches(channel(events="version"), note("instance_version_changed", "version"))
    assert not send.matches(channel(enabled=False), note())
    assert send.matches(channel(events="version", tags=("zzz",)), note("test", "test"))  # test always matches


# --- rendering --------------------------------------------------------------------------------

def sample():
    return [
        note(status="down", message=pack("1 node offline: {host}", host="n1"), since=NOW),
        note("cert_red", "certificate", "bw2", domain="a.example", not_after=NOW + timedelta(days=3), days_left=2),
        note("instance_resolved", "degraded", "bw3", status="ok", since=NOW),
    ]


def test_render_email_english_default_and_french():
    subject, body = send.render_email("en", sample(), NOW)
    assert "bw1" in body and "bw2" in body and "bw3" in body and "a.example" in body and "n1" in body
    assert "3" in subject and "[Periscope]" in subject
    sujet, corps = send.render_email("fr", sample(), NOW)
    assert (sujet, corps) != (subject, body)
    assert "bw1" in corps and "a.example" in corps
    assert re.search(r"[éèàêç]", corps) and not re.search(r"[éèàêç]", body)


def test_render_never_breaks_on_braces_and_unicode():
    weird = [note(instance="a{b}%s é", message="{0} {x} %s"), note("cert_red", "certificate", "n{}", domain="{x}.é",
                                                                     days_left=1, not_after=NOW)]
    for lang in ("en", "fr"):
        _subject, body = send.render_email(lang, weird, NOW)
        assert "a{b}%s é" in body and "{x}.é" in body and "n{}" in body
        data = json.loads(send.render_webhook(lang, weird, NOW))
        assert data["events"][0]["instance"] == "a{b}%s é" and data["events"][1]["domain"] == "{x}.é"


def test_render_webhook_contract():
    data = json.loads(send.render_webhook("en", sample(), NOW))
    assert set(data) == {"version", "sent_at", "lang", "summary", "events"}
    assert data["version"] == 1 and data["lang"] == "en" and data["sent_at"] == "2026-11-04T12:00:00Z"
    assert isinstance(data["summary"], str) and data["summary"]
    first, second, third = data["events"]
    keys = {"type", "instance", "tags", "status", "message", "domain", "not_after", "days_left", "since"}
    assert all(set(e) == keys for e in data["events"])
    assert (first["type"], first["instance"], first["tags"], first["status"]) == ("instance_down", "bw1", ["a"], "down")
    assert first["message"] == "1 node offline: n1" and first["since"] == "2026-11-04T12:00:00Z"
    assert (second["type"], second["domain"], second["days_left"], second["not_after"]) == (
        "cert_red", "a.example", 2, "2026-11-07T12:00:00Z")
    assert third["type"] == "instance_resolved" and third["message"] == "" and third["domain"] == ""
    assert second["since"] is None
    assert json.loads(send.render_webhook("fr", sample(), NOW))["lang"] == "fr"


def test_sign_matches_hmac_sha256():
    body = b'{"a": 1}'
    expected = "sha256=" + hmac.new(b"k", body, hashlib.sha256).hexdigest()
    assert send.sign("k", body) == expected


# --- delivery ---------------------------------------------------------------------------------

SMTP = {"host": "smtp.example", "port": 587, "security": "starttls", "username": "u", "password": "S3cret!",
        "sender": "periscope@example.com"}


@pytest.fixture
def fast(monkeypatch):
    monkeypatch.setattr(send, "BACKOFF", (0, 0))


def add_channel(name="MSP", kind="email", tags=(), events="down,degraded,certificate", secret="", **kw):
    with session_scope() as s:
        ch = AlertChannel(name=name, kind=kind, events=events, recipients="ops@example.com\nb@example.com",
                          webhook_url="https://hooks.example/x?token=T0K", webhook_secret_enc=encrypt(secret) if secret else "",
                          **kw)
        s.add(ch)
        existing = {t.name: t for t in s.query(Tag)}
        ch.tags = [existing.get(t) or Tag(name=t) for t in tags]


def logs():
    with session_scope() as s:
        return [(r.channel_name, r.ok, r.error, r.events, r.instances) for r in s.query(AlertLog).order_by(AlertLog.id)]


def record(monkeypatch, fail=0, exc=None):
    calls = []

    async def fake_email(smtp, recipients, subject, body):
        calls.append(("email", recipients, subject, body))
        if exc is not None:
            raise exc
        if len([c for c in calls if c[0] == "email"]) <= fail:
            raise send.DeliveryError("boom")

    async def fake_hook(url, secret, body, transport=None):
        calls.append(("webhook", url, secret, body))
        if exc is not None:
            raise exc
        if len([c for c in calls if c[0] == "webhook"]) <= fail:
            raise send.DeliveryError("boom")

    monkeypatch.setattr(send, "send_email", fake_email)
    monkeypatch.setattr(send, "send_webhook", fake_hook)
    return calls


async def test_dispatch_groups_one_message_per_channel(fresh_db, fast, monkeypatch):
    with session_scope() as s:
        alert_config.save_smtp(s, **SMTP)
    add_channel("MSP")
    add_channel("hook", kind="webhook", secret="k")
    calls = record(monkeypatch)
    batch = [note(instance="bw1"), note("instance_degraded", "degraded", "bw2"),
             note("cert_red", "certificate", "bw3", domain="a.example", days_left=1, not_after=NOW)]
    await send.dispatch(batch, NOW)
    assert [c[0] for c in calls] == ["email", "webhook"]
    body = calls[0][3]
    assert all(n in body for n in ("bw1", "bw2", "bw3"))
    assert calls[0][1] == ["ops@example.com", "b@example.com"]
    assert len(json.loads(calls[1][3])["events"]) == 3 and calls[1][2] == "k"
    assert [(n, ok) for n, ok, *_ in logs()] == [("MSP", True), ("hook", True)]
    assert logs()[0][3] == "instance_down,instance_degraded,cert_red" and logs()[0][4] == "bw1,bw2,bw3"


async def test_dispatch_filters_by_tag_for_msp_case(fresh_db, fast, monkeypatch):
    with session_scope() as s:
        alert_config.save_smtp(s, **SMTP)
    add_channel("MSP")
    add_channel("Customer A", tags=("a",))
    calls = record(monkeypatch)
    await send.dispatch([note(instance="bw-a", tags=("a",))], NOW)
    assert len(calls) == 2
    calls.clear()
    await send.dispatch([note(instance="bw-b", tags=("b",))], NOW)
    assert len(calls) == 1 and "bw-b" in calls[0][3]


async def test_dispatch_retries_then_logs_failure(fresh_db, fast, monkeypatch):
    add_channel("hook", kind="webhook")
    calls = record(monkeypatch, fail=2)
    await send.dispatch([note()], NOW)
    assert len(calls) == 3 and logs()[-1][1] is True
    calls = record(monkeypatch, fail=99)
    await send.dispatch([note()], NOW)
    assert len(calls) == 3
    assert logs()[-1][1:3] == (False, "boom")


async def test_dispatch_never_raises_and_smtp_not_configured_is_logged(fresh_db, fast, monkeypatch):
    add_channel("MSP")
    await send.dispatch([note()], NOW)
    assert logs() == [("MSP", False, "SMTP not configured", "instance_down", "bw1")]
    add_channel("hook", kind="webhook")
    record(monkeypatch, exc=RuntimeError("secret detail"))
    await send.dispatch([note()], NOW)
    last = logs()[-1]
    assert last[1] is False and "secret detail" not in last[2]

    monkeypatch.setattr(send, "_plan", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("db down")))
    await send.dispatch([note()], NOW)  # must not raise


async def test_dispatch_does_nothing_without_notifications(fresh_db, monkeypatch):
    calls = record(monkeypatch)
    add_channel("hook", kind="webhook")
    await send.dispatch([], NOW)
    assert calls == [] and logs() == []


async def test_log_pruned(fresh_db, fast, monkeypatch):
    add_channel("hook", kind="webhook")
    record(monkeypatch)
    old = utcnow() - timedelta(days=31)
    with session_scope() as s:
        s.add(AlertLog(at=old, channel_name="ancient", ok=True))
        s.add_all([AlertLog(at=utcnow(), channel_name=f"n{i}", ok=True) for i in range(1004)])
    await send.dispatch([note()], NOW)
    with session_scope() as s:
        names = [r.channel_name for r in s.query(AlertLog)]
    assert len(names) == 1000 and "ancient" not in names and "hook" in names


async def test_send_webhook_signature_and_headers():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(204)

    body = b'{"x": 1}'
    await send.send_webhook("https://hooks.example/x", "k", body, transport=httpx.MockTransport(handler))
    req = seen[0]
    assert req.headers["x-periscope-signature"] == send.sign("k", body)
    assert req.headers["content-type"].startswith("application/json")
    assert req.headers["user-agent"].startswith("Periscope/") and req.content == body
    await send.send_webhook("https://hooks.example/x", "", body, transport=httpx.MockTransport(handler))
    assert "x-periscope-signature" not in seen[1].headers


async def test_send_webhook_302_is_failure_and_not_followed():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(302, headers={"location": "https://evil.example/"})

    with pytest.raises(send.DeliveryError, match="HTTP 302"):
        await send.send_webhook("https://hooks.example/x?token=T0K", "", b"{}", transport=httpx.MockTransport(handler))
    assert seen == ["https://hooks.example/x?token=T0K"]


async def test_send_webhook_500_and_network_errors_are_generic():
    with pytest.raises(send.DeliveryError, match="HTTP 500"):
        await send.send_webhook("https://h.example/x", "", b"{}",
                                transport=httpx.MockTransport(lambda r: httpx.Response(500)))

    def boom(request):
        raise httpx.ConnectError("failed to reach https://hooks.example/x?token=T0K")

    with pytest.raises(send.DeliveryError) as e:
        await send.send_webhook("https://hooks.example/x?token=T0K", "", b"{}", transport=httpx.MockTransport(boom))
    assert "T0K" not in str(e.value)


class FakeSMTP:
    instances: ClassVar[list] = []

    def __init__(self, host, port, timeout=None, context=None):
        self.host, self.port, self.context, self.steps, self.sent = host, port, context, [], None
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context=None):
        self.steps.append("starttls")

    def login(self, user, password):
        self.steps.append(("login", user, password))

    def send_message(self, msg):
        self.steps.append("send")
        self.sent = msg


@pytest.mark.parametrize("security,cls,steps", [
    ("starttls", "SMTP", ["starttls", ("login", "u", "S3cret!"), "send"]),
    ("ssl", "SMTP_SSL", [("login", "u", "S3cret!"), "send"]),
    ("none", "SMTP", [("login", "u", "S3cret!"), "send"]),
])
async def test_send_email_modes(monkeypatch, security, cls, steps):
    FakeSMTP.instances = []
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP if cls == "SMTP" else None)
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTP if cls == "SMTP_SSL" else None)
    smtp = alert_config.SmtpSettings("smtp.example", 587, security, "u", "S3cret!", "periscope@example.com")
    await send.send_email(smtp, ["a@b.example", "c@d.example"], "[Periscope] 1 event(s)\r\nBcc: x@y.example", "hello")
    (inst,) = FakeSMTP.instances
    assert inst.steps == steps and inst.host == "smtp.example"
    msg = inst.sent
    assert msg["To"] == "a@b.example, c@d.example" and msg["From"] == "periscope@example.com"
    assert "\n" not in msg["Subject"] and "Bcc" not in msg and msg.get_content().strip() == "hello"


async def test_send_email_without_username_skips_login(monkeypatch):
    FakeSMTP.instances = []
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    smtp = alert_config.SmtpSettings("h", 25, "none", "", "", "p@example.com")
    await send.send_email(smtp, ["a@b.example"], "s", "b")
    assert FakeSMTP.instances[0].steps == ["send"]


async def test_send_email_errors_are_generic(monkeypatch):
    class Leaky(FakeSMTP):
        def login(self, user, password):
            raise smtplib.SMTPAuthenticationError(535, b"bad credentials for S3cret!")

    monkeypatch.setattr(smtplib, "SMTP", Leaky)
    smtp = alert_config.SmtpSettings("h", 587, "starttls", "u", "S3cret!", "p@example.com")
    with pytest.raises(send.DeliveryError) as e:
        await send.send_email(smtp, ["a@b.example"], "s", "b")
    assert "S3cret!" not in str(e.value)

    class Refuse(FakeSMTP):
        def __init__(self, *a, **k):
            raise ConnectionRefusedError("refused S3cret!")

    monkeypatch.setattr(smtplib, "SMTP", Refuse)
    with pytest.raises(send.DeliveryError) as e:
        await send.send_email(smtp, ["a@b.example"], "s", "b")
    assert "S3cret!" not in str(e.value)


async def test_secrets_never_in_log(fresh_db, fast, monkeypatch):
    with session_scope() as s:
        alert_config.save_smtp(s, **SMTP)
    add_channel("MSP")
    add_channel("hook", kind="webhook", secret="HookSecret")

    class Leaky(FakeSMTP):
        def login(self, user, password):
            raise smtplib.SMTPAuthenticationError(535, b"nope S3cret!")

    monkeypatch.setattr(smtplib, "SMTP", Leaky)
    await send.dispatch([note()], NOW)
    # the real webhook sender runs against a failing transport that leaks the secret in its message
    real = send.send_webhook

    async def leaky_hook(url, secret, body, transport=None):
        def boom(request):
            raise httpx.ConnectError(f"cannot reach {url} with {secret}")
        return await real(url, secret, body, transport=httpx.MockTransport(boom))

    monkeypatch.setattr(send, "send_webhook", leaky_hook)
    await send.dispatch([note()], NOW)
    blob = json.dumps(logs())
    assert "S3cret!" not in blob and "HookSecret" not in blob and "T0K" not in blob
    assert [ok for _, ok, *_ in logs()] == [False, False, False, False]


async def test_send_test_logs_and_reports_without_touching_state(fresh_db, fast, monkeypatch):
    from periscope.models import AlertState
    add_channel("hook", kind="webhook", tags=("zzz",))
    calls = record(monkeypatch)
    with session_scope() as s:
        cid = s.query(AlertChannel.id).scalar()
    assert await send.send_test(cid) == (True, "")
    assert calls[0][0] == "webhook" and json.loads(calls[0][3])["events"][0]["type"] == "test"
    assert logs()[-1][:2] == ("hook", True) and logs()[-1][3] == "test"
    record(monkeypatch, fail=99)
    ok, err = await send.send_test(cid)
    assert (ok, err) == (False, "boom")
    assert await send.send_test(9999) == (False, "Channel not found")
    with session_scope() as s:
        assert s.query(AlertState).count() == 0


async def test_send_smtp_test(fresh_db, monkeypatch):
    calls = record(monkeypatch)
    assert await send.send_smtp_test("ops@example.com") == (False, "SMTP not configured")
    with session_scope() as s:
        alert_config.save_smtp(s, **SMTP)
    assert await send.send_smtp_test("not-an-address") == (False, "Invalid e-mail address")
    assert await send.send_smtp_test("ops@example.com") == (True, "")
    assert calls[0][:2] == ("email", ["ops@example.com"])
    assert logs()[-1][:2] == ("SMTP test", True)
