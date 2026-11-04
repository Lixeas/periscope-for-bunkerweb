import hashlib
import hmac
import json
from datetime import datetime, timedelta

from periscope import alert_send as send
from periscope.alert_engine import Notification
from periscope.i18n import pack
from periscope.models import AlertChannel, Tag

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
    import re
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
