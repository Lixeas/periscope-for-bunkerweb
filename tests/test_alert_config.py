import pytest

from periscope import alert_config as cfg
from periscope.crypto import decrypt
from periscope.db import session_scope
from periscope.i18n import LocalizedError
from periscope.models import Setting

SMTP = {"host": "smtp.example", "port": 587, "security": "starttls", "username": "u", "password": "S3cret!",
        "sender": "periscope@example.com"}


def test_save_and_load_smtp_encrypts_password(fresh_db):
    with session_scope() as s:
        cfg.save_smtp(s, **SMTP)
    with session_scope() as s:
        raw = {r.key: r.value for r in s.query(Setting) if r.key.startswith("alert_smtp_")}
        assert "S3cret!" not in "".join(raw.values())
        assert decrypt(raw["alert_smtp_password"]) == "S3cret!"
        loaded = cfg.load_smtp(s)
        assert loaded == cfg.SmtpSettings(**SMTP)
        public = cfg.smtp_public(s)
        assert public["has_password"] is True and public["host"] == "smtp.example"
        assert "S3cret!" not in str(public)


def test_blank_password_keeps_existing(fresh_db):
    with session_scope() as s:
        cfg.save_smtp(s, **SMTP)
        cfg.save_smtp(s, **{**SMTP, "host": "other.example", "password": ""})
    with session_scope() as s:
        loaded = cfg.load_smtp(s)
        assert (loaded.host, loaded.password) == ("other.example", "S3cret!")


def test_load_smtp_none_when_unconfigured(fresh_db):
    with session_scope() as s:
        assert cfg.load_smtp(s) is None
        assert cfg.smtp_public(s)["has_password"] is False
        cfg.save_smtp(s, **{**SMTP, "host": ""})
        assert cfg.load_smtp(s) is None


@pytest.mark.parametrize("bad", [{"port": 0}, {"port": 70000}, {"security": "tls13"}, {"sender": "nope"},
                                 {"sender": "a@b.example\r\nBcc: x@y.example"}])
def test_save_smtp_rejects_bad_values(fresh_db, bad):
    with session_scope() as s, pytest.raises(LocalizedError):
        cfg.save_smtp(s, **{**SMTP, **bad})


def test_recipients_accepts_mixed_separators_and_dedupes():
    assert cfg.parse_recipients("a@b.example, C@d.example;a@B.example\n e@f.example ") == [
        "a@b.example", "C@d.example", "e@f.example"]


@pytest.mark.parametrize("raw", [
    "a@b.example\r\nBcc: x@y.example",  # a newline separates tokens: "Bcc: x@y.example" is not an address
    "a@b\rc.example", "a@b.example\x00", "a@b.example, not-an-address", "", "  ,;\n ",
    ",".join(f"u{i}@b.example" for i in range(21)),
])
def test_recipients_reject_header_injection_and_garbage(raw):
    with pytest.raises(LocalizedError):
        cfg.parse_recipients(raw)


def test_recipients_twenty_is_the_limit():
    assert len(cfg.parse_recipients(",".join(f"u{i}@b.example" for i in range(20)))) == 20


def test_webhook_url_schemes():
    assert cfg.clean_webhook_url("  https://h.example/x?t=1 ") == "https://h.example/x?t=1"
    assert cfg.clean_webhook_url("http://10.0.0.5:8080/hook") == "http://10.0.0.5:8080/hook"
    for bad in ("file:///etc/passwd", "javascript:alert(1)", "ftp://h.example", "https://", "http:///x", "", "h.example/x"):
        with pytest.raises(LocalizedError):
            cfg.clean_webhook_url(bad)


def test_parse_events():
    assert cfg.parse_events(["certificate", "down"]) == "down,certificate"
    assert cfg.parse_events(["version", "version"]) == "version"
    for bad in ([], ["nope"], ["down", "nope"]):
        with pytest.raises(LocalizedError):
            cfg.parse_events(bad)
    assert cfg.DEFAULT_EVENTS == "down,degraded,certificate"
    assert cfg.EVENTS == ("down", "degraded", "certificate", "version")


def test_is_address_stays_fast_on_hostile_input():
    """CodeQL: the old regular expression was quadratic on a long run of dots (16 000 chars took ~1 s)."""
    import time
    for hostile in ("a@" + "." * 200_000 + " ", "a" * 200_000, "@" * 200_000, "a@" + "b." * 100_000 + "@"):
        t = time.perf_counter()
        assert cfg.is_address(hostile) is False
        assert time.perf_counter() - t < 0.2, hostile[:10]


@pytest.mark.parametrize("good", ["a@b.example", "first.last+tag@sub.domain.example", "é@münchen.example", "x@y.zz"])
def test_is_address_accepts_ordinary_addresses(good):
    assert cfg.is_address(good) is True


@pytest.mark.parametrize("bad", ["", "a", "a@", "@b.example", "a@b", "a@.example", "a@b.", "a@b..example", "a b@c.example",
                                 "a@@b.example", "a@b@c.example", "a@b.example\r", "<a@b.example>", "a,b@c.example",
                                 "x" * 65 + "@b.example", "a@" + "b" * 250 + ".example"])
def test_is_address_rejects_malformed_addresses(bad):
    assert cfg.is_address(bad) is False
