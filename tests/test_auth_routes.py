import base64

import pyotp
import pytest

from periscope.auth import mfa
from periscope.auth import webauthn_ as wa
from periscope.db import session_scope
from periscope.models import AuditLog, BackupCode, Credential, User
from tests.helpers import PW, csrf_of, full_login, make_client, make_user, post_login


@pytest.fixture
def client(fresh_db):
    with make_client() as c:
        yield c


def audit_events():
    with session_scope() as s:
        return [e.event for e in s.query(AuditLog).order_by(AuditLog.id)]


def test_login_page_renders(client):
    r = client.get("/login")
    assert r.status_code == 200 and 'name="username"' in r.text


def test_login_page_sets_csrf_cookie_and_field(client):
    r = client.get("/login")
    token = csrf_of(r.text)
    cookie = r.headers["set-cookie"]
    assert f"periscope_login_csrf={token}" in cookie and "HttpOnly" in cookie and "SameSite=strict" in cookie


def test_login_post_without_csrf_cookie_is_403(client):
    make_user()
    r = client.post("/login", data={"username": "alice", "password": PW, "csrf": "x"}, follow_redirects=False)
    assert r.status_code == 403
    assert audit_events() == []


def test_login_post_with_mismatched_csrf_is_403(client):
    make_user()
    client.get("/login")
    r = client.post("/login", data={"username": "alice", "password": PW, "csrf": "nope"}, follow_redirects=False)
    assert r.status_code == 403
    r = client.post("/login", data={"username": "alice", "password": PW}, follow_redirects=False)
    assert r.status_code == 403


def test_full_login_with_totp_then_dashboard_then_logout(client):
    secret = make_user()
    r = post_login(client)
    assert r.status_code == 303 and r.headers["location"] == "/login/2fa"
    assert client.get("/dashboard", follow_redirects=False).status_code == 303  # pending session: no access
    page = client.get("/login/2fa")
    r = client.post("/login/2fa", data={"code": pyotp.TOTP(secret).now(), "csrf": csrf_of(page.text)},
                    follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    dash = client.get("/dashboard")
    assert dash.status_code == 200 and "alice" in dash.text
    assert audit_events() == ["password_ok", "login"]
    assert client.post("/logout", data={}, follow_redirects=False).status_code == 403  # without CSRF
    r = client.post("/logout", data={"csrf": csrf_of(dash.text)}, follow_redirects=False)
    assert r.status_code == 303
    assert client.get("/dashboard", follow_redirects=False).status_code == 303


def test_wrong_password_and_unknown_user_look_identical(client):
    make_user()
    r1 = post_login(client, "alice", "wrong password here")
    r2 = post_login(client, "nobody", "wrong password here")
    assert r1.status_code == r2.status_code == 401
    assert r1.text == r2.text and "Invalid credentials" in r1.text
    assert audit_events() == ["login_failed", "login_failed"]


def test_password_failures_lock_the_username_ip_pair_not_the_account(client):
    make_user()
    for _ in range(5):
        post_login(client, "alice", "wrong password here")
    r = post_login(client)
    assert r.status_code == 401
    assert "login_locked" in audit_events()
    with session_scope() as s:
        u = s.query(User).one()
        assert u.failed_attempts == 0 and u.locked_until is None


def test_password_lock_is_per_ip(client, monkeypatch):
    from periscope.web import routes_auth
    make_user()
    monkeypatch.setattr(routes_auth, "ip_of", lambda request: "10.0.0.1")
    for _ in range(5):
        post_login(client, "alice", "wrong password here")
    assert post_login(client).status_code == 401  # IP A locked for alice
    monkeypatch.setattr(routes_auth, "ip_of", lambda request: "10.0.0.2")
    r = post_login(client)  # IP B: the correct password goes through
    assert r.status_code == 303 and r.headers["location"] == "/login/2fa"


def test_attacker_failures_do_not_block_legitimate_user_elsewhere(client, monkeypatch):
    from periscope.web import routes_auth
    make_user()
    monkeypatch.setattr(routes_auth, "ip_of", lambda request: "6.6.6.6")
    for _ in range(8):
        post_login(client, "alice", "wrong password here")
    monkeypatch.setattr(routes_auth, "ip_of", lambda request: "7.7.7.7")
    r = post_login(client)
    assert r.status_code == 303 and r.headers["location"] == "/login/2fa"
    assert client.get("/login/2fa").status_code == 200


def test_unknown_and_known_username_lock_identically(client):
    make_user()
    for name in ("alice", "nobody"):
        for _ in range(5):
            post_login(client, name, "wrong password here")
    r1, r2 = post_login(client, "alice", "wrong password here"), post_login(client, "nobody", "wrong password here")
    assert r1.status_code == r2.status_code == 401 and r1.text == r2.text
    ev = audit_events()
    assert ev.count("login_locked") == 2 and ev.count("login_failed") == 10


def test_username_case_insensitive_for_lock(client):
    make_user()
    for _ in range(5):
        post_login(client, "ALICE", "wrong password here")
    assert post_login(client, "alice").status_code == 401


def test_successful_login_clears_pair(client):
    secret = make_user()
    for _ in range(3):
        post_login(client, "alice", "wrong password here")
    assert full_login(client, secret).status_code == 303
    from periscope.web import routes_auth
    assert routes_auth.login_failures.retry_after("alice", "testclient") == 0
    assert not routes_auth.login_failures._state


def test_ip_throttle(client):
    make_user()
    from periscope.web import routes_auth
    routes_auth.limiter.max = 2
    try:
        codes = [post_login(client, "x", "y").status_code for _ in range(3)]
    finally:
        routes_auth.limiter.max = 20
    assert codes == [401, 401, 429]


def test_foreign_origin_blocked_on_login(client):
    make_user()
    r = client.post("/login", data={"username": "alice", "password": PW},
                    headers={"origin": "https://evil.example"}, follow_redirects=False)
    assert r.status_code == 403


def test_2fa_wrong_code_counts_failure_and_audits(client):
    make_user()
    post_login(client)
    page = client.get("/login/2fa")
    r = client.post("/login/2fa", data={"code": "000000", "csrf": csrf_of(page.text)}, follow_redirects=False)
    assert r.status_code == 401
    assert audit_events() == ["password_ok", "login_2fa_failed"]
    with session_scope() as s:
        assert s.query(User).one().failed_attempts == 1


def test_2fa_requires_csrf(client):
    secret = make_user()
    post_login(client)
    r = client.post("/login/2fa", data={"code": pyotp.TOTP(secret).now()}, follow_redirects=False)
    assert r.status_code == 403


def test_backup_code_login_is_single_use(client):
    make_user()
    with session_scope() as s:
        codes = mfa.reset_backup_codes(s, s.query(User).one())
    post_login(client)
    page = client.get("/login/2fa")
    r = client.post("/login/2fa", data={"code": codes[0], "csrf": csrf_of(page.text)}, follow_redirects=False)
    assert r.status_code == 303
    client.cookies.clear()
    post_login(client)
    page = client.get("/login/2fa")
    r = client.post("/login/2fa", data={"code": codes[0], "csrf": csrf_of(page.text)}, follow_redirects=False)
    assert r.status_code == 401
    with session_scope() as s:
        assert s.query(BackupCode).filter_by(used=True).count() == 1


def test_enrollment_is_forced_for_user_without_second_factor(client):
    make_user(totp=False)
    r = post_login(client)
    assert r.headers["location"] == "/enroll"
    assert client.get("/dashboard", follow_redirects=False).status_code == 303
    page = client.get("/enroll")
    assert page.status_code == 200 and "data:image/png;base64," in page.text
    with session_scope() as s:
        secret = mfa.secret_plain(s.query(User).one().totp_secret_enc)
    r = client.post("/enroll", data={"code": "000000", "csrf": csrf_of(page.text)})
    assert r.status_code == 401
    r = client.post("/enroll", data={"code": pyotp.TOTP(secret).now(), "csrf": csrf_of(page.text)})
    assert r.status_code == 200 and "only once" in r.text
    assert client.get("/dashboard").status_code == 200
    with session_scope() as s:
        u = s.query(User).one()
        assert u.totp_confirmed and len(u.backup_codes) == 10


def test_passkey_options_and_verify(client, monkeypatch):
    make_user(totp=False)
    with session_scope() as s:
        user = s.query(User).one()
        user.credentials.append(Credential(credential_id=b"cred-1", public_key=b"k", sign_count=1))
    assert post_login(client).headers["location"] == "/login/2fa"
    csrf = csrf_of(client.get("/login/2fa").text)
    h = {"X-CSRF-Token": csrf}
    opts = client.post("/webauthn/auth/options", headers=h, json={})
    assert opts.status_code == 200 and "challenge" in opts.json()

    cid = base64.urlsafe_b64encode(b"cred-1").rstrip(b"=").decode()
    monkeypatch.setattr(wa, "verify_authentication", lambda cred, ch, stored: 7)
    r = client.post("/webauthn/auth/verify", headers=h, json={"id": cid})
    assert r.status_code == 200 and r.json()["redirect"] == "/"
    assert client.get("/dashboard").status_code == 200
    with session_scope() as s:
        assert s.query(Credential).one().sign_count == 7


def test_passkey_verify_failure_is_401(client, monkeypatch):
    make_user(totp=False)
    with session_scope() as s:
        user = s.query(User).one()
        user.credentials.append(Credential(credential_id=b"cred-1", public_key=b"k"))
    post_login(client)
    h = {"X-CSRF-Token": csrf_of(client.get("/login/2fa").text)}
    client.post("/webauthn/auth/options", headers=h, json={})

    def boom(*a):
        raise ValueError("bad signature")

    monkeypatch.setattr(wa, "verify_authentication", boom)
    cid = base64.urlsafe_b64encode(b"cred-1").rstrip(b"=").decode()
    r = client.post("/webauthn/auth/verify", headers=h, json={"id": cid})
    assert r.status_code == 401
    assert client.get("/dashboard", follow_redirects=False).status_code == 303


def test_ip_throttle_escalates_and_sets_retry_after(client):
    from periscope.web import routes_auth
    make_user()
    routes_auth.limiter.max = 1
    try:
        assert post_login(client, "x", "y").status_code == 401
        r = post_login(client, "x", "y")
        assert r.status_code == 429 and r.headers["retry-after"] == "60"
    finally:
        routes_auth.limiter.max = 20


def test_2fa_ip_throttle_is_separate_bucket(client):
    from periscope.web import routes_auth
    make_user()
    post_login(client)
    csrf = csrf_of(client.get("/login/2fa").text)
    routes_auth.limiter.max = 2
    try:
        codes = [client.post("/login/2fa", data={"code": "000000", "csrf": csrf}).status_code for _ in range(3)]
    finally:
        routes_auth.limiter.max = 20
    assert codes == [401, 401, 429]


def test_enroll_ip_throttle(client):
    from periscope.web import routes_auth
    make_user(totp=False)
    post_login(client)
    page = client.get("/enroll")
    routes_auth.limiter.max = 1
    try:
        codes = [client.post("/enroll", data={"code": "000000", "csrf": csrf_of(page.text)}).status_code
                 for _ in range(2)]
    finally:
        routes_auth.limiter.max = 20
    assert codes == [401, 429]


def test_enroll_page_offers_passkey_button(client):
    make_user(totp=False)
    post_login(client)
    assert 'data-passkey="enroll"' in client.get("/enroll").text


def test_first_enrollment_with_passkey(client, monkeypatch):
    make_user(totp=False)
    post_login(client)
    h = {"X-CSRF-Token": csrf_of(client.get("/enroll").text)}
    opts = client.post("/webauthn/enroll/options", headers=h, json={})
    assert opts.status_code == 200 and "challenge" in opts.json()
    monkeypatch.setattr(wa, "verify_registration", lambda cred, ch: (b"pk-1", b"pub", 3))
    r = client.post("/webauthn/enroll/verify", headers=h, json={})
    assert r.status_code == 200 and r.json() == {"ok": True, "redirect": "/account?m=codes_hint"}
    page = client.get("/account?m=codes_hint")
    assert page.status_code == 200 and "Remember to generate your backup codes" in page.text
    with session_scope() as s:
        c = s.query(Credential).one()
        assert c.credential_id == b"pk-1" and c.sign_count == 3
    assert audit_events()[-1] == "login"


def test_passkey_enroll_failure_keeps_session_pending(client, monkeypatch):
    make_user(totp=False)
    post_login(client)
    h = {"X-CSRF-Token": csrf_of(client.get("/enroll").text)}
    client.post("/webauthn/enroll/options", headers=h, json={})

    def boom(*a):
        raise ValueError("bad")

    monkeypatch.setattr(wa, "verify_registration", boom)
    assert client.post("/webauthn/enroll/verify", headers=h, json={}).status_code == 400
    assert client.get("/dashboard", follow_redirects=False).status_code == 303
    with session_scope() as s:
        assert s.query(Credential).count() == 0


def test_passkey_enroll_refused_when_user_has_second_factor(client):
    make_user()  # TOTP already active
    post_login(client)
    h = {"X-CSRF-Token": csrf_of(client.get("/login/2fa").text)}
    assert client.post("/webauthn/enroll/options", headers=h, json={}).status_code == 403
    assert client.post("/webauthn/enroll/verify", headers=h, json={}).status_code == 403


def test_passkey_enroll_requires_pending_session_and_csrf(client):
    make_user(totp=False)
    assert client.post("/webauthn/enroll/options", json={}, follow_redirects=False).status_code == 303
    post_login(client)
    assert client.post("/webauthn/enroll/options", json={}).status_code == 403  # no CSRF
