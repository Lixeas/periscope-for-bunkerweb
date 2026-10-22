import base64

import pyotp
import pytest

from mc.auth import mfa
from mc.auth import webauthn_ as wa
from mc.db import session_scope
from mc.models import AuditLog, BackupCode, Credential, User
from tests.helpers import PW, csrf_of, make_client, make_user, post_login


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


def test_full_login_with_totp_then_dashboard_then_logout(client):
    secret = make_user()
    r = post_login(client)
    assert r.status_code == 303 and r.headers["location"] == "/login/2fa"
    assert client.get("/dashboard", follow_redirects=False).status_code == 303  # session en attente : pas d'accès
    page = client.get("/login/2fa")
    r = client.post("/login/2fa", data={"code": pyotp.TOTP(secret).now(), "csrf": csrf_of(page.text)},
                    follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    dash = client.get("/dashboard")
    assert dash.status_code == 200 and "alice" in dash.text
    assert audit_events() == ["password_ok", "login"]
    assert client.post("/logout", data={}, follow_redirects=False).status_code == 403  # sans CSRF
    r = client.post("/logout", data={"csrf": csrf_of(dash.text)}, follow_redirects=False)
    assert r.status_code == 303
    assert client.get("/dashboard", follow_redirects=False).status_code == 303


def test_wrong_password_and_unknown_user_look_identical(client):
    make_user()
    r1 = post_login(client, "alice", "wrong password here")
    r2 = post_login(client, "nobody", "wrong password here")
    assert r1.status_code == r2.status_code == 401
    assert r1.text == r2.text and "invalides" in r1.text
    assert audit_events() == ["login_failed", "login_failed"]


def test_account_locks_after_five_failures_even_with_good_password(client):
    make_user()
    for _ in range(5):
        post_login(client, "alice", "wrong password here")
    r = post_login(client)
    assert r.status_code == 401
    assert "login_locked" in audit_events()


def test_ip_throttle(client):
    make_user()
    from mc.web import routes_auth
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
    assert r.status_code == 200 and "une seule fois" in r.text
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
