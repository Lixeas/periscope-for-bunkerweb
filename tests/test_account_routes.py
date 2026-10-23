import pytest

from mc.auth.passwords import verify_password
from mc.db import session_scope
from mc.models import Credential, Session, User
from tests.helpers import PW, csrf_of, full_login, make_client, make_user


@pytest.fixture
def client(fresh_db):
    with make_client() as c:
        yield c


@pytest.fixture
def logged(client):
    secret = make_user()
    assert full_login(client, secret).status_code == 303
    page = client.get("/account")
    return client, csrf_of(page.text)


def test_account_page_shows_factors(logged):
    client, _ = logged
    page = client.get("/account")
    assert page.status_code == 200 and "TOTP" in page.text and "Passkeys" in page.text


def test_change_password(logged):
    client, csrf = logged
    new = "another long passphrase"
    r = client.post("/account/password", follow_redirects=False,
                    data={"csrf": csrf, "current": "wrong", "new": new, "confirm": new})
    assert r.headers["location"] == "/account?m=pwd_bad"
    r = client.post("/account/password", follow_redirects=False,
                    data={"csrf": csrf, "current": PW, "new": "short", "confirm": "short"})
    assert r.headers["location"] == "/account?m=pwd_short"
    r = client.post("/account/password", follow_redirects=False,
                    data={"csrf": csrf, "current": PW, "new": new, "confirm": "different one here"})
    assert r.headers["location"] == "/account?m=pwd_mismatch"
    r = client.post("/account/password", follow_redirects=False,
                    data={"csrf": csrf, "current": PW, "new": new, "confirm": new})
    assert r.headers["location"] == "/account?m=pwd_ok"
    with session_scope() as s:
        assert verify_password(s.query(User).one().password_hash, new)


def test_change_password_revokes_other_sessions(logged):
    client, csrf = logged
    with session_scope() as s:
        user = s.query(User).one()
        from mc.auth import sessions
        from mc.clock import utcnow
        sessions.create(s, user, True, utcnow())  # une autre session
        assert s.query(Session).count() == 2
    new = "another long passphrase"
    client.post("/account/password", data={"csrf": csrf, "current": PW, "new": new, "confirm": new})
    with session_scope() as s:
        assert s.query(Session).count() == 1


def test_regenerate_backup_codes_requires_password(logged):
    client, csrf = logged
    r = client.post("/account/backup-codes", data={"csrf": csrf, "password": "wrong"}, follow_redirects=False)
    assert r.headers["location"] == "/account?m=pwd_bad"
    r = client.post("/account/backup-codes", data={"csrf": csrf, "password": PW})
    assert r.status_code == 200 and "une seule fois" in r.text
    with session_scope() as s:
        assert len(s.query(User).one().backup_codes) == 10


def test_cannot_remove_last_second_factor(logged):
    client, csrf = logged
    r = client.post("/account/totp/remove", data={"csrf": csrf, "password": PW}, follow_redirects=False)
    assert r.headers["location"] == "/account?m=last_factor"
    with session_scope() as s:
        assert s.query(User).one().totp_confirmed is True


def test_remove_totp_when_passkey_exists_and_delete_passkey_guard(logged):
    client, csrf = logged
    with session_scope() as s:
        user = s.query(User).one()
        user.credentials.append(Credential(credential_id=b"c1", public_key=b"k"))
        s.flush()
        cred_id = s.query(Credential).one().id
    r = client.post("/account/totp/remove", data={"csrf": csrf, "password": PW}, follow_redirects=False)
    assert r.headers["location"] == "/account?m=totp_removed"
    r = client.post(f"/account/passkeys/{cred_id}/delete", data={"csrf": csrf, "password": PW}, follow_redirects=False)
    assert r.headers["location"] == "/account?m=last_factor"  # c'est maintenant le dernier facteur
    with session_scope() as s:
        assert s.query(Credential).count() == 1


def test_account_requires_login(client):
    assert client.get("/account", follow_redirects=False).status_code == 303


def test_reauth_failures_lock_the_account(logged):
    client, csrf = logged
    for _ in range(5):
        r = client.post("/account/backup-codes", data={"csrf": csrf, "password": "wrong"}, follow_redirects=False)
        assert r.headers["location"] == "/account?m=pwd_bad"
    r = client.post("/account/backup-codes", data={"csrf": csrf, "password": PW}, follow_redirects=False)
    assert r.headers["location"] == "/account?m=locked"


def _other_session():
    from mc.auth import sessions
    from mc.clock import utcnow
    with session_scope() as s:
        user = s.query(User).one()
        sessions.create(s, user, True, utcnow())
        return s.query(Session).count()


def _sessions():
    with session_scope() as s:
        return s.query(Session).count()


def _events():
    from mc.models import AuditLog
    with session_scope() as s:
        return [e.event for e in s.query(AuditLog).order_by(AuditLog.id)]


def _add_cred():
    with session_scope() as s:
        user = s.query(User).one()
        user.credentials.append(Credential(credential_id=b"c1", public_key=b"k"))
        s.flush()
        return s.query(Credential).one().id


def test_passkey_delete_closes_other_sessions(logged):
    client, csrf = logged
    cred_id = _add_cred()
    assert _other_session() == 2
    r = client.post(f"/account/passkeys/{cred_id}/delete", data={"csrf": csrf, "password": PW},
                    follow_redirects=False)
    assert r.headers["location"] == "/account?m=pk_deleted"
    assert _sessions() == 1
    assert "sessions_revoked" in _events()
    assert client.get("/account").status_code == 200  # la session courante survit


def test_totp_remove_closes_other_sessions(logged):
    client, csrf = logged
    _add_cred()
    assert _other_session() == 2
    client.post("/account/totp/remove", data={"csrf": csrf, "password": PW})
    assert _sessions() == 1
    assert "sessions_revoked" in _events()


def test_backup_codes_regeneration_closes_other_sessions(logged):
    client, csrf = logged
    assert _other_session() == 2
    client.post("/account/backup-codes", data={"csrf": csrf, "password": PW})
    assert _sessions() == 1


def test_failed_reauth_keeps_other_sessions(logged):
    client, csrf = logged
    assert _other_session() == 2
    client.post("/account/backup-codes", data={"csrf": csrf, "password": "wrong"})
    assert _sessions() == 2


def test_passkey_register_closes_other_sessions(logged, monkeypatch):
    from mc.auth import webauthn_ as wa
    client, csrf = logged
    h = {"X-CSRF-Token": csrf}
    assert client.post("/webauthn/register/options", headers=h, json={"password": PW}).status_code == 200
    monkeypatch.setattr(wa, "verify_registration", lambda cred, ch: (b"new", b"pub", 0))
    assert _other_session() == 2
    assert client.post("/webauthn/register/verify", headers=h, json={}).json() == {"ok": True}
    assert _sessions() == 1


def test_passkey_register_options_requires_password(logged):
    client, csrf = logged
    h = {"X-CSRF-Token": csrf}
    r = client.post("/webauthn/register/options", headers=h, json={})
    assert r.status_code == 403 and "error" in r.json()
    r = client.post("/webauthn/register/options", headers=h, json={"password": "wrong"})
    assert r.status_code == 403
    assert "reauth_failed" in _events()
    assert client.post("/webauthn/register/options", headers=h, json={"password": PW}).status_code == 200


def test_account_page_has_password_field_for_passkey(logged):
    client, _ = logged
    assert 'id="pk-add-pw"' in client.get("/account").text
