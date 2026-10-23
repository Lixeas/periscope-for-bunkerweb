import pytest

from periscope.auth import mfa
from periscope.auth.passwords import verify_password
from periscope.auth.users import create_user
from periscope.clock import utcnow
from periscope.db import session_scope
from periscope.models import Credential, Session, User
from tests.helpers import PW, login_as, make_client


@pytest.fixture
def client(fresh_db):
    with make_client() as c:
        yield c


@pytest.fixture
def csrf(client):
    return login_as(client)  # alice, admin


def post(client, csrf, path, **data):
    return client.post(path, data={"csrf": csrf, **data}, follow_redirects=False)


def uid(name):
    with session_scope() as s:
        return s.query(User).filter_by(username=name).one().id


def test_create_user_and_listing(client, csrf):
    r = post(client, csrf, "/admin/users", username="bob", role="reader", password="temporary password 1")
    assert r.status_code == 303 and r.headers["location"] == "/admin/users?m=created"
    with session_scope() as s:
        bob = s.query(User).filter_by(username="bob").one()
        assert bob.role == "reader" and not bob.totp_confirmed
    page = client.get("/admin/users")
    assert "bob" in page.text and "temporary password 1" not in page.text


def test_create_user_errors(client, csrf):
    r = client.post("/admin/users", data={"csrf": csrf, "username": "bob", "role": "reader", "password": "short"})
    assert r.status_code == 400 and "too short" in r.text
    r = client.post("/admin/users", data={"csrf": csrf, "username": "alice", "role": "reader", "password": PW})
    assert r.status_code == 400 and "already exists" in r.text


def test_cannot_delete_self_or_last_admin_or_demote_last_admin(client, csrf):
    me = uid("alice")
    assert post(client, csrf, f"/admin/users/{me}/delete").headers["location"] == "/admin/users?m=self"
    assert post(client, csrf, f"/admin/users/{me}/role", role="reader").headers["location"] == "/admin/users?m=last_admin"
    with session_scope() as s:
        create_user(s, "carol", PW, "admin")
    carol = uid("carol")
    assert post(client, csrf, f"/admin/users/{carol}/role", role="reader").headers["location"] == "/admin/users?m=role_ok"
    # alice is the only admin again: can no longer demote herself
    assert post(client, csrf, f"/admin/users/{me}/role", role="reader").headers["location"] == "/admin/users?m=last_admin"


def test_delete_other_user(client, csrf):
    with session_scope() as s:
        create_user(s, "bob", PW)
    assert post(client, csrf, f"/admin/users/{uid('bob')}/delete").headers["location"] == "/admin/users?m=deleted"
    with session_scope() as s:
        assert s.query(User).filter_by(username="bob").count() == 0


def test_reset_2fa_clears_factors_and_sessions(client, csrf):
    with session_scope() as s:
        bob = create_user(s, "bob", PW)
        bob.totp_secret_enc, bob.totp_confirmed = mfa.new_secret_enc(), True
        bob.credentials.append(Credential(credential_id=b"c", public_key=b"k"))
        mfa.reset_backup_codes(s, bob)
        s.flush()
        from periscope.auth import sessions
        sessions.create(s, bob, True, utcnow())
    r = post(client, csrf, f"/admin/users/{uid('bob')}/reset-2fa")
    assert r.headers["location"] == "/admin/users?m=reset_ok"
    with session_scope() as s:
        bob = s.query(User).filter_by(username="bob").one()
        assert not bob.totp_confirmed and bob.totp_secret_enc is None
        assert not bob.credentials and not bob.backup_codes
        assert s.query(Session).filter_by(user_id=bob.id).count() == 0
        assert not mfa.has_second_factor(bob)


def test_reset_password_unlocks_and_revokes_sessions(client, csrf):
    with session_scope() as s:
        bob = create_user(s, "bob", PW)
        bob.failed_attempts, bob.locked_until = 7, utcnow()
    r = post(client, csrf, f"/admin/users/{uid('bob')}/password", password="brand new passphrase")
    assert r.headers["location"] == "/admin/users?m=pwd_ok"
    with session_scope() as s:
        bob = s.query(User).filter_by(username="bob").one()
        assert verify_password(bob.password_hash, "brand new passphrase")
        assert bob.failed_attempts == 0 and bob.locked_until is None
    r = post(client, csrf, f"/admin/users/{uid('bob')}/password", password="short")
    assert r.headers["location"] == "/admin/users?m=pwd_short"


def test_self_reset_goes_through_account_page(client, csrf):
    me = uid("alice")
    assert post(client, csrf, f"/admin/users/{me}/reset-2fa").headers["location"] == "/admin/users?m=self"
    assert post(client, csrf, f"/admin/users/{me}/password", password="brand new passphrase"
                ).headers["location"] == "/admin/users?m=self"


def test_audit_page_lists_admin_actions_and_is_admin_only(client, csrf):
    post(client, csrf, "/admin/users", username="bob", role="reader", password="temporary password 1")
    page = client.get("/admin/audit")
    assert page.status_code == 200 and "user_created" in page.text and "alice" in page.text
    with make_client() as c2:
        login_as(c2, "reader1", "reader")
        assert c2.get("/admin/audit").status_code == 403
        assert c2.get("/admin/users").status_code == 403
