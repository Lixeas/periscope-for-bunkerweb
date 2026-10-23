from datetime import datetime, timedelta

from periscope.auth import sessions
from periscope.auth.users import create_user
from periscope.db import session_scope
from periscope.models import Session

T0 = datetime(2026, 1, 1, 12, 0)
IDLE, MAXAGE = 8 * 3600, 24 * 3600


def mk(s):
    return create_user(s, "alice", "correct horse battery")


def test_token_not_stored_in_clear_and_lookup_touches(fresh_db):
    with session_scope() as s:
        user = mk(s)
        token, row = sessions.create(s, user, True, T0)
        assert row.id != token and len(row.id) == 64
        found = sessions.lookup(s, token, T0 + timedelta(hours=1), IDLE, MAXAGE)
        assert found is row and found.last_seen == T0 + timedelta(hours=1)


def test_idle_and_absolute_expiry(fresh_db):
    with session_scope() as s:
        user = mk(s)
        token, _ = sessions.create(s, user, True, T0)
        assert sessions.lookup(s, token, T0 + timedelta(hours=9), IDLE, MAXAGE) is None
        token, _ = sessions.create(s, user, True, T0)
        for h in (7, 14, 21):  # actif toutes les 7 h : idle OK mais plafond 24 h
            assert sessions.lookup(s, token, T0 + timedelta(hours=h), IDLE, MAXAGE) is not None
        assert sessions.lookup(s, token, T0 + timedelta(hours=25), IDLE, MAXAGE) is None


def test_pending_session_short_ttl(fresh_db):
    with session_scope() as s:
        user = mk(s)
        token, _ = sessions.create(s, user, False, T0)
        assert sessions.lookup(s, token, T0 + timedelta(seconds=299), IDLE, MAXAGE) is not None
        assert sessions.lookup(s, token, T0 + timedelta(seconds=299 + 301), IDLE, MAXAGE) is None


def test_promote_rotates_token(fresh_db):
    with session_scope() as s:
        user = mk(s)
        old, row = sessions.create(s, user, False, T0)
        new = sessions.promote(s, row, user, T0)
        assert new != old
        assert sessions.lookup(s, old, T0, IDLE, MAXAGE) is None
        assert sessions.lookup(s, new, T0, IDLE, MAXAGE).mfa_ok is True


def test_destroy_and_purge(fresh_db):
    with session_scope() as s:
        user = mk(s)
        token, _ = sessions.create(s, user, True, T0)
        sessions.destroy(s, token)
        assert s.query(Session).count() == 0
        sessions.create(s, user, True, T0)
        sessions.create(s, user, True, T0 + timedelta(days=3))  # purge les sessions de plus de 24 h d'inactivité
        assert s.query(Session).count() == 1
