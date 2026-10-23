import pytest

from periscope.auth.users import create_user
from periscope.db import session_scope
from periscope.models import User


def test_create_user_and_reject_duplicates_and_bad_input(fresh_db):
    with session_scope() as s:
        u = create_user(s, "alice", "correct horse battery", "admin")
        assert u.role == "admin" and u.password_hash.startswith("$argon2id$")
    with session_scope() as s:
        with pytest.raises(ValueError, match="existant"):
            create_user(s, "alice", "correct horse battery")
        with pytest.raises(ValueError, match="invalide"):
            create_user(s, "a b", "correct horse battery")
        with pytest.raises(ValueError, match="rôle"):
            create_user(s, "bob", "correct horse battery", "root")
        assert s.query(User).count() == 1
