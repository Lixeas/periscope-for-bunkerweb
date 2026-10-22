from mc.auth import webauthn_ as wa
from mc.auth.users import create_user
from mc.db import session_scope
from mc.models import Credential


def test_registration_options_shape_and_exclusion(fresh_db):
    with session_scope() as s:
        user = create_user(s, "alice", "correct horse battery")
        user.credentials.append(Credential(credential_id=b"abc", public_key=b"k"))
        s.flush()
        opts, challenge = wa.registration_options(user)
    assert opts["rp"]["id"] == "localhost" and opts["user"]["name"] == "alice"
    assert isinstance(challenge, bytes) and len(challenge) >= 16
    assert len(opts["excludeCredentials"]) == 1


def test_authentication_options_list_allowed_credentials(fresh_db):
    with session_scope() as s:
        user = create_user(s, "alice", "correct horse battery")
        user.credentials.append(Credential(credential_id=b"abc", public_key=b"k"))
        s.flush()
        opts, challenge = wa.authentication_options(user)
    assert opts["rpId"] == "localhost" and len(opts["allowCredentials"]) == 1
    assert isinstance(challenge, bytes)
