import time

import pyotp

from periscope.auth import mfa
from periscope.auth.users import create_user
from periscope.db import session_scope


def test_totp_accepts_valid_and_rejects_replay_and_wrong(fresh_db):
    enc = mfa.new_secret_enc()
    secret = mfa.secret_plain(enc)
    code = pyotp.TOTP(secret).now()
    step = mfa.verify_totp(enc, code, last_step=0)
    assert step == int(time.time() // 30) or step in (int(time.time() // 30) - 1, int(time.time() // 30) + 1)
    assert mfa.verify_totp(enc, code, last_step=step) is None  # rejeu
    assert mfa.verify_totp(enc, "000000" if code != "000000" else "111111", 0) is None
    assert mfa.verify_totp(enc, " " + code[:3] + " " + code[3:], 0) == step  # spaces tolerated


def test_provisioning_uri_contains_issuer_and_user():
    uri = mfa.provisioning_uri(mfa.new_secret_enc(), "alice", "Periscope")
    assert uri.startswith("otpauth://totp/") and "alice" in uri and "Periscope" in uri


def test_backup_codes_single_use_and_stored_hashed(fresh_db):
    with session_scope() as s:
        user = create_user(s, "alice", "correct horse battery")
        codes = mfa.reset_backup_codes(s, user)
        assert len(codes) == 10 and len(set(codes)) == 10
        assert all(codes[0] not in b.code_hash for b in user.backup_codes)
        assert mfa.consume_backup(user, codes[0]) is True
        assert mfa.consume_backup(user, codes[0]) is False
        assert mfa.consume_backup(user, "nope") is False
        mfa.reset_backup_codes(s, user)
        assert sum(not b.used for b in user.backup_codes) == 10


def test_has_second_factor(fresh_db):
    with session_scope() as s:
        user = create_user(s, "alice", "correct horse battery")
        assert mfa.has_second_factor(user) is False
        user.totp_confirmed = True
        assert mfa.has_second_factor(user) is True
