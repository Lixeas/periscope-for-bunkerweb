import hashlib
import hmac
import secrets
import time

import pyotp
from sqlalchemy.orm import Session

from periscope.crypto import decrypt, encrypt
from periscope.models import BackupCode, User


def has_second_factor(user: User) -> bool:
    return user.totp_confirmed or bool(user.credentials)


def new_secret_enc() -> str:
    return encrypt(pyotp.random_base32())


def secret_plain(secret_enc: str) -> str:
    return decrypt(secret_enc)


def provisioning_uri(secret_enc: str, username: str, issuer: str) -> str:
    return pyotp.TOTP(decrypt(secret_enc)).provisioning_uri(name=username, issuer_name=issuer)


def verify_totp(secret_enc: str, code: str, last_step: int) -> int | None:
    """Return the accepted TOTP step (to store in user.totp_last_step) or None.
    ±1 step window; an already consumed step is rejected (replay protection)."""
    totp = pyotp.TOTP(decrypt(secret_enc))
    code = code.strip().replace(" ", "")
    cur = int(time.time() // 30)
    for step in (cur - 1, cur, cur + 1):
        if step > last_step and hmac.compare_digest(totp.at(step * 30), code):
            return step
    return None


def _hash(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()  # codes carry 96 bits of entropy: SHA-256 is enough


def reset_backup_codes(db: Session, user: User, n: int = 10) -> list[str]:
    """Replace the codes; return the plaintext codes (to display only once)."""
    plain = [secrets.token_urlsafe(12) for _ in range(n)]
    user.backup_codes.clear()
    user.backup_codes.extend(BackupCode(code_hash=_hash(c)) for c in plain)
    return plain


def consume_backup(user: User, code: str) -> bool:
    h = _hash(code.strip())
    for b in user.backup_codes:
        if not b.used and hmac.compare_digest(b.code_hash, h):
            b.used = True
            return True
    return False
