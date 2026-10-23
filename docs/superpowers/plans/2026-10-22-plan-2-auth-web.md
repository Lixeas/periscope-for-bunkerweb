> Note: this document is historical. The project was called "BunkerWeb Mission Control"; it has since been renamed "Periscope for BunkerWeb" (package `periscope`, prefix `PERISCOPE_`). The names below are the original ones.

# BunkerWeb Mission Control — Plan 2/3: Authentication and web shell

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Strong authentication (argon2id password + mandatory TOTP/passkey/backup codes, server-side sessions, CSRF, brute-force protection, audit), FastAPI application with security headers, login/enrollment/account pages, CLI to bootstrap the first admin.

**Architecture:** Package `mc.auth` (pure logic + DB access, testable without the web layer) and `mc.web` (FastAPI: session dependencies, routes, Jinja2 templates, static files served locally to comply with a `'self'` CSP). Two-step login: the password creates a "pending" session (`mfa_ok=False`, short TTL); the second factor replaces it with a full session (token rotation).

**Tech Stack:** FastAPI, Jinja2, argon2-cffi, pyotp, py_webauthn (`webauthn`), segno (QR PNG), Bootstrap 5.3 (CSS seul, copie locale).

**Prerequisites:** Plan 1 completed (`docs/superpowers/plans/2026-10-22-plan-1-core.md`).

**Assumption to verify (Task 5):** `webauthn` API ≥ 2.2 (`generate_*_options`, `verify_*_response`, `options_to_json`). If a signature differs at install time, only adapt `src/mc/auth/webauthn_.py`.

**Browsers:** the passkey JS uses `PublicKeyCredential.parseCreationOptionsFromJSON` / `toJSON()` (Chrome ≥ 129, Safari ≥ 18.4, Firefox ≥ 119). Otherwise TOTP remains available.

---

## File structure

```
src/mc/auth/__init__.py
src/mc/auth/passwords.py   argon2id, minimum length
src/mc/auth/users.py       create_user (CLI + future admin UI)
src/mc/auth/audit.py       audit()
src/mc/auth/mfa.py         TOTP (replay protection), backup codes, has_second_factor
src/mc/auth/ratelimit.py   per-account lockout, per-IP limiter
src/mc/auth/sessions.py    server-side sessions, rotation
src/mc/auth/webauthn_.py   py_webauthn wrapper
src/mc/web/__init__.py
src/mc/web/app.py          create_app(), security middleware
src/mc/web/deps.py         session/CSRF/role dependencies, Redirect
src/mc/web/render.py       template rendering
src/mc/web/routes_auth.py  login, 2FA, enrollment, logout, passkeys
src/mc/web/routes_account.py  /account page
src/mc/web/routes_pages.py    "/" and "/dashboard" (replaced in Plan 3)
src/mc/web/templates/*.html
src/mc/web/static/{app.js,app.css,bootstrap.min.css}
src/mc/cli.py              bootstrap-admin, migrate
```

Addition to Plan 1: `User.totp_last_step` column (Task 1 below).

---

### Task 1: Passwords, users, audit

**Files:**
- Modify: `src/mc/models.py` (`totp_last_step` column)
- Create: `src/mc/auth/__init__.py`, `src/mc/auth/passwords.py`, `src/mc/auth/users.py`, `src/mc/auth/audit.py`
- Test: `tests/test_passwords.py`, `tests/test_users.py`

- [ ] **Step 1: Add the column and regenerate the migration**

In `src/mc/models.py`, class `User`, after `totp_confirmed`:
```python
    totp_last_step: Mapped[int] = mapped_column(default=0)  # TOTP replay protection
```
If migration `0001` has not been pushed to production (true here: nothing deployed yet), regenerate it:
```bash
rm src/mc/migrations/versions/0001_initial_schema.py
mkdir -p data
alembic revision --autogenerate -m "initial schema" --rev-id 0001
rm -f data/autogen.db
python -m pytest tests/test_migrate.py -q
```
Expected: 1 passed.

- [ ] **Step 2: Write the tests**

`tests/test_passwords.py`:
```python
import pytest

from mc.auth.passwords import hash_password, verify_password


def test_hash_is_argon2id_and_verifies():
    h = hash_password("correct horse battery")
    assert h.startswith("$argon2id$")
    assert verify_password(h, "correct horse battery")
    assert not verify_password(h, "wrong password here")


def test_min_length_enforced():
    with pytest.raises(ValueError):
        hash_password("short")


def test_unknown_user_hash_is_false_but_still_hashes():
    assert verify_password(None, "whatever password") is False
```

`tests/test_users.py`:
```python
import pytest

from mc.auth.users import create_user
from mc.db import session_scope
from mc.models import User


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
```

- [ ] **Step 3: Run, verify failure**

Run: `python -m pytest tests/test_passwords.py tests/test_users.py -v`
Expected: FAIL (`ModuleNotFoundError: mc.auth`).

- [ ] **Step 4: Implement**

`src/mc/auth/__init__.py`: empty file.

`src/mc/auth/passwords.py` :
```python
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

MIN_LENGTH = 12
_ph = PasswordHasher()  # argon2id by default
_DUMMY = _ph.hash("dummy-password-for-timing")


def hash_password(password: str) -> str:
    if len(password) < MIN_LENGTH:
        raise ValueError(f"mot de passe trop court ({MIN_LENGTH} caractères minimum)")
    return _ph.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    """Unknown user (None): still verify a dummy hash to equalize timing."""
    try:
        _ph.verify(password_hash or _DUMMY, password)
    except (VerifyMismatchError, InvalidHashError):
        return False
    return password_hash is not None
```

`src/mc/auth/users.py` :
```python
import re

from sqlalchemy.orm import Session

from mc.auth.passwords import hash_password
from mc.models import User


def create_user(db: Session, username: str, password: str, role: str = "reader") -> User:
    username = username.strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,64}", username):
        raise ValueError("nom d'utilisateur invalide (3-64 caractères : lettres, chiffres, . _ -)")
    if role not in ("admin", "reader"):
        raise ValueError("rôle invalide")
    if db.query(User).filter_by(username=username).first():
        raise ValueError("utilisateur déjà existant")
    user = User(username=username, password_hash=hash_password(password), role=role)
    db.add(user)
    db.flush()
    return user
```

`src/mc/auth/audit.py` :
```python
from sqlalchemy.orm import Session

from mc.models import AuditLog


def audit(db: Session, event: str, username: str = "", detail: str = "", ip: str = "") -> None:
    db.add(AuditLog(event=event, username=username[:64], detail=detail[:512], ip=ip[:64]))
```

- [ ] **Step 5: Run, verify success**

Run: `python -m pytest tests/test_passwords.py tests/test_users.py -v`
Expected: 4 passed.

- [ ] **Step 6: Commit**

```bash
git add src/mc/models.py src/mc/migrations src/mc/auth tests/test_passwords.py tests/test_users.py
git commit -m "feat: password hashing, user creation, audit helper"
```

---

### Task 2: Second factor (TOTP, backup codes)

**Files:**
- Create: `src/mc/auth/mfa.py`
- Test: `tests/test_mfa.py`

- [ ] **Step 1: Write the test**

```python
import time

import pyotp

from mc.auth import mfa
from mc.auth.users import create_user
from mc.db import session_scope


def test_totp_accepts_valid_and_rejects_replay_and_wrong(fresh_db):
    enc = mfa.new_secret_enc()
    secret = mfa.secret_plain(enc)
    code = pyotp.TOTP(secret).now()
    step = mfa.verify_totp(enc, code, last_step=0)
    assert step == int(time.time() // 30) or step in (int(time.time() // 30) - 1, int(time.time() // 30) + 1)
    assert mfa.verify_totp(enc, code, last_step=step) is None  # replay
    assert mfa.verify_totp(enc, "000000" if code != "000000" else "111111", 0) is None
    assert mfa.verify_totp(enc, " " + code[:3] + " " + code[3:], 0) == step  # spaces tolerated


def test_provisioning_uri_contains_issuer_and_user():
    uri = mfa.provisioning_uri(mfa.new_secret_enc(), "alice", "Mission Control")
    assert uri.startswith("otpauth://totp/") and "alice" in uri and "Mission%20Control" in uri


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
```

- [ ] **Step 2: Run, verify failure**

Run: `python -m pytest tests/test_mfa.py -v`
Expected: FAIL (`ImportError`).

- [ ] **Step 3: Implement `src/mc/auth/mfa.py`**

```python
import hashlib
import hmac
import secrets
import time

import pyotp
from sqlalchemy.orm import Session

from mc.crypto import decrypt, encrypt
from mc.models import BackupCode, User


def has_second_factor(user: User) -> bool:
    return user.totp_confirmed or bool(user.credentials)


def new_secret_enc() -> str:
    return encrypt(pyotp.random_base32())


def secret_plain(secret_enc: str) -> str:
    return decrypt(secret_enc)


def provisioning_uri(secret_enc: str, username: str, issuer: str) -> str:
    return pyotp.TOTP(decrypt(secret_enc)).provisioning_uri(name=username, issuer_name=issuer)


def verify_totp(secret_enc: str, code: str, last_step: int) -> int | None:
    """Return the accepted TOTP step (to be stored in user.totp_last_step) or None.
    ±1 step window; an already consumed step is rejected (replay protection)."""
    totp = pyotp.TOTP(decrypt(secret_enc))
    code = code.strip().replace(" ", "")
    cur = int(time.time() // 30)
    for step in (cur - 1, cur, cur + 1):
        if step > last_step and hmac.compare_digest(totp.at(step * 30), code):
            return step
    return None


def _hash(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()  # codes have 96 bits of entropy: SHA-256 is enough


def reset_backup_codes(db: Session, user: User, n: int = 10) -> list[str]:
    """Replace the codes; return the plaintext codes (to be shown only once)."""
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
```

- [ ] **Step 4: Run, verify success**

Run: `python -m pytest tests/test_mfa.py -v`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add src/mc/auth/mfa.py tests/test_mfa.py
git commit -m "feat: TOTP with replay protection and backup codes"
```

---

### Task 3: Brute-force protection

**Files:**
- Create: `src/mc/auth/ratelimit.py`
- Test: `tests/test_ratelimit.py`

- [ ] **Step 1: Write the test**

```python
from datetime import datetime, timedelta

from mc.auth import ratelimit
from mc.models import User

NOW = datetime(2026, 1, 1)


def test_lock_seconds_progression():
    assert [ratelimit.lock_seconds(n) for n in (1, 4, 5, 6, 7, 20)] == [0, 0, 30, 60, 120, 900]


def test_account_lock_cycle():
    u = User(username="a", password_hash="x", failed_attempts=0)
    for _ in range(4):
        ratelimit.register_failure(u, NOW)
    assert not ratelimit.is_locked(u, NOW)
    ratelimit.register_failure(u, NOW)
    assert ratelimit.is_locked(u, NOW)
    assert ratelimit.is_locked(u, NOW + timedelta(seconds=29))
    assert not ratelimit.is_locked(u, NOW + timedelta(seconds=31))
    ratelimit.register_success(u)
    assert u.failed_attempts == 0 and u.locked_until is None


def test_ip_limiter_window():
    lim = ratelimit.IPLimiter(max_events=3, window=10)
    assert [lim.hit("1.1.1.1", now=t) for t in (0, 1, 2, 3)] == [True, True, True, False]
    assert lim.hit("2.2.2.2", now=3) is True  # other IP
    assert lim.hit("1.1.1.1", now=11.5) is True  # window elapsed
```

- [ ] **Step 2: Run, verify failure**

Run: `python -m pytest tests/test_ratelimit.py -v`
Expected: FAIL (`ImportError`).

- [ ] **Step 3: Implement `src/mc/auth/ratelimit.py`**

```python
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

from mc.models import User

LOCK_AFTER = 5


def lock_seconds(failures: int) -> int:
    """0 up to 4 failures, then 30 s doubling with each failure, capped at 15 min."""
    return 0 if failures < LOCK_AFTER else min(900, 30 * 2 ** (failures - LOCK_AFTER))


def is_locked(user: User, now: datetime) -> bool:
    return user.locked_until is not None and user.locked_until > now


def register_failure(user: User, now: datetime) -> None:
    user.failed_attempts += 1
    secs = lock_seconds(user.failed_attempts)
    if secs:
        user.locked_until = now + timedelta(seconds=secs)


def register_success(user: User) -> None:
    user.failed_attempts = 0
    user.locked_until = None


class IPLimiter:
    """In-memory sliding window (single process); ponytail: Redis if we move to several workers."""

    def __init__(self, max_events: int = 20, window: float = 300):
        self.max, self.window = max_events, window
        self._events: dict[str, deque] = defaultdict(deque)

    def hit(self, ip: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        q = self._events[ip]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.max:
            return False
        q.append(now)
        return True

    def reset(self) -> None:
        self._events.clear()
```

- [ ] **Step 4: Run, verify success**

Run: `python -m pytest tests/test_ratelimit.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/mc/auth/ratelimit.py tests/test_ratelimit.py
git commit -m "feat: account lockout and per-IP limiter"
```

---

### Task 4: Server-side sessions

**Files:**
- Create: `src/mc/auth/sessions.py`
- Test: `tests/test_sessions.py`

- [ ] **Step 1: Write the test**

```python
from datetime import datetime, timedelta

from mc.auth import sessions
from mc.auth.users import create_user
from mc.db import session_scope
from mc.models import Session

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
        for h in (7, 14, 21):  # active every 7 h: idle OK but 24 h cap
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
        sessions.create(s, user, True, T0 + timedelta(days=3))  # purges sessions idle for more than 24 h
        assert s.query(Session).count() == 1
```

- [ ] **Step 2: Run, verify failure**

Run: `python -m pytest tests/test_sessions.py -v`
Expected: FAIL (`ImportError`).

- [ ] **Step 3: Implement `src/mc/auth/sessions.py`**

```python
import hashlib
import secrets
from datetime import datetime, timedelta

from sqlalchemy.orm import Session as DB

from mc.models import Session, User

COOKIE = "mc_session"
PENDING_IDLE = 300  # "password OK, 2FA pending" session
PENDING_MAX = 900


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create(db: DB, user: User, mfa_ok: bool, now: datetime) -> tuple[str, Session]:
    db.query(Session).filter(Session.last_seen < now - timedelta(days=1)).delete()  # purge
    token = secrets.token_urlsafe(32)
    row = Session(id=_hash(token), user_id=user.id, csrf=secrets.token_urlsafe(24),
                  mfa_ok=mfa_ok, created_at=now, last_seen=now)
    db.add(row)
    db.flush()
    return token, row


def lookup(db: DB, token: str, now: datetime, idle: int, max_age: int) -> Session | None:
    row = db.get(Session, _hash(token))
    if row is None:
        return None
    idle_limit, max_limit = (idle, max_age) if row.mfa_ok else (PENDING_IDLE, PENDING_MAX)
    if (now - row.last_seen > timedelta(seconds=idle_limit)
            or now - row.created_at > timedelta(seconds=max_limit)):
        db.delete(row)
        return None
    row.last_seen = now
    return row


def destroy(db: DB, token: str) -> None:
    row = db.get(Session, _hash(token))
    if row:
        db.delete(row)


def promote(db: DB, row: Session, user: User, now: datetime) -> str:
    """After 2FA validation: new full session, new token (session fixation protection)."""
    db.delete(row)
    token, _ = create(db, user, True, now)
    return token
```

- [ ] **Step 4: Run, verify success**

Run: `python -m pytest tests/test_sessions.py -v`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add src/mc/auth/sessions.py tests/test_sessions.py
git commit -m "feat: server-side sessions with rotation"
```

---

### Task 5: WebAuthn wrapper

**Files:**
- Create: `src/mc/auth/webauthn_.py`
- Test: `tests/test_webauthn_wrapper.py`

- [ ] **Step 1: Write the test** (the cryptographic checks are the library's; we test the shape of the options and the propagation of parameters)

```python
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
```

- [ ] **Step 2: Run, verify failure**

Run: `python -m pytest tests/test_webauthn_wrapper.py -v`
Expected: FAIL (`ImportError`).

- [ ] **Step 3: Implement `src/mc/auth/webauthn_.py`**

```python
import json

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

from mc.config import get_settings
from mc.models import Credential, User


def registration_options(user: User) -> tuple[dict, bytes]:
    cfg = get_settings()
    opts = generate_registration_options(
        rp_id=cfg.rp_id, rp_name=cfg.rp_name,
        user_id=str(user.id).encode(), user_name=user.username,
        exclude_credentials=[PublicKeyCredentialDescriptor(id=c.credential_id) for c in user.credentials],
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED),
    )
    return json.loads(options_to_json(opts)), opts.challenge


def verify_registration(credential: dict, challenge: bytes) -> tuple[bytes, bytes, int]:
    cfg = get_settings()
    v = verify_registration_response(
        credential=credential, expected_challenge=challenge,
        expected_rp_id=cfg.rp_id, expected_origin=cfg.origins)
    return v.credential_id, v.credential_public_key, v.sign_count


def authentication_options(user: User) -> tuple[dict, bytes]:
    cfg = get_settings()
    opts = generate_authentication_options(
        rp_id=cfg.rp_id,
        allow_credentials=[PublicKeyCredentialDescriptor(id=c.credential_id) for c in user.credentials],
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return json.loads(options_to_json(opts)), opts.challenge


def verify_authentication(credential: dict, challenge: bytes, stored: Credential) -> int:
    """Return the new signature counter."""
    cfg = get_settings()
    v = verify_authentication_response(
        credential=credential, expected_challenge=challenge,
        expected_rp_id=cfg.rp_id, expected_origin=cfg.origins,
        credential_public_key=stored.public_key, credential_current_sign_count=stored.sign_count)
    return v.new_sign_count
```

- [ ] **Step 4: Run, verify success**

Run: `python -m pytest tests/test_webauthn_wrapper.py -v`
Expected: 2 passed. If `ImportError`/`TypeError` from the library: check the docs of the installed version (`pip show webauthn`) and only adapt this file.

- [ ] **Step 5: Commit**

```bash
git add src/mc/auth/webauthn_.py tests/test_webauthn_wrapper.py
git commit -m "feat: WebAuthn wrapper"
```

---

### Task 6: Web shell (app, middleware, dependencies, static files)

**Files:**
- Create: `src/mc/web/__init__.py`, `app.py`, `deps.py`, `render.py`, `routes_pages.py`, `templates/base.html`, `templates/dashboard.html`, `static/app.js`, `static/app.css`, `static/bootstrap.min.css`
- Test: `tests/test_web_shell.py`

- [ ] **Step 1: Write the test**

```python
import pytest
from fastapi.testclient import TestClient

from mc.web.app import create_app


@pytest.fixture
def client(fresh_db):
    with TestClient(create_app(run_migrations=False)) as c:
        yield c


def test_unauthenticated_dashboard_redirects_to_login(client):
    r = client.get("/dashboard", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_security_headers_present(client):
    r = client.get("/dashboard", follow_redirects=False)
    csp = r.headers["content-security-policy"]
    assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp and "script-src 'self'" in csp
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["referrer-policy"] == "same-origin"


def test_static_assets_served_and_cacheable(client):
    r = client.get("/static/app.js")
    assert r.status_code == 200 and "no-store" not in r.headers.get("cache-control", "")


def test_foreign_origin_rejected_on_unsafe_methods(client):
    r = client.post("/login", headers={"origin": "https://evil.example"})
    assert r.status_code == 403
    r = client.post("/login", headers={"origin": "http://localhost:8000"})
    assert r.status_code != 403  # allowed origin (the route does not exist yet: 404/405 expected)


def test_docs_disabled(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
```

- [ ] **Step 2: Run, verify failure**

Run: `python -m pytest tests/test_web_shell.py -v`
Expected: FAIL (`ModuleNotFoundError: mc.web`).

- [ ] **Step 3: Copy Bootstrap locally**

Run:
```bash
mkdir -p src/mc/web/static src/mc/web/templates
curl -fsSL -o src/mc/web/static/bootstrap.min.css https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css
ls -l src/mc/web/static/bootstrap.min.css
```
Expected: a file of about 160 KB.

- [ ] **Step 4: Implement the Python files**

`src/mc/web/__init__.py`: empty file.

`src/mc/web/render.py` :
```python
from pathlib import Path

from fastapi import Request
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def render(request: Request, name: str, status: int = 200, **ctx):
    row = getattr(request.state, "session", None)
    ctx.setdefault("user", None)
    ctx["csrf"] = row.csrf if row else ""
    return templates.TemplateResponse(request, name, ctx, status_code=status)
```

`src/mc/web/deps.py` :
```python
import hmac

from fastapi import Depends, HTTPException, Request

from mc.auth import sessions
from mc.clock import utcnow
from mc.config import get_settings
from mc.db import get_db
from mc.models import Session, User


class Redirect(Exception):
    def __init__(self, url: str):
        self.url = url


def session_row(request: Request, db) -> Session | None:
    token = request.cookies.get(sessions.COOKIE)
    if not token:
        return None
    cfg = get_settings()
    return sessions.lookup(db, token, utcnow(), cfg.session_idle_seconds, cfg.session_max_seconds)


async def _check_csrf(request: Request, row: Session) -> None:
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    sent = request.headers.get("x-csrf-token")
    if sent is None:
        form = await request.form()
        sent = form.get("csrf")
    if not isinstance(sent, str) or not hmac.compare_digest(sent, row.csrf):
        raise HTTPException(403, "CSRF invalide")


async def _user_for(request: Request, db, *, full: bool) -> User:
    row = session_row(request, db)
    if row is None or row.mfa_ok != full:
        raise Redirect("/login")
    user = db.get(User, row.user_id)
    if user is None:
        raise Redirect("/login")
    await _check_csrf(request, row)
    request.state.session = row
    return user


async def pending_user(request: Request, db=Depends(get_db)) -> User:
    """Password validated, second factor pending."""
    return await _user_for(request, db, full=False)


async def current_user(request: Request, db=Depends(get_db)) -> User:
    return await _user_for(request, db, full=True)


async def require_admin(user: User = Depends(current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(403, "Réservé aux administrateurs")
    return user
```

`src/mc/web/routes_pages.py` :
```python
from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse

from mc.models import User
from mc.web.deps import current_user
from mc.web.render import render

router = APIRouter()


@router.get("/")
async def index():
    return RedirectResponse("/dashboard", 303)


@router.get("/dashboard")
async def dashboard(request: Request, user: User = Depends(current_user)):
    return render(request, "dashboard.html", user=user)
```

`src/mc/web/app.py` :
```python
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from mc.config import get_settings
from mc.db import migrate
from mc.web.deps import Redirect

CSP = ("default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


def create_app(run_migrations: bool = True) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        cfg = get_settings()
        if run_migrations:
            migrate()
        task = None
        if cfg.collector_enabled:
            from mc import collector

            task = asyncio.create_task(collector.run_forever())
        try:
            yield
        finally:
            if task:
                task.cancel()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

    @app.exception_handler(Redirect)
    async def _redirect(_: Request, exc: Redirect):
        return RedirectResponse(exc.url, 303)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        cfg = get_settings()
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            if origin and origin not in cfg.origins:
                return PlainTextResponse("Origine refusée", status_code=403)
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "same-origin"
        if cfg.cookie_secure:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if not request.url.path.startswith("/static/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    from mc.web import routes_pages

    app.include_router(routes_pages.router)
    return app
```

- [ ] **Step 5: Write templates and static files**

`src/mc/web/templates/base.html` :
```html
<!doctype html>
<html lang="fr" data-bs-theme="light">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{% block title %}Accueil{% endblock %} · BunkerWeb Mission Control</title>
  <link rel="stylesheet" href="/static/bootstrap.min.css">
  <link rel="stylesheet" href="/static/app.css">
  <script src="/static/app.js"></script>
</head>
<body>
{% if user %}
<nav class="navbar border-bottom mb-4">
  <div class="container d-flex flex-wrap gap-3 align-items-center">
    <a class="navbar-brand fw-semibold" href="/dashboard">Mission Control</a>
    <div class="d-flex flex-wrap gap-3 me-auto" id="main-nav">
      <a href="/dashboard">Accueil</a>
    </div>
    <button type="button" id="theme-toggle" class="btn btn-sm btn-outline-secondary">Thème</button>
    <a href="/account">{{ user.username }}</a>
    <form method="post" action="/logout" class="m-0">
      <input type="hidden" name="csrf" value="{{ csrf }}">
      <button class="btn btn-sm btn-outline-secondary">Déconnexion</button>
    </form>
  </div>
</nav>
{% endif %}
<main class="container pb-5">
{% block content %}{% endblock %}
</main>
</body>
</html>
```

`src/mc/web/templates/dashboard.html` :
```html
{% extends "base.html" %}
{% block title %}Accueil{% endblock %}
{% block content %}
<h1 class="h4">Bonjour {{ user.username }}</h1>
<p class="text-secondary">Connecté ({{ user.role }}).</p>
{% endblock %}
```

`src/mc/web/static/app.css` :
```css
body { min-height: 100vh; }
nav a { text-decoration: none; }
code.secret { word-break: break-all; }
```

`src/mc/web/static/app.js` :
```js
(() => {
  let t = "light";
  try {
    t = localStorage.getItem("theme") || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  } catch (e) { /* storage blocked: light theme */ }
  document.documentElement.setAttribute("data-bs-theme", t);
})();

async function api(url, body, csrf) {
  const r = await fetch(url, {
    method: "POST", credentials: "same-origin",
    headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf},
    body: JSON.stringify(body || {}),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || "Erreur " + r.status);
  return data;
}

async function registerPasskey(csrf) {
  const opts = await api("/webauthn/register/options", null, csrf);
  const cred = await navigator.credentials.create({publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(opts)});
  await api("/webauthn/register/verify", cred.toJSON(), csrf);
  location.reload();
}

async function loginPasskey(csrf) {
  const opts = await api("/webauthn/auth/options", null, csrf);
  const cred = await navigator.credentials.get({publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(opts)});
  const res = await api("/webauthn/auth/verify", cred.toJSON(), csrf);
  location.href = res.redirect;
}

document.addEventListener("DOMContentLoaded", () => {
  const toggle = document.getElementById("theme-toggle");
  if (toggle) {
    toggle.addEventListener("click", () => {
      const next = document.documentElement.getAttribute("data-bs-theme") === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-bs-theme", next);
      try { localStorage.setItem("theme", next); } catch (e) { /* ignored */ }
    });
  }
  document.querySelectorAll("[data-passkey]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const out = document.getElementById("passkey-error");
      if (out) out.textContent = "";
      try {
        const fn = btn.dataset.passkey === "register" ? registerPasskey : loginPasskey;
        await fn(btn.dataset.csrf);
      } catch (e) {
        if (out) out.textContent = e.message;
      }
    });
  });
});
```

- [ ] **Step 6: Run, verify success**

Run: `python -m pytest tests/test_web_shell.py -v`
Expected: 5 passed.

- [ ] **Step 7: Commit**

```bash
git add src/mc/web tests/test_web_shell.py
git commit -m "feat: web shell with security headers, CSRF and session dependencies"
```

---

### Task 7: Authentication routes (login, 2FA, enrollment, logout, passkeys)

**Files:**
- Create: `src/mc/web/routes_auth.py`, `templates/login.html`, `templates/login_2fa.html`, `templates/enroll.html`, `templates/backup_codes.html`
- Modify: `src/mc/web/app.py` (include the router)
- Test: `tests/helpers.py`, `tests/test_auth_routes.py`

- [ ] **Step 1: Write the test helpers** — first create `tests/__init__.py` (empty file, so that `from tests.helpers import …` works), then `tests/helpers.py`

```python
import re

import pyotp
from fastapi.testclient import TestClient

from mc.auth import mfa
from mc.auth.users import create_user
from mc.db import session_scope
from mc.web import routes_auth
from mc.web.app import create_app

PW = "correct horse battery"


def make_client() -> TestClient:
    routes_auth.limiter.reset()
    return TestClient(create_app(run_migrations=False))


def make_user(username="alice", role="admin", totp=True) -> str | None:
    """Create a user; return the plaintext TOTP secret (or None)."""
    with session_scope() as s:
        user = create_user(s, username, PW, role)
        if not totp:
            return None
        user.totp_secret_enc = mfa.new_secret_enc()
        user.totp_confirmed = True
        return mfa.secret_plain(user.totp_secret_enc)


def csrf_of(html: str) -> str:
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def post_login(client, username="alice", password=PW):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=False)


def full_login(client, secret: str, username="alice"):
    """Password + TOTP code; returns the POST /login/2fa response."""
    post_login(client, username)
    page = client.get("/login/2fa")
    return client.post("/login/2fa", data={"code": pyotp.TOTP(secret).now(), "csrf": csrf_of(page.text)},
                       follow_redirects=False)
```

- [ ] **Step 2: Write the tests** — `tests/test_auth_routes.py`

```python
import base64

import pyotp
import pytest

from mc.auth import mfa
from mc.auth import webauthn_ as wa
from mc.db import session_scope
from mc.models import AuditLog, BackupCode, Credential, User
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
        s.query(User).one().credentials.append(Credential(credential_id=b"cred-1", public_key=b"k", sign_count=1))
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
        s.query(User).one().credentials.append(Credential(credential_id=b"cred-1", public_key=b"k"))
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
```

- [ ] **Step 3: Run, verify failure**

Run: `python -m pytest tests/test_auth_routes.py -v`
Expected: FAIL (404 on `/login`, or `ImportError: mc.web.routes_auth`).

- [ ] **Step 4: Implement `src/mc/web/routes_auth.py`**

```python
import logging
import re

import segno
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse
from webauthn.helpers import base64url_to_bytes

from mc.auth import mfa, ratelimit, sessions
from mc.auth import webauthn_ as wa
from mc.auth.audit import audit
from mc.auth.passwords import verify_password
from mc.clock import utcnow
from mc.config import get_settings
from mc.db import get_db
from mc.models import Credential, User
from mc.web.deps import current_user, pending_user, session_row
from mc.web.render import render

log = logging.getLogger("mc.auth")
router = APIRouter()
limiter = ratelimit.IPLimiter()
GENERIC = "Identifiants invalides ou compte temporairement verrouillé."


def ip_of(request: Request) -> str:
    return request.client.host if request.client else ""


def set_cookie(resp, token: str, *, final: bool):
    cfg = get_settings()
    resp.set_cookie(sessions.COOKIE, token, httponly=True, secure=cfg.cookie_secure,
                    samesite="strict", path="/", max_age=cfg.session_max_seconds if final else None)
    return resp


def finish_login(request: Request, db, user: User, method: str) -> str:
    """Promote the session to a full session; return the new token."""
    ratelimit.register_success(user)
    token = sessions.promote(db, request.state.session, user, utcnow())
    audit(db, "login", user.username, detail=method, ip=ip_of(request))
    db.commit()
    return token


def fail_2fa(request: Request, db, user: User, event: str = "login_2fa_failed") -> None:
    ratelimit.register_failure(user, utcnow())
    audit(db, event, user.username, ip=ip_of(request))
    db.commit()


def twofa_page(request: Request, user: User, error: str | None = None, status: int = 200):
    return render(request, "login_2fa.html", status=status, error=error,
                  has_totp=user.totp_confirmed, has_passkey=bool(user.credentials))


# --- password ---------------------------------------------------------

@router.get("/login")
async def login_page(request: Request, db=Depends(get_db)):
    row = session_row(request, db)
    if row and row.mfa_ok:
        return RedirectResponse("/", 303)
    return render(request, "login.html")


@router.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...), db=Depends(get_db)):
    ip, now = ip_of(request), utcnow()
    if not limiter.hit(ip):
        audit(db, "login_throttled", username, ip=ip)
        db.commit()
        return render(request, "login.html", status=429, error="Trop de tentatives, réessayez plus tard.")
    user = db.query(User).filter_by(username=username).one_or_none()
    locked = bool(user and ratelimit.is_locked(user, now))
    if not (verify_password(user.password_hash if user else None, password) and not locked):
        if user and not locked:
            ratelimit.register_failure(user, now)
        audit(db, "login_locked" if locked else "login_failed", username, ip=ip)
        db.commit()
        return render(request, "login.html", status=401, error=GENERIC)
    token, _ = sessions.create(db, user, False, now)
    audit(db, "password_ok", username, ip=ip)
    db.commit()
    dest = "/login/2fa" if mfa.has_second_factor(user) else "/enroll"
    return set_cookie(RedirectResponse(dest, 303), token, final=False)


# --- second factor -------------------------------------------------------

@router.get("/login/2fa")
async def twofa_get(request: Request, user: User = Depends(pending_user)):
    if not mfa.has_second_factor(user):
        return RedirectResponse("/enroll", 303)
    return twofa_page(request, user)


@router.post("/login/2fa")
async def twofa_post(request: Request, code: str = Form(...), user: User = Depends(pending_user),
                     db=Depends(get_db)):
    if ratelimit.is_locked(user, utcnow()):
        audit(db, "login_locked", user.username, ip=ip_of(request))
        db.commit()
        return twofa_page(request, user, "Compte temporairement verrouillé.", 429)
    method = None
    if user.totp_confirmed and re.fullmatch(r"\d{6}", code.strip().replace(" ", "")):
        step = mfa.verify_totp(user.totp_secret_enc, code, user.totp_last_step)
        if step:
            user.totp_last_step, method = step, "totp"
    if method is None and mfa.consume_backup(user, code):
        method = "backup_code"
    if method is None:
        fail_2fa(request, db, user)
        return twofa_page(request, user, "Code invalide.", 401)
    token = finish_login(request, db, user, method)
    return set_cookie(RedirectResponse("/", 303), token, final=True)


@router.post("/webauthn/auth/options")
async def passkey_auth_options(request: Request, user: User = Depends(pending_user), db=Depends(get_db)):
    opts, challenge = wa.authentication_options(user)
    request.state.session.challenge = challenge
    db.commit()
    return opts


@router.post("/webauthn/auth/verify")
async def passkey_auth_verify(request: Request, user: User = Depends(pending_user), db=Depends(get_db)):
    row = request.state.session
    body = await request.json()
    challenge, row.challenge = row.challenge, None
    try:
        stored = db.query(Credential).filter_by(
            user_id=user.id, credential_id=base64url_to_bytes(body["id"])).one()
        stored.sign_count = wa.verify_authentication(body, challenge, stored)
    except Exception:  # noqa: BLE001  (any verification error = authentication failure)
        log.info("passkey verification failed for %s", user.username, exc_info=True)
        fail_2fa(request, db, user, "login_passkey_failed")
        return JSONResponse({"error": "Vérification de la passkey échouée"}, status_code=401)
    token = finish_login(request, db, user, "passkey")
    return set_cookie(JSONResponse({"ok": True, "redirect": "/"}), token, final=True)


# --- initial enrollment (TOTP) -------------------------------------------

def enroll_page(request: Request, db, user: User, error: str | None = None, status: int = 200):
    if not user.totp_secret_enc:
        user.totp_secret_enc = mfa.new_secret_enc()
        db.commit()
    uri = mfa.provisioning_uri(user.totp_secret_enc, user.username, get_settings().rp_name)
    return render(request, "enroll.html", status=status, error=error,
                  qr=segno.make(uri).png_data_uri(scale=5), secret=mfa.secret_plain(user.totp_secret_enc))


@router.get("/enroll")
async def enroll_get(request: Request, user: User = Depends(pending_user), db=Depends(get_db)):
    if mfa.has_second_factor(user):
        return RedirectResponse("/login/2fa", 303)
    return enroll_page(request, db, user)


@router.post("/enroll")
async def enroll_post(request: Request, code: str = Form(...), user: User = Depends(pending_user),
                      db=Depends(get_db)):
    if mfa.has_second_factor(user):
        return RedirectResponse("/login/2fa", 303)
    step = mfa.verify_totp(user.totp_secret_enc, code, 0) if user.totp_secret_enc else None
    if not step:
        fail_2fa(request, db, user, "enroll_failed")
        return enroll_page(request, db, user, "Code invalide.", 401)
    user.totp_confirmed, user.totp_last_step = True, step
    codes = mfa.reset_backup_codes(db, user)
    audit(db, "totp_enrolled", user.username, ip=ip_of(request))
    token = finish_login(request, db, user, "enroll")
    request.state.session = None  # the old session no longer exists
    return set_cookie(render(request, "backup_codes.html", codes=codes), token, final=True)


# --- logout ----------------------------------------------------------

@router.post("/logout")
async def logout(request: Request, user: User = Depends(current_user), db=Depends(get_db)):
    sessions.destroy(db, request.cookies.get(sessions.COOKIE, ""))
    audit(db, "logout", user.username, ip=ip_of(request))
    db.commit()
    resp = RedirectResponse("/login", 303)
    resp.delete_cookie(sessions.COOKIE, path="/")
    return resp


# --- passkey registration (logged-in user) --------------------

@router.post("/webauthn/register/options")
async def passkey_register_options(request: Request, user: User = Depends(current_user), db=Depends(get_db)):
    opts, challenge = wa.registration_options(user)
    request.state.session.challenge = challenge
    db.commit()
    return opts


@router.post("/webauthn/register/verify")
async def passkey_register_verify(request: Request, user: User = Depends(current_user), db=Depends(get_db)):
    row = request.state.session
    body = await request.json()
    challenge, row.challenge = row.challenge, None
    try:
        cid, pub, count = wa.verify_registration(body, challenge)
    except Exception:  # noqa: BLE001
        log.info("passkey registration failed for %s", user.username, exc_info=True)
        db.commit()
        return JSONResponse({"error": "Enregistrement de la passkey échoué"}, status_code=400)
    db.add(Credential(user_id=user.id, credential_id=cid, public_key=pub, sign_count=count,
                      name=f"Passkey {len(user.credentials) + 1}"))
    audit(db, "passkey_added", user.username, ip=ip_of(request))
    db.commit()
    return {"ok": True}
```

- [ ] **Step 5: Include the router** — in `src/mc/web/app.py`, replace the route imports block:

```python
    from mc.web import routes_auth, routes_pages

    app.include_router(routes_auth.router)
    app.include_router(routes_pages.router)
```

- [ ] **Step 6: Write the templates**

`src/mc/web/templates/login.html` :
```html
{% extends "base.html" %}
{% block title %}Connexion{% endblock %}
{% block content %}
<div class="row justify-content-center mt-5"><div class="col-md-6 col-lg-4">
  <h1 class="h4 mb-4">BunkerWeb Mission Control</h1>
  {% if error %}<div class="alert alert-danger" role="alert">{{ error }}</div>{% endif %}
  <form method="post" action="/login">
    <div class="mb-3">
      <label class="form-label" for="username">Utilisateur</label>
      <input class="form-control" id="username" name="username" autocomplete="username" required autofocus>
    </div>
    <div class="mb-3">
      <label class="form-label" for="password">Mot de passe</label>
      <input class="form-control" id="password" name="password" type="password" autocomplete="current-password" required>
    </div>
    <button class="btn btn-primary w-100">Continuer</button>
  </form>
</div></div>
{% endblock %}
```

`src/mc/web/templates/login_2fa.html` :
```html
{% extends "base.html" %}
{% block title %}Second facteur{% endblock %}
{% block content %}
<div class="row justify-content-center mt-5"><div class="col-md-6 col-lg-4">
  <h1 class="h4 mb-4">Vérification en deux étapes</h1>
  {% if error %}<div class="alert alert-danger" role="alert">{{ error }}</div>{% endif %}
  <form method="post" action="/login/2fa" class="mb-4">
    <input type="hidden" name="csrf" value="{{ csrf }}">
    <div class="mb-3">
      <label class="form-label" for="code">{% if has_totp %}Code à 6 chiffres ou code de secours{% else %}Code de secours{% endif %}</label>
      <input class="form-control" id="code" name="code" autocomplete="one-time-code" inputmode="text" required autofocus>
    </div>
    <button class="btn btn-primary w-100">Valider</button>
  </form>
  {% if has_passkey %}
  <button type="button" class="btn btn-outline-secondary w-100" data-passkey="login" data-csrf="{{ csrf }}">Utiliser une passkey</button>
  <p id="passkey-error" class="text-danger mt-2" role="alert"></p>
  {% endif %}
</div></div>
{% endblock %}
```

`src/mc/web/templates/enroll.html` :
```html
{% extends "base.html" %}
{% block title %}Activer le second facteur{% endblock %}
{% block content %}
<div class="row justify-content-center mt-5"><div class="col-md-8 col-lg-5">
  <h1 class="h4 mb-3">Activez l'authentification à deux facteurs</h1>
  <p>Un second facteur est obligatoire. Scannez ce QR code avec une application TOTP (FreeOTP, Aegis, Google Authenticator…), puis saisissez le code affiché.</p>
  {% if error %}<div class="alert alert-danger" role="alert">{{ error }}</div>{% endif %}
  <img src="{{ qr }}" alt="QR code TOTP" width="200" height="200" class="mb-2">
  <p class="small text-secondary">Saisie manuelle : <code class="secret">{{ secret }}</code></p>
  <form method="post" action="/enroll">
    <input type="hidden" name="csrf" value="{{ csrf }}">
    <div class="mb-3">
      <label class="form-label" for="code">Code à 6 chiffres</label>
      <input class="form-control" id="code" name="code" inputmode="numeric" autocomplete="one-time-code" required autofocus>
    </div>
    <button class="btn btn-primary">Activer</button>
  </form>
</div></div>
{% endblock %}
```

`src/mc/web/templates/backup_codes.html` :
```html
{% extends "base.html" %}
{% block title %}Codes de secours{% endblock %}
{% block content %}
<div class="row justify-content-center mt-5"><div class="col-md-8 col-lg-5">
  <h1 class="h4 mb-3">Codes de secours</h1>
  <div class="alert alert-warning" role="alert">Ces codes ne sont affichés qu'<strong>une seule fois</strong>. Conservez-les en lieu sûr : chacun ne sert qu'une fois si vous perdez votre second facteur.</div>
  <ul class="list-unstyled font-monospace">{% for c in codes %}<li>{{ c }}</li>{% endfor %}</ul>
  <a class="btn btn-primary" href="/dashboard">J'ai enregistré mes codes</a>
</div></div>
{% endblock %}
```

- [ ] **Step 7: Run, verify success**

Run: `python -m pytest tests/test_auth_routes.py tests/test_web_shell.py -v`
Expected: all pass. If `test_foreign_origin...` in `test_web_shell.py` fails because `/login` now answers 422: that is `!= 403`, so it is fine.

- [ ] **Step 8: Commit**

```bash
git add src/mc/web tests/__init__.py tests/helpers.py tests/test_auth_routes.py
git commit -m "feat: login, 2FA, forced enrollment, passkeys, logout"
```

---

### Task 8: Account page

**Files:**
- Create: `src/mc/web/routes_account.py`, `templates/account.html`
- Modify: `src/mc/web/app.py`
- Test: `tests/test_account_routes.py`

- [ ] **Step 1: Write the test**

```python
import pytest

from mc.auth import mfa
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
        sessions.create(s, user, True, utcnow())  # another session
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
        s.query(User).one().credentials.append(Credential(credential_id=b"c1", public_key=b"k"))
        s.flush()
        cred_id = s.query(Credential).one().id
    r = client.post("/account/totp/remove", data={"csrf": csrf, "password": PW}, follow_redirects=False)
    assert r.headers["location"] == "/account?m=totp_removed"
    r = client.post(f"/account/passkeys/{cred_id}/delete", data={"csrf": csrf}, follow_redirects=False)
    assert r.headers["location"] == "/account?m=last_factor"  # it is now the last factor
    with session_scope() as s:
        assert s.query(Credential).count() == 1


def test_account_requires_login(client):
    assert client.get("/account", follow_redirects=False).status_code == 303
```

- [ ] **Step 2: Run, verify failure**

Run: `python -m pytest tests/test_account_routes.py -v`
Expected: FAIL (404 on `/account`).

- [ ] **Step 3: Implement `src/mc/web/routes_account.py`**

```python
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from mc.auth import mfa
from mc.auth.audit import audit
from mc.auth.passwords import MIN_LENGTH, hash_password, verify_password
from mc.db import get_db
from mc.models import Credential, Session, User
from mc.web.deps import current_user
from mc.web.render import render
from mc.web.routes_auth import ip_of

router = APIRouter(prefix="/account")

MESSAGES = {
    "pwd_ok": "Mot de passe modifié ; les autres sessions ont été fermées.",
    "pwd_bad": "Mot de passe actuel incorrect.",
    "pwd_short": f"Mot de passe trop court ({MIN_LENGTH} caractères minimum).",
    "pwd_mismatch": "La confirmation ne correspond pas.",
    "last_factor": "Impossible : c'est votre dernier second facteur.",
    "totp_removed": "TOTP désactivé.",
    "pk_deleted": "Passkey supprimée.",
}


def back(code: str) -> RedirectResponse:
    return RedirectResponse(f"/account?m={code}", 303)


def factor_count(user: User) -> int:
    return int(user.totp_confirmed) + len(user.credentials)


@router.get("")
async def account(request: Request, user: User = Depends(current_user)):
    return render(request, "account.html", user=user, msg=MESSAGES.get(request.query_params.get("m")),
                  backup_left=sum(not b.used for b in user.backup_codes))


@router.post("/password")
async def change_password(request: Request, current: str = Form(...), new: str = Form(...),
                          confirm: str = Form(...), user: User = Depends(current_user), db=Depends(get_db)):
    if not verify_password(user.password_hash, current):
        return back("pwd_bad")
    if len(new) < MIN_LENGTH:
        return back("pwd_short")
    if new != confirm:
        return back("pwd_mismatch")
    user.password_hash = hash_password(new)
    db.query(Session).filter(Session.user_id == user.id, Session.id != request.state.session.id).delete()
    audit(db, "password_changed", user.username, ip=ip_of(request))
    db.commit()
    return back("pwd_ok")


@router.post("/backup-codes")
async def regenerate_codes(request: Request, password: str = Form(...), user: User = Depends(current_user),
                           db=Depends(get_db)):
    if not verify_password(user.password_hash, password):
        return back("pwd_bad")
    codes = mfa.reset_backup_codes(db, user)
    audit(db, "backup_codes_regenerated", user.username, ip=ip_of(request))
    db.commit()
    return render(request, "backup_codes.html", user=user, codes=codes)


@router.post("/totp/remove")
async def remove_totp(request: Request, password: str = Form(...), user: User = Depends(current_user),
                      db=Depends(get_db)):
    if not verify_password(user.password_hash, password):
        return back("pwd_bad")
    if not user.credentials:
        return back("last_factor")
    user.totp_confirmed, user.totp_secret_enc = False, None
    audit(db, "totp_removed", user.username, ip=ip_of(request))
    db.commit()
    return back("totp_removed")


@router.post("/passkeys/{cred_id}/delete")
async def delete_passkey(request: Request, cred_id: int, user: User = Depends(current_user), db=Depends(get_db)):
    cred = db.query(Credential).filter_by(id=cred_id, user_id=user.id).one_or_none()
    if cred is None:
        return back("pk_deleted")
    if factor_count(user) <= 1:
        return back("last_factor")
    user.credentials.remove(cred)
    audit(db, "passkey_deleted", user.username, ip=ip_of(request))
    db.commit()
    return back("pk_deleted")
```

- [ ] **Step 4: Template** — `src/mc/web/templates/account.html`

```html
{% extends "base.html" %}
{% block title %}Mon compte{% endblock %}
{% block content %}
<h1 class="h4 mb-3">Mon compte</h1>
{% if msg %}<div class="alert alert-info" role="status">{{ msg }}</div>{% endif %}

<section class="mb-5">
  <h2 class="h5">Second facteur</h2>
  <p>TOTP : {% if user.totp_confirmed %}<span class="badge text-bg-success">actif</span>{% else %}<span class="badge text-bg-secondary">inactif</span>{% endif %}
     · Codes de secours restants : <strong>{{ backup_left }}</strong></p>

  <h3 class="h6 mt-4">Passkeys</h3>
  {% if user.credentials %}
  <ul class="list-group mb-3">
    {% for c in user.credentials %}
    <li class="list-group-item d-flex justify-content-between align-items-center">
      <span>{{ c.name }} <small class="text-secondary">· ajoutée le {{ c.created_at.strftime('%d/%m/%Y') }}</small></span>
      <form method="post" action="/account/passkeys/{{ c.id }}/delete" class="m-0">
        <input type="hidden" name="csrf" value="{{ csrf }}">
        <button class="btn btn-sm btn-outline-danger">Supprimer</button>
      </form>
    </li>
    {% endfor %}
  </ul>
  {% else %}<p class="text-secondary">Aucune passkey enregistrée.</p>{% endif %}
  <button type="button" class="btn btn-outline-primary" data-passkey="register" data-csrf="{{ csrf }}">Ajouter une passkey</button>
  <p id="passkey-error" class="text-danger mt-2" role="alert"></p>
  <p class="small text-secondary">Les passkeys sont liées au domaine du site : une passkey créée sur le domaine ne fonctionne pas via l'adresse locale (utilisez le TOTP en local).</p>
</section>

<section class="mb-5">
  <h2 class="h5">Régénérer les codes de secours</h2>
  <form method="post" action="/account/backup-codes" class="row g-2 align-items-end">
    <input type="hidden" name="csrf" value="{{ csrf }}">
    <div class="col-md-5"><label class="form-label" for="bc-pw">Mot de passe</label>
      <input class="form-control" id="bc-pw" name="password" type="password" autocomplete="current-password" required></div>
    <div class="col-auto"><button class="btn btn-outline-secondary">Régénérer</button></div>
  </form>
</section>

{% if user.totp_confirmed and user.credentials %}
<section class="mb-5">
  <h2 class="h5">Désactiver le TOTP</h2>
  <form method="post" action="/account/totp/remove" class="row g-2 align-items-end">
    <input type="hidden" name="csrf" value="{{ csrf }}">
    <div class="col-md-5"><label class="form-label" for="rt-pw">Mot de passe</label>
      <input class="form-control" id="rt-pw" name="password" type="password" autocomplete="current-password" required></div>
    <div class="col-auto"><button class="btn btn-outline-danger">Désactiver</button></div>
  </form>
</section>
{% endif %}

<section class="mb-5">
  <h2 class="h5">Changer le mot de passe</h2>
  <form method="post" action="/account/password" class="col-md-5">
    <input type="hidden" name="csrf" value="{{ csrf }}">
    <div class="mb-3"><label class="form-label" for="cur">Mot de passe actuel</label>
      <input class="form-control" id="cur" name="current" type="password" autocomplete="current-password" required></div>
    <div class="mb-3"><label class="form-label" for="new">Nouveau mot de passe (12 caractères minimum)</label>
      <input class="form-control" id="new" name="new" type="password" autocomplete="new-password" minlength="12" required></div>
    <div class="mb-3"><label class="form-label" for="conf">Confirmation</label>
      <input class="form-control" id="conf" name="confirm" type="password" autocomplete="new-password" required></div>
    <button class="btn btn-primary">Modifier</button>
  </form>
</section>
{% endblock %}
```

- [ ] **Step 5: Include the router** — in `src/mc/web/app.py`:

```python
    from mc.web import routes_account, routes_auth, routes_pages

    app.include_router(routes_auth.router)
    app.include_router(routes_account.router)
    app.include_router(routes_pages.router)
```

- [ ] **Step 6: Run, verify success**

Run: `python -m pytest tests/test_account_routes.py -v`
Expected: 7 passed.

- [ ] **Step 7: Commit**

```bash
git add src/mc/web tests/test_account_routes.py
git commit -m "feat: account page (password, backup codes, passkeys, TOTP)"
```

---

### Task 9: CLI (first admin bootstrap, migrate)

**Files:**
- Create: `src/mc/cli.py`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Write the test**

```python
import getpass

from mc import cli
from mc.db import session_scope
from mc.models import User


def fake_migrate(monkeypatch):
    monkeypatch.setattr(cli, "migrate", lambda: None)


def test_bootstrap_admin_creates_admin_without_second_factor(fresh_db, monkeypatch):
    fake_migrate(monkeypatch)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "correct horse battery")
    assert cli.main(["bootstrap-admin", "--username", "root"]) == 0
    with session_scope() as s:
        u = s.query(User).one()
        assert (u.username, u.role, u.totp_confirmed) == ("root", "admin", False)


def test_bootstrap_admin_rejects_mismatch_and_duplicates(fresh_db, monkeypatch, capsys):
    fake_migrate(monkeypatch)
    answers = iter(["correct horse battery", "something else entirely"])
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(answers))
    assert cli.main(["bootstrap-admin", "--username", "root"]) == 1
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "correct horse battery")
    assert cli.main(["bootstrap-admin", "--username", "root"]) == 0
    assert cli.main(["bootstrap-admin", "--username", "root"]) == 1
    assert "existant" in capsys.readouterr().err
```

- [ ] **Step 2: Run, verify failure**

Run: `python -m pytest tests/test_cli.py -v`
Expected: FAIL (`ImportError: cli`).

- [ ] **Step 3: Implement `src/mc/cli.py`**

```python
import argparse
import getpass
import sys

from mc.auth.users import create_user
from mc.db import migrate, session_scope


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="mc")
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("bootstrap-admin", help="créer le premier administrateur")
    b.add_argument("--username", required=True)
    sub.add_parser("migrate", help="appliquer les migrations de base de données")
    args = p.parse_args(argv)

    if args.cmd == "migrate":
        migrate()
        print("Base de données à jour.")
        return 0

    password = getpass.getpass("Mot de passe (12 caractères minimum) : ")
    if password != getpass.getpass("Confirmation : "):
        print("Erreur : les mots de passe diffèrent.", file=sys.stderr)
        return 1
    migrate()
    try:
        with session_scope() as s:
            create_user(s, args.username, password, "admin")
    except ValueError as e:
        print(f"Erreur : {e}", file=sys.stderr)
        return 1
    print("Administrateur créé. À la première connexion, enregistrez un second facteur (TOTP).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run, verify success**

Run: `python -m pytest tests/test_cli.py -v`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add src/mc/cli.py tests/test_cli.py
git commit -m "feat: CLI to bootstrap first admin and run migrations"
```

---

### Task 10: Overall verification of part 2

- [ ] **Step 1: Full suite + lint**

Run:
```bash
python -m pytest -q
ruff check src tests
```
Expected: all tests pass, `All checks passed!`. Fix any ruff warning.

- [ ] **Step 2: Manual test**

Run (Git Bash):
```bash
export MC_SECRET_KEY=$(python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())")
export MC_COOKIE_SECURE=false MC_COLLECTOR_ENABLED=false
mc bootstrap-admin --username admin
uvicorn mc.web.app:create_app --factory --port 8000
```
Open `http://localhost:8000`: login, TOTP enrollment, backup codes, Account page. Stop with Ctrl+C.

- [ ] **Step 3: Push**

```bash
git push
```
