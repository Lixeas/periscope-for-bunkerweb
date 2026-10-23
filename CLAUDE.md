# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**Read-only** monitoring web application for 2 to 10 BunkerWeb instances (same network) through their API. Python 3.11+, FastAPI, SQLAlchemy, Jinja2. Spec: `docs/superpowers/specs/`, implementation plans: `docs/superpowers/plans/`. UI and user-facing messages are currently French; an English/French language switch is being added.

## Commands

```bash
python -m venv .venv && source .venv/Scripts/activate   # Git Bash on Windows
pip install -e ".[dev]"
python -m pytest -q                                      # full suite
python -m pytest tests/test_collector.py::test_collect_ok_stores_snapshots -v   # a single test
ruff check src tests dev                                 # lint (must stay clean)
```

Run the app locally (`PERISCOPE_*` variables read by `periscope.config.Settings`, `PERISCOPE_SECRET_KEY` is required):

```bash
export PERISCOPE_SECRET_KEY=$(python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())")
export PERISCOPE_COOKIE_SECURE=false          # local HTTP only
periscope bootstrap-admin --username admin    # creates the first admin (+ applies migrations)
uvicorn periscope.web.app:create_app --factory --port 8000
```

Demo without a real instance: `dev/fake_bunkerweb.py` (see its header for the 2 uvicorn commands, ports 9001/9002, TLS 9443/9444). `FAKE_AUTH=1 FAKE_TTL=<s>` enables `POST /auth` (user `periscope`, password `FAKE_PASSWORD`, default `secret`) and requires an expiring Bearer on the data endpoints.

Migration: `alembic revision --autogenerate -m "..."` (uses `alembic.ini`, throwaway SQLite `data/autogen.db`); the app applies `alembic upgrade head` at startup via `periscope.db.migrate()`. Migrations live in `src/periscope/migrations/` (inside the package).

## Architecture

A single process: `periscope.web.app.create_app()` starts the FastAPI server **and**, in the `lifespan`, the `periscope.collector.run_forever()` task (can be disabled with `PERISCOPE_COLLECTOR_ENABLED=false`, which the tests do).

Data flow — **the web layer never reads BunkerWeb**, only the database:
1. `collector`: every `PERISCOPE_POLL_INTERVAL` s, one task per instance → `BWClient` (`bw_client.py`: all data goes through `_get`, GET only; the only other allowed request is `POST /auth`, no public write method; two authentication modes, see below) → `normalize.py` → upsert of one `Snapshot` per (instance, type: services/bans/jobs/plugins/instances). Network failure = `down` status, last snapshot kept; partial failure = `degraded`.
2. TLS probe (`tlsprobe.py`, slower loop `PERISCOPE_PROBE_INTERVAL`): handshake to `instance_IP:port` with SNI = domain of each non-draft service; reads the certificate without validating it (deliberate: detect expired/self-signed ones). Results go in `CertProbe`.
3. `queries.py` turns snapshots into view models (differences between instances via `diff.py`, certificate statuses 7 d red / 21 d orange). `web/routes_views.py` is thin.

Roles: one Periscope instance = one BunkerWeb API endpoint, hence the **scheduler** (fixed `scheduler` badge). The `instances` snapshot (`GET /instances`, permission `instances_read`, parsed by `normalize.nodes`) lists the nginx nodes it manages, shown below it with the fixed `worker` badge. A `down` or `failover` node forces the `degraded` status with a `last_error` such as « 1 nœud hors ligne : <hostname> » (a French user-facing string, i.e. "1 node offline"; `collector._node_problems`); `loading` is not an error; failure of the call itself is a partial failure like the other types. The fake serves `/instances` (the 2nd node is `down` with `FAKE_EXTRA=1`). Shape derived from the source, not validated on a real instance.

`normalize.py` is the **only place coupled to the JSON shape of the BunkerWeb API**, which is undocumented. The shapes are now **derived from reading the BunkerWeb v1.6.17 source** (routers/*.py, Database.py, api.lua, banlease.lua), not captured from a live instance: `/services` provides `security_mode` per service (falls back to `/services/{id}?full=true` → `config` only if it is missing), `/bans` is a dict per nginx instance (deduplicated by (ip, service, ban_scope, kind), `exp` = remaining seconds, 0 = permanent; HTTP 502 accepted if the body is that dict), `/jobs` is a dict indexed by name (`plugin_id`, `history` by descending `end_date`), `/ping` has no `version`: it is read by `BWClient.version()`: first from the `version` fact of the held Biscuit token (`user` mode; `biscuit_version.py`, a dependency-free protobuf extractor reading the symbol table of the authority block, with no key and no request), otherwise from `info.version` of the public document `GET /openapi.json` (which returns a 500 on at least one real 1.6.17 instance; the fake imitates this unless `FAKE_OPENAPI=1`) (under the API root prefix, already included in `base_url`; never fatal, returns None at the slightest problem; the collector only requests it if unknown or older than 1 h, `collector._VERSION_CHECKED`). A 500 was observed there on a real instance without the root prefix; not confirmed on a real instance. The historical assumed shapes remain accepted. If the real API differs, adjust only this file and its tests. Validation on a real instance is still to be done (Plan 3, task 8).

Authentication (`src/periscope/auth/` logic, `src/periscope/web/routes_auth.py` + `routes_account.py` routes):
- Two-step login: the password creates a session with `mfa_ok=False` (TTL 5 min); the second factor replaces it with a full session with **token rotation** (`sessions.promote`). Sessions are server-side (`sessions` table, token stored hashed).
- Mandatory second factor: a user without a factor is forced to `/enroll` (TOTP). WebAuthn passkeys can then be added from `/account`. TOTP replay protection via `User.totp_last_step`.
- `web/deps.py`: `current_user` / `pending_user` / `require_admin` validate the session **and the CSRF** (`csrf` field or `X-CSRF-Token` header) for every non-GET method; a middleware rejects `Origin`s outside `PERISCOPE_ORIGINS`. Every new authenticated write route must go through these dependencies.
- Lockout: at the password step, per (username, IP) in memory (`ratelimit.LoginFailures`, never on the real account, anti-DoS); the account lock (`User.failed_attempts`, `ratelimit.register_failure`) only applies from 2FA/enrollment/passkey onward and to re-authentication. + in-memory per-IP limiter (single process). Sensitive account actions go through `reauth()` / `revoke_other_sessions()` (`web/reauth.py`).
- BunkerWeb authentication (`Instance.auth_mode`): `user` (recommended) = restricted API user, `api_username` + `api_password_enc`; `BWClient(credentials=...)` obtains a Biscuit token via `POST /auth` (Basic), sends it as Bearer, and on 401 re-authenticates once and replays once (failure of `/auth` = `BWError('auth')`, no loop). `token` = static `API_TOKEN` (`token_enc`, admin, discouraged). The collector keeps tokens in `collector._TOKEN_CACHE` (in memory, key = instance id + sha256 fingerprint of the encrypted credentials, hence invalidated on edit). Never a password/token in error messages or logs.
- BunkerWeb passwords and API tokens are encrypted in the database (Fernet, key `PERISCOPE_SECRET_KEY`, `crypto.py`) and never displayed again.

Useful conventions:
- Datetimes are **naive UTC** everywhere (`clock.utcnow()`), because SQLite does not keep the time zone.
- Synchronous DB access in async code (accepted, ≤ 10 instances); in tests, use the `fresh_db` fixture (in-memory SQLite) and `session_scope()`, never an open session during the collector call.
- Front end without CDN: local copy of Bootstrap, vanilla JS in `web/static/`, strict CSP (`script-src 'self'`, no inline JS or style).
- Passkeys are bound to `PERISCOPE_RP_ID` (domain): unusable via IP/localhost, where TOTP is the fallback.
- Web tests: helpers in `tests/helpers.py` (`login_as`, `make_user`, `csrf_of`); in SQLAlchemy tests, bind the object to a variable before `x.relation.append(...)` (otherwise `ObjectDereferencedError`).
