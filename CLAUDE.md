# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**Read-only** monitoring web application for BunkerWeb instances through their API: polled directly on the same network, or through a Periscope agent in remote networks (mutual TLS; e.g. one network per customer for an MSP). Designed for a few to several dozen instances. Python 3.11+, FastAPI, SQLAlchemy, Jinja2. The UI is bilingual: English (source, default) and French, with a language switch (see "Internationalisation").

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

Agent mode locally: also export `PERISCOPE_AGENT_PUBLIC_URL=https://localhost:8443` (starts the mTLS listener on `PERISCOPE_AGENT_LISTEN_PORT`, default 8443), add an instance in "Periscope agent" mode, then in another shell without the console variables: `periscope agent enroll '<bundle>' --dir ./agent` and `PERISCOPE_AGENT_DIR=./agent PERISCOPE_AGENT_BW_URL=http://127.0.0.1:9001 PERISCOPE_AGENT_BW_USERNAME=periscope PERISCOPE_AGENT_BW_PASSWORD=secret periscope agent run`.

Demo without a real instance: `dev/fake_bunkerweb.py` (see its header for the 2 uvicorn commands, ports 9001/9002, TLS 9443/9444). `FAKE_AUTH=1 FAKE_TTL=<s>` enables `POST /auth` (user `periscope`, password `FAKE_PASSWORD`, default `secret`) and requires an expiring Bearer on the data endpoints.

Releases (`docs/releasing.md`): semantic version `vX.Y.Z`, single source `__version__` in `src/periscope/__init__.py` (pyproject reads it); notes in `CHANGELOG.md` (write under `## [Unreleased]`). `python dev/release.py bump major|minor|patch` sets the version and moves the notes. Never tag or publish by hand: the `release` job of `.github/workflows/ci.yml` creates the tag, the GitHub release and the GHCR image on push to `main` (i.e. at merge) when the tag does not exist yet; the `version` job checks pull requests.

Deployment: `docker-compose.yml` runs the released image `ghcr.io/lixeas/periscope-for-bunkerweb:${PERISCOPE_VERSION}` (recommended); `docker-compose.build.yml` is an override that builds from the checkout instead; `docker-compose.agent.yml` runs an agent from the released image.

Migration: `alembic revision --autogenerate -m "..."` (uses `alembic.ini`, throwaway SQLite `data/autogen.db`); the app applies `alembic upgrade head` at startup via `periscope.db.migrate()`. Migrations live in `src/periscope/migrations/` (inside the package).

## Architecture

A single process: `periscope.web.app.create_app()` starts the FastAPI server **and**, in the `lifespan`, the `periscope.collector.run_forever()` task (can be disabled with `PERISCOPE_COLLECTOR_ENABLED=false`, which the tests do) and, when `PERISCOPE_AGENT_PUBLIC_URL` is set, the agent listener (`agent_server.AgentListener`, a second uvicorn server on its own port).

Each `Instance` has a `connection`: `direct` (the console polls it) or `agent` (a remote agent pushes reports; the console never opens a connection to it).

Data flow — **the web layer never reads BunkerWeb**, only the database:
1. `collector`: every `PERISCOPE_POLL_INTERVAL` s, one task per `direct` instance (bounded by `PERISCOPE_MAX_PARALLEL`; DB access through `asyncio.to_thread`) → `collector.gather()` (network only, returns a `Collected`, shared with the agent) → `BWClient` (`bw_client.py`: all data goes through `_get`, GET only; the only other allowed request is `POST /auth`, no public write method; API user authentication, see below) → `normalize.py` → upsert of one `Snapshot` per (instance, type: services/bans/jobs/plugins/instances). Network failure = `down` status, last snapshot kept; partial failure = `degraded`. `collector.check_agents()` marks agent instances `down` after `stale_cycles × poll_interval` s (60 s minimum) without a report.
2. TLS probe (`tlsprobe.py`, slower loop `PERISCOPE_PROBE_INTERVAL`): handshake to `instance_IP:port` with SNI = domain of each non-draft service; reads the certificate without validating it (deliberate: detect expired/self-signed ones). Results go in `CertProbe`.
3. `queries.py` turns snapshots into view models (differences between instances via `diff.py`, certificate statuses 7 d red / 21 d orange). Every query takes an optional `ids` scope = `queries.scope(db, tag)` (instances carrying a tag; `None` = all), so gaps are computed within a tag. `web/routes_views.py` is thin; view routes are sync `def` (run in the thread pool, never blocking the loop shared with the collector and the agent listener).

Agent mode (`docs/agent.md`):
- `pki.py`: private CA (EC P-256, key Fernet-encrypted in the `settings` table, created on first use). Signs agent client certificates from a CSR (key generated on the agent; subject chosen by the console; 90 days, renewal under 30 days) and the listener's server certificate (regenerated at each start for the host of `PERISCOPE_AGENT_PUBLIC_URL`).
- `agent_server.py`: separate FastAPI app (no cookies/sessions/CSRF: mTLS is the authentication). uvicorn with `ssl_cert_reqs=CERT_OPTIONAL` + our CA; `MTLSProtocol` (subclass of uvicorn's H11Protocol) puts the verified client cert DER in the scope extension `CERT_EXT` (never from a header). Routes: `GET /v1/ca`, `POST /v1/enroll` (single-use token, hashed in `Instance.agent_enroll_hash`, TTL `PERISCOPE_AGENT_ENROLL_TTL`, IP rate limit), `POST /v1/report`, `POST /v1/renew`. `authenticate()` maps the cert fingerprint to ONE agent instance (`agent_cert_fp`, or `agent_next_cert_fp` promoted at first use after a renewal). `parse_report()` validates strictly (an agent machine may be compromised); then `collector.store()` / `store_probes()` as for a direct collection.
- `agent.py` (`periscope agent enroll|run`, settings `AgentSettings`, prefix `PERISCOPE_AGENT_`, must not need `PERISCOPE_SECRET_KEY`): enrollment bundle `psc1.<base64 json {u,t,f}>`; the CA is fetched unverified then accepted only if its SHA-256 matches `f`; afterwards only that CA is trusted. The loop reuses `collector.gather` / `probe_domains`; intervals come from the console's answers.
- Admin routes: `/admin/instances/{id}/agent-token` (new bundle, shown once) and `/agent-revoke` (forget the fingerprints). The connection mode cannot be changed after creation.

Tags (`tags.py`, tables `tags` / `instance_tags`): comma-separated input, case-insensitive reuse, unused tags pruned. `render()` provides `all_tags` / `current_tag`; the switcher in `base.html` and the nav links keep `?tag=`.

Roles: one Periscope instance = one BunkerWeb API endpoint, hence the **scheduler** (fixed `scheduler` badge). The `instances` snapshot (`GET /instances`, permission `instances_read`, parsed by `normalize.nodes`) lists the nginx nodes it manages, shown below it with the fixed `worker` badge. A `down` or `failover` node forces the `degraded` status with a `last_error` such as "1 node offline: <hostname>" (stored language-neutral through `i18n.pack`, displayed in the reader's language; `collector._node_problems`); `loading` is not an error; failure of the call itself is a partial failure like the other types. The fake serves `/instances` (the 2nd node is `down` with `FAKE_EXTRA=1`). Shape derived from the source, not validated on a real instance.

`normalize.py` is the **only place coupled to the JSON shape of the BunkerWeb API**, which is undocumented. The shapes are now **derived from reading the BunkerWeb v1.6.17 source** (routers/*.py, Database.py, api.lua, banlease.lua), not captured from a live instance: `/services` provides `security_mode` per service (falls back to `/services/{id}?full=true` → `config` only if it is missing), `/bans` is a dict per nginx instance (deduplicated by (ip, service, ban_scope, kind), `exp` = remaining seconds, 0 = permanent; HTTP 502 accepted if the body is that dict), `/jobs` is a dict indexed by name (`plugin_id`, `history` by descending `end_date`), `/ping` has no `version`: it is read by `BWClient.version()`: first from the `version` fact of the held Biscuit token (`biscuit_version.py`, a dependency-free protobuf extractor reading the symbol table of the authority block, with no key and no request), otherwise from `info.version` of the public document `GET /openapi.json` (which returns a 500 on at least one real 1.6.17 instance; the fake imitates this unless `FAKE_OPENAPI=1`) (under the API root prefix, already included in `base_url`; never fatal, returns None at the slightest problem; the collector only requests it if unknown or older than 1 h, `collector._VERSION_CHECKED`). A 500 was observed there on a real instance without the root prefix; not confirmed on a real instance. The historical assumed shapes remain accepted. If the real API differs, adjust only this file and its tests. Validation on a real instance is still to be done (Plan 3, task 8).

Authentication (`src/periscope/auth/` logic, `src/periscope/web/routes_auth.py` + `routes_account.py` routes):
- Two-step login: the password creates a session with `mfa_ok=False` (TTL 5 min); the second factor replaces it with a full session with **token rotation** (`sessions.promote`). Sessions are server-side (`sessions` table, token stored hashed).
- Mandatory second factor: a user without a factor is forced to `/enroll` (TOTP). WebAuthn passkeys can then be added from `/account`. TOTP replay protection via `User.totp_last_step`.
- `web/deps.py`: `current_user` / `pending_user` / `require_admin` validate the session **and the CSRF** (`csrf` field or `X-CSRF-Token` header) for every non-GET method; a middleware rejects `Origin`s outside `PERISCOPE_ORIGINS`. Every new authenticated write route must go through these dependencies.
- Lockout: at the password step, per (username, IP) in memory (`ratelimit.LoginFailures`, never on the real account, anti-DoS); the account lock (`User.failed_attempts`, `ratelimit.register_failure`) only applies from 2FA/enrollment/passkey onward and to re-authentication. + in-memory per-IP limiter (single process). Sensitive account actions go through `reauth()` / `revoke_other_sessions()` (`web/reauth.py`).
- BunkerWeb authentication: restricted API user only (`api_username` + `api_password_enc`; the static `API_TOKEN` mode was removed by migration 0004, which disables former token instances with a stored message). `BWClient(base_url, credentials, token=None)` obtains a Biscuit token via `POST /auth` (Basic), sends it as Bearer, and on 401 re-authenticates once and replays once (failure of `/auth` = `BWError('auth')`, no loop). The collector keeps tokens in `collector._TOKEN_CACHE` (in memory, key = instance id + sha256 fingerprint of the encrypted credentials, hence invalidated on edit). Never a password/token in error messages or logs.
- BunkerWeb passwords and the agent CA key are encrypted in the database (Fernet, key `PERISCOPE_SECRET_KEY`, `crypto.py`) and never displayed again. In agent mode the API password stays on the agent side.

Internationalisation (`src/periscope/i18n.py`, French catalog `src/periscope/locales/fr.py`, stdlib only, no compile step):
- English is the source language: the **English sentence is the msgid**, written directly in the code (`tr(request, "...")`, `N_("...")` for constants such as label dicts) and in templates (`{{ _("...") }}`, named placeholders `{count}` passed as keyword arguments). `fr.py` is a plain dict msgid -> French (same `{placeholders}`); an unknown msgid or `en` returns the msgid. Template `_()` escapes the text and its parameters (pass `{% set x %}...{% endset %}` blocks to embed markup). Imported macros need `{% from ... import x with context %}` to see the language.
- **To add a string**: write the English msgid with `_()` / `tr()` / `N_()`, add the French value to `locales/fr.py`; `tests/test_i18n.py` enforces it (every msgid used exists, no dead entry, same placeholders, no runtime-built msgid, English pages contain no accented letters). Never build a msgid with an f-string: use placeholders. Validation errors raise `i18n.LocalizedError(N_("..."), **params)` (`str(e)` stays English; handlers call `i18n.localize(lang, e)`); `BWError(kind, msgid, **params)` works the same way.
- **Language resolution** (`i18n.lang_for`): saved preference `users.lang` (set on `request.state.lang_pref` by `web/deps.py`) > cookie `periscope_lang` > `Accept-Language` > `en`; only `SUPPORTED` values are accepted. `POST /lang` (`routes_pages.py`, fields `lang`, `next`, `csrf`) sets the cookie and saves the preference; the CSRF token is the session one or the pre-login double-submit cookie, `next` goes through `i18n.safe_next` (local paths only). The switcher lives in `base.html` (hidden on `backup_codes.html`, whose codes are shown once).
- **Stored messages are language-neutral**: `Instance.last_error` holds `i18n.pack(...)` / `pack_many(...)` JSON (`{"m": msgid, "p": {...}}`), displayed with the `stored` template filter / `i18n.render(lang, value)`, which shows non-JSON legacy text as is. Audit rows keep stable English event codes (`routes_admin.EVENT_LABELS` translates them at display; unknown codes are shown raw). The CLI is English only.
- JS strings come from `data-*` attributes (e.g. `<body data-msg-error>`), never inline scripts. `dt`/`date`/`ago`/`epoch`/`duration` filters are language-aware (French dates `dd/mm/yyyy`, English ISO).

Useful conventions:
- Datetimes are **naive UTC** everywhere (`clock.utcnow()`), because SQLite does not keep the time zone.
- Collector and agent listener: DB access through `asyncio.to_thread` (sync SQLAlchemy); in tests, use the `fresh_db` fixture (in-memory SQLite) and `session_scope()`, never an open session during the collector call.
- Front end without CDN: local copy of Bootstrap, vanilla JS in `web/static/`, strict CSP (`script-src 'self'`, no inline JS or style).
- Passkeys are bound to `PERISCOPE_RP_ID` (domain): unusable via IP/localhost, where TOTP is the fallback.
- Agent tests (`tests/test_agent.py`): inject a client certificate into the listener app with `with_cert(app, der)`; one test runs a real `AgentListener` on a free port with real mutual TLS.
- Web tests: helpers in `tests/helpers.py` (`login_as`, `make_user`, `csrf_of`); in SQLAlchemy tests, bind the object to a variable before `x.relation.append(...)` (otherwise `ObjectDereferencedError`).
