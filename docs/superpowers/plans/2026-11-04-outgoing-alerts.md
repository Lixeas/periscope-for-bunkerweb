# Outgoing Alerts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Notify by e-mail or webhook when an instance is `degraded`/`down`, when a certificate enters the orange/red/expired zone (or its probe fails), and on BunkerWeb version change; configured from an admin-only **Alerts** page.

**Architecture:** A DB-only engine (`alert_engine`) compares observed state with a persisted per-subject state machine after each collection / probe cycle and returns `Notification`s; `alert_send` routes them to channels (tag + event filters), renders one grouped message per channel in the channel's language, delivers with retries and writes a send log. The web layer is a thin admin page over `AlertChannel` rows and SMTP settings.

**Tech Stack:** FastAPI, SQLAlchemy 2, Alembic, Jinja2, stdlib `smtplib`, `httpx` (already a dependency). No new dependency.

**Spec:** `docs/superpowers/specs/2026-11-04-outgoing-alerts-design.md` (read it first; section "Calls made by the designer" is binding).

## Global Constraints

- Confirmation: a different status must be observed on **2 consecutive evaluations** before it is notified; reminder every **24 h** while `degraded`/`down` (instance status only, never certificates).
- Certificate zones come from `diff.cert_status` (red < 7 d, orange < 21 d); `none` = probe failed, reported as `cert_error`.
- First sight of a subject = silent baseline (current status already "notified"; `unknown` baselines as `ok`).
- Delivery: up to **3 attempts**, backoff **1 s, 5 s**; webhook timeout **10 s**, no redirects, success = 2xx; never raises into the collector.
- E-mail: plain text, STARTTLS by default (`starttls` | `ssl` | `none`), certificates verified, **≤ 20 recipients** per channel, no CR/LF in addresses.
- Webhook: `http`/`https` only; header `X-Periscope-Signature: sha256=<hex HMAC-SHA256 of raw body>` when a secret is set; payload v1 exactly as in the spec (field names are a contract).
- Send log: keep **30 days / 1000 rows**. Default channel language `en`; new channels default to events `down,degraded,certificate`.
- Secrets (SMTP password, webhook secret) encrypted with `crypto.encrypt`, never rendered, logged, audited or sent. Blank field on edit keeps the stored value.
- Datetimes naive UTC (`clock.utcnow()`). Admin routes use `require_admin` (session + CSRF). English msgid in code/templates + French in `locales/fr.py` (`tests/test_i18n.py` enforces; never build a msgid with an f-string; English text has no accented letters). New audit codes get labels in `routes_admin.EVENT_LABELS`.
- Repo rules (`CLAUDE.md`): `CHANGELOG.md` under `## [Unreleased]`, update `ROADMAP.md`, do not bump the version. Migration must pass on SQLite **and** PostgreSQL (`tests/test_postgres.py` `compare_metadata`). `ruff check src tests dev` clean. Use `.venv/bin/python -m pytest`.
- Tests: `fresh_db` fixture + `session_scope()`; bind an ORM object to a variable before `x.relation.append(...)`.

## Review Focus

1. Recipient address with CR/LF or garbage (`a@b.c\r\nBcc: x@y.z`) → rejected (header injection) — Task 4.
2. Webhook URL `file:///etc/passwd`, `javascript:`, no host → rejected; a 302 answer is a failure, not followed — Tasks 4, 6.
3. Instance or domain name containing `{}` / `%` / non-ASCII must not break message formatting — Task 5.
4. SMTP password / webhook secret never appears in HTML, send log, audit, or error text after a failed send — Tasks 6, 8.
5. Flapping (`down, ok, down, ok` on consecutive cycles) never produces a message; a failing channel never raises into the collector — Tasks 2, 7.

## File Structure

- Modify `src/periscope/models.py`: `Instance.silenced_until`, `AlertChannel`, `alert_channel_tags`, `AlertState`, `AlertLog`.
- Create `src/periscope/migrations/versions/0005_alerts.py`.
- Create `src/periscope/alert_engine.py`: `Notification`, `step()`, `evaluate_status()`, `evaluate_certs()`, `run_status()`, `run_certs()`.
- Create `src/periscope/alert_config.py`: SMTP settings, recipients / URL / events validation.
- Create `src/periscope/alert_send.py`: `matches()`, rendering, senders, `dispatch()`, `send_test()`, `send_smtp_test()`.
- Modify `src/periscope/collector.py` (hooks), `src/periscope/web/app.py` (router), `src/periscope/web/routes_admin.py` (silence, `EVENT_LABELS`).
- Create `src/periscope/web/routes_alerts.py`, `templates/admin_alerts.html`, `templates/admin_alert_form.html`; modify `templates/base.html`, `templates/_macros.html` (icon), `templates/admin_instance_edit.html`, `src/periscope/locales/fr.py`.
- Create `docs/alerts.md`; modify `CHANGELOG.md`, `ROADMAP.md`, `README.md`.
- Tests: `tests/test_alert_models.py`, `tests/test_alert_engine.py`, `tests/test_alert_config.py`, `tests/test_alert_send.py`, `tests/test_alert_routes.py`; extend `tests/test_postgres.py` only if its generic checks do not already cover the new tables.

---

### Task 1: Models and migration 0005

**Files:**
- Modify: `src/periscope/models.py`
- Create: `src/periscope/migrations/versions/0005_alerts.py`
- Test: `tests/test_alert_models.py`

**Interfaces:**
- Produces (all in `periscope.models`):
  - `Instance.silenced_until: datetime | None`
  - `AlertChannel(id, name: str unique ≤64, kind: "email"|"webhook", enabled: bool=True, lang: str="en", events: str="down,degraded,certificate", recipients: str="", webhook_url: str="", webhook_secret_enc: str="", created_at, tags: list[Tag])` with `def has_event(self, name: str) -> bool`.
  - `alert_channel_tags` association table (channel_id, tag_id; both ON DELETE CASCADE, composite PK).
  - `AlertState(id, kind: "status"|"cert"|"version", instance_id FK CASCADE, subject: str="", notified: str="", pending: str="", pending_count: int=0, notified_at: datetime|None)`; `UniqueConstraint(kind, instance_id, subject)`.
  - `AlertLog(id, at, channel_id: int|None FK ON DELETE SET NULL, channel_name: str≤64, events: str≤255, instances: str≤255, ok: bool, error: str≤512)`.

- [ ] **Step 1: Write failing tests** in `tests/test_alert_models.py`: `test_channel_roundtrip_with_tags_and_events` (create channel with `events="down,certificate"`, two tags; `has_event("down")` true, `has_event("version")` false; reload shows tags ordered by name); `test_state_unique_per_subject` (second identical `(kind, instance_id, subject)` raises `IntegrityError`); `test_instance_delete_cascades_state_and_deleting_channel_keeps_log` (delete instance → its `AlertState` rows gone; delete channel → `AlertLog.channel_id` is None, `channel_name` kept; needs `PRAGMA foreign_keys` which `db.init_engine` sets); `test_migration_0005_from_0004` (upgrade to `0004` on a temp SQLite file as in `tests/test_migrate.py`, `migrate()`, assert tables `alert_channels`, `alert_channel_tags`, `alert_state`, `alert_log` and column `instances.silenced_until` exist and `silenced_until` is nullable).
- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_alert_models.py -v` → FAIL (imports).
- [ ] **Step 3: Add the models** to `models.py` following the style of `Tag`/`instance_tags`; write `0005_alerts.py` with explicit `op.create_table` / `batch_alter_table` (revision `'0005'`, down `'0004'`), `server_default` for non-null strings like migration 0004.
- [ ] **Step 4: Run** the new tests + `.venv/bin/python -m pytest -q` → all pass.
- [ ] **Step 5: Verify PostgreSQL** (Docker): `docker run -d --rm --name pgtest -e POSTGRES_PASSWORD=pw -p 55432:5432 postgres:16`, then `PERISCOPE_TEST_POSTGRES_URL=postgresql://postgres:pw@localhost:55432/postgres .venv/bin/python -m pytest tests/test_postgres.py -v` → pass (`compare_metadata` empty means the migration matches the models); `docker stop pgtest`.
- [ ] **Step 6: Commit** `git add -A && git commit -m "Alerts: models and migration 0005"`.

---

### Task 2: State machine and instance-status evaluation

**Files:**
- Create: `src/periscope/alert_engine.py`
- Test: `tests/test_alert_engine.py`

**Interfaces:**
- Consumes: models from Task 1, `clock.utcnow`.
- Produces in `periscope.alert_engine`:
  - `CONFIRM = 2`, `REMIND_AFTER = timedelta(hours=24)`.
  - `@dataclass(frozen=True) class Notification`: `type: str` (`instance_down|instance_degraded|instance_resolved|instance_reminder|cert_orange|cert_red|cert_expired|cert_error|cert_resolved|instance_version_changed|test`), `event: str` (`down|degraded|certificate|version|test`: the channel switch it falls under; a resolved/reminder takes the event of the problem it relates to), `instance_id: int`, `instance: str`, `tags: tuple[str, ...]`, `status: str = ""`, `message: str = ""` (stored packed `last_error`, rendered later in the channel language), `domain: str = ""`, `not_after: datetime | None = None`, `days_left: int | None = None`, `since: datetime | None = None`, `version: str = ""`.
  - `step(st: AlertState, observed: str, now: datetime) -> tuple[str, str] | None`: advances one state; returns `("change", previous_notified)`, `("reminder", observed)` or `None`.
  - `evaluate_status(now: datetime | None = None) -> list[Notification]`.

- [ ] **Step 1: Write failing tests** in `tests/test_alert_engine.py` (helper builds an `Instance` with given status; evaluation calls pass explicit `now` values 30 s apart):
  - `test_step_needs_two_consecutive_observations`: `down` once → `None`; `down` again → `("change", "ok")`; state `notified == "down"`, `pending == ""`.
  - `test_flapping_never_notifies`: alternate `down, ok, down, ok, down` → every call returns `None` (Review Focus 5).
  - `test_reminder_after_24h_only_for_a_problem`: notified `down` at t0; observed `down` at t0+23h → `None`; t0+24h → `("reminder", "down")` and `notified_at` moves; notified `ok` never reminds.
  - `test_first_sight_is_a_silent_baseline`: instance already `down` before any state → `evaluate_status` returns `[]` and creates a `status` state with `notified == "down"`; `unknown` baselines as `ok`; later `down` ×2 notifies.
  - `test_status_change_types`: `ok→down` gives `instance_down` (`event="down"`, `message` = instance `last_error`, `tags` = current tag names); `down→degraded` gives `instance_degraded`; `degraded→ok` gives `instance_resolved` with `event="degraded"`; `down→ok` gives `event="down"`.
  - `test_unknown_status_is_ignored`: `ok → unknown ×3` leaves `notified == "ok"`, no notification.
  - `test_silenced_instance_is_skipped_and_resumes`: `silenced_until` in the future → no state advance and no notification even for 5 `down` observations; once `now` passes it, two `down` observations notify. Notified `down` before silence + `ok` after it → `instance_resolved` sent once the silence ended.
  - `test_disabled_instance_state_is_dropped`: disabling the instance removes its `AlertState` rows at next evaluation; disabled instances produce nothing.
  - `test_version_change` : first version `1.6.16` baseline silent; `None`/`""` ignored; `1.6.17` → one `instance_version_changed` (`event="version"`, `version="1.6.17"`), no confirmation delay, state updated.
- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_alert_engine.py -v` → FAIL.
- [ ] **Step 3: Implement** `step()` (algorithm: same as notified → clear pending, maybe remind; else count consecutive identical pending observations, switch when `>= CONFIRM`) and `evaluate_status()` (one `session_scope`, loops enabled instances, drops state of disabled ones, skips silenced, handles `status` and `version` kinds, returns notifications; `tags` from `inst.tags`).
- [ ] **Step 4: Run** the new tests → PASS.
- [ ] **Step 5: Commit** `git add -A && git commit -m "Alerts: state machine and status/version evaluation"`.

---

### Task 3: Certificate evaluation

**Files:**
- Modify: `src/periscope/alert_engine.py`
- Test: `tests/test_alert_engine.py`

**Interfaces:**
- Consumes: `step()`, `Notification`, `diff.cert_status(present, not_after, now)`, `diff.days_left`.
- Produces: `evaluate_certs(now: datetime | None = None) -> list[Notification]`.

- [ ] **Step 1: Write failing tests**: `test_cert_zone_change_is_notified_once` (probe `ok` baseline; `not_after` 20 days out ×2 → one `cert_orange` with `event="certificate"`, `domain`, `days_left`, `not_after`; a third identical evaluation → nothing; 5 days → `cert_red`; past → `cert_expired`); `test_cert_probe_failure_is_cert_error_not_expiry` (`present=False` ×2 → `cert_error`); `test_cert_renewal_resolves` (red → `not_after` +60 d ×2 → `cert_resolved`); `test_cert_has_no_reminders` (orange for 3 days of evaluations → exactly one notification); `test_vanished_domain_state_dropped_silently` (probe row deleted → state removed, no notification, no "resolved"); `test_cert_silenced_and_disabled_instances_skipped`; `test_cert_domain_with_braces_and_unicode` (`domain="é{x}.example"` works).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** `evaluate_certs()`: kind `cert`, `subject=domain`, observed = `diff.cert_status(...)`; map new status to type (`orange→cert_orange`, `red→cert_red`, `expired→cert_expired`, `none→cert_error`, `ok→cert_resolved`); ignore the `"reminder"` result of `step()`; delete states whose domain has no `CertProbe` row.
- [ ] **Step 4: Run** → PASS. **Step 5: Commit** `git commit -am "Alerts: certificate evaluation"`.

---

### Task 4: SMTP settings and input validation

**Files:**
- Create: `src/periscope/alert_config.py`
- Test: `tests/test_alert_config.py`

**Interfaces:**
- Produces in `periscope.alert_config`:
  - `@dataclass(frozen=True) class SmtpSettings: host: str; port: int; security: str; username: str; password: str; sender: str`.
  - `load_smtp(db) -> SmtpSettings | None` (`None` unless host and sender are set; password decrypted).
  - `save_smtp(db, *, host: str, port: int, security: str, username: str, password: str, sender: str) -> None` (empty `password` keeps the stored one; stored in the `settings` table under `alert_smtp_*` keys, password via `crypto.encrypt`; raises `LocalizedError` for bad port / security / sender).
  - `smtp_public(db) -> dict` (host, port, security, username, sender, `has_password: bool`; never the password).
  - `parse_recipients(raw: str) -> list[str]` (split on comma, semicolon, newline; unique, case-insensitive; 1–20 addresses; raises `LocalizedError`).
  - `clean_webhook_url(raw: str) -> str` (`http`/`https` with a host; raises `LocalizedError`).
  - `parse_events(selected: list[str]) -> str` (subset of `down, degraded, certificate, version`, at least one; returns comma string in canonical order).
  - `EVENTS = ("down", "degraded", "certificate", "version")`, `DEFAULT_EVENTS = "down,degraded,certificate"`.

- [ ] **Step 1: Write failing tests**: `test_save_and_load_smtp_encrypts_password` (raw `settings` row for the password is not the plaintext and decrypts to it; `smtp_public` has `has_password=True` and no password key anywhere in its values); `test_blank_password_keeps_existing`; `test_load_smtp_none_when_unconfigured`; `test_recipients_accepts_mixed_separators_and_dedupes`; `test_recipients_reject_header_injection` (`"a@b.example\r\nBcc: x@y.example"`: a newline separates tokens, so the token `"Bcc: x@y.example"` must be rejected as an invalid address; also a lone address containing `\r` or `\x00` inside is rejected), `"a@b.example, not-an-address"`, `""`, 21 addresses → `LocalizedError`; `test_webhook_url_schemes` (`https://h.example/x?t=1` ok and returned stripped; `file:///etc/passwd`, `javascript:alert(1)`, `ftp://h`, `https://`, `http:///x` rejected); `test_parse_events`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** the functions (address check: one `@`, non-empty local part, dotted domain, no whitespace or control characters).
- [ ] **Step 4: Run** → PASS. **Step 5: Commit** `git commit -am "Alerts: SMTP settings and validation"`.

---

### Task 5: Routing and message rendering

**Files:**
- Create: `src/periscope/alert_send.py` (routing + rendering part)
- Modify: `src/periscope/locales/fr.py`
- Test: `tests/test_alert_send.py`

**Interfaces:**
- Consumes: `Notification`, `AlertChannel`, `i18n.translate(lang, msgid, **params)`, `i18n.render(lang, stored)`.
- Produces in `periscope.alert_send`:
  - `matches(channel: AlertChannel, n: Notification) -> bool` (enabled; `n.event` in channel events — `test` always; channel with no tags matches all, otherwise at least one common tag name).
  - `render_email(lang: str, notifications: list[Notification], now: datetime) -> tuple[str, str]` (subject, plain-text body; subject contains the event count and instance names; body sections: down, degraded, certificates, resolved, version; instance `message` rendered with `i18n.render(lang, ...)`).
  - `render_webhook(lang: str, notifications: list[Notification], now: datetime) -> bytes` (UTF-8 JSON `{"version": 1, "sent_at", "lang", "summary", "events": [...]}`; each event has `type, instance, tags, status, message, domain, not_after, days_left, since`; datetimes ISO-8601 with `Z`).
  - `sign(secret: str, body: bytes) -> str` returning `"sha256=<hex>"`.

- [ ] **Step 1: Write failing tests**: `test_matches_by_tag_and_event` (no tag → all; tag filter; `cert_*` only with `certificate`; resolved of a `down` follows `down`; disabled channel never; `test` always matches an enabled channel); `test_render_email_english_default_and_french` (same notifications; French output contains a word from the new `fr.py` entries and the English one does not; both contain the instance name and count); `test_render_never_breaks_on_braces_and_unicode` (instance `"a{b}%s é"`, domain `"{x}.example"`, message with braces → no exception, names present verbatim, Review Focus 3); `test_render_webhook_contract` (parsed JSON has exactly the keys of the spec, `version == 1`, ISO dates end with `Z`, `tags` is a list, `lang` echoes); `test_sign_matches_hmac_sha256`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** with `N_()` msgids and named placeholders for every sentence (never f-strings into msgids), add the French values to `locales/fr.py`; run `.venv/bin/python -m pytest tests/test_i18n.py -q` to satisfy the catalog rules.
- [ ] **Step 4: Run** `tests/test_alert_send.py` and `tests/test_i18n.py` → PASS. **Step 5: Commit** `git commit -am "Alerts: routing and message rendering"`.

---

### Task 6: Senders, dispatch, send log

**Files:**
- Modify: `src/periscope/alert_send.py`
- Test: `tests/test_alert_send.py`

**Interfaces:**
- Consumes: `alert_config.load_smtp`, `SmtpSettings`, Task 5 functions, `crypto.decrypt`.
- Produces in `periscope.alert_send`:
  - `class DeliveryError(Exception)` (message is already free of secrets).
  - `async def send_email(smtp: SmtpSettings, recipients: list[str], subject: str, body: str) -> None` (stdlib `smtplib` in `asyncio.to_thread`; `starttls`/`ssl`/`none`; default SSL context, so certificates are verified; login only if username set; timeout 10 s).
  - `async def send_webhook(url: str, secret: str, body: bytes, transport: httpx.AsyncBaseTransport | None = None) -> None` (POST, `Content-Type: application/json`, `User-Agent: Periscope/<version>`, signature header when `secret`, `follow_redirects=False`, timeout 10 s; non-2xx → `DeliveryError`).
  - `ATTEMPTS = 3`, `BACKOFF = (1.0, 5.0)`.
  - `async def dispatch(notifications: list[Notification], now: datetime | None = None) -> None` (never raises; per matching enabled channel: one grouped message, up to `ATTEMPTS` tries with `BACKOFF`, one `AlertLog` row per channel with `ok`, `error`, comma event types, instance names, then prune the log to 30 days / 1000 rows).
  - `async def send_test(channel_id: int) -> tuple[bool, str]` and `async def send_smtp_test(to: str) -> tuple[bool, str]` (error text empty on success; both log).

- [ ] **Step 1: Write failing tests** (monkeypatch `alert_send.send_email` / `send_webhook` as needed, `BACKOFF = (0, 0)`): `test_dispatch_groups_one_message_per_channel` (3 notifications, two matching channels → exactly one send call per channel; each body contains all matching instances); `test_dispatch_filters_by_tag_for_msp_case` (channel "MSP" no tag + channel "A" tag `a`: incident on an instance tagged `a` reaches both, one tagged `b` reaches only MSP); `test_dispatch_retries_then_logs_failure` (sender raises `DeliveryError("boom")` twice then succeeds → 3 calls, log `ok=True`; always raises → 3 calls, log `ok=False`, `error == "boom"`); `test_dispatch_never_raises` (sender raises `RuntimeError`, DB-unconfigured SMTP → returns normally, failure logged as `SMTP not configured`); `test_log_pruned` (1005 rows → 1000 kept; rows older than 30 days removed); `test_send_webhook_signature_and_headers` (`httpx.MockTransport`: header `X-Periscope-Signature` equals `sign(secret, body)`, content type JSON; no header when secret empty); `test_send_webhook_302_is_failure_and_not_followed` (mock returns 302 with `Location`; second request never made; `DeliveryError`); `test_send_webhook_500_is_failure`; `test_send_email_modes` (monkeypatch `smtplib.SMTP` / `SMTP_SSL` with a recording fake: `starttls` mode calls `starttls` before `login`; `ssl` mode uses `SMTP_SSL`; `none` neither; message has `To`, `Subject`, plain text body); `test_secrets_never_in_log_or_error` (password `S3cret!` and webhook secret `HookSecret` never appear in any `AlertLog` column after failures, including a fake that puts the password in its exception text → `DeliveryError` message is generic) (Review Focus 4); `test_send_test_logs_and_reports` (returns `(True, "")` / `(False, "<error>")`, creates a log row with event `test`, does not touch `AlertState`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** (DB reads through `asyncio.to_thread` with `session_scope`; convert any sender exception other than `DeliveryError` to a generic `DeliveryError`/log text so a secret in an exception string can never be stored).
- [ ] **Step 4: Run** → PASS. **Step 5: Commit** `git commit -am "Alerts: delivery, retries and send log"`.

---

### Task 7: Wire the engine into the collector

**Files:**
- Modify: `src/periscope/alert_engine.py`, `src/periscope/collector.py`
- Test: `tests/test_alert_engine.py`

**Interfaces:**
- Produces: `async def run_status() -> None`, `async def run_certs() -> None` in `alert_engine` (each: `await asyncio.to_thread(evaluate_*)` then `await alert_send.dispatch(...)`; catches and logs every exception).
- Consumes: `collector.collect_all()` (after `check_agents`) and `collector.probe_all()` call them.

- [ ] **Step 1: Write failing tests**: `test_run_status_dispatches_what_evaluate_returns` (monkeypatch `alert_send.dispatch` to record; instance `down` observed twice via two `run_status()` awaits → one recorded batch containing one `instance_down`); `test_run_never_raises` (patch `evaluate_status` to raise → `run_status()` returns, error logged, collector unaffected); `test_collect_all_and_probe_all_call_alert_runs` (monkeypatch `collector._enabled_ids` to `[]`, patch `alert_engine.run_status` / `run_certs` with recorders; `await collector.collect_all()` and `await collector.probe_all()` each call exactly their own).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement**; in `collector.py` import `alert_engine` lazily inside the functions if a circular import appears.
- [ ] **Step 4: Run** the full suite `.venv/bin/python -m pytest -q` → PASS (the existing collector tests must still pass; `PERISCOPE_COLLECTOR_ENABLED=false` keeps loops off). **Step 5: Commit** `git commit -am "Alerts: hook the engine into the collector loops"`.

---

### Task 8: Alerts page, routes, sidebar

**Files:**
- Create: `src/periscope/web/routes_alerts.py`, `src/periscope/web/templates/admin_alerts.html`, `src/periscope/web/templates/admin_alert_form.html`
- Modify: `src/periscope/web/app.py` (include router), `src/periscope/web/templates/base.html` (link below Instances), `src/periscope/web/templates/_macros.html` (icon), `src/periscope/web/routes_admin.py` (`EVENT_LABELS`), `src/periscope/locales/fr.py`
- Test: `tests/test_alert_routes.py`

**Interfaces:**
- Consumes: `alert_config.*`, `alert_send.send_test`, `alert_send.send_smtp_test`, `tags.parse/assign`-style tag helpers (`tags.parse`, `tags.names`; channel tags reuse existing `Tag` rows, create missing ones like `tags.assign` does — add a small shared helper in `tags.py` only if duplication results), `audit()`, `require_admin`, `render()`.
- Produces routes (router prefix `/admin/alerts`, all `require_admin`; POSTs redirect with `?m=<code>`):
  - `GET /admin/alerts` page: SMTP form (password field empty, shows `has_password`), channel list (name, type, recipients or webhook host only, tags, events, language, enabled, last result), buttons New e-mail alert / New webhook alert / Edit / Delete / Send test, last 50 send-log rows.
  - `POST /admin/alerts/smtp` (fields `host, port, security, username, password, sender`), `POST /admin/alerts/smtp/test` (field `to`; result shown on the page, never the password).
  - `GET /admin/alerts/new?kind=email|webhook`, `POST /admin/alerts` (fields `kind, name, enabled, lang, events[], tags, recipients | webhook_url, webhook_secret`), `GET /admin/alerts/{id}`, `POST /admin/alerts/{id}`, `POST /admin/alerts/{id}/delete`, `POST /admin/alerts/{id}/test`.
  - Audit codes: `alert_channel_created`, `alert_channel_edited`, `alert_channel_deleted`, `alert_smtp_updated`, `alert_test_sent` (detail = channel name; never a URL query, secret or password).
  - Sidebar entry "Alerts" right after Instances, only for admins, `aria-current` when path starts with `/admin/alerts`.

- [ ] **Step 1: Write failing tests** (`make_client()` + `login_as()` from `tests/helpers.py`; follow `tests/test_admin_instances.py` for style): `test_alerts_page_admin_only` (reader gets redirected/403 like other admin pages, anonymous goes to login); `test_sidebar_link_below_instances` (admin dashboard HTML has the Alerts link after the Instances link; reader's does not); `test_create_email_channel_and_list` (POST then GET: name, recipients, tags and events shown; `AlertChannel` stored with chosen `lang`, default `en`, default events when none posted); `test_create_webhook_channel_secret_encrypted_and_never_shown` (stored `webhook_secret_enc != secret`, `decrypt` gives it back, secret and full URL query absent from the page HTML; editing with blank secret keeps it, with a new one replaces it); `test_invalid_input_rejected_with_message` (recipient with CR/LF, `file:///x` URL, duplicate name, no event → 400 and nothing stored) (Review Focus 1, 2); `test_edit_and_delete_channel_audited` (audit rows exist with the new codes and contain no secret); `test_csrf_required_on_every_post`; `test_smtp_form_saves_without_echoing_password` (response and later page never contain the password; `has_password` shown) (Review Focus 4); `test_send_test_buttons` (monkeypatch `alert_send.send_test` / `send_smtp_test` to return `(False, "boom")`, page shows `boom`); `test_page_in_french_has_no_missing_msgids` (covered by `tests/test_i18n.py`; run it).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** the router, templates (Bootstrap local copy, no inline JS/style, strict CSP; delete asks confirmation via a normal form page or `data-confirm` handled in existing `web/static/` JS if the instances page does it — mirror that page), sidebar link and icon, `EVENT_LABELS`, French strings.
- [ ] **Step 4: Run** `tests/test_alert_routes.py`, `tests/test_i18n.py`, then full suite. **Step 5: Commit** `git commit -am "Alerts: admin page and routes"`.

---

### Task 9: Per-instance silence

**Files:**
- Modify: `src/periscope/web/routes_admin.py`, `src/periscope/web/templates/admin_instance_edit.html`, `src/periscope/locales/fr.py`
- Test: `tests/test_admin_instances.py` (append)

**Interfaces:**
- Produces: `POST /admin/instances/{inst_id}/silence` (field `hours` ∈ `0` (clear), `1`, `4`, `24`; `require_admin`; sets `Instance.silenced_until = utcnow() + hours` or `None`; audit `instance_silenced` / `instance_unsilenced`, detail = instance name; redirect to the instance page). The edit page shows the active silence end time (localized `dt` filter) and the four buttons.

- [ ] **Step 1: Write failing tests**: `test_silence_sets_and_clears` (hours 4 → `silenced_until` about 4 h ahead; 0 → `None`; audit rows written); `test_silence_rejects_other_values_and_unknown_instance` (`hours=999` → 400/ignored with nothing changed; unknown id → redirect to the list); `test_silence_requires_admin_and_csrf`; `test_edit_page_shows_active_silence`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** (new `EVENT_LABELS` entries + French). **Step 4: Run** tests + `tests/test_i18n.py`. **Step 5: Commit** `git commit -am "Alerts: per-instance silence"`.

---

### Task 10: Documentation, roadmap, final verification

**Files:**
- Create: `docs/alerts.md`
- Modify: `CHANGELOG.md`, `ROADMAP.md`, `README.md`

- [ ] **Step 1: Write `docs/alerts.md`**: what triggers an alert and the confirmation/reminder/silence rules, setup (SMTP then channels), the MSP example (channel "MSP" without tag + channel "Customer A" with tag), webhook payload v1 table and signature verification snippet (Python, 5 lines), send log, limits (no persistent queue, single process, first-sight silent baseline, two mails possible per incident, SMTP-not-configured behaviour).
- [ ] **Step 2: Update** `CHANGELOG.md` (`### Added`: outgoing alerts, Alerts page, silence, send log, `docs/alerts.md`), `ROADMAP.md` (goal 1 → `in progress`, then `done` only when the PR link exists), README feature list / link to `docs/alerts.md`.
- [ ] **Step 3: Full verification**: `.venv/bin/python -m pytest -q` (all pass), `.venv/bin/ruff check src tests dev` (clean), PostgreSQL run as in Task 1 Step 5 (`tests/test_postgres.py` passes with migration 0005).
- [ ] **Step 4: Manual smoke** with `dev/fake_bunkerweb.py` (see its header): add a direct instance, stop the fake → after about 1 min a webhook (e.g. a throwaway local `python -m http.server`-style receiver or `nc -l`) receives one `instance_down`; restart the fake → one `instance_resolved`. Report what was observed.
- [ ] **Step 5: Commit** `git commit -am "Alerts: documentation and roadmap"`.
