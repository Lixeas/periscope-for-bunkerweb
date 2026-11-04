# Outgoing alerts — design (ROADMAP v0.3.0, goal 1)

## Intent

Today a problem is only seen if someone opens the dashboard. Periscope is used by MSPs watching several
customers' BunkerWeb instances: the customer and the MSP must both be told when something breaks, and
a different customer has different recipients. Notify by e-mail or webhook when an instance is degraded
or down, and warn ahead of certificate expiry.

## Goals

- Notify on: instance `degraded`, instance `down` (an agent that went silent is already `down`; an
  offline nginx node already makes the instance `degraded`: no separate event), certificate entering the
  orange (< 21 d) / red (< 7 d) / expired zone, TLS probe failure, BunkerWeb version change.
- One notification per confirmed state change, a "resolved" notification on return to normal, an
  optional reminder every 24 h while a problem lasts.
- Channels: e-mail (SMTP) and generic JSON webhook. Several of each.
- Routing per channel by tag (empty = all instances) and by event type. MSP use: channel "MSP" (no
  tag) + channel "Customer A" (tag `customer-a`); an incident at customer A reaches both.
- Admin-only configuration page, **Alerts**, in the sidebar right below **Instances**.
- Per-instance temporary silence (maintenance).
- Send log (success / failure) so a broken channel is visible.

## Non-goals / anti-goals

- No alerts on bans, jobs, plugins, service differences (later, if wanted).
- No alert when Periscope itself is down (needs an external check, e.g. a dead man's switch).
- No per-user subscriptions, escalation chains, on-call schedules, Slack/Teams-specific formatting
  (the generic webhook covers them through their incoming-webhook adapters).
- No persistent delivery queue (see "Delivery").
- Anti-goals: alert storms (one flapping check must not send a mail per cycle), a secret appearing in
  any message or log, a failed channel stopping the collector.

## Decisions taken with the user

- E-mail channel = a plain list of recipient addresses (no per-recipient settings). A webhook channel
  has a URL and an optional secret.
- SMTP server (host, port, security, username, password, sender address) is configured **on the Alerts
  page**, not in environment variables.
- Default language of messages is **English**; each channel has its own language setting (en / fr)
  because recipients have no Periscope account.
- Confirmation delay 2 cycles; grouping; test button; silence; send log; 24 h reminders; HMAC
  signature of the webhook; extra events (probe failure, version change) — all in v0.3.0.
- Admin only, like Instances. Configuration changes are audited. Secrets encrypted like the BunkerWeb
  passwords (Fernet, `PERISCOPE_SECRET_KEY`) and never displayed again (blank field on edit = keep).

## Behaviour

**Evaluation.** A function `alerts.evaluate()` runs at the end of each `collector.collect_all()` (after
`check_agents`, so agents are covered) and at the end of `probe_all()` (certificates). It works only
from the database, like the web layer, and then hands the notifications to the dispatcher.

**Instance status.** Per enabled instance the engine remembers the last *notified* status (initial
assumption: `ok`) and a counter of consecutive observations of a different status. When the counter
reaches 2 (about 1 minute) the change is notified: to `degraded` or `down` → alert; back to `ok` →
"resolved". `unknown` is never alerted and never counts. While a problem lasts and 24 h passed since
the last message, a "reminder" is sent. Down→degraded and degraded→down are changes and are notified.

**Certificates.** Per (instance, domain) probe: states from `diff.cert_status` (`ok`, `orange`, `red`,
`expired`, `none` = probe failed / no certificate). Same confirmation (2 consecutive evaluations, i.e.
2 probe cycles) and one message per zone change; "resolved" when back to `ok` (renewal). `none` is
reported as "TLS probe failed" and not as an expiry.

**Version change.** When the version of an instance differs from the last known one (after the first
observation), one informational message; no "resolved", no reminder.

**Silence.** `Instance.silenced_until` (UTC naive). A silenced instance is skipped entirely by
`evaluate()`: state is not advanced, so if the problem is still there when the silence ends, the normal
confirmation produces the alert; a problem that came and went during the silence produces nothing.
Set from the instance's admin page (1 h, 4 h, 24 h, clear); audited.

**Grouping.** Per evaluation run, each channel gets **one** message containing every notification
matching its tag filter and events (sections: down, degraded, certificates, resolved, version).
E-mail: one mail with a subject such as `[Periscope] 3 instances down` / `…` (localized). Webhook: one
POST with an `events` array.

**Filtering.** A channel receives a notification if the instance carries one of the channel's tags
(or the channel has no tag) and the event type is enabled on the channel. Event switches on a channel:
`down`, `degraded`, `certificate` (also covers probe failure), `version`; resolved and reminder follow
the type they relate to. New channels default to down + degraded + certificate on, version off.

**Test.** A "Send test" button per channel sends a clearly labelled test message through the real
path and shows the result immediately (and logs it). It does not touch alert state.

## Messages and security

- Never a secret in a message, in the log, in the audit or in an error shown to the UI. Instance
  `last_error` texts are included (rendered in the channel's language); they are already free of
  credentials by the existing rule.
- E-mail: plain text; recipients validated (simple address check, no CR/LF — header injection); cap on
  the number of recipients per channel (20, my call). SMTP security: STARTTLS (default), implicit TLS or
  none; certificates always verified; authentication optional.
- Webhook: `http` or `https` URL accepted (admin-defined; an admin can already reach internal hosts via
  instance URLs); no redirects followed; timeout 10 s; success = 2xx. Header
  `X-Periscope-Signature: sha256=<hex HMAC-SHA256 of the raw body>` when a secret is set. Payload v1:
  `{"version": 1, "sent_at", "lang", "summary", "events": [{"type", "instance", "tags", "status",
  "message", "domain", "not_after", "days_left", "since"}]}`; `type` ∈ `instance_down`,
  `instance_degraded`, `instance_resolved`, `instance_reminder`, `cert_orange`, `cert_red`,
  `cert_expired`, `cert_error`, `cert_resolved`, `instance_version_changed`, `test`.
  Field names are a stable contract (document them in `docs/`).

## Delivery

Sent from the collector process without blocking it: SMTP (`smtplib`, stdlib) in a thread, webhook
with `httpx` (already a dependency). Up to 3 attempts with short backoff (1 s, 5 s); each message gets
one send-log row per channel (success or the final error, secrets stripped). Alert state advances even
if delivery failed (no endless retries); the failure is visible in the log. No persistent queue: a
console restart during retries loses that message (acceptable ceiling, documented). No new dependency.

## Data model (migration 0005; must work on SQLite and PostgreSQL, see `tests/test_postgres.py`)

- `alert_channels`: id, name (unique), kind (`email` | `webhook`), enabled, lang, events (flags),
  recipients (text, email), webhook_url, webhook_secret_enc, created_at.
- `alert_channel_tags`: channel ↔ tag (same pattern as `instance_tags`, ON DELETE CASCADE).
- SMTP settings in the existing `settings` key/value table (password Fernet-encrypted).
- `alert_state`: per subject (instance, or instance + domain for certificates, or instance for version):
  kind, notified status, pending status + counter, last_notified_at. Removed with the instance.
- `alert_log`: at, channel id (nullable) and channel name copy, event types, instance names (short),
  ok, error. Pruned (keep the last 30 days / 1000 rows, my call).
- `instances.silenced_until` (nullable datetime).
- Deleting a channel keeps its log rows (name copy).

## UI

- Sidebar: **Alerts** (admin only) right below **Instances**, active state like the other entries.
- `/admin/alerts` (admin only): SMTP server form (with "send test e-mail" to an address), list of
  channels (name, type, recipients or webhook host, tags, events, language, enabled, last result) with
  **New e-mail alert**, **New webhook alert**, **Edit**, **Delete** (confirmation), **Send test**; the
  send log below (my call: same page, last 50 entries).
- Instance admin page: silence control (1 h / 4 h / 24 h / clear) showing the current silence.
- Every new write route goes through `require_admin` (session + CSRF). English msgids with `_()` /
  `tr()` plus French entries in `locales/fr.py` (`tests/test_i18n.py` enforces them). New audit event
  codes with labels in `EVENT_LABELS`: channel created / updated / deleted, SMTP updated, test sent,
  instance silenced / unsilenced.
- Messages sent to recipients use the channel's language, not the reader's.

## Left to the builder

Table and column names, exact layout and CSS of the page, templates of the messages, retry mechanics,
how the dispatcher is injected for tests, the e-mail address validation details, icon for the sidebar.

## Testing and docs

- Unit tests of `evaluate()` with a fake clock and a fake dispatcher: confirmation, resolved, reminder,
  grouping, tag/event filtering, silence, certificate zones, version change, flapping.
- Tests of the SMTP and webhook senders against local fakes (HMAC checked, no secret in the log).
- Web tests of the Alerts routes (admin only, CSRF, secret never re-displayed, audit rows).
- Migration test on SQLite and PostgreSQL.
- Docs: `docs/alerts.md` (setup, payload contract, MSP example, limits), `CHANGELOG.md`, `ROADMAP.md`,
  README mention. Single console process: state and rate limits stay in-process (existing constraint).
