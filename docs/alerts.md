# Outgoing alerts

Periscope can notify you by **e-mail** (SMTP) or **webhook** when an instance is degraded or down, when a
certificate is about to expire, and when BunkerWeb is upgraded. Everything is configured by an
administrator on the **Alerts** page (sidebar, right below **Instances**).

## What triggers a message

| Event | Message when | Switch on the alert |
|---|---|---|
| Instance `down` | the status is `down` on 2 consecutive cycles (about 1 minute). An agent that went silent is already `down`. | `down` |
| Instance `degraded` | the status is `degraded` on 2 consecutive cycles (partial failure, an offline nginx node…). | `degraded` |
| Back to normal | the instance is `ok` again (2 cycles). Sent to every alert that has `down` or `degraded` on, since the instance may have gone down, then degraded, before recovering. | `down` / `degraded` |
| Reminder | the instance is still `degraded` / `down` 24 h after the last message. | `down` / `degraded` |
| Certificate | a domain enters the orange zone (< 21 days), the red zone (< 7 days) or expires; the TLS probe fails; the certificate is valid again. One message per change, no reminder. | `certificate` |
| Version | BunkerWeb reports a different version (informational). | `version` |

Rules that apply to all of them:

- **One message per confirmed change**, never one per cycle. A check that flaps (`down`, `ok`, `down`…)
  does not reach the 2 consecutive observations and stays silent.
- **Grouping.** Each alert receives one message per evaluation listing everything that changed for the
  instances it covers. The collection and the certificate probe run on their own schedules, so one
  incident can produce one message for the status and another for the certificates.
- **First sight is silent.** When Periscope sees an instance, a domain or a version for the first time
  (first deployment of 0.3.0, a new instance), it records the current state as already notified. A fleet
  that already has problems does not send a burst of messages; reminders start from that moment.
- **Silence.** On the instance's edit page, *Silence for 1 h / 4 h / 24 h* mutes everything about that
  instance. If a problem was already notified before the silence and is over when it ends, the
  "back to normal" message is sent then; a problem that began and ended during the silence sends nothing.
- A disabled instance sends nothing, and its alert state is forgotten.

## Setting it up

1. **SMTP server** (only for e-mail alerts): host, port, security (`starttls`, `ssl` or `none`;
   certificates are always verified), optional username and password, sender address. The password is
   encrypted in the database and never displayed again (empty field on edit = keep). *Send a test e-mail*
   checks it.
2. **New e-mail alert** or **New webhook alert**:
   - e-mail: one address per line (20 at most);
   - webhook: the URL (`http` or `https`) and an optional signing secret;
   - **tags**: only instances carrying one of them are reported (empty = all instances);
   - **events**: which of the switches above are on (new alerts: `down`, `degraded`, `certificate`);
   - **language** of the messages: English by default, French available. Recipients need no Periscope
     account, so the language is a property of the alert, not of the reader.
3. **Send test** (per alert) sends a clearly labelled test message through the real path and shows the
   result. The **send log** at the bottom lists every message (date, alert, events, instances, result).

### MSP example

One console, two customers, and the MSP wants to see everything:

| Alert | Tags | Recipients |
|---|---|---|
| MSP | *(none)* | `noc@msp.example` |
| Customer A | `customer-a` | `it@customer-a.example` |
| Customer B | `customer-b` | `ops@customer-b.example` |

An incident on an instance tagged `customer-a` reaches *MSP* and *Customer A*, nobody else. Tags are the
ones of the instances (see **Instances**); the routing uses the instance's current tags when the message
is sent.

## Webhook format

`POST` with `Content-Type: application/json` and `User-Agent: Periscope/<version>`. Any `2xx` answer is a
success; redirects are **not** followed. Up to 3 attempts (1 s, then 5 s apart), 10 s timeout each.

```json
{
  "version": 1,
  "sent_at": "2026-11-04T12:00:00Z",
  "lang": "en",
  "summary": "2 event(s): bw1, bw2",
  "events": [
    {"type": "instance_down", "instance": "bw1", "tags": ["customer-a"], "status": "down",
     "message": "1 node offline: n1", "domain": "", "not_after": null, "days_left": null,
     "since": "2026-11-04T12:00:00Z", "version": ""},
    {"type": "cert_red", "instance": "bw2", "tags": [], "status": "",
     "message": "", "domain": "a.example", "not_after": "2026-11-07T12:00:00Z", "days_left": 2,
     "since": "2026-11-04T12:00:00Z", "version": ""}
  ]
}
```

| `type` | Meaning |
|---|---|
| `instance_down`, `instance_degraded` | the instance turned `down` / `degraded` (`message` = the reason shown on the dashboard) |
| `instance_resolved` | back to `ok` |
| `instance_reminder` | still `down` / `degraded` (`status` tells which); `since` = last message |
| `cert_orange`, `cert_red`, `cert_expired` | the certificate of `domain` entered the zone (`days_left`, `not_after`) |
| `cert_error` | the TLS probe of `domain` failed |
| `cert_resolved` | the certificate is valid again |
| `instance_version_changed` | BunkerWeb now runs `version` (the only event where this field is not empty) |
| `test` | message of the *Send test* button |

These field names are a contract: new fields may be added, existing ones keep their meaning.

**Signature.** With a signing secret, each request carries `X-Periscope-Signature: sha256=<hex>`, the
HMAC-SHA256 of the raw request body. Verify it before trusting the content:

```python
import hashlib, hmac

def valid(secret: str, body: bytes, header: str) -> bool:
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)
```

For Slack, Teams, Mattermost or ntfy, point the webhook at an adapter or an automation tool that accepts
generic JSON (there is no vendor-specific formatting).

## Security and limits

- Messages never contain a secret. SMTP passwords, webhook secrets and webhook URLs (which often hold a
  token) are never displayed again once saved: the list shows the host only, and an empty field on edit
  keeps the stored value. The first two are encrypted with `PERISCOPE_SECRET_KEY`.
- The webhook URL is chosen by an administrator and may point to an internal host.
- Delivery runs in the background and the alerts of one evaluation are sent concurrently: a dead webhook or a slow SMTP server never delays the next collection.
- **No persistent queue.** A message is retried in memory; if the console restarts during the retries,
  that message is lost. A failed delivery never blocks the collector and appears in the send log.
- A channel can be created before the SMTP server is configured: its e-mails are logged as failed
  ("SMTP not configured").
- Alert state and rate limits live in the single console process (see the one-replica constraint in
  the roadmap for Kubernetes).
- Configuration changes, test messages and silences are recorded in the audit log.
