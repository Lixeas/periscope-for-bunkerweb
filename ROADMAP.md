# Roadmap

What the next versions should deliver, and where each goal stands. Read it before starting work;
update it in the pull request that moves a goal (status, link to the PR, decisions taken).

Statuses: `todo`, `in progress`, `done`, `dropped`. Released changes are described in
[CHANGELOG.md](CHANGELOG.md); how versions are released: [docs/releasing.md](docs/releasing.md).

## v0.3.0

Goals are listed in the order they will be done (numbers are stable identifiers, not the order).
Goal 5 (agent CA rotation) moved to v0.4.0.

| # | Goal | Status | PR / notes |
|---|---|---|---|
| 3 | Agent healthcheck (+ `/healthz`) | in progress | Branch `v0.3.0`. `/healthz` is also needed by goal 2 |
| 4 | Agent enrollment rate limit behind a proxy | todo | Decision: documentation only, no PROXY protocol |
| 6 | PostgreSQL driver in the image | todo | Needed by goal 2 |
| 1 | Outgoing alerts | todo | |
| 2 | Kubernetes compatibility | todo | Last: depends on goals 3 and 6 |

### 1. Outgoing alerts

Today a problem is only seen on the dashboard. Notify when an instance turns `down` or `degraded`,
an agent goes silent, a node goes offline, or a certificate enters the orange / red zone.

- Channels: e-mail (SMTP) and generic webhook (JSON POST; covers Slack, Teams, Mattermost, ntfy…).
- One notification per state change (not one per cycle), plus a "resolved" notification.
- Configuration from the admin UI (channels, which events), secrets encrypted like the BunkerWeb
  passwords; optionally filtered by tag (e.g. one webhook per customer).
- Audit the configuration changes; never put a secret in an alert.

### 2. Kubernetes compatibility

Run the console (and the agent) on Kubernetes, and monitor BunkerWeb deployed on Kubernetes.

- Manifests or a Helm chart: console Deployment (1 replica), Service for the web UI, separate Service
  for the agent listener (TCP / `LoadBalancer`, TLS passthrough: never terminated by an Ingress),
  Secret for `PERISCOPE_SECRET_KEY`, PersistentVolumeClaim for `/data` or an external PostgreSQL
  (goal 6).
- Health endpoints for liveness / readiness probes (today only `/login` answers; add a light
  unauthenticated `/healthz` with no data in it).
- Constraint to document or lift: one console replica only (collector, agent listener, rate limits
  and lockouts are in-process state).
- Already compatible: non-root user (uid 10001), read-only root filesystem, configuration through
  environment variables.
- Agent in a customer cluster: Deployment + Secret (API password) + PVC (key and certificates);
  enrollment through a one-off `kubectl exec` or a Job.
- BunkerWeb on Kubernetes (ingress controller / autoconf): check how its API and nodes are exposed
  and that `normalize.py` handles them.

### 3. Agent healthcheck

`docker-compose.agent.yml` disables the healthcheck (the image's one targets the web UI). The agent
could write a timestamp after each accepted report, and `periscope agent health` would check it
(used by Docker and by a Kubernetes liveness probe).

### 4. Agent enrollment rate limit behind a proxy

The enrollment limiter is keyed by client IP: behind a TCP proxy every agent shares one address.
Decision for v0.3.0: document the behaviour and workarounds in `docs/agent.md` only. PROXY protocol
(header read before the TLS handshake, trusted proxy IPs only) and a limit keyed by token (needs a
global cap too) are left for later if a real use case appears.

### 5. Agent CA rotation (moved to v0.4.0)

No tooling to replace the agents' CA (e.g. after a leak of `PERISCOPE_SECRET_KEY` with the
database). Add a rotation that keeps the old CA trusted during a transition period and lets agents
fetch the new one over their existing mutual TLS session.

### 6. PostgreSQL driver in the image

`PERISCOPE_DATABASE_URL` accepts PostgreSQL, but the image has no driver. Add `psycopg` (optional
extra installed in the image), test the migrations against PostgreSQL in CI, document it.
