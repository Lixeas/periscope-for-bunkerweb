# Architecture

```
                       ┌──────────────────────────── Periscope (one process) ───────────────────────────┐
                       │                                                                                │
 BunkerWeb instance 1 ─┤  Collector (every 30 s)            SQLite / PostgreSQL / MariaDB               │
 BunkerWeb instance 2 ─┼─▶ BWClient (GET only) ─▶ normalize ─▶ snapshots (last state per instance+kind) │
          ...         ─┤  TLS probe (every 15 min) ────────▶ cert_probes                                │
                       │                                          │                                     │
                       │                                          ▼                                     │
 Browser ◀── HTTPS ───▶│  FastAPI + Jinja2 ◀── queries / diff (cross-instance gaps, cert status)        │
                       │  sessions, CSRF, MFA, roles, audit                                             │
                       └────────────────────────────────────────────────────────────────────────────────┘
```

- **One process, two parts.** `periscope.web.app.create_app()` serves the web UI and, in its lifespan, starts the background collector.
- **The web layer never talks to BunkerWeb.** It only reads what the collector stored, so pages stay fast, an unreachable instance shows as `down` with its last known data, and the browser never sees instance credentials.
- **Collector.** Every `PERISCOPE_POLL_INTERVAL` seconds it queries each enabled instance in parallel (health, services, bans, jobs, plugins, nodes) and stores the latest snapshot per instance and type. A network failure marks the instance `down` and keeps the previous snapshot; a partial failure marks it `degraded`.
- **TLS probe.** Every `PERISCOPE_PROBE_INTERVAL` seconds it connects to `instance_host:tls_port` with SNI set to each service's domain and reads the certificate that is actually served. The certificate is inspected, not validated, so expired and self-signed certificates are reported rather than hidden. No HTTP request is sent.
- **API response parsing** lives in a single module, `src/periscope/normalize.py`, which is the only part coupled to the shape of BunkerWeb's JSON.
- **Authentication.** Password login creates a short-lived "pending" session; completing the second factor replaces it with a full server-side session (the token is rotated). Every state-changing request is protected by CSRF tokens and an `Origin` allow-list.
- **Agent mode.** An instance in another network is reached through a Periscope agent (`periscope agent run`, `src/periscope/agent.py`) that runs next to it, collects it with the same functions (`collector.gather`, `collector.probe_domains`) and pushes a report to the console's **agent listener** (`src/periscope/agent_server.py`): a second HTTPS server started in the same lifespan, on its own port, with mutual TLS against Periscope's private CA (`src/periscope/pki.py`). Each client certificate maps to one instance by fingerprint; reports are validated strictly, then stored like a direct collection. The collector only marks silent agents `down`. See [agent.md](agent.md).

```
 Customer network                      │              Periscope (one process)
  BunkerWeb ◀─ GET ─ Agent ── HTTPS + client cert (outbound) ──▶  agent listener :8443 ─┐
                                       │                                                ▼
                                       │              web UI :8000 ◀── queries ◀── snapshots / cert_probes
```

- **Tags.** Instances carry tags (`tags`, `instance_tags`); every view takes an optional `tag` that limits it, and the cross-instance gaps, to the instances of that tag.
- **Scale.** Instances are collected concurrently (bounded by `PERISCOPE_MAX_PARALLEL`), database access of the collector runs in worker threads, and the page routes are synchronous so FastAPI runs them in its thread pool: the event loop shared by the web UI, the collector and the agent listener is never blocked by SQLite.
- **Secrets.** BunkerWeb credentials and the agent CA's private key are encrypted at rest with Fernet, using `PERISCOPE_SECRET_KEY`, and are never displayed again. Agent enrollment tokens are stored hashed and shown once.
