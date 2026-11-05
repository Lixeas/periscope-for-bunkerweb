# Changelog

All notable changes to Periscope for BunkerWeb are documented here. Versions follow
[semantic versioning](https://semver.org/) (`vX.Y.Z`); a version is released when the change that
introduces it is merged into `main` (see [docs/releasing.md](docs/releasing.md)).

Write new entries under `[Unreleased]`; `python dev/release.py bump major|minor|patch` moves them under
the new version.

## [Unreleased]

## [0.3.0]

### Added
- Kubernetes support: Helm charts `periscope` (console) and `periscope-agent` in `deploy/helm`. Non-root,
  read-only filesystem, probes, one enforced console replica, secrets by reference, optional Ingress,
  separate Service for the mutual-TLS agent listener, SQLite volume or external PostgreSQL, and an agent
  that enrolls itself from a bundle Secret. CI lints and schema-checks them and runs the console on a
  kind cluster; at release they are published to `oci://ghcr.io/<owner>/charts`. See `docs/kubernetes.md`.
- `GET /readyz`: readiness probe that checks the database (503 when it is unreachable); `/healthz`
  stays a pure liveness check.
- Outgoing alerts: notify by e-mail (SMTP) or JSON webhook (optional HMAC signature) when an instance
  turns `degraded` / `down`, when a certificate enters the orange / red / expired zone or its TLS probe
  fails, and when BunkerWeb changes version. One message per confirmed change (2 cycles), "back to
  normal" messages, 24 h reminders, grouped messages, per-alert tag and event filters and language
  (English by default). Configured by admins on the new **Alerts** page (SMTP server, alerts, test
  buttons, send log); secrets are encrypted and never displayed again. See `docs/alerts.md`.
- Per-instance alert silence (1 h / 4 h / 24 h) on the instance's edit page.
- PostgreSQL support in the image: `psycopg` is installed (optional extra `postgres` outside Docker),
  `postgresql://` URLs are accepted as is, dead connections are detected (`pool_pre_ping`). CI runs
  the migrations and an ORM round trip against PostgreSQL 16.
- `periscope agent health`: exit code telling whether the console accepted a recent report; used as
  the healthcheck of `docker-compose.agent.yml` (and usable as a Kubernetes liveness probe).
- `GET /healthz` on the console: unauthenticated, returns `ok` and no data (liveness / readiness
  probes). The image's healthcheck now uses it instead of `/login`.

### Changed
- Documented the enrollment rate limit behind a TCP proxy or load balancer (`docs/agent.md`): the quota
  is per IP, so agents behind one proxy share it.
- `docker-compose.yml` runs the released image `ghcr.io/lixeas/periscope-for-bunkerweb` (pinned with
  `PERISCOPE_VERSION` in `.env`) by default; building from source is still available with
  `docker-compose.build.yml`. The README's getting started and upgrade steps cover both.

## [0.2.1]

### Changed
- `docker-compose.agent.yml` uses the released image `ghcr.io/lixeas/periscope-for-bunkerweb`
  (pinned with `PERISCOPE_VERSION`) instead of building from a checkout: the file alone is enough to
  deploy an agent at a customer's site.

### Security
- Agent listener: an invalid agent report no longer echoes the exception text in the HTTP response;
  the reason is logged on the console only (code scanning: information exposure through an exception).
- Agent listener: error messages sent by an agent are only kept if they are messages of Periscope's own
  code with plain parameters; anything else is stored as plain text. A compromised agent could
  otherwise inject a Python format string, rendered at each page view (memory exhaustion,
  attribute walk).
- Agent: the agent directory is created `0700`, and the private key can no longer inherit the mode of
  a leftover temporary file.

## [0.2.0]

### Added
- **Agent mode** for BunkerWeb instances in networks the console cannot reach (for example one network
  per customer): `periscope agent enroll|run` collects the instance locally and pushes its reports to
  a dedicated listener over **mutual TLS**, with Periscope's own certificate authority, single-use
  enrollment bundles, automatic certificate renewal and immediate revocation. See
  [docs/agent.md](docs/agent.md).
- **Tags** on instances (for example one per customer); every view can be filtered by tag, and the
  differences between instances are then computed within the tag.
- Parallel collection bounded by `PERISCOPE_MAX_PARALLEL` / `PERISCOPE_MAX_PARALLEL_PROBES`, and
  database access outside the event loop, for fleets beyond ten instances.
- Release process: version in `src/periscope/__init__.py`, this changelog, automatic tag, GitHub
  release and container image at merge.

### Removed
- **Breaking:** the static `API_TOKEN` authentication mode (full administrator access). Instances
  that used it are kept but disabled after the upgrade: edit them and enter a restricted API user.

## [0.1.0]

First version (not tagged): read-only multi-instance console for BunkerWeb polled directly through
its API (services, bans, jobs and plugins, nodes, TLS certificates), mandatory second factor,
English and French interface.
