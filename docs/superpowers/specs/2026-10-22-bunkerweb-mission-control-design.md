> Note: this document is historical. The project was called "BunkerWeb Mission Control"; it was renamed "Periscope for BunkerWeb" (package `periscope`, prefix `PERISCOPE_`). The names below are the original ones.

# BunkerWeb Mission Control — Design

Date: 2026-10-22
Status: approved by the user, pending review of the written spec.

## 1. Goal

A single web application for monitoring several BunkerWeb instances (2 to 10, same network) through the BunkerWeb API. Secure, reachable locally and through a domain, with strong authentication. Long-term vision: offer the tool to the BunkerWeb team for adoption or official status, hence the alignment with their stack (Python, FastAPI, SQLAlchemy, Jinja2, Bootstrap, Docker) and their license (AGPLv3).

## 2. v1 scope

Read-only monitoring. No writes to BunkerWeb.

Views: instance health, protected services, active bans, jobs and plugins, Let's Encrypt certificates (existence, issuer, expiry).

## 3. Architecture

A single Python container (FastAPI), two components in the same process:

- **Collector**: periodic task (30 s by default). For each registered instance, calls the BunkerWeb API with the instance token (ping/health, services, bans, jobs, plugins) and stores snapshots in the database. The TLS probe runs at a slower cadence (15 min by default). Instances are processed in parallel. A failure marks the instance as "unreachable" while keeping the last valid snapshot.
- **Web/API**: FastAPI serves Jinja2 + Bootstrap pages and an internal JSON API for refreshes. It reads only the database, never BunkerWeb directly.

Chosen approach: collector + database cache (rejected: live proxy without storage; one agent per instance).

### Data

SQLAlchemy + Alembic. SQLite by default, PostgreSQL/MariaDB optional. Tables: `users`, `credentials` (TOTP, passkeys, hashed backup codes), `instances` (URL, encrypted token), `snapshots` by type, `cert_probes`, `audit_log`.

### TLS probe

Direct TLS connection to `IP_instance:443` with SNI = service domain. Stays inside the internal network, tests the certificate actually served by each instance, with no internet access. No HTTP request. Reads the issuer (Let's Encrypt or other badge) and the expiry date. Probing through the public domain: out of v1.

## 4. Authentication and access

- Password: argon2id, 12 characters minimum.
- Second factor mandatory for all accounts: TOTP or WebAuthn passkey. The first admin is created through a bootstrap CLI command and must register a second factor before any access.
- 10 single-use backup codes, displayed once, stored hashed.
- Session: `HttpOnly`, `Secure`, `SameSite=Strict` cookie, expires after 8 h of inactivity, 24 h maximum. CSRF on all write requests.
- Brute-force protection per account and per IP: increasing delay, temporary lockout.
- Roles: `admin` (users, instances, audit) and `lecteur` (reader, read-only).
- Audit: logins, failures, 2FA changes, instance and user addition/removal. Viewable by admins.
- Headers: strict CSP, HSTS, `X-Frame-Options: DENY`.
- Local and domain access: passkeys are bound to the domain (RP ID and allowed origins configurable through environment variables). Local access (IP, localhost) uses password + TOTP.
- BunkerWeb tokens encrypted at rest with a key stored outside the database. BunkerWeb client limited to GET requests.
- The application runs behind HTTPS (BunkerWeb or a reverse proxy).

## 5. Views

1. **Home / Health**: one card per instance (OK, degraded, unreachable), version, latency, last collection. Global counters: instances OK, active bans, certificates close to expiry. Stale-data indicator if the collection is more than 3 cycles old.
2. **Services**: consolidated table (domain, instance, detect/block mode, status), filters by instance and mode. Flags services missing from some instances.
3. **Bans**: merged list (IP, reason, instance, date, expiry), search by IP. Flags an IP banned on one instance but not on the others.
4. **Jobs and plugins**: jobs (last run, success/failure, next due date). Instance × plugin matrix for presence or version differences.
5. **Certificates**: one row per probed service (present or not, issuer, expiry, days left). Red under 7 days or expired, orange under 21 days, "Aucun" (none) if no certificate is served.
6. **Administration** (admin): instances (add with connection test, edit, delete), users, audit.
7. **Account**: TOTP, passkeys, backup codes.

Cross-cutting: bilingual UI (English default, French; see CLAUDE.md, "Internationalisation"), light/dark theme, sortable and filterable tables.

## 6. Error handling

- 5 s timeout per BunkerWeb call and per TLS probe; a slow instance does not block the others.
- A collection failure records the error type and message in the instance state; the UI shows the age of the data.
- BunkerWeb authentication errors (invalid/expired token) are distinguished from network errors, with a clear message in the administration.
- No secrets (tokens, codes, keys) or session data in the logs.

## 7. Tests

- Unit (`pytest`): parsing of BunkerWeb responses, computing differences between instances, certificate thresholds, token encryption, brute-force protection.
- Integration: fake BunkerWeb server (recorded responses) for the collector; TLS probe against a local server with a self-signed certificate.
- Authentication: full flow of password, 2FA, session, CSRF, lockout.
- Dev `docker-compose` with 2 real BunkerWeb instances for end-to-end validation.

## 8. Delivery

- Single Docker image and an example `docker-compose.yml`, configuration through environment variables.
- Bootstrap CLI command for the first admin.
- Repository aligned with BunkerWeb conventions: AGPLv3 license, README, docs, CI (tests + `ruff` lint).

## 9. Out of scope for v1 (possible evolutions)

- Writing to BunkerWeb: ban/unban, reload, service and settings management, bulk configuration deployment across instances.
- SSO/OIDC (Keycloak, Authentik, Entra…), possibly in addition to local authentication.
- Fine-grained RBAC: custom roles, per-instance or per-service permissions.
- Long metrics history and trend charts.
- Email or webhook alerts (unreachable instance, certificate close to expiry, differences between instances).
- TLS probe through the public domain (visitor view).
- Scaling beyond 10 instances (distributed collector, dedicated PostgreSQL database).
