# Periscope for BunkerWeb

> **Independent community project.** Periscope for BunkerWeb is not affiliated with, endorsed by, or supported by Bunkerity. BunkerWeb is a trademark of Bunkerity. This project only uses BunkerWeb's public API, in read-only mode.

**Periscope for BunkerWeb** (short name: **Periscope**) is a self-hosted web console that gives you a single, read-only view over several [BunkerWeb](https://www.bunkerweb.io/) instances. It is built for small fleets (2 to 10 instances on the same network) where checking each instance's own UI one by one gets tedious.

> **Status: early release.** The test suite passes, but Periscope has not yet been validated against real BunkerWeb instances. The BunkerWeb API does not document its JSON response shapes: the parsers follow the shapes read from the BunkerWeb v1.6.17 source (not captured from a live instance) and may need adjusting; see [Validating against real instances](#validating-against-real-instances).

## Features

- **Fleet health** at a glance: status, version, latency and last successful collection per instance, with a stale-data indicator.
- **Scheduler and nodes**: each Periscope instance is one BunkerWeb API endpoint, i.e. the scheduler, and is tagged `scheduler`. The nginx nodes it manages (including workers on other VMs, from `GET /instances`) are listed under it, each tagged `worker` with its status (up, loading, down, failover) and last-seen time. A node that is `down` or in `failover` makes the instance `degraded`; `loading` is not treated as an error.
- **Protected services** across all instances, with their security mode (`detect` / `block`) and a flag for services that exist on some instances but not others.
- **Active bans** merged across instances, searchable by IP, with a flag for IPs banned on only some instances.
- **Jobs and plugins**: job schedule and last result, and an instance × plugin matrix highlighting missing plugins and version drift.
- **Certificates**: whether a certificate is actually served, its issuer (Let's Encrypt badge) and its expiry, checked by a direct TLS probe of each instance (red under 7 days or expired, orange under 21 days).
- **Strong authentication**: argon2id passwords plus a **mandatory** second factor (TOTP or WebAuthn passkey), one-time backup codes, progressive lockout, CSRF protection, strict CSP and an audit log.
- **Roles**: `admin` (manages users and instances) and `reader` (read-only dashboards).
- **Read-only by design**: the BunkerWeb client only issues `GET` requests (plus a single `POST /auth` to obtain a token).
- **English and French UI** with a language switch (footer of every page, and a preference on the account page). English is the default; the language is picked from your saved preference, then a cookie, then the browser's `Accept-Language`.
- Works both **locally and behind a domain name**.

## Architecture

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
- **Secrets.** BunkerWeb credentials are encrypted at rest with Fernet, using `PERISCOPE_SECRET_KEY`, and are never displayed again.

## Getting started

The quickest path is Docker Compose. You need Docker with the Compose plugin and at least two reachable BunkerWeb instances whose API is enabled.

### 1. Create a read-only API user on each BunkerWeb instance

Periscope should never use your BunkerWeb admin account. Create a dedicated, non-admin API user with read permissions only (the [step-by-step guide](#creating-the-read-only-api-user-step-by-step) below walks through the bootstrap file, the permissions and a `curl` test).

### 2. Configure Periscope

```bash
git clone https://github.com/Lixeas/periscope-for-bunkerweb.git
cd periscope-for-bunkerweb
cp .env.example .env
```

Edit `.env`:

- `PERISCOPE_SECRET_KEY`: generate one with  
  `python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())"`  
  and **back it up somewhere safe**: without it, stored BunkerWeb credentials cannot be decrypted.
- `PERISCOPE_ORIGINS`: every URL you will use to reach Periscope, as a JSON list.
- `PERISCOPE_RP_ID`: the domain used for passkeys.
- `PERISCOPE_COOKIE_SECURE`: keep `true` behind HTTPS. For a quick trial over plain HTTP on `localhost`, set it to `false`.

### 3. Start it

```bash
docker compose up -d --build
docker compose exec -it periscope periscope bootstrap-admin --username admin
```

The second command creates the first administrator and prompts for a password (12 characters minimum).

### 4. Sign in and add your instances

1. Open `http://localhost:8000` and sign in as `admin`.
2. Periscope requires a second factor before granting any access: scan the QR code with an authenticator app (or register a passkey), then save your backup codes (shown only once).
3. Go to **Instances**, add each BunkerWeb instance with its API URL, choose **API user** and enter the read-only user's name and password. The connection test must succeed before the instance is saved.
4. After about 30 seconds the dashboard fills in. Certificate data appears after the first TLS probe (about 15 seconds after start-up, then every 15 minutes).

By default `docker-compose.yml` publishes Periscope on `127.0.0.1:8000` only (set `PERISCOPE_BIND` and `PERISCOPE_PORT` in `.env` to change it, see the next section).

### Exposing it behind a domain (HTTPS)

Put Periscope behind a reverse proxy that terminates TLS, for example BunkerWeb itself. The same setup works whether BunkerWeb runs **on the same machine** (in another folder or Compose project) or **on another server**, because it does not rely on a shared Docker network: Periscope publishes its port on a private address and the proxy connects to that address.

1. **Publish Periscope on the machine's private IP.** In `.env`, set `PERISCOPE_BIND` to the private IP of the machine running Periscope (for example `10.154.0.20`; `PERISCOPE_PORT` defaults to `8000`). The default `127.0.0.1` is reachable only from that machine itself, **not** from another container or server. Never use `0.0.0.0` or a public address, and use the firewall to allow only the proxy's IP to reach that port.
2. **Point the reverse proxy at it.** In BunkerWeb, for the Periscope service set `USE_REVERSE_PROXY=yes`, `REVERSE_PROXY_URL=/` and `REVERSE_PROXY_HOST=http://PERISCOPE_BIND:8000` (use the same private IP as in step 1, with `http://`). From a BunkerWeb container on the same machine this works too: the container reaches the published port through the machine's private IP, not through `127.0.0.1` (which would be the container itself).
3. **Set the public identity.** `PERISCOPE_COOKIE_SECURE=true`, the public URL in `PERISCOPE_ORIGINS` and its domain in `PERISCOPE_RP_ID`.
4. **Set the trusted proxy.** `PERISCOPE_TRUSTED_PROXY` must be the address from which the proxy's requests **arrive inside the Periscope container**. It is not always the proxy's own IP:
   - BunkerWeb on **another server**: the proxy's IP (for example `10.154.0.10`).
   - BunkerWeb on the **same machine**: traffic goes through Docker's NAT, so Periscope usually sees the gateway of its own Docker network (something like `172.18.0.1`). To find the value, load the site once, then look at `docker compose logs periscope`: the address in front of each `GET /login` access line is the one to use. A CIDR range such as `172.18.0.0/16` also works with recent uvicorn versions.
5. **Restart** with `docker compose up -d`.

Notes:

- **Passkeys are bound to the domain** (`PERISCOPE_RP_ID`): they work through the domain name but not through `localhost` or a bare IP. Use TOTP for local access.
- A wrong `PERISCOPE_TRUSTED_PROXY` makes every client share a single IP bucket for rate limiting, and the audit log shows the proxy's address instead of the client's.
- **`502 Bad Gateway` troubleshooting:** check `docker compose ps` and `docker compose logs periscope` (is it running? is `PERISCOPE_SECRET_KEY` set?), then test from the BunkerWeb host with `curl -sI http://PERISCOPE_BIND:8000/login`, which must answer `200`. A refused connection means Periscope is not listening on that address (check `PERISCOPE_BIND`); a timeout points to a firewall.
- **`403 Forbidden` on a form (sign-in, adding an instance...):** Periscope rejects any state-changing request whose `Origin` header is not listed in `PERISCOPE_ORIGINS` (the response body is `Origin rejected`). List every URL you use to reach Periscope, with `https://` and without a trailing slash, for example `["https://periscope.example.com"]`, then restart the container. If you still get a 403 and the access log of `docker compose logs periscope` shows no matching request, the answer came from the WAF in front of Periscope: check the **Reports** page of the BunkerWeb UI for the rule that fired.
- Optional alternative when BunkerWeb runs on the same machine: attach Periscope to BunkerWeb's Docker network and use `http://periscope:8000` as the target. It works only on one machine, which is why the published-port setup above is the default.

## Authenticating to the BunkerWeb API

BunkerWeb's API knows three kinds of credentials. Periscope should only ever use the third one:

| Credential | What it can do | Use it for Periscope? |
|---|---|---|
| Admin API account (`API_USERNAME` / `API_PASSWORD`) | Everything | **No** |
| Static `API_TOKEN` | Everything (admin) | **No** (troubleshooting only) |
| **Restricted API user** (declared in an ACL bootstrap file) | Only the permissions you grant, e.g. read-only | **Yes** |

The restricted API user is a login of BunkerWeb's **API** only. It is independent of the BunkerWeb web UI account and of the admin API account, and you can declare several of them.

### How Periscope uses it

In **Instances**, choose the "API user" mode and enter the username and password. Periscope stores them encrypted, exchanges them for a short-lived token with `POST /auth` (HTTP Basic), sends it as `Authorization: Bearer <token>`, and **renews it automatically**: the token is kept in memory and, on a `401` (expiry; `API_BISCUIT_TTL_SECONDS` defaults to 3600 s), Periscope re-authenticates once and replays the request. The connection test in the "add instance" form exercises `/auth`, so a wrong password is reported as "Authentication refused".

### Creating the read-only API user, step by step

This guide targets BunkerWeb 1.6.17 and assumes a Docker Compose deployment where the API runs as its own service (called `bw-api` in the official examples; yours may differ). Repeat it for each instance.

**1. Pick the identity.** Use the username `periscope` and a strong, unique password. Do **not** reuse the username of the admin API account (`API_USERNAME`): the bootstrap would overwrite that account's password at every start.

**2. Hash the password (recommended).** BunkerWeb accepts a bcrypt hash with a cost of at least 10 (12 or more is recommended) starting with `$2a$`, `$2b$` or `$2y$`. Either of these produces one:

```bash
# with Docker (Apache utilities); keep everything after the first colon
docker run --rm httpd:2.4 htpasswd -nbB -C 12 periscope 'YourStrongPassword!1'

# or with Python
pip install bcrypt
python -c "import bcrypt; print(bcrypt.hashpw(b'YourStrongPassword!1', bcrypt.gensalt(12)).decode())"
```

The result looks like `$2y$12$Xyz...` (or `$2b$12$...`).

About plain-text passwords: you can use `"password": "..."` instead of a hash, but it must be at least 8 characters with an upper-case letter, a lower-case letter, a digit and a special character. **A password that is too weak is silently replaced by a random one that nobody can recover, and the user becomes unusable.** A hash avoids that trap and keeps the password out of the file.

**3. Write the bootstrap file.** Create `api_acl_bootstrap.json` (JSON only, no YAML):

```json
{
  "users": {
    "periscope": {
      "admin": false,
      "password_hash": "$2y$12$PASTE_YOUR_HASH_HERE",
      "permissions": {
        "instances": { "*": { "instances_read": true } },
        "global_config": { "*": { "global_config_read": true } },
        "services": { "*": { "service_read": true } },
        "bans": { "*": { "ban_read": true } },
        "jobs": { "*": { "job_read": true } },
        "plugins": { "*": { "plugin_read": true } }
      }
    }
  }
}
```

- `"admin": false` makes it a restricted user.
- Each line under `permissions` reads: *resource type*, then `"*"` (all resources), then *permission name* set to `true`. These six read permissions are exactly what Periscope needs (instances, global configuration, services, bans, jobs and plugins). The `instances_read` permission is the one that gives visibility of the scheduler's nodes (workers): without it, the node listing fails and the instance shows as `degraded`.
- **Never** grant `*_update`, `*_create`, `*_delete`, `*_execute` or `config_update`: BunkerWeb documents configuration, service, plugin, global-settings and instance write permissions as admin-equivalent.

**4. Give the file to the API container.** This takes **two** settings in the API service, and you need both: a **volume** that makes the file visible inside the container, and the `API_ACL_BOOTSTRAP_FILE` **environment variable** that tells the API where to find it. The variable holds a path **inside the container**, never a path on the host.

```yaml
services:
  bw-api:
    image: bunkerity/bunkerweb-api:1.6.17
    environment:
      API_ACL_BOOTSTRAP_FILE: "/var/lib/bunkerweb/api_acl_bootstrap.json"
    volumes:
      # host path : container path (must match the variable above)
      - ./api_acl_bootstrap.json:/var/lib/bunkerweb/api_acl_bootstrap.json:ro
```

- If the service already has `volumes` or `environment` entries, add these lines to them instead of replacing them.
- Setting only the variable with a host path (for example `/home/me/bunkerweb/api_acl_bootstrap.json`) fails with `API_ACL_BOOTSTRAP_FILE set but not found`, because that path does not exist inside the container.
- Setting only the volume works only if you mount the file exactly at the default path `/var/lib/bunkerweb/api_acl_bootstrap.json`; setting the variable too makes the intent explicit and is the recommended setup.
- The file must be readable by the container user (for example `chmod 644`).

**5. Restart the API service and check the logs.** The file is read once at start-up.

```bash
docker compose up -d bw-api
docker compose logs bw-api | grep -i -E "bootstrap|acl|password"
```

You should see a line similar to `Bootstrapping API users/permissions from ...`. Lines such as `Skipping weak password` or `is not a valid bcrypt hash` mean the password was rejected (see the troubleshooting table below).

How the bootstrap behaves, so it holds no surprises:

- It runs at **every** start. For an existing user, the password in the file is re-applied each time (change the password by editing the file and restarting); the `admin` flag is ignored for existing users.
- Permissions are **only added, never revoked**: removing a permission from the file does not remove it from an existing user.
- Errors in the file are logged but do not stop the API from starting.

**6. Test the user with `curl` before using it in Periscope.** Run this on the BunkerWeb host (adjust the address; the API is often published on `127.0.0.1:8888`):

```bash
TOKEN=$(curl -s -u periscope:'YourStrongPassword!1' -X POST http://127.0.0.1:8888/auth \
        | python -c "import sys,json; print(json.load(sys.stdin)['token'])")
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8888/services
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8888/bans
```

The first call must return a JSON object with a `token`; the next two must return JSON data (`"status": "success"` for `/services`, per-instance data for `/bans`). `POST /auth` is rate-limited (10 requests per minute by default), so do not call it in a loop.

**7. Make the API reachable from Periscope, then add the instance.** Periscope must be able to reach the API URL:

- **Never use `127.0.0.1` in Periscope's instance URL when Periscope runs in Docker**: inside its container, `127.0.0.1` is the container itself, not the BunkerWeb host. (`127.0.0.1` is only fine for the `curl` tests of step 6, run directly on the BunkerWeb host.)
- Publish the API port on the machine's **private IP** only, in the BunkerWeb compose file, for example `ports: ["10.154.0.20:8888:8888"]` on the `bw-api` service, then restart it. This works the same whether Periscope is on the same machine (in another folder or Compose project) or on another server.
- **Include the API root path in the URL.** If the API service sets `API_ROOT_PATH` (for example `"/bwapi"`), the API is served under that prefix and the URL to enter is `http://10.154.0.20:8888/bwapi`. Check it first with `curl -s http://10.154.0.20:8888/bwapi/ping`, which must answer `{"status":"ok","message":"pong"}`.
- The API has an IP allow-list (`API_WHITELIST_IPS`, which defaults to the private RFC 1918 ranges): the address from which Periscope reaches the API must be allowed. With Docker's NAT it is usually the host or the gateway of Periscope's Docker network, both private addresses.
- Never expose the API port on a public interface.

Finally, in Periscope open **Instances**, enter the API URL, choose **API user**, and fill in `periscope` and its password.

### Troubleshooting

| Symptom | Likely cause |
|---|---|
| `POST /auth` returns 404 | No API user exists yet (the auth routes only exist once at least one API user is configured) |
| `401 Invalid credentials` | Wrong username or password, or the password was too weak and got replaced by a random one: use a bcrypt hash |
| `403 No permissions assigned to user` | The user has no read permission: check the `permissions` block, then restart the API |
| One Periscope view is empty, or the instance is "Degraded" with a `403` | The matching read permission is missing (for example `ban_read` for Bans) |
| `429` on `/auth` | Rate limit reached (10 requests per minute by default) |
| Connection refused or timeout from Periscope | The API port is not reachable from where Periscope runs, or the IP allow-list blocks it (step 7) |
| `API_ACL_BOOTSTRAP_FILE set but not found` in the API logs | The variable points to a host path, or the volume is missing: set both (step 4) |
| "Instance unreachable" when adding an instance using `127.0.0.1` | `127.0.0.1` is Periscope's own container: use the host's private IP (step 7) |
| `404` on every API call | The API root path is missing from the URL (for example `/bwapi`) |

### What is confirmed and what is not

The resource-type keys (`instances`, `services`, `bans`, `jobs`, `plugins`, `global_config`, plus `cache` and `configs`), the permission names, the `/auth` credential fields (HTTP Basic, or form/JSON fields `username` and `password`) and its response (`{"token": "<biscuit>"}`, errors 401, 403 and 500) are **confirmed from the BunkerWeb v1.6.17 source code and documentation**. This comes from **reading the source, not from testing a live instance**. Other facts from the source: a non-admin user cannot use Basic auth on the other routes (only the Bearer token from `POST /auth` works), and the `cache_read` and `configs_read` permissions exist if you ever want to extend what is read.

**Instance version.** In "API user" mode, Periscope reads the BunkerWeb version from the `version` fact embedded in the Biscuit token issued by `/auth`; it is readable without any key (derived from the v1.6.17 source, to be confirmed on a live instance). It falls back to `info.version` of the public `/openapi.json` document (under the API root path if one is set), which currently returns HTTP 500 on at least one real 1.6.17 instance. In "API token" mode only the OpenAPI fallback is available. If neither works the version shows "—"; the instance status is unaffected.

### "API token" mode (discouraged)

A static `API_TOKEN` is sent as-is as a Bearer token. It grants **full administrator** access to BunkerWeb. It is stored encrypted and never displayed again, but reserve it for troubleshooting and restrict network access to the API (IP allow-list).

To migrate an existing instance, edit it, switch to "API user" and enter the new credentials (the stored token is then erased).

## Configuration reference

All settings are environment variables prefixed with `PERISCOPE_` (read from the environment or a `.env` file).

| Variable | Default | Description |
|---|---|---|
| `PERISCOPE_SECRET_KEY` | *(required)* | Fernet key used to encrypt BunkerWeb credentials |
| `PERISCOPE_DATABASE_URL` | `sqlite:///./data/periscope.db` | SQLAlchemy URL (the Docker image uses `/data/periscope.db`) |
| `PERISCOPE_ORIGINS` | `["http://localhost:8000"]` | Allowed browser origins (JSON list) |
| `PERISCOPE_RP_ID` | `localhost` | WebAuthn relying-party ID (your domain) |
| `PERISCOPE_COOKIE_SECURE` | `true` | `Secure` cookies and HSTS; set `false` only for plain-HTTP trials |
| `PERISCOPE_TRUSTED_PROXY` | `127.0.0.1` | Reverse-proxy IP trusted for `X-Forwarded-For` (Docker/compose) |
| `PERISCOPE_BIND` | `127.0.0.1` | Address on which docker compose publishes Periscope (private IP of the host to reach it from a reverse proxy) |
| `PERISCOPE_PORT` | `8000` | Host port published by docker compose |
| `PERISCOPE_POLL_INTERVAL` | `30` | Seconds between collection cycles |
| `PERISCOPE_PROBE_INTERVAL` | `900` | Seconds between TLS probes |
| `PERISCOPE_HTTP_TIMEOUT` | `5` | Timeout (seconds) for BunkerWeb API calls and TLS probes |
| `PERISCOPE_COLLECTOR_ENABLED` | `true` | Disable to run the web UI without collecting |

## Security

- Cookies are `HttpOnly`, `Secure` and `SameSite=Strict`; server-side sessions expire after 8 h of inactivity and 24 h at most; CSRF tokens and an `Origin` allow-list protect state-changing requests; strict CSP and HSTS.
- A second factor is mandatory for every account. TOTP codes cannot be replayed; backup codes are single-use and stored hashed.
- Password failures lock the (username, IP) pair with a growing delay; second-factor failures lock the account itself.
- BunkerWeb credentials are encrypted at rest. **Back up `PERISCOPE_SECRET_KEY`** and the `/data` volume (SQLite).
- The TLS probe deliberately does not validate certificates: it reads the certificate being served so that expired or self-signed ones show up. It sends no HTTP request.

## Development

```bash
python -m venv .venv
source .venv/Scripts/activate        # Windows (Git Bash); use .venv/bin/activate on Linux/macOS
pip install -e ".[dev]"

python -m pytest -q                  # full test suite
python -m pytest tests/test_collector.py -v      # one file
ruff check src tests dev             # lint (kept clean)
```

Run the app locally:

```bash
export PERISCOPE_SECRET_KEY=$(python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())")
export PERISCOPE_COOKIE_SECURE=false           # plain HTTP, local only
periscope bootstrap-admin --username admin     # creates the first admin and applies migrations
uvicorn periscope.web.app:create_app --factory --port 8000
```

Project layout:

```
src/periscope/
  auth/        passwords, MFA (TOTP, backup codes), sessions, rate limiting, WebAuthn wrapper
  web/         FastAPI app, routes, dependencies (session + CSRF), Jinja2 templates, static assets
  collector.py, bw_client.py, tlsprobe.py, normalize.py, diff.py, queries.py
  models.py, db.py, migrations/   SQLAlchemy models and Alembic migrations
tests/         pytest suite (in-memory SQLite, respx for the BunkerWeb API)
dev/           fake BunkerWeb server and a dev compose file for real instances
docs/superpowers/   historical design spec and implementation plans
```

Database migrations: edit `src/periscope/models.py`, then run `alembic revision --autogenerate -m "describe change"` (uses `alembic.ini` and a throw-away SQLite file). The app applies `alembic upgrade head` at start-up.

### Trying it without real instances

`dev/fake_bunkerweb.py` mimics the BunkerWeb API and serves a self-signed "Let's Encrypt" certificate for the TLS probe. Its header explains how to start two fake instances (ports 9001 and 9002, TLS ports 9443 and 9444); it can also simulate token expiry to exercise the automatic re-authentication.

### Validating against real instances

`dev/docker-compose.bunkerweb.yml` defines two independent BunkerWeb stacks (bw1: API on 8081, TLS on 8443; bw2: API on 8082, TLS on 9443). **This file has never been run** (Docker was not available where it was written). It follows the official documentation but must be validated; uncertain points are commented in the file, notably the ACL bootstrap file for the API user. Its header explains how to register the instances in Periscope. The parsers were derived by reading the BunkerWeb v1.6.17 source and have never been run against a live instance: compare the real API responses (`/services`, `/bans`, `/jobs`, `/plugins`) with `src/periscope/normalize.py` and adjust the parsers and their tests; the procedure is described in Task 8 of `docs/superpowers/plans/2026-10-22-plan-3-views-delivery.md`.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
