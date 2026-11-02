<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/periscope-lockup-dark.svg">
    <img src="docs/brand/periscope-lockup-light.svg" alt="Periscope for BunkerWeb" width="330">
  </picture>
</p>

# Periscope for BunkerWeb

> **Independent community project.** Periscope for BunkerWeb is not affiliated with, endorsed by, or supported by Bunkerity. BunkerWeb is a trademark of Bunkerity. This project only uses BunkerWeb's public API, in read-only mode.

**Periscope for BunkerWeb** (short name: **Periscope**) is a self-hosted web console that gives you a single, read-only view over several [BunkerWeb](https://www.bunkerweb.io/) instances. It is built for fleets where checking each instance's own UI one by one gets tedious: a few instances on the same network, or dozens spread across separate networks (for example one network per customer for a managed service provider).

> **Status: early release.** The test suite passes, but Periscope has not yet been validated against real BunkerWeb instances. The BunkerWeb API does not document its JSON response shapes: the parsers follow the shapes read from the BunkerWeb v1.6.17 source (not captured from a live instance) and may need adjusting; see [Validating against real instances](docs/development.md#validating-against-real-instances).

## Features

- **Fleet health** at a glance: status, version, latency and last successful collection per instance, with a stale-data indicator. Each instance is one BunkerWeb API endpoint (the `scheduler`); the nginx nodes it manages are listed under it as `worker`s, and a node that is down or in failover makes the instance `degraded`.
- **Protected services** across all instances, with their security mode (`detect` / `block`) and a flag for services missing on some instances.
- **Active bans** merged across instances, searchable by IP, with a flag for IPs banned on only some instances.
- **Jobs and plugins**: job schedule and last result, and an instance × plugin matrix highlighting missing plugins and version drift.
- **Certificates** actually served, checked by a direct TLS probe (red under 7 days or expired, orange under 21 days).
- **Strong authentication**: argon2id passwords plus a **mandatory** second factor (TOTP or WebAuthn passkey), backup codes, progressive lockout, CSRF protection, strict CSP and an audit log. Roles: `admin` and `reader`.
- **Two ways to reach an instance**: **direct** (Periscope polls the BunkerWeb API on its network) or through a **Periscope agent** installed next to the instance, which pushes its reports over **mutual TLS** (outbound connections only, credentials kept on the customer side). See [docs/agent.md](docs/agent.md).
- **Tags** (for example one per customer): every view can be scoped to a tag, and cross-instance differences are then computed within that tag.
- **Read-only by design**: the BunkerWeb client only issues `GET` requests (plus a single `POST /auth` to exchange the API user's credentials for a token).
- **English and French UI**, picked from your saved preference, then a cookie, then the browser's `Accept-Language`.

How it works: [docs/architecture.md](docs/architecture.md).

## Getting started

You need Docker with the Compose plugin and BunkerWeb instances whose API is enabled.

1. **Create a read-only API user** on each BunkerWeb instance. Never use the admin account: follow [the step-by-step guide](docs/bunkerweb-api-user.md#creating-the-read-only-api-user-step-by-step).
2. **Configure Periscope.**

   ```bash
   git clone https://github.com/Lixeas/periscope-for-bunkerweb.git
   cd periscope-for-bunkerweb
   cp .env.example .env
   ```

   In `.env`, set `PERISCOPE_SECRET_KEY` (and **back it up**: without it the stored BunkerWeb credentials cannot be decrypted):

   ```bash
   python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())"
   ```

   For a trial over plain HTTP on `localhost`, also set `PERISCOPE_COOKIE_SECURE=false`.
3. **Start it** and create the first administrator (12-character password minimum):

   ```bash
   docker compose up -d --build
   docker compose exec -it periscope periscope bootstrap-admin --username admin
   ```

4. **Sign in** at `http://localhost:8000`, enrol the mandatory second factor (authenticator app or passkey) and save the backup codes. Then open **Instances** and add each instance: **Direct API** with its API URL and the read-only user's credentials, or **Periscope agent** for an instance in another network ([agent guide](docs/agent.md)). The dashboard fills in after about 30 seconds; certificates appear after the first TLS probe.

By default Periscope listens on `127.0.0.1:8000` only. To serve it on a domain with HTTPS, see [docs/deploy-behind-proxy.md](docs/deploy-behind-proxy.md).

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
| `PERISCOPE_MAX_PARALLEL` | `20` | Instances collected or probed at the same time |
| `PERISCOPE_MAX_PARALLEL_PROBES` | `50` | TLS handshakes in flight at the same time |
| `PERISCOPE_AGENT_PUBLIC_URL` | *(empty: agent mode off)* | `https://host:port` the agents use to reach the agent listener; its host goes in the listener's certificate |
| `PERISCOPE_AGENT_LISTEN_HOST` / `PERISCOPE_AGENT_LISTEN_PORT` | `0.0.0.0` / `8443` | Where the agent listener binds inside the container |
| `PERISCOPE_AGENT_BIND` / `PERISCOPE_AGENT_PORT` | `127.0.0.1` / `8443` | Address and port on which docker compose publishes the agent listener |
| `PERISCOPE_AGENT_ENROLL_TTL` | `86400` | Validity (seconds) of an agent enrollment token |
| `PERISCOPE_AGENT_MAX_REPORT_BYTES` | `8388608` | Largest agent report accepted |

The agent itself is configured with `PERISCOPE_AGENT_DIR` and `PERISCOPE_AGENT_BW_*` variables: see [docs/agent.md](docs/agent.md#agent-configuration).

**Larger fleets.** Collection runs instances in parallel (bounded by `PERISCOPE_MAX_PARALLEL`) and database writes happen outside the event loop. SQLite is fine for a few dozen instances; beyond that, or for heavy use, point `PERISCOPE_DATABASE_URL` to PostgreSQL (install the `psycopg` driver in the image).

## Security

- Cookies are `HttpOnly`, `Secure` and `SameSite=Strict`; server-side sessions expire after 8 h of inactivity and 24 h at most; CSRF tokens and an `Origin` allow-list protect state-changing requests; strict CSP and HSTS.
- A second factor is mandatory for every account. TOTP codes cannot be replayed; backup codes are single-use and stored hashed.
- Password failures lock the (username, IP) pair with a growing delay; second-factor failures lock the account itself.
- BunkerWeb credentials are encrypted at rest. **Back up `PERISCOPE_SECRET_KEY`** and the `/data` volume (SQLite). Only restricted API users are supported: the static `API_TOKEN` (full administrator access) is no longer accepted.
- Agents authenticate with a client certificate issued by Periscope's own CA (key generated on the agent, CA pinned by fingerprint, certificates mapped one-to-one to instances, immediate revocation, automatic renewal). Details in [docs/agent.md](docs/agent.md#security-model).
- The TLS probe deliberately does not validate certificates: it reads the certificate being served so that expired or self-signed ones show up. It sends no HTTP request.

## More

- [Creating the BunkerWeb API user and troubleshooting](docs/bunkerweb-api-user.md)
- [Agent mode: instances in other networks (mutual TLS)](docs/agent.md)
- [Exposing Periscope behind a domain (HTTPS)](docs/deploy-behind-proxy.md)
- [Architecture](docs/architecture.md)
- [Development, fake instances and validation against real instances](docs/development.md)
- [Releases (vX.Y.Z) and the changelog](docs/releasing.md) · [CHANGELOG](CHANGELOG.md)

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
