# Agent mode: instances in other networks

By default Periscope polls each BunkerWeb API **directly**, so it must sit on the same network as the instances. When the instances live in networks that Periscope cannot reach (one network per customer for a managed service provider, sites behind NAT, etc.), use the **Periscope agent**:

```
 Customer A network                     │            Your network
                                        │
  BunkerWeb API ◀── GET ── Agent ─────────── HTTPS + client certificate ──▶  Periscope console
  BunkerWeb :443 ◀─ TLS probe ┘         │   (outbound only, port 8443)       (agent listener)
                                        │
 Customer B network                     │
  BunkerWeb API ◀── GET ── Agent ───────────────────────────────────────────▶
```

The agent runs next to one BunkerWeb instance, collects it with exactly the same code as the console's direct mode (same read-only client, same parsing, same TLS probe), and **pushes** the result to the console. Both modes can be used side by side: each instance is either `direct` or `agent`.

## Security model

- **Outbound only.** The agent opens connections to its local BunkerWeb API, to the TLS ports of its services, and to the console. Nothing listens on the agent side, and nothing has to be opened in the customer's firewall except outbound HTTPS to the console. The console has no network path into the customers' networks: a compromised console cannot be used to reach them.
- **The BunkerWeb credentials stay on the customer side.** The agent holds the read-only API user's password (environment variable or Docker secret). The console never sees it.
- **Mutual TLS with a private certificate authority.** The console creates its own CA on first use (EC P-256; the private key is encrypted with `PERISCOPE_SECRET_KEY` in the database). It issues:
  - the server certificate of the agent listener (regenerated at each start for the host of `PERISCOPE_AGENT_PUBLIC_URL`);
  - one client certificate per agent, from a certificate signing request: **the agent's private key is generated on the agent's machine and never leaves it.**
- **Pinned CA.** At enrollment the agent downloads the CA certificate and accepts it only if its SHA-256 fingerprint matches the one in the enrollment bundle. Afterwards the agent trusts nothing but this CA: a public certificate or an intercepting proxy cannot impersonate the console.
- **One certificate = one instance.** The listener only accepts client certificates signed by its CA (checked during the TLS handshake), then maps the certificate to an instance by its SHA-256 fingerprint. An agent can only write the data of its own instance.
- **Immediate revocation.** "Revoke the agent" forgets the fingerprint: the next report is refused. No certificate revocation list to distribute.
- **Single-use, short-lived enrollment.** The enrollment token is random (256 bits), stored hashed, valid 24 h by default (`PERISCOPE_AGENT_ENROLL_TTL`), and consumed by the first enrollment. Enrollment attempts are rate-limited per IP and audited.
- **Automatic renewal.** Client certificates are valid 90 days. Under 30 days the agent requests a new one with a fresh key; the console keeps accepting the old certificate until the new one is used, so a failed renewal never locks the agent out.
- **Untrusted reports.** A customer machine may be compromised, so the console validates every report strictly (protocol version, status, list and string sizes, date formats; 8 MiB at most) and stores it exactly like a direct collection. Templates escape everything they display.
- **Still read-only.** The agent uses the same BunkerWeb client as the console: `GET` requests only, plus `POST /auth` to exchange the API user's credentials for a token.

### Behind a TCP proxy: enrollment rate limit

`POST /v1/enroll` is limited to 10 attempts per 10 minutes **per client IP**, successful ones included. After that the IP is blocked 60 s (the agent gets HTTP 429), then 120 s, 240 s… up to 1 h; the counter is forgotten after 1 h without a new violation. State is in memory: restarting the console resets it.

Behind a TCP / passthrough proxy or load balancer, the listener sees the proxy's address, not the agent's (an HTTP header such as `X-Forwarded-For` cannot help: the proxy does not read the HTTP traffic, and the listener never trusts such headers). **All agents then share one quota**, and so do audit entries: `agent_enroll_failed` and the like show the proxy's IP.

In practice:
- Enroll agents a few at a time (fewer than 10 per 10 minutes through the same proxy); on a 429, wait and retry.
- Only enrollment is limited this way. Reports and renewals are authenticated by the client certificate and are not affected, so running agents never lock each other out.
- The enrollment token is 256 bits and single-use, so a shared quota is a convenience limit, not what protects enrollment.
- If you can expose the listener directly (no proxy), each agent keeps its own quota.

PROXY protocol support (real client address read from the proxy's header, trusted proxies only) is not implemented; it can be added if a deployment needs it.

### Why a dedicated port

The agent listener is a separate HTTPS server (its own FastAPI app, no cookies, no sessions, no HTML) on its own port, 8443 by default. It terminates TLS itself because it must see the client certificate. Expose it **directly** or through a **TCP / TLS passthrough** (for example an nginx `stream` block or a cloud load balancer in TCP mode), never through an HTTP reverse proxy that terminates TLS. The web UI stays where it is (private address, behind your reverse proxy).

## Setting up the console

1. Choose the address the agents will use, for example `https://periscope-agents.example.com:8443`, and point the DNS name to the console host. An IP address works too (`https://203.0.113.10:8443`).
2. In `.env`:

   ```bash
   PERISCOPE_AGENT_PUBLIC_URL=https://periscope-agents.example.com:8443
   # docker compose publishes the listener on PERISCOPE_AGENT_BIND:PERISCOPE_AGENT_PORT
   PERISCOPE_AGENT_BIND=0.0.0.0
   PERISCOPE_AGENT_PORT=8443
   ```

   The host in the URL goes into the listener's certificate, so the agents must use exactly this name (or IP).
3. Restart Periscope. The log shows `agent listener on 0.0.0.0:8443`.
4. In the firewall, allow the customers' public IPs (or the Internet) to reach this port. Without a valid client certificate only the enrollment route answers.

## Adding an agent instance

1. In **Instances → Add an instance**, give it a name and tags (for example the customer's name), and choose **Periscope agent**.
2. Periscope shows an **enrollment bundle** once. It contains the listener URL, the single-use token and the CA fingerprint. Treat it as a secret until it is used.
3. On a machine in the customer's network that can reach the BunkerWeb API (and the TLS port of its services), deploy the agent. With Docker, only `docker-compose.agent.yml` is needed: it uses the released image `ghcr.io/lixeas/periscope-for-bunkerweb`, no checkout or build.

   ```bash
   curl -fsSLO https://raw.githubusercontent.com/Lixeas/periscope-for-bunkerweb/v0.3.0/docker-compose.agent.yml
   echo 'TheReadOnlyApiUserPassword' > bw_api_password.txt && chmod 600 bw_api_password.txt
   export BW_API_URL=http://10.0.0.5:8888   # the local BunkerWeb API (root path included)
   export PERISCOPE_VERSION=0.3.0           # the version of your console
   docker compose -f docker-compose.agent.yml run --rm periscope-agent periscope agent enroll 'psc1.…'
   docker compose -f docker-compose.agent.yml up -d
   ```

   Keep the agents on the same version as the console (`PERISCOPE_VERSION=0.3` follows the patch releases of 0.3). To upgrade: change `PERISCOPE_VERSION`, then `docker compose -f docker-compose.agent.yml pull && docker compose -f docker-compose.agent.yml up -d`; the enrollment (volume `agent-data`) is kept. If the container package is private, run `docker login ghcr.io` first with a token allowed to read packages.

   Without Docker: `pip install .` from a checkout, set the variables below, then `periscope agent enroll 'psc1.…'` and `periscope agent run` (as a systemd service, for example).
4. The instance turns `ok` on the dashboard after the first report (about 30 s).

Create the read-only API user on that BunkerWeb exactly as for the direct mode ([guide](bunkerweb-api-user.md)); its IP allow-list only needs the agent's address.

### Agent configuration

| Variable | Default | Description |
|---|---|---|
| `PERISCOPE_AGENT_DIR` | `./data/agent` | Key, certificates and console address (keep it on a persistent volume) |
| `PERISCOPE_AGENT_BW_URL` | *(required)* | Local BunkerWeb API URL, e.g. `http://bw-api:8888` |
| `PERISCOPE_AGENT_BW_USERNAME` | *(required)* | Read-only API user |
| `PERISCOPE_AGENT_BW_PASSWORD` / `PERISCOPE_AGENT_BW_PASSWORD_FILE` | *(required)* | Its password, or a file holding it (Docker secret) |
| `PERISCOPE_AGENT_BW_VERIFY_TLS` | `true` | Verify the API certificate if it is HTTPS |
| `PERISCOPE_AGENT_PROBE_HOST` | host of the API URL | Address for the TLS probe of the services |
| `PERISCOPE_AGENT_TLS_PORT` | `443` | TLS port of the services |
| `PERISCOPE_AGENT_HTTP_TIMEOUT` | `5` | Timeout (s) for API calls and TLS probes |

The collection and probe intervals are set by the console (`PERISCOPE_POLL_INTERVAL`, `PERISCOPE_PROBE_INTERVAL`) and sent to the agents with each answer.

## Operations

- **Agent silent.** If no report arrives for `PERISCOPE_STALE_CYCLES × PERISCOPE_POLL_INTERVAL` seconds (90 s by default, 60 s at least), the instance turns `down` with "No report from the agent". The last data is kept, as for a direct instance.
- **Reinstall an agent / lost files.** On the instance page, **New enrollment bundle**, then enroll again. The previous certificate stops working once the new enrollment is done.
- **Revoke.** **Revoke the agent** on the instance page (for example when a customer leaves, or if a machine is compromised). Deleting the instance revokes it too.
- **Backups.** The CA lives in the database, encrypted with `PERISCOPE_SECRET_KEY`: back up both. If the CA is lost, every agent has to be enrolled again.
- **Audit.** Token creation, enrollment (successful or refused), renewal and revocation are recorded in the audit log.

## Health check

`periscope agent health` exits 0 if the console accepted a report within 3 poll intervals (+ 30 s), 1 otherwise (no report yet, console unreachable or refusing the agent). It reads `health.json` in `PERISCOPE_AGENT_DIR`, written after each accepted report, and needs no other variable. `docker-compose.agent.yml` uses it as the container healthcheck. For a Kubernetes liveness probe: `exec: command: ["periscope", "agent", "health"]` with a generous `initialDelaySeconds` (about 90). Note that a console outage makes the probe fail, hence restarts the pod.

The console answers `GET /healthz` (`ok`, no authentication, no data) for liveness / readiness probes.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `CA fingerprint mismatch` at enrollment | Wrong URL, or something intercepts TLS between the agent and the console (proxy, TLS-terminating load balancer) |
| `enrollment refused (HTTP 429)` | Too many enrollments from the same IP (all agents share it behind a proxy): wait a few minutes, see [Behind a TCP proxy](#behind-a-tcp-proxy-enrollment-rate-limit) |
| `enrollment refused (HTTP 403)` | Token already used or expired: create a new bundle |
| `console refused this agent (HTTP 403)` | The agent was revoked or re-enrolled elsewhere: enroll it again |
| TLS error / `certificate verify failed` | The host in `PERISCOPE_AGENT_PUBLIC_URL` does not match the address the agent uses, or TLS is terminated in front of the listener |
| Instance `degraded` with `403` errors | A read permission is missing for the API user (see the API user guide) |
