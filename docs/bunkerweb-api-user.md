# Authenticating to the BunkerWeb API

BunkerWeb's API knows three kinds of credentials. Periscope should only ever use the third one:

| Credential | What it can do | Use it for Periscope? |
|---|---|---|
| Admin API account (`API_USERNAME` / `API_PASSWORD`) | Everything | **No** |
| Static `API_TOKEN` | Everything (admin) | **No** (troubleshooting only) |
| **Restricted API user** (declared in an ACL bootstrap file) | Only the permissions you grant, e.g. read-only | **Yes** |

The restricted API user is a login of BunkerWeb's **API** only. It is independent of the BunkerWeb web UI account and of the admin API account, and you can declare several of them.

## How Periscope uses it

In **Instances**, choose the "API user" mode and enter the username and password. Periscope stores them encrypted, exchanges them for a short-lived token with `POST /auth` (HTTP Basic), sends it as `Authorization: Bearer <token>`, and **renews it automatically**: the token is kept in memory and, on a `401` (expiry; `API_BISCUIT_TTL_SECONDS` defaults to 3600 s), Periscope re-authenticates once and replays the request. The connection test in the "add instance" form exercises `/auth`, so a wrong password is reported as "Authentication refused".

## Creating the read-only API user, step by step

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

## Troubleshooting

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

## What is confirmed and what is not

The resource-type keys (`instances`, `services`, `bans`, `jobs`, `plugins`, `global_config`, plus `cache` and `configs`), the permission names, the `/auth` credential fields (HTTP Basic, or form/JSON fields `username` and `password`) and its response (`{"token": "<biscuit>"}`, errors 401, 403 and 500) are **confirmed from the BunkerWeb v1.6.17 source code and documentation**. This comes from **reading the source, not from testing a live instance**. Other facts from the source: a non-admin user cannot use Basic auth on the other routes (only the Bearer token from `POST /auth` works), and the `cache_read` and `configs_read` permissions exist if you ever want to extend what is read.

**Instance version.** In "API user" mode, Periscope reads the BunkerWeb version from the `version` fact embedded in the Biscuit token issued by `/auth`; it is readable without any key (derived from the v1.6.17 source, to be confirmed on a live instance). It falls back to `info.version` of the public `/openapi.json` document (under the API root path if one is set), which currently returns HTTP 500 on at least one real 1.6.17 instance. In "API token" mode only the OpenAPI fallback is available. If neither works the version shows "—"; the instance status is unaffected.

## "API token" mode (discouraged)

A static `API_TOKEN` is sent as-is as a Bearer token. It grants **full administrator** access to BunkerWeb. It is stored encrypted and never displayed again, but reserve it for troubleshooting and restrict network access to the API (IP allow-list).

To migrate an existing instance, edit it, switch to "API user" and enter the new credentials (the stored token is then erased).
