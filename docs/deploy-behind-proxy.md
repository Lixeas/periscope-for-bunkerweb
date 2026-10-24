# Exposing Periscope behind a domain (HTTPS)

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
