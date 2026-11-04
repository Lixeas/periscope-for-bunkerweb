# Running Periscope on Kubernetes

Two Helm charts live in [`deploy/helm`](../deploy/helm):

| Chart | What it runs | Where |
|---|---|---|
| `periscope` | the **console** (web UI, collector, agent listener) | your cluster |
| `periscope-agent` | an **agent**, next to a BunkerWeb that agents can reach | a customer's cluster, or yours |

The Docker Compose files stay the reference for a single host; the charts give the same result on Kubernetes without assuming a cloud, an Ingress controller or a storage class.

## What you need

- a Kubernetes cluster (1.27 or newer) and `kubectl` configured for it;
- [`helm`](https://helm.sh/docs/intro/install/) 3;
- for the first steps below, nothing else: no domain name, no Ingress.

Vocabulary in five lines: a **pod** is a running container; a **Deployment** keeps one pod alive; a **Service** gives it a stable address inside the cluster; an **Ingress** publishes a Service on a domain name over HTTP(S); a **Secret** stores a password. **Helm** installs a bundle of these ("a chart") from a short settings file ("values").

Until a release has published the charts, install from a checkout of this repository (`deploy/helm/periscope`). Afterwards the same charts are available as `oci://ghcr.io/lixeas/charts/periscope` and `oci://ghcr.io/lixeas/charts/periscope-agent` (add `--version X.Y.Z`; keep the agents on the console's version). New GitHub packages start private: after the first release, make `charts/periscope` and `charts/periscope-agent` public in the package settings, or `helm registry login ghcr.io` first.

## 1. The console

### Create the encryption key

Periscope encrypts the BunkerWeb credentials it stores with a key. **The chart never generates it for you**: a key that is lost or silently replaced makes every stored credential unreadable. Create it once and keep a copy somewhere safe:

```bash
kubectl create namespace periscope
kubectl --namespace periscope create secret generic periscope-secret-key \
  --from-literal=secret-key="$(openssl rand -base64 32 | tr '+/' '-_')"
```

If you use a secret manager (External Secrets, Sealed Secrets, Vault…), create a Secret with a `secret-key` entry any way you like and point to it in the same way.

### Try it (no domain name, plain HTTP)

`trial.yaml`:

```yaml
secretKey:
  existingSecret: periscope-secret-key
config:
  cookieSecure: false        # plain HTTP, trials only
  origins: ["http://localhost:8000"]
  rpId: localhost
```

```bash
helm install periscope deploy/helm/periscope --namespace periscope -f trial.yaml
kubectl --namespace periscope get pods                 # wait for 1/1 Running
kubectl --namespace periscope exec -it deploy/periscope -- periscope bootstrap-admin --username admin
kubectl --namespace periscope port-forward svc/periscope 8000:8000   # then open http://localhost:8000
```

Data lives on a 1 Gi volume (SQLite). That is fine to start with; see "Database" below for PostgreSQL.

### Give it a domain name (Ingress)

`values.yaml`:

```yaml
secretKey:
  existingSecret: periscope-secret-key
ingress:
  enabled: true
  className: nginx                 # whatever Ingress controller class your cluster has
  hosts:
    - host: periscope.example.com
  tls:
    - secretName: periscope-tls    # a TLS Secret (for example issued by cert-manager from this list of hosts)
      hosts: [periscope.example.com]
```

The browser origin (`https://periscope.example.com`) and the WebAuthn domain are derived from the host; set `config.origins` and `config.rpId` yourself to override. Passkeys only work through the domain name, not through a port-forward (use TOTP there).

`config.trustedProxies` defaults to `"*"` (who may set `X-Forwarded-For`) because the chart cannot know your Ingress controller's address. While that is `*`, any other pod in the cluster could forge client addresses (rate-limit buckets, audit log). Set it to your controller's pod CIDR when you can.

### Database

SQLite on a volume is the default and works for a few dozen instances. For more, or to avoid a volume, use PostgreSQL, ideally managed by an operator such as CloudNativePG or by your cloud:

```yaml
database:
  existingSecret: periscope-db      # a Secret whose `database-url` entry is postgresql://user:password@host:5432/periscope
persistence:
  enabled: false
```

(`database.url` also works but puts the password in your values file.) The readiness probe checks the database, so the pod receives no traffic while it is down and is not restarted for it.

### Why only one replica

The collector, the agent listener, the rate limits and the account lockouts live inside the console process. Two copies would collect everything twice and each keep their own lockout counters. The chart therefore fixes **one** replica (there is no `replicaCount` value; passing it is an error) and replaces the pod rather than running two side by side during an upgrade (`Recreate` strategy). Expect a short interruption of the web UI while upgrading; agents simply retry.

## 2. Agents in remote networks

### Open the agent listener

Agents connect to a mutual-TLS listener on port 8443. **Do not put it behind an Ingress that terminates TLS**: it must see the agents' client certificates. Expose it with its own Service:

```yaml
agentListener:
  enabled: true
  publicUrl: https://agents.periscope.example.com:8443    # the name agents will use (a DNS name you control is best)
  service:
    type: LoadBalancer            # or NodePort; add cloud-specific `annotations` here
    loadBalancerSourceRanges: ["203.0.113.0/24"]   # optional: who may reach it
```

Reserve the DNS name (or a static IP) before installing: the host of `publicUrl` goes into the listener's certificate, and every agent keeps the URL from its enrollment bundle and checks that name. If you only learn the load balancer address after the install, run `helm upgrade` with the right `publicUrl` **before enrolling any agent**. Once agents are enrolled the host must not change: repoint the DNS name to a new address instead, or enroll the agents again with new bundles.

### Install an agent

1. In the console, **Instances → Add an instance → Periscope agent**. Copy the enrollment bundle (`psc1.…`), it is shown once and works once, for 24 hours.
2. In the cluster where BunkerWeb runs, store the bundle and the BunkerWeb API user's password:

   ```bash
   kubectl create namespace periscope-agent
   kubectl --namespace periscope-agent create secret generic periscope-enrollment --from-literal=bundle='psc1.…'
   kubectl --namespace periscope-agent create secret generic bunkerweb-api --from-literal=password='THE-API-USER-PASSWORD'
   ```

3. `agent-values.yaml`:

   ```yaml
   enrollment:
     existingSecret: periscope-enrollment
   bunkerweb:
     url: http://bunkerweb-api.bunkerweb.svc:8888   # where BunkerWeb's API answers inside the cluster (see below)
     username: periscope
     existingSecret: bunkerweb-api
   ```

   ```bash
   helm install periscope-agent deploy/helm/periscope-agent --namespace periscope-agent -f agent-values.yaml
   kubectl --namespace periscope-agent get pods      # Init:0/1 for a moment, then 1/1 Running
   ```

The agent enrolls itself in an init container and keeps its key and certificates on a small volume; restarts never enroll again. Keep the enrollment Secret in place (the chart expects it on every start, even though an enrolled agent no longer uses it). Create the read-only API user on BunkerWeb as for any direct instance ([guide](bunkerweb-api-user.md)).

**Which URL?** Use the address at which BunkerWeb's API answers *from inside the agent's cluster*, root prefix included. The chart cannot discover it. To check a candidate from the same namespace:

```bash
kubectl --namespace periscope-agent run curl --rm -it --restart=Never --image=curlimages/curl -- curl -s http://bunkerweb-api.bunkerweb.svc:8888/ping
```

### When an agent is revoked or its certificate expired

An agent that stays down longer than its certificate lifetime (90 days), or that you revoked, keeps failing its health check and is restarted again and again. Recover it: in the console create a **New enrollment bundle** for the instance, put it in the Secret, then

```bash
helm upgrade periscope-agent deploy/helm/periscope-agent --namespace periscope-agent -f agent-values.yaml --set enrollment.force=true
```

`force` makes the init container enroll again with the new bundle, **once**: it remembers which bundle it used, so leaving `force` on does not enroll again at every restart (a bundle can only be used once). Without `force`, a pod that already has an identity never enrolls again, whatever bundle it is given.

A console outage also makes the agent's health probe fail, which restarts the pod; that is harmless.

## Operating

- **Upgrade:** `helm upgrade …` with the new chart version (the chart's `appVersion` is the image tag). Upgrade the agents to the same version as the console.
- **Configuration changes** restart the pod automatically.
- **Back up** the encryption key Secret and the database (a snapshot of the volume, or `pg_dump`). Without the key, stored credentials cannot be decrypted.
- **Uninstall:** `helm uninstall`. Secrets created from chart values (not those you created yourself) and the volumes are **kept** on purpose; delete them by hand when you are sure.
- **Private image:** if the GHCR package is private, create an image pull secret and set `imagePullSecrets: [{name: ghcr}]`.
- All settings: `helm show values deploy/helm/periscope` (or `periscope-agent`). Extra `PERISCOPE_*` settings go under `config.extra`.
- **No Helm?** `helm template … > manifests.yaml` renders plain Kubernetes manifests you can apply with `kubectl`.

## Troubleshooting

| Symptom | Cause / what to do |
|---|---|
| `helm install` fails with `secretKey: set …` | no encryption key given: create the Secret and set `secretKey.existingSecret` |
| `helm install` fails with `config.origins` / `config.rpId` | needed for HTTPS: set them or enable the Ingress with a host; `cookieSecure: false` for a plain-HTTP trial |
| Console pod `Pending` | the volume cannot be created: check `kubectl get pvc` and the storage class (`persistence.storageClass`) |
| Console pod `Running` but `0/1` ready | `/readyz` fails: the database is unreachable (`kubectl logs`) |
| `CrashLoopBackOff` on the console | `kubectl logs deploy/periscope`; usually a wrong `database` URL |
| 403 on a form (sign-in…) | the browser origin is not in `config.origins` (`https://…`, no trailing slash) |
| Agent pod `Init:Error` | bundle already used or expired: new bundle in the Secret, then `enrollment.force=true` as above (`kubectl logs … -c enroll`) |
| Agent `Running` but the instance stays `down` | `kubectl logs … -c agent`: wrong `publicUrl` host in the listener certificate, listener not reachable from the agent's cluster, or wrong BunkerWeb URL |
| TLS error from the agent | the listener is behind something that terminates TLS: expose it with the Service only |

## What is not validated

- A BunkerWeb that really runs on Kubernetes: the parsers follow the BunkerWeb source (see the project README), and the API address in your cluster is yours to find (above).
- Real cloud load balancers and TLS passthrough through a customer's network.
- The agent chart end to end in CI (enrolling needs a bundle issued by a console); CI runs the console on a throwaway kind cluster and checks that the agent refuses to start without a valid enrollment.
