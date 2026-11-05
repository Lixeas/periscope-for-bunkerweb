# Kubernetes Compatibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the Periscope console and the Periscope agent on Kubernetes through two Helm charts that are secure by default, configurable by values, verified in CI (including a real kind cluster) and documented for a newcomer.

**Architecture:** `deploy/helm/periscope` (console) and `deploy/helm/periscope-agent` (agent) are plain Helm 3 charts. The application only gains a `/readyz` endpoint. Chart behaviour is pinned by pytest tests that run `helm template` and assert on the rendered objects (skipped when `helm` is absent), schema-checked by `kubeconform`, and exercised end to end on kind by `dev/k8s-smoke.sh`. Chart versions follow the application version through `dev/release.py`.

**Tech Stack:** Helm 3, Kubernetes ≥ 1.27, kind, kubeconform, GitHub Actions, pytest (PyYAML is already installed through `uvicorn[standard]`), FastAPI.

**Spec:** `docs/superpowers/specs/2026-11-05-kubernetes-design.md` (read it first; "Calls made by the designer" and "Facts checked in the repository" are binding).

## Global Constraints

- Console: **1 replica, not a value**, `strategy: Recreate`; unknown top-level values are rejected by `values.schema.json` (`additionalProperties: false`), so `--set replicaCount=3` fails loudly.
- Container security (both charts): `runAsNonRoot: true`, `runAsUser/runAsGroup: 10001`, `fsGroup: 10001`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault`, `automountServiceAccountToken: false`. Writable paths: `/data` (volume) and `/tmp` (`emptyDir`).
- Image default `ghcr.io/lixeas/periscope-for-bunkerweb:<chart appVersion>`; `image.digest` wins over the tag; `imagePullSecrets` supported.
- Console secret key: `secretKey.existingSecret` (+ `existingSecretKey`, default `secret-key`) **or** `secretKey.value`; neither → `helm` fails with a message naming `secretKey`. A chart-created Secret carries `helm.sh/resource-policy: keep`. The chart never generates or `lookup`s secrets.
- `persistence.enabled=false` without an external database → fail with a message naming `persistence`. External database: `database.url` (stored in the chart Secret, never in the ConfigMap) or `database.existingSecret`/`existingSecretKey`.
- Agent: bundle required (`enrollment.bundle` or `enrollment.existingSecret`+`existingSecretKey`), `bunkerweb.url` required, API password mounted as a file and passed with `PERISCOPE_AGENT_BW_PASSWORD_FILE` (never an env value); no bundle, password or secret key may appear literally in a pod spec, ConfigMap or `NOTES.txt`.
- Agent init container enrolls only when `/data/agent/agent.crt` is missing, or unconditionally when `enrollment.force=true`.
- Probes: console startup+liveness `GET /healthz`, readiness `GET /readyz`; agent startup+liveness `exec: periscope agent health`, no readiness.
- Pod annotation `checksum/config` (ConfigMap + chart Secret content hash) so configuration changes restart the pod.
- `Chart.yaml` `version` and `appVersion` equal `periscope.__version__` (currently from `src/periscope/__init__.py`) in both charts.
- No new Python dependency. Repo rules (`CLAUDE.md`): `CHANGELOG.md` under `## [Unreleased]`, update `ROADMAP.md`, do not bump the version. `ruff check src tests dev` clean. Use `.venv/bin/python -m pytest`.
- Tools (`helm`, `kind`, `kubeconform`) are not installed on this machine: `dev/k8s-tools.sh` (Task 3) downloads pinned binaries into the git-excluded `.tools/bin`. Chart tests find `helm` on `PATH` or in `.tools/bin` and **skip** if absent.

## Review Focus

1. The secret key / agent bundle / BunkerWeb password / database URL never appear literally in the Deployment, ConfigMap or `NOTES.txt`; the chart-created Secret survives `helm uninstall` (`keep`) — Tasks 3, 5.
2. `persistence.enabled=false` without external database, `replicaCount`-style unknown values, missing secret key, missing agent URL/bundle all **fail** with a readable message — Tasks 3, 4, 5.
3. A configuration change restarts the pod (checksum) and awkward values (quotes, `%`, `$`, unicode in origins / URLs) render as valid YAML with the exact value — Tasks 3, 4.
4. An ordinary agent restart never re-enrolls or wipes an enrolled volume; `enrollment.force` is the only way to overwrite — Task 5.
5. `/readyz` answers 503 (not 500, no traceback, no data) when the database is unreachable, while `/healthz` stays 200 — Task 1.

## File Structure

- Modify `src/periscope/web/routes_pages.py` (`/readyz`), `tests/test_web_shell.py`.
- Modify `dev/release.py`, `tests/test_release.py`; create both `Chart.yaml`.
- Create `deploy/helm/periscope/` and `deploy/helm/periscope-agent/` (`Chart.yaml`, `values.yaml`, `values.schema.json`, `.helmignore`, `templates/`, `ci/*.yaml` values sets).
- Create `dev/k8s-tools.sh`, `dev/k8s-smoke.sh`; modify `.gitignore`.
- Create `tests/helm_utils.py`, `tests/test_helm_console.py`, `tests/test_helm_agent.py`.
- Modify `.github/workflows/ci.yml`.
- Create `docs/kubernetes.md`; modify `README.md`, `CHANGELOG.md`, `ROADMAP.md`, `docs/releasing.md`.

---

### Task 1: `/readyz`

**Files:**
- Modify: `src/periscope/web/routes_pages.py`
- Test: `tests/test_web_shell.py`

**Interfaces:**
- Produces: `GET /readyz` → `200 "ok"` or `503 "unavailable"` (plain text, unauthenticated, never any detail); `/healthz` unchanged.

- [ ] **Step 1: Write failing tests** in `tests/test_web_shell.py`: `test_readyz_ok_when_database_answers` (200, body `ok`); `test_readyz_503_when_database_is_down` (monkeypatch `periscope.db.engine` to return an engine whose `connect()` raises `OperationalError`, or drop the table backend: assert status 503, body exactly `unavailable`, no exception text), and `test_healthz_stays_up_when_database_is_down` (same patch, `/healthz` 200).
- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_web_shell.py -k readyz -v` → FAIL (404).
- [ ] **Step 3: Implement** `async def readyz()` in `routes_pages.py`: run `SELECT 1` through `asyncio.to_thread` on a short-lived connection from `periscope.db.engine()`; any `Exception` → `PlainTextResponse("unavailable", 503)`; log the exception class only.
- [ ] **Step 4: Run** the three tests + whole suite → PASS.
- [ ] **Step 5: Commit** `git add -A && git commit -m "Add /readyz (database readiness probe)"`.

---

### Task 2: Chart skeletons and version sync

**Files:**
- Create: `deploy/helm/periscope/Chart.yaml`, `deploy/helm/periscope-agent/Chart.yaml`, `.helmignore` in each
- Modify: `dev/release.py`, `tests/test_release.py`

**Interfaces:**
- Produces in `dev/release.py`: `CHARTS: list[Path]` (both `Chart.yaml` files); `set_chart_versions(version: str, charts) -> None` (rewrites the `version:` and `appVersion:` lines, `appVersion` quoted); `chart_versions(charts) -> list[tuple[str, str]]`; `bump(part, init=INIT, changelog=CHANGELOG, charts=())` — new optional `charts` argument, **default empty** so the existing tests never touch the real charts; `main` passes `CHARTS` when running `bump`.

- [ ] **Step 1: Write failing tests**: `test_chart_versions_match_the_application` (for every file in `release.CHARTS`: `version` and `appVersion` equal `release.current()`); `test_bump_rewrites_chart_versions` (tmp chart files, `bump("minor", init, log, charts=[c1, c2])` → both contain `version: 1.3.0` and `appVersion: "1.3.0"`, other lines untouched); `test_bump_without_charts_leaves_them_alone` (existing behaviour); `test_chart_metadata` (name, `apiVersion: v2`, `type: application`, `kubeVersion: ">=1.27.0-0"`, description present).
- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_release.py -v` → FAIL.
- [ ] **Step 3: Create** both `Chart.yaml` (`name: periscope` / `periscope-agent`, `apiVersion: v2`, `type: application`, `kubeVersion: ">=1.27.0-0"`, `version` and `appVersion` = current application version) and `.helmignore`; implement the `release.py` additions; `python dev/release.py bump` must call them.
- [ ] **Step 4: Run** `tests/test_release.py` and the whole suite → PASS.
- [ ] **Step 5: Commit** `git commit -m "Charts: skeletons and version sync in dev/release.py"`.

---

### Task 3: Tools, test harness and console chart core

**Files:**
- Create: `dev/k8s-tools.sh`, `tests/helm_utils.py`, `tests/test_helm_console.py`, `deploy/helm/periscope/{values.yaml,values.schema.json,templates/_helpers.tpl,templates/deployment.yaml,templates/configmap.yaml,templates/secret.yaml,templates/service.yaml,templates/serviceaccount.yaml,templates/pvc.yaml,templates/NOTES.txt,ci/minimal-values.yaml,ci/postgres-values.yaml}`
- Modify: `.gitignore` (add `.tools/`)

**Interfaces:**
- Produces `tests/helm_utils.py`: `helm_bin() -> str | None` (PATH, then `.tools/bin/helm`); `requires_helm` (pytest skip marker); `class HelmError(Exception)` (message = helm's stderr); `render(chart: str, values: dict | None = None, release: str = "p") -> list[dict]` (writes `values` to a temp file, runs `helm template <release> deploy/helm/<chart> -f …`, returns the parsed non-empty YAML documents); `render_notes(chart: str, values: dict | None = None) -> str` (the rendered `templates/NOTES.txt`); `kinds(objs) -> list[str]`; `one(objs, kind, name=None) -> dict`.
- Produces `dev/k8s-tools.sh`: downloads pinned `helm`, `kind`, `kubeconform` for the current OS/arch over HTTPS from the projects' official release URLs into `.tools/bin` (verify the SHA-256 the project publishes where it exists, e.g. helm), idempotent, prints versions.
- Console chart values/semantics exactly as the spec's "Console chart" section. Helper names: `periscope.fullname`, `periscope.labels`, `periscope.selectorLabels`, `periscope.image`, `periscope.secretName`.
- ConfigMap keys (`PERISCOPE_*`): `ORIGINS` (JSON list via `toJson`), `RP_ID`, `COOKIE_SECURE`, `POLL_INTERVAL`, `PROBE_INTERVAL`, `FORWARDED_ALLOW_IPS`, plus every `config.extra` entry. Secret keys: `secret-key`, `database-url`.
- `ci/minimal-values.yaml`: `secretKey.value` (a 44-char urlsafe-base64 test key), `config.origins: ["http://localhost:8000"]`, `config.rpId: localhost`, `config.cookieSecure: false`. `ci/postgres-values.yaml`: `database.url: postgresql://u:p@db/periscope`, `persistence.enabled: false`, same secret key / origins.

- [ ] **Step 1: Write `dev/k8s-tools.sh`, run it**, check `.tools/bin/helm version`, `kind version`, `kubeconform -v` work.
- [ ] **Step 2: Write `tests/helm_utils.py` and the failing tests** in `tests/test_helm_console.py` (all decorated `requires_helm`, base values = `ci/minimal-values.yaml`):
  - `test_minimal_install_objects`: kinds are exactly `ConfigMap, Deployment, PersistentVolumeClaim, Secret, Service, ServiceAccount`; Deployment `replicas == 1`, `strategy.type == "Recreate"`; image `ghcr.io/lixeas/periscope-for-bunkerweb:<release.current()>`.
  - `test_security_defaults`: pod `automountServiceAccountToken is False`, `securityContext.fsGroup == 10001`, `seccompProfile.type == "RuntimeDefault"`; container `runAsNonRoot`, `runAsUser == 10001`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation is False`, `capabilities.drop == ["ALL"]`; volumes `data` (PVC) and `tmp` (`emptyDir`) mounted at `/data` and `/tmp`; resources requests present.
  - `test_probes`: startup and liveness `httpGet /healthz`, readiness `httpGet /readyz`, port name `http` = 8000.
  - `test_secret_key_is_a_secret_reference_never_literal`: env `PERISCOPE_SECRET_KEY` uses `valueFrom.secretKeyRef` (name = chart Secret, key `secret-key`); the key value from the values appears nowhere in the Deployment or ConfigMap documents (serialize and search); the Secret has annotation `helm.sh/resource-policy: keep`; `NOTES.txt` (use `helm template --show-only templates/NOTES.txt` through a `render_notes` helper) does not contain it.
  - `test_existing_secret_is_referenced_and_no_secret_created`: `secretKey.existingSecret=ext`, `existingSecretKey=k` → no `Secret` kind, `secretKeyRef` name `ext` key `k`.
  - `test_missing_secret_key_fails`: no `secretKey` at all → `HelmError` whose text contains `secretKey`.
  - `test_database_external_postgres`: `ci/postgres-values.yaml` → no PVC, no `data` PVC volume, env `PERISCOPE_DATABASE_URL` from `secretKeyRef` key `database-url`, and the URL (password) appears only in the Secret document; with `database.existingSecret` the env refers to that Secret and none is created for it.
  - `test_persistence_variants`: `existingClaim` → no PVC, `claimName` used; `storageClass`/`size`/`accessModes` rendered; `persistence.enabled=false` without database → `HelmError` containing `persistence`.
  - `test_replica_count_cannot_be_overridden`: `{"replicaCount": 3}` → `HelmError` (schema rejects unknown values).
  - `test_config_checksum_changes_with_config`: rendering with `config.pollInterval` 30 vs 60 gives different `checksum/config` pod annotations; same values → same checksum.
  - `test_awkward_values_render_exactly`: `config.origins: ['https://a"b.example', 'https://é.example/%25$x']`, `config.extra: {PERISCOPE_POLL_INTERVAL: "5"}`, `database.url` with `%40` and `$`/quotes → ConfigMap `PERISCOPE_ORIGINS` JSON-decodes to exactly the input list; Secret value decodes (base64) to exactly the URL; rendering yields valid YAML.
  - `test_service_and_image_options`: `service.type=NodePort`, port, annotations; `image.digest` overrides tag (`repo@sha256:…`); `imagePullSecrets`; `nodeSelector`/`tolerations`/`affinity`/`podAnnotations`/`podLabels` passed through; `serviceAccount.create=false` + `name` → no ServiceAccount document and pod uses the name.
  - `test_cookie_secure_requires_origins_and_rpid`: `cookieSecure` true (default) without `config.origins`/`config.rpId` and without Ingress → `HelmError` naming `origins`.
- [ ] **Step 3: Run** `.venv/bin/python -m pytest tests/test_helm_console.py -v` → FAIL (chart missing).
- [ ] **Step 4: Implement the templates and `values.yaml` / `values.schema.json`** (schema types every value, `additionalProperties: false` at the top level; required combinations enforced with `fail "…"` in templates so messages stay readable). Modest resource defaults (requests 100m CPU / 192Mi, memory limit 512Mi, my call). `NOTES.txt` prints how to reach the UI and the URL of the secret-key backup advice, no secret.
- [ ] **Step 5: Run** the tests + `helm lint deploy/helm/periscope -f deploy/helm/periscope/ci/minimal-values.yaml` + whole suite → PASS.
- [ ] **Step 6: Commit** `git commit -m "Console Helm chart: core objects, secrets, database, persistence"`.

---

### Task 4: Console Ingress, origins derivation, agent listener

**Files:**
- Create: `deploy/helm/periscope/templates/ingress.yaml`, `templates/service-agents.yaml`, `ci/ingress-values.yaml`, `ci/agents-values.yaml`
- Modify: `deploy/helm/periscope/{values.yaml,values.schema.json,templates/deployment.yaml,templates/configmap.yaml}`, `tests/test_helm_console.py`

**Interfaces:**
- Values per spec: `ingress.{enabled,className,annotations,hosts[],tls[]}`, `agentListener.{enabled,publicUrl,service.{type,port,annotations,loadBalancerSourceRanges}}`. `ingress.hosts` is a list of `{host, paths: [{path, pathType}]}` (defaults `/`, `Prefix`) like the common Helm convention; `tls` a list of `{secretName, hosts}`.
- Derivation rule (spec): empty `config.origins` + Ingress enabled → `PERISCOPE_ORIGINS` = each host as `https://host` if any `tls` entry lists it (or any tls entry exists, simplest: tls non-empty) else `http://host`; empty `config.rpId` → first host. Explicit values win.
- `ci/ingress-values.yaml`: minimal + ingress on `periscope.example.com` with tls; `ci/agents-values.yaml`: minimal + agent listener with `publicUrl: https://agents.example.com:8443`, `service.type: LoadBalancer`.

- [ ] **Step 1: Write failing tests**: `test_ingress_renders_and_derives_origins` (kinds include `Ingress`; `className`, host, path, tls secret; ConfigMap origins `["https://periscope.example.com"]`, rpId `periscope.example.com`; without tls → `http://…`); `test_explicit_origins_win_over_derivation`; `test_ingress_disabled_by_default`; `test_agent_listener_service_and_env` (second `Service` named `*-agents`, port 8443 → targetPort 8443, `type` from values, annotations and `loadBalancerSourceRanges` rendered; env `PERISCOPE_AGENT_PUBLIC_URL` in the ConfigMap; container port 8443 declared; with the listener disabled neither exists); `test_agent_listener_requires_public_url` (`enabled` without `publicUrl` → `HelmError` naming `publicUrl`); `test_public_url_must_be_https_with_a_host` (`http://x` or no host → `HelmError`); `test_trusted_proxies_value_reaches_forwarded_allow_ips` (`config.trustedProxies: "10.0.0.0/8"`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** the templates and value handling (derivation in `_helpers.tpl`). **Step 4: Run** the tests + `helm lint` with each `ci/*.yaml` + whole suite → PASS. **Step 5: Commit** `git commit -m "Console chart: ingress, derived origins, agent listener service"`.

---

### Task 5: Agent chart

**Files:**
- Create: `deploy/helm/periscope-agent/{values.yaml,values.schema.json,templates/_helpers.tpl,templates/deployment.yaml,templates/secret.yaml,templates/pvc.yaml,templates/serviceaccount.yaml,templates/NOTES.txt,ci/minimal-values.yaml}`, `tests/test_helm_agent.py`

**Interfaces:**
- Values per spec "Agent chart": `image.*`, `imagePullSecrets`, `enrollment.{bundle,existingSecret,existingSecretKey,force}`, `bunkerweb.{url,username,password,existingSecret,existingSecretKey,verifyTls,probeHost,tlsPort}`, `persistence.{size,storageClass,existingClaim}` (default 100Mi, `ReadWriteOnce`), scheduling/security/resources values as the console chart.
- Pod: init container `enroll` (same image) running `sh -c` that does nothing when `/data/agent/agent.crt` exists, otherwise `periscope agent enroll "$PERISCOPE_ENROLLMENT_BUNDLE"` (bundle env from a `secretKeyRef`, never literal; `--dir /data/agent` or `PERISCOPE_AGENT_DIR`); with `enrollment.force` the existence test is omitted. Main container: `periscope agent run`, env `PERISCOPE_AGENT_DIR=/data/agent`, `PERISCOPE_AGENT_BW_URL`, `_BW_USERNAME`, `_BW_VERIFY_TLS`, `_PROBE_HOST`, `_TLS_PORT`, and `PERISCOPE_AGENT_BW_PASSWORD_FILE=/run/secrets/bw/password` with the Secret mounted read-only; volumes `data` (PVC at `/data`) and `tmp` (`emptyDir`).
- `ci/minimal-values.yaml`: `enrollment.bundle: psc1.dGVzdA`, `bunkerweb.url: http://bunkerweb-api:8888`, `bunkerweb.password: pw`.

- [ ] **Step 1: Write failing tests** in `tests/test_helm_agent.py` (`requires_helm`): `test_minimal_install_objects` (kinds exactly `Deployment, PersistentVolumeClaim, Secret, ServiceAccount`; no `Service`; `replicas == 1`, `Recreate`); `test_security_defaults` (same assertions as the console, for the main and the init container); `test_enroll_init_container_is_idempotent` (init command contains `/data/agent/agent.crt` and `periscope agent enroll`, tests the file first; with `enrollment.force: true` it does not); `test_bundle_and_password_are_never_literal` (bundle env uses `secretKeyRef`, password only as mounted file + `PERISCOPE_AGENT_BW_PASSWORD_FILE`, no `PERISCOPE_AGENT_BW_PASSWORD` env; neither value appears in the Deployment, init spec, or `NOTES.txt`; both live only in the chart Secret, which has `helm.sh/resource-policy: keep`); `test_existing_secrets_are_referenced` (`enrollment.existingSecret` and `bunkerweb.existingSecret` → no chart Secret, references used); `test_missing_inputs_fail` (no `bunkerweb.url` → error naming `bunkerweb.url`; no bundle source → error naming `enrollment`; no password source → error naming `bunkerweb`); `test_probes_use_the_health_command` (startup and liveness `exec.command == ["periscope","agent","health"]`, generous `initialDelaySeconds`/`failureThreshold`, no readinessProbe); `test_persistence_variants` (`existingClaim`, size, storageClass); `test_awkward_values_render_exactly` (URL with `%`, `$`, quotes, unicode username); `test_replica_count_cannot_be_overridden`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** the chart (schema `additionalProperties: false`). **Step 4: Run** the agent tests + `helm lint deploy/helm/periscope-agent -f …/ci/minimal-values.yaml` + whole suite → PASS. **Step 5: Commit** `git commit -m "Agent Helm chart with self-enrollment"`.

---

### Task 6: Schema validation, packaging and the chart CI job

**Files:**
- Modify: `tests/test_helm_console.py`, `tests/test_helm_agent.py`, `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: every `deploy/helm/*/ci/*.yaml` values file.
- Produces: pytest tests `test_rendered_manifests_are_schema_valid[chart-values]` (parametrized over every chart × `ci/*.yaml`; renders with `helm template`, pipes to `kubeconform -strict -summary -kubernetes-version 1.27.0` and again `1.31.0`; skipped when `kubeconform` is absent); `test_helm_package_matches_application_version` (`helm package` of both charts into a tmp dir produces `periscope-<v>.tgz` and `periscope-agent-<v>.tgz`).
- CI job `helm` (name it `charts`): `azure/setup-helm`, `kubeconform` download, `helm lint` for every `ci/*.yaml`, `pytest tests/test_helm_console.py tests/test_helm_agent.py tests/test_release.py -q`, `helm package` (no publish).

- [ ] **Step 1: Write the two tests** and run them locally (kubeconform from `.tools/bin`) → they must pass for every values set; any schema error is a chart bug to fix now in the templates, with the failing test as RED.
- [ ] **Step 2: Add the `charts` job** to `ci.yml` (runs on push and pull request, like `test`); add it to `release.needs`. Validate the YAML locally with `python -c "import yaml,sys;yaml.safe_load(open('.github/workflows/ci.yml'))"`.
- [ ] **Step 3: Run** the whole suite and `.venv/bin/ruff check src tests dev` → PASS.
- [ ] **Step 4: Commit** `git commit -m "Charts: kubeconform validation, packaging check and CI job"`.

---

### Task 7: kind smoke test and release publishing

**Files:**
- Create: `dev/k8s-smoke.sh`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- `dev/k8s-smoke.sh [IMAGE]` (default: build `periscope:ci` from the checkout): creates a kind cluster named `periscope-smoke` (reuses it if it exists, deletes it at the end unless `KEEP=1`), loads the image, `helm install` of the console chart with `ci/minimal-values.yaml` plus `--set image.repository=periscope --set image.tag=ci --set image.pullPolicy=Never`, waits for the rollout, then through `kubectl port-forward` asserts `GET /healthz` = `ok` and `GET /readyz` = `ok`; runs `helm upgrade` with a changed `config.pollInterval`, waits for the new pod (Recreate) and asserts both endpoints again; also installs the **agent** chart with a dummy bundle and asserts the pod ends in `Init:Error`/`Init:CrashLoopBackOff` (proves the enrollment guard works and nothing crashes silently) — then uninstalls it. Exit non-zero with `kubectl describe`/`logs` output on any failure. Uses `.tools/bin` when present.
- CI job `kind`: checkout, `docker build -t periscope:ci .`, `helm/kind-action` (or the tools from `dev/k8s-tools.sh`), run `dev/k8s-smoke.sh periscope:ci`. Added to `release.needs`.
- `release` job gains, after the image push and only when `steps.v.outputs.new == 'true'`: `helm registry login ghcr.io`, `helm package` both charts, `helm push <tgz> oci://ghcr.io/${OWNER,,}/charts`.

- [ ] **Step 1: Write `dev/k8s-smoke.sh`**, shellcheck-clean style (`set -euo pipefail`, traps for cleanup). **Step 2: Run it locally** (Docker Desktop is available): expected output ends with `smoke test passed`; fix chart or script defects found (a chart defect gets a pytest regression test first).
- [ ] **Step 3: Add the `kind` job and the publish steps** to `ci.yml`; validate the YAML.
- [ ] **Step 4: Run** the whole suite + ruff → PASS. **Step 5: Commit** `git commit -m "Kind smoke test, CI job and chart publishing at release"`.

---

### Task 8: Documentation, roadmap and final verification

**Files:**
- Create: `docs/kubernetes.md`
- Modify: `README.md`, `CHANGELOG.md`, `ROADMAP.md`, `docs/releasing.md`

- [ ] **Step 1: Write `docs/kubernetes.md`** for a newcomer, covering exactly the list in the spec's "Documentation" section, with copy-paste commands that were run against the kind cluster of Task 7 (secret key creation with `openssl rand -base64 32 | tr '+/' '-_'`, install, port-forward to try it, Ingress values example, agent listener values with the DNS-name advice, agent install in a customer cluster, `enrollment.force` recovery, upgrade, uninstall, backup of the secret key and database, one-replica explanation, `--set` vs values file, troubleshooting table by symptom). State clearly what is **not** validated (BunkerWeb on Kubernetes API address/service name; real cloud load balancers; agent end-to-end in CI) and what to put in `bunkerweb.url`.
- [ ] **Step 2: Update** `README.md` (Features/Deployment pointer to the guide), `CHANGELOG.md` (`### Added`: charts, `/readyz`, kind CI, OCI publishing; mention the one-replica rule), `ROADMAP.md` (goal 2 → `in progress`, link the design and guide; `done` only once a PR exists), `docs/releasing.md` (charts versioned with the app, published at release, how `bump` updates them).
- [ ] **Step 3: Final verification**: `.venv/bin/python -m pytest -q` (all pass, helm tests running), `.venv/bin/ruff check src tests dev`, `dev/k8s-smoke.sh` passes, PostgreSQL job still green locally (`tests/test_postgres.py` with Docker), `helm lint` of every values set.
- [ ] **Step 4: Commit** `git commit -m "Kubernetes guide, changelog and roadmap"`, then `git push origin v0.3.0` and report the result of the GitHub Actions run (`gh run list --branch v0.3.0 --limit 3` and `gh run view <id>`): the new `charts` and `kind` jobs must be green; if one fails, fix it (with a test when it is a chart defect) and push again.
