#!/usr/bin/env bash
# End-to-end check of the Helm charts on a throwaway kind cluster (needs Docker; dev/k8s-tools.sh fetches
# helm, kind and kubeconform into .tools/bin). Used by the CI job `kind` and runnable locally:
#
#   dev/k8s-smoke.sh [IMAGE]     # IMAGE defaults to periscope:ci, built from this checkout when absent
#   KEEP=1 dev/k8s-smoke.sh      # keep the cluster afterwards (kind delete cluster --name periscope-smoke)
#
# It installs the console (SQLite on a volume), checks /healthz and /readyz, upgrades it (the pod is
# replaced: Recreate) and checks again, then installs the agent with a dummy bundle and checks that the
# enrollment guard stops it in the init container instead of running half-configured.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$root/.tools/bin:$PATH"
cluster=periscope-smoke
ns=periscope-smoke
image="${1:-periscope:ci}"
repo="${image%:*}"
tag="${image##*:}"
ctx="kind-$cluster"
port=18000
pf_pid=""

k() { kubectl --context "$ctx" --namespace "$ns" "$@"; }

diagnose() {
  echo "=== smoke test FAILED; cluster state ===" >&2
  k get pods,svc,pvc -o wide >&2 || true
  k describe pods >&2 || true
  for p in $(k get pods -o name 2>/dev/null); do
    echo "--- logs $p" >&2
    k logs "$p" --all-containers --tail=60 >&2 || true
  done
}

cleanup() {
  status=$?
  stop_forward
  [ "$status" -ne 0 ] && diagnose
  if [ "${KEEP:-0}" != 1 ]; then kind delete cluster --name "$cluster" >/dev/null 2>&1 || true; fi
  exit "$status"
}
trap cleanup EXIT

for t in docker kind helm kubectl curl; do
  command -v "$t" >/dev/null || { echo "missing tool: $t (run dev/k8s-tools.sh)" >&2; exit 1; }
done

if ! docker image inspect "$image" >/dev/null 2>&1; then
  echo "building $image"
  docker build -q -t "$image" "$root"
fi

if ! kind get clusters 2>/dev/null | grep -qx "$cluster"; then
  kind create cluster --name "$cluster" --wait 180s
fi
kind load docker-image "$image" --name "$cluster"

image_args=(--set "image.repository=$repo" --set "image.tag=$tag" --set image.pullPolicy=Never)

stop_forward() {
  if [ -n "$pf_pid" ]; then kill "$pf_pid" 2>/dev/null || true; wait "$pf_pid" 2>/dev/null || true; pf_pid=""; fi
}

forward() {
  stop_forward
  k port-forward svc/periscope "$port:8000" >/dev/null 2>&1 &
  pf_pid=$!
  for _ in $(seq 1 30); do
    curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "port-forward never became reachable" >&2
  return 1
}

check() {
  forward
  [ "$(curl -fsS "http://127.0.0.1:$port/healthz")" = ok ] || { echo "/healthz is not ok" >&2; return 1; }
  [ "$(curl -fsS "http://127.0.0.1:$port/readyz")" = ok ] || { echo "/readyz is not ok" >&2; return 1; }
  echo "ok: /healthz and /readyz ($1)"
}

echo "== console: install"
helm upgrade --install periscope "$root/deploy/helm/periscope" --namespace "$ns" --create-namespace \
  -f "$root/deploy/helm/periscope/ci/minimal-values.yaml" "${image_args[@]}" --wait --timeout 240s
check "after install"

echo "== console: upgrade (the pod is replaced)"
before="$(k get pod -l app.kubernetes.io/instance=periscope -o jsonpath='{.items[0].metadata.uid}')"
helm upgrade periscope "$root/deploy/helm/periscope" --namespace "$ns" \
  -f "$root/deploy/helm/periscope/ci/minimal-values.yaml" "${image_args[@]}" --set config.pollInterval=60 \
  --wait --timeout 240s
after="$(k get pod -l app.kubernetes.io/instance=periscope -o jsonpath='{.items[0].metadata.uid}')"
[ "$before" != "$after" ] || { echo "configuration change did not restart the pod" >&2; exit 1; }
[ "$(k get pods -l app.kubernetes.io/instance=periscope --no-headers | wc -l | tr -d ' ')" = 1 ] || {
  echo "more than one console pod" >&2; exit 1; }
check "after upgrade"

echo "== agent: dummy bundle must stop in the init container"
helm upgrade --install agent "$root/deploy/helm/periscope-agent" --namespace "$ns" \
  -f "$root/deploy/helm/periscope-agent/ci/minimal-values.yaml" "${image_args[@]}"
for _ in $(seq 1 60); do
  state="$(k get pod -l app.kubernetes.io/instance=agent \
    -o jsonpath='{.items[0].status.initContainerStatuses[0].state}{.items[0].status.initContainerStatuses[0].lastState}' 2>/dev/null || true)"
  case "$state" in *terminated*|*CrashLoopBackOff*) break ;; esac
  sleep 2
done
case "$state" in *terminated*|*CrashLoopBackOff*) ;; *) echo "init container never failed: $state" >&2; exit 1 ;; esac
phase="$(k get pod -l app.kubernetes.io/instance=agent -o jsonpath='{.items[0].status.phase}')"
[ "$phase" != Running ] || { echo "agent main container started without enrolling" >&2; exit 1; }
k logs -l app.kubernetes.io/instance=agent -c enroll --tail=20 2>&1 | grep -q "corrupted enrollment bundle" || {
  echo "unexpected enrollment error" >&2; exit 1; }
echo "ok: the agent refuses to run without a valid enrollment"
helm uninstall agent --namespace "$ns" >/dev/null

echo "smoke test passed"
