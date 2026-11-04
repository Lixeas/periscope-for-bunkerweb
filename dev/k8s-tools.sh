#!/usr/bin/env bash
# Download pinned helm, kind and kubeconform into .tools/bin (git-ignored; nothing is installed globally).
# Used to run the chart tests and dev/k8s-smoke.sh locally; CI has its own setup steps.
#   dev/k8s-tools.sh            # fetch what is missing
#   PATH="$PWD/.tools/bin:$PATH" helm version
set -euo pipefail

HELM_VERSION=3.16.4
KIND_VERSION=0.25.0
KUBECONFORM_VERSION=0.6.7

root="$(cd "$(dirname "$0")/.." && pwd)"
bin="$root/.tools/bin"
mkdir -p "$bin"

case "$(uname -s)" in Darwin) os=darwin ;; Linux) os=linux ;; *) echo "unsupported OS" >&2; exit 1 ;; esac
case "$(uname -m)" in arm64|aarch64) arch=arm64 ;; x86_64|amd64) arch=amd64 ;; *) echo "unsupported CPU" >&2; exit 1 ;; esac

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

# fetch URL DEST EXPECTED_SHA256_URL_OR_EMPTY NAME_IN_CHECKSUM_FILE
fetch() {
  local url=$1 dest=$2 sumurl=$3 name=$4 want
  curl -fsSL --retry 3 -o "$dest" "$url"
  if [ -n "$sumurl" ]; then
    want="$(curl -fsSL --retry 3 "$sumurl" | grep -F "$name" | head -n1 | cut -d' ' -f1 | tr -d '[:space:]')"
    [ -n "$want" ] || { echo "no checksum found for $name" >&2; exit 1; }
    [ "$(sha256 "$dest")" = "$want" ] || { echo "checksum mismatch for $name" >&2; exit 1; }
  fi
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if [ ! -x "$bin/helm" ]; then
  f="helm-v${HELM_VERSION}-${os}-${arch}.tar.gz"
  mkdir "$work/helm"
  fetch "https://get.helm.sh/$f" "$work/helm/$f" "https://get.helm.sh/$f.sha256sum" "$f"
  tar -xzf "$work/helm/$f" -C "$work/helm"
  install -m 0755 "$work/helm/${os}-${arch}/helm" "$bin/helm"
fi

if [ ! -x "$bin/kind" ]; then
  f="kind-${os}-${arch}"
  mkdir "$work/kind"
  fetch "https://kind.sigs.k8s.io/dl/v${KIND_VERSION}/$f" "$work/kind/$f" "https://kind.sigs.k8s.io/dl/v${KIND_VERSION}/$f.sha256sum" "$f"
  install -m 0755 "$work/kind/$f" "$bin/kind"
fi

if [ ! -x "$bin/kubeconform" ]; then
  f="kubeconform-${os}-${arch}.tar.gz"
  mkdir "$work/kc"
  fetch "https://github.com/yannh/kubeconform/releases/download/v${KUBECONFORM_VERSION}/$f" "$work/kc/$f" \
    "https://github.com/yannh/kubeconform/releases/download/v${KUBECONFORM_VERSION}/CHECKSUMS" "$f"
  tar -xzf "$work/kc/$f" -C "$work/kc" kubeconform
  install -m 0755 "$work/kc/kubeconform" "$bin/kubeconform"
fi

"$bin/helm" version --short
"$bin/kind" version
"$bin/kubeconform" -v
