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

# SHA-256 of the pinned downloads, committed here so that a swapped download (or a swapped checksum file on
# the same host) is caught. To bump a version: update the *_VERSION line, fetch the new checksums from the
# project's release page, review the diff.
sum_of() {
  case "$1" in
    helm-darwin-arm64) echo e2442d8f05d53d84c39b869bc5fe5affad247ee2f4c706a040919c146edb1f94 ;;
    kind-darwin-arm64) echo 222701bb72ff596928c57b3c64ca3e0b969d593ef24ccc790f9c17904e7b63ea ;;
    kubeconform-darwin-arm64) echo cbb47d938a8d18eb5f79cb33663b2cecdee0c8ac0bf562ebcfca903df5f0802f ;;
    helm-darwin-amd64) echo 8dc25671120a4af197afe7ad9041fb8e1dd71bc01e5ef73dba1139cbc9e9f44b ;;
    kind-darwin-amd64) echo 180404ae1c0de8d333583d2958cdfac5338ec3e32cd765a158cfd6d09eb8cd7d ;;
    kubeconform-darwin-amd64) echo 3b5324ac4fd38ac60a49823b4051ff42ff7eb70144f1e9741fed1d14bc4fdb4e ;;
    helm-linux-arm64) echo d3f8f15b3d9ec8c8678fbf3280c3e5902efabe5912e2f9fcf29107efbc8ead69 ;;
    kind-linux-arm64) echo 06e544e3f12ea54de5962ceaecd97513a25dbab4168a44f03f01833349afdda3 ;;
    kubeconform-linux-arm64) echo dc82f79bb03c5479b1ae5fd4af221e4b5a3111f62bf01a2795d9c5c20fa96644 ;;
    helm-linux-amd64) echo fc307327959aa38ed8f9f7e66d45492bb022a66c3e5da6063958254b9767d179 ;;
    kind-linux-amd64) echo b22ff7e5c02b8011e82cc3223d069d178b9e1543f1deb21e936d11764780a3d8 ;;
    kubeconform-linux-amd64) echo 95f14e87aa28c09d5941f11bd024c1d02fdc0303ccaa23f61cef67bc92619d73 ;;
    *) echo "no pinned checksum for $1" >&2; exit 1 ;;
  esac
}

# fetch URL DEST PINNED_NAME : download, then compare with the committed checksum
fetch() {
  local url=$1 dest=$2 name=$3
  curl -fsSL --retry 3 -o "$dest" "$url"
  [ "$(sha256 "$dest")" = "$(sum_of "$name")" ] || { echo "checksum mismatch for $name: refusing to use it" >&2; exit 1; }
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if [ ! -x "$bin/helm" ]; then
  f="helm-v${HELM_VERSION}-${os}-${arch}.tar.gz"
  mkdir "$work/helm"
  fetch "https://get.helm.sh/$f" "$work/helm/$f" "helm-${os}-${arch}"
  tar -xzf "$work/helm/$f" -C "$work/helm"
  install -m 0755 "$work/helm/${os}-${arch}/helm" "$bin/helm"
fi

if [ ! -x "$bin/kind" ]; then
  f="kind-${os}-${arch}"
  mkdir "$work/kind"
  fetch "https://kind.sigs.k8s.io/dl/v${KIND_VERSION}/$f" "$work/kind/$f" "kind-${os}-${arch}"
  install -m 0755 "$work/kind/$f" "$bin/kind"
fi

if [ ! -x "$bin/kubeconform" ]; then
  f="kubeconform-${os}-${arch}.tar.gz"
  mkdir "$work/kc"
  fetch "https://github.com/yannh/kubeconform/releases/download/v${KUBECONFORM_VERSION}/$f" "$work/kc/$f" "kubeconform-${os}-${arch}"
  tar -xzf "$work/kc/$f" -C "$work/kc" kubeconform
  install -m 0755 "$work/kc/kubeconform" "$bin/kubeconform"
fi

"$bin/helm" version --short
"$bin/kind" version
"$bin/kubeconform" -v
