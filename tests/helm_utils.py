"""Render the Helm charts with `helm template` for the chart tests (skipped when helm is absent)."""
import copy
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
CHARTS = ROOT / "deploy" / "helm"


def helm_bin() -> str | None:
    return shutil.which("helm") or (str(p) if (p := ROOT / ".tools" / "bin" / "helm").exists() else None)


def tool(name: str) -> str | None:
    return shutil.which(name) or (str(p) if (p := ROOT / ".tools" / "bin" / name).exists() else None)


requires_helm = pytest.mark.skipif(helm_bin() is None, reason="helm not installed (run dev/k8s-tools.sh)")


class HelmError(Exception):
    """helm refused to render; the message is its stderr."""


def ci_values(chart: str, name: str = "minimal-values.yaml") -> dict:
    return yaml.safe_load((CHARTS / chart / "ci" / name).read_text())


def merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in over.items():
        out[k] = merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def _run(chart: str, values: dict | None, release: str, *args: str) -> str:
    with tempfile.TemporaryDirectory() as d:
        vf = Path(d) / "values.json"
        vf.write_text(json.dumps(values or {}))
        r = subprocess.run([helm_bin(), "template", release, str(CHARTS / chart), "-f", str(vf), *args],
                           check=False, capture_output=True, text=True)
    if r.returncode != 0:
        raise HelmError(r.stderr)
    return r.stdout


def render(chart: str, values: dict | None = None, release: str = "p") -> list[dict]:
    return [d for d in yaml.safe_load_all(_run(chart, values, release)) if d]


def render_notes(chart: str, values: dict | None = None) -> str:
    """The rendered NOTES.txt. `helm template` never prints it and a client-side dry run wants a cluster, so
    a temporary copy of the chart carries it as a commented template that `helm template` does render."""
    with tempfile.TemporaryDirectory() as d:
        copy_dir = Path(d) / chart
        shutil.copytree(CHARTS / chart, copy_dir)
        notes = (copy_dir / "templates" / "NOTES.txt").read_text()
        header = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: notes-copy\n"
        (copy_dir / "templates" / "notes-copy.yaml").write_text(
            header + "\n".join("# " + line for line in notes.splitlines()) + "\n")
        vf = Path(d) / "values.json"
        vf.write_text(json.dumps(values or {}))
        r = subprocess.run([helm_bin(), "template", "p", str(copy_dir), "-f", str(vf), "--show-only",
                            "templates/notes-copy.yaml"], check=False, capture_output=True, text=True)
    if r.returncode != 0:
        raise HelmError(r.stderr)
    return r.stdout


def kinds(objs: list[dict]) -> list[str]:
    return sorted(o["kind"] for o in objs)


def one(objs: list[dict], kind: str, name: str | None = None) -> dict:
    found = [o for o in objs if o["kind"] == kind and (name is None or o["metadata"]["name"] == name)]
    assert len(found) == 1, f"expected one {kind} {name or ''}, got {len(found)}"
    return found[0]
