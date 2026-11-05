"""Every chart x every ci/*.yaml values set: valid Kubernetes manifests, lintable, packageable."""
import subprocess
import tarfile

import pytest

from tests.helm_utils import CHARTS, helm_bin, requires_helm, tool
from tests.test_release import release

CASES = sorted((c.parent.parent.name, c.name) for c in CHARTS.glob("*/ci/*.yaml"))
KUBERNETES_VERSIONS = ("1.27.0", "1.31.0")


def test_every_chart_has_ci_values():
    assert {c for c, _ in CASES} == {"periscope", "periscope-agent"}
    assert len(CASES) >= 5  # minimal + postgres + ingress + agents (console), minimal (agent)


@requires_helm
@pytest.mark.parametrize(("chart", "values"), CASES)
def test_helm_lint(chart, values):
    r = subprocess.run([helm_bin(), "lint", str(CHARTS / chart), "-f", str(CHARTS / chart / "ci" / values), "--strict"],
                       check=False, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


@requires_helm
@pytest.mark.skipif(tool("kubeconform") is None, reason="kubeconform not installed (run dev/k8s-tools.sh)")
@pytest.mark.parametrize("k8s", KUBERNETES_VERSIONS)
@pytest.mark.parametrize(("chart", "values"), CASES)
def test_rendered_manifests_are_schema_valid(chart, values, k8s):
    manifests = subprocess.run([helm_bin(), "template", "p", str(CHARTS / chart), "-f",
                                str(CHARTS / chart / "ci" / values)], check=True, capture_output=True, text=True).stdout
    r = subprocess.run([tool("kubeconform"), "-strict", "-summary", "-kubernetes-version", k8s, "-"],
                       input=manifests, check=False, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


@requires_helm
def test_helm_package_matches_application_version(tmp_path):
    version = release.current()
    for chart in ("periscope", "periscope-agent"):
        subprocess.run([helm_bin(), "package", str(CHARTS / chart), "-d", str(tmp_path)], check=True,
                       capture_output=True, text=True)
        archive = tmp_path / f"{chart}-{version}.tgz"
        assert archive.exists()
        with tarfile.open(archive) as tar:
            names = tar.getnames()
        assert f"{chart}/Chart.yaml" in names and f"{chart}/values.schema.json" in names
        assert not any("/ci/" in n for n in names)  # .helmignore keeps the test values out of the package
