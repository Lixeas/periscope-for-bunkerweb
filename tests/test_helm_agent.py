import json

import pytest

from tests.helm_utils import (
    HelmError,
    ci_values,
    kinds,
    merge,
    one,
    render,
    render_notes,
    requires_helm,
)

pytestmark = requires_helm
CHART = "periscope-agent"
BUNDLE, PASSWORD = "psc1.dGVzdA", "bw-api-password"


def values(**over) -> dict:
    return merge(ci_values(CHART), over)


def pod(objs) -> dict:
    return one(objs, "Deployment")["spec"]["template"]["spec"]


def main(objs) -> dict:
    return pod(objs)["containers"][0]


def init(objs) -> dict:
    return pod(objs)["initContainers"][0]


def env(c) -> dict:
    return {e["name"]: e for e in c.get("env", [])}


def secret_data(objs) -> dict:
    import base64
    return {k: base64.b64decode(v).decode() for k, v in one(objs, "Secret").get("data", {}).items()}


def test_minimal_install_objects():
    objs = render(CHART, values())
    assert kinds(objs) == ["Deployment", "PersistentVolumeClaim", "Secret", "ServiceAccount"]
    dep = one(objs, "Deployment")
    assert dep["spec"]["replicas"] == 1 and dep["spec"]["strategy"]["type"] == "Recreate"
    assert main(objs)["image"].startswith("ghcr.io/lixeas/periscope-for-bunkerweb:")
    assert main(objs)["command"] == ["periscope", "agent", "run"]


def test_security_defaults():
    objs = render(CHART, values())
    p = pod(objs)
    assert p["automountServiceAccountToken"] is False and p["securityContext"]["fsGroup"] == 10001
    assert p["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
    for c in (main(objs), init(objs)):
        sc = c["securityContext"]
        assert sc["runAsNonRoot"] is True and sc["runAsUser"] == 10001 and sc["readOnlyRootFilesystem"] is True
        assert sc["allowPrivilegeEscalation"] is False and sc["capabilities"]["drop"] == ["ALL"]
        assert {m["name"]: m["mountPath"] for m in c["volumeMounts"]}["tmp"] == "/tmp"
    vols = {v["name"]: v for v in p["volumes"]}
    assert "persistentVolumeClaim" in vols["data"] and "emptyDir" in vols["tmp"]
    assert {m["name"]: m["mountPath"] for m in main(objs)["volumeMounts"]}["data"] == "/data"


def test_enroll_init_container_is_idempotent():
    cmd = " ".join(init(render(CHART, values()))["command"] + init(render(CHART, values())).get("args", []))
    assert "periscope agent enroll" in cmd and "/data/agent/agent.crt" in cmd and "console.json" in cmd
    assert cmd.index("test -f") < cmd.index("periscope agent enroll") and "||" in cmd
    forced = init(render(CHART, values(enrollment={"force": True})))
    fcmd = " ".join(forced["command"] + forced.get("args", []))
    assert "periscope agent enroll" in fcmd and "test -f" not in fcmd and "||" not in fcmd


def test_bundle_and_password_are_never_literal():
    objs = render(CHART, values())
    ref = env(init(objs))["PERISCOPE_ENROLLMENT_BUNDLE"]["valueFrom"]["secretKeyRef"]
    assert ref == {"name": one(objs, "Secret")["metadata"]["name"], "key": "bundle"}
    e = env(main(objs))
    assert "PERISCOPE_AGENT_BW_PASSWORD" not in e
    assert e["PERISCOPE_AGENT_BW_PASSWORD_FILE"]["value"] == "/run/secrets/bw/password"
    mount = next(m for m in main(objs)["volumeMounts"] if m["mountPath"] == "/run/secrets/bw")
    assert mount["readOnly"] is True
    vol = next(v for v in pod(objs)["volumes"] if v["name"] == mount["name"])
    assert vol["secret"]["secretName"] == one(objs, "Secret")["metadata"]["name"]
    assert vol["secret"]["items"] == [{"key": "password", "path": "password"}]
    spec_text = json.dumps(one(objs, "Deployment"))
    assert BUNDLE not in spec_text and PASSWORD not in spec_text
    notes = render_notes(CHART, values())
    assert BUNDLE not in notes and PASSWORD not in notes
    sec = one(objs, "Secret")
    assert sec["metadata"]["annotations"]["helm.sh/resource-policy"] == "keep"
    assert secret_data(objs) == {"bundle": BUNDLE, "password": PASSWORD}


def test_existing_secrets_are_referenced():
    v = values(enrollment={"bundle": "", "existingSecret": "enr", "existingSecretKey": "b"},
               bunkerweb={"password": "", "existingSecret": "bw", "existingSecretKey": "pw"})
    objs = render(CHART, v)
    assert "Secret" not in kinds(objs)
    assert env(init(objs))["PERISCOPE_ENROLLMENT_BUNDLE"]["valueFrom"]["secretKeyRef"] == {"name": "enr", "key": "b"}
    vol = next(x for x in pod(objs)["volumes"] if "secret" in x)
    assert vol["secret"]["secretName"] == "bw" and vol["secret"]["items"] == [{"key": "pw", "path": "password"}]


def test_missing_inputs_fail():
    for path, match in ((("bunkerweb", "url"), "bunkerweb.url"), (("enrollment", "bundle"), "enrollment"),
                        (("bunkerweb", "password"), "bunkerweb")):
        v = values()
        del v[path[0]][path[1]]
        with pytest.raises(HelmError, match=match):
            render(CHART, v)


def test_probes_use_the_health_command():
    c = main(render(CHART, values()))
    for probe in ("startupProbe", "livenessProbe"):
        assert c[probe]["exec"]["command"] == ["periscope", "agent", "health"]
    assert c["startupProbe"]["failureThreshold"] >= 10 and c["livenessProbe"]["initialDelaySeconds"] >= 60
    assert "readinessProbe" not in c


def test_persistence_variants():
    objs = render(CHART, values(persistence={"existingClaim": "mine"}))
    assert "PersistentVolumeClaim" not in kinds(objs)
    assert next(v for v in pod(objs)["volumes"] if v["name"] == "data")["persistentVolumeClaim"]["claimName"] == "mine"
    pvc = one(render(CHART, values(persistence={"size": "1Gi", "storageClass": "fast"})), "PersistentVolumeClaim")
    assert pvc["spec"]["resources"]["requests"]["storage"] == "1Gi" and pvc["spec"]["storageClassName"] == "fast"
    assert one(render(CHART, values()), "PersistentVolumeClaim")["spec"]["resources"]["requests"]["storage"] == "100Mi"


def test_settings_reach_the_agent_environment():
    e = env(main(render(CHART, values(bunkerweb={"verifyTls": False, "probeHost": "10.1.2.3", "tlsPort": 8443,
                                                 "username": "svc"}))))
    assert e["PERISCOPE_AGENT_DIR"]["value"] == "/data/agent"
    assert e["PERISCOPE_AGENT_BW_URL"]["value"] == "http://bunkerweb-api:8888"
    assert e["PERISCOPE_AGENT_BW_USERNAME"]["value"] == "svc"
    assert e["PERISCOPE_AGENT_BW_VERIFY_TLS"]["value"] == "false"
    assert e["PERISCOPE_AGENT_PROBE_HOST"]["value"] == "10.1.2.3" and e["PERISCOPE_AGENT_TLS_PORT"]["value"] == "8443"
    assert "PERISCOPE_AGENT_PROBE_HOST" not in env(main(render(CHART, values())))
    assert env(main(render(CHART, values())))["PERISCOPE_AGENT_BW_USERNAME"]["value"] == "periscope"


def test_awkward_values_render_exactly():
    url = 'http://bw%20api:8888/x?a="b"$c'
    objs = render(CHART, values(bunkerweb={"url": url, "username": "périscope", "password": 'p%w"$d\\n'}))
    assert env(main(objs))["PERISCOPE_AGENT_BW_URL"]["value"] == url
    assert env(main(objs))["PERISCOPE_AGENT_BW_USERNAME"]["value"] == "périscope"
    assert secret_data(objs)["password"] == 'p%w"$d\\n'


def test_replica_count_cannot_be_overridden():
    with pytest.raises(HelmError):
        render(CHART, values(replicaCount=3))


def test_scheduling_and_image_options_pass_through():
    objs = render(CHART, values(nodeSelector={"a": "b"}, tolerations=[{"key": "k", "operator": "Exists"}],
                                imagePullSecrets=[{"name": "ghcr"}], podAnnotations={"x": "y"},
                                image={"digest": "sha256:" + "b" * 64}))
    p = pod(objs)
    assert p["nodeSelector"] == {"a": "b"} and p["imagePullSecrets"] == [{"name": "ghcr"}]
    assert main(objs)["image"].endswith("@sha256:" + "b" * 64) and init(objs)["image"].endswith("@sha256:" + "b" * 64)
    assert one(objs, "Deployment")["spec"]["template"]["metadata"]["annotations"]["x"] == "y"
