import base64
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
CHART = "periscope"


def values(**over) -> dict:
    return merge(ci_values(CHART), over)


def dump(*objs) -> str:
    return json.dumps(objs)


def pod(objs) -> dict:
    return one(objs, "Deployment")["spec"]["template"]["spec"]


def container(objs) -> dict:
    return pod(objs)["containers"][0]


def secret_text(objs) -> str:
    sec = one(objs, "Secret")
    return " ".join(base64.b64decode(v).decode() for v in sec.get("data", {}).values())


def env(objs) -> dict:
    return {e["name"]: e for e in container(objs).get("env", [])}


def test_minimal_install_objects():
    from tests.test_release import release
    objs = render(CHART, values())
    assert kinds(objs) == ["ConfigMap", "Deployment", "PersistentVolumeClaim", "Secret", "Service", "ServiceAccount"]
    dep = one(objs, "Deployment")
    assert dep["spec"]["replicas"] == 1 and dep["spec"]["strategy"]["type"] == "Recreate"
    assert container(objs)["image"] == f"ghcr.io/lixeas/periscope-for-bunkerweb:{release.current()}"


def test_security_defaults():
    objs = render(CHART, values())
    p, c = pod(objs), container(objs)
    assert p["automountServiceAccountToken"] is False
    assert p["securityContext"]["fsGroup"] == 10001 and p["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
    sc = c["securityContext"]
    assert sc["runAsNonRoot"] is True and sc["runAsUser"] == 10001 and sc["readOnlyRootFilesystem"] is True
    assert sc["allowPrivilegeEscalation"] is False and sc["capabilities"]["drop"] == ["ALL"]
    mounts = {m["name"]: m["mountPath"] for m in c["volumeMounts"]}
    assert mounts == {"data": "/data", "tmp": "/tmp"}
    vols = {v["name"]: v for v in p["volumes"]}
    assert "persistentVolumeClaim" in vols["data"] and "emptyDir" in vols["tmp"]
    assert c["resources"]["requests"]["cpu"] and c["resources"]["limits"]["memory"]


def test_probes():
    c = container(render(CHART, values()))
    assert c["ports"][0]["name"] == "http" and c["ports"][0]["containerPort"] == 8000
    for probe in ("startupProbe", "livenessProbe"):
        assert c[probe]["httpGet"]["path"] == "/healthz" and c[probe]["httpGet"]["port"] == "http"
    assert c["readinessProbe"]["httpGet"]["path"] == "/readyz"


def test_secret_key_is_a_secret_reference_never_literal():
    v = values()
    key = v["secretKey"]["value"]
    objs = render(CHART, v)
    ref = env(objs)["PERISCOPE_SECRET_KEY"]["valueFrom"]["secretKeyRef"]
    sec = one(objs, "Secret")
    assert ref == {"name": sec["metadata"]["name"], "key": "secret-key"}
    assert sec["metadata"]["annotations"]["helm.sh/resource-policy"] == "keep"
    assert key not in dump(one(objs, "Deployment"), one(objs, "ConfigMap"))
    notes = render_notes(CHART, v)
    assert "port-forward" in notes and key not in notes


def test_existing_secret_is_referenced_and_no_secret_created():
    v = values()
    del v["secretKey"]["value"]
    v["secretKey"].update(existingSecret="ext", existingSecretKey="k")
    objs = render(CHART, v)
    assert "Secret" not in kinds(objs)
    assert env(objs)["PERISCOPE_SECRET_KEY"]["valueFrom"]["secretKeyRef"] == {"name": "ext", "key": "k"}


def test_missing_secret_key_fails():
    v = values()
    del v["secretKey"]
    with pytest.raises(HelmError, match="secretKey"):
        render(CHART, v)


def test_database_external_postgres():
    v = ci_values(CHART, "postgres-values.yaml")
    objs = render(CHART, v)
    assert "PersistentVolumeClaim" not in kinds(objs)
    assert "persistentVolumeClaim" not in {x["name"]: x for x in pod(objs)["volumes"]}["data"]
    ref = env(objs)["PERISCOPE_DATABASE_URL"]["valueFrom"]["secretKeyRef"]
    assert ref["key"] == "database-url" and "pw@db.example" in secret_text(objs)
    assert "pw@db.example" not in dump(one(objs, "Deployment"), one(objs, "ConfigMap"))
    v2 = merge(v, {"database": {"url": "", "existingSecret": "dbs", "existingSecretKey": "url"}})
    objs = render(CHART, v2)
    assert env(objs)["PERISCOPE_DATABASE_URL"]["valueFrom"]["secretKeyRef"] == {"name": "dbs", "key": "url"}
    assert "database-url" not in dump(objs)


def test_persistence_variants():
    objs = render(CHART, values(persistence={"existingClaim": "mine"}))
    assert "PersistentVolumeClaim" not in kinds(objs)
    assert {x["name"]: x for x in pod(objs)["volumes"]}["data"]["persistentVolumeClaim"]["claimName"] == "mine"
    pvc = one(render(CHART, values(persistence={"size": "5Gi", "storageClass": "fast", "accessModes": ["ReadWriteOnce"]})),
              "PersistentVolumeClaim")
    assert pvc["spec"]["resources"]["requests"]["storage"] == "5Gi" and pvc["spec"]["storageClassName"] == "fast"
    with pytest.raises(HelmError, match="persistence"):
        render(CHART, values(persistence={"enabled": False}))


def test_replica_count_cannot_be_overridden():
    with pytest.raises(HelmError):
        render(CHART, values(replicaCount=3))


def test_config_checksum_changes_with_config():
    def checksum(v):
        return one(render(CHART, v), "Deployment")["spec"]["template"]["metadata"]["annotations"]["checksum/config"]

    assert checksum(values()) == checksum(values())
    assert checksum(values()) != checksum(values(config={"pollInterval": 60}))
    assert checksum(values()) != checksum(values(secretKey={"value": "another-key-value"}))


def test_awkward_values_render_exactly():
    origins = ['https://a"b.example', "https://é.example/%25$x"]
    url = 'postgresql://u:p%40x$y"z@db/p?sslmode=require'
    objs = render(CHART, values(config={"origins": origins, "extra": {"PERISCOPE_HTTP_TIMEOUT": "7"}},
                                database={"url": url}, persistence={"enabled": False}))
    cm = one(objs, "ConfigMap")["data"]
    assert json.loads(cm["PERISCOPE_ORIGINS"]) == origins and cm["PERISCOPE_HTTP_TIMEOUT"] == "7"
    assert url in secret_text(objs)


def test_service_and_image_options():
    objs = render(CHART, values(
        service={"type": "NodePort", "port": 9000, "annotations": {"a": "b"}},
        image={"digest": "sha256:" + "a" * 64, "pullPolicy": "Always"},
        imagePullSecrets=[{"name": "ghcr"}], nodeSelector={"disk": "ssd"},
        tolerations=[{"key": "k", "operator": "Exists"}], podAnnotations={"x": "y"}, podLabels={"team": "t"},
        affinity={"podAntiAffinity": {}}))
    svc = one(objs, "Service")
    assert svc["spec"]["type"] == "NodePort" and svc["spec"]["ports"][0]["port"] == 9000
    assert svc["metadata"]["annotations"]["a"] == "b"
    p = pod(objs)
    assert container(objs)["image"].endswith("@sha256:" + "a" * 64) and container(objs)["imagePullPolicy"] == "Always"
    assert p["imagePullSecrets"] == [{"name": "ghcr"}] and p["nodeSelector"] == {"disk": "ssd"}
    assert p["tolerations"][0]["key"] == "k" and "affinity" in p
    meta = one(objs, "Deployment")["spec"]["template"]["metadata"]
    assert meta["annotations"]["x"] == "y" and meta["labels"]["team"] == "t"
    objs = render(CHART, values(serviceAccount={"create": False, "name": "preexisting"}))
    assert "ServiceAccount" not in kinds(objs) and pod(objs)["serviceAccountName"] == "preexisting"


def test_cookie_secure_requires_origins_and_rpid():
    v = values(config={"cookieSecure": True})
    del v["config"]["origins"]
    with pytest.raises(HelmError, match="origins"):
        render(CHART, v)
    v = values(config={"cookieSecure": True})
    del v["config"]["rpId"]
    with pytest.raises(HelmError, match="rpId"):
        render(CHART, v)


def test_configmap_defaults():
    cm = one(render(CHART, values(config={"cookieSecure": True})), "ConfigMap")["data"]
    assert cm["PERISCOPE_COOKIE_SECURE"] == "true" and cm["PERISCOPE_RP_ID"] == "localhost"
    assert cm["FORWARDED_ALLOW_IPS"] == "*"
    assert one(render(CHART, values(config={"trustedProxies": "10.0.0.0/8"})), "ConfigMap")["data"][
        "FORWARDED_ALLOW_IPS"] == "10.0.0.0/8"
