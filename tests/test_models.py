from mc.db import session_scope
from mc.models import CertProbe, Instance, Snapshot


def test_instance_probe_target_defaults_to_base_url_host(fresh_db):
    inst = Instance(name="a", base_url="http://10.0.0.5:8888", token_enc="x")
    assert inst.probe_target == "10.0.0.5"
    inst.probe_host = "10.0.0.9"
    assert inst.probe_target == "10.0.0.9"


def test_delete_instance_cascades(fresh_db):
    with session_scope() as s:
        inst = Instance(name="a", base_url="http://h:8888", token_enc="x")
        inst.snapshots.append(Snapshot(kind="bans", payload=[]))
        inst.probes.append(CertProbe(domain="a.example", present=False))
        s.add(inst)
    with session_scope() as s:
        s.delete(s.query(Instance).one())
    with session_scope() as s:
        assert s.query(Snapshot).count() == 0
        assert s.query(CertProbe).count() == 0
