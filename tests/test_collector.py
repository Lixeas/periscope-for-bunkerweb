from datetime import datetime

from mc import collector
from mc.bw_client import BWError
from mc.crypto import encrypt
from mc.db import session_scope
from mc.models import CertProbe, Instance, Snapshot
from mc.tlsprobe import CertInfo


class Fake:
    def __init__(self, ping_err=None, fail=()):
        self.ping_err, self.fail = ping_err, fail

    async def ping(self):
        if self.ping_err:
            raise self.ping_err
        return 12.0, "1.6.0"

    async def _kind(self, kind, data):
        if kind in self.fail:
            raise BWError("auth", "HTTP 403")
        return data

    async def services(self):
        return await self._kind("services", [{"name": "a.example", "draft": False, "mode": "block"},
                                              {"name": "d.example", "draft": True, "mode": None}])

    async def bans(self):
        return await self._kind("bans", [{"ip": "1.1.1.1"}])

    async def jobs(self):
        return await self._kind("jobs", [])

    async def plugins(self):
        return await self._kind("plugins", [])

    async def aclose(self):
        pass


def add_instance() -> int:
    with session_scope() as s:
        inst = Instance(name="i1", base_url="http://10.0.0.5:8888", token_enc=encrypt("t"))
        s.add(inst)
        s.flush()
        return inst.id


def snap(inst_id, kind):
    with session_scope() as s:
        row = s.query(Snapshot).filter_by(instance_id=inst_id, kind=kind).one_or_none()
        return row.payload if row else None


async def test_collect_ok_stores_snapshots(fresh_db):
    iid = add_instance()
    await collector.collect_one(iid, lambda inst: Fake())
    with session_scope() as s:
        inst = s.get(Instance, iid)
        assert (inst.status, inst.version, inst.latency_ms) == ("ok", "1.6.0", 12.0)
        assert inst.last_ok_at is not None and inst.last_error == ""
    assert snap(iid, "bans") == [{"ip": "1.1.1.1"}]
    assert len(snap(iid, "services")) == 2


async def test_collect_down_keeps_last_snapshot(fresh_db):
    iid = add_instance()
    await collector.collect_one(iid, lambda inst: Fake())
    await collector.collect_one(iid, lambda inst: Fake(ping_err=BWError("network", "refused")))
    with session_scope() as s:
        inst = s.get(Instance, iid)
        assert inst.status == "down" and inst.last_error.startswith("network:")
        assert inst.last_ok_at is not None
    assert snap(iid, "bans") == [{"ip": "1.1.1.1"}]


async def test_collect_partial_failure_is_degraded_and_keeps_old_kind(fresh_db):
    iid = add_instance()
    await collector.collect_one(iid, lambda inst: Fake())
    with session_scope() as s:
        s.query(Snapshot).filter_by(instance_id=iid, kind="bans").one().payload = [{"ip": "old"}]
    await collector.collect_one(iid, lambda inst: Fake(fail=("bans",)))
    with session_scope() as s:
        inst = s.get(Instance, iid)
        assert inst.status == "degraded" and "bans: auth" in inst.last_error
    assert snap(iid, "bans") == [{"ip": "old"}]


async def test_probe_one_uses_non_draft_domains_and_prunes(fresh_db):
    iid = add_instance()
    await collector.collect_one(iid, lambda inst: Fake())
    with session_scope() as s:
        s.add(CertProbe(instance_id=iid, domain="gone.example", present=True))
    calls = []

    async def fake_probe(host, port, domain, timeout):
        calls.append((host, port, domain))
        return CertInfo(True, "Let's Encrypt", datetime(2030, 1, 1))

    await collector.probe_one(iid, fake_probe)
    assert calls == [("10.0.0.5", 443, "a.example")]
    with session_scope() as s:
        rows = s.query(CertProbe).all()
        assert [(r.domain, r.issuer, r.present) for r in rows] == [("a.example", "Let's Encrypt", True)]
