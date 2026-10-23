from datetime import datetime, timedelta

import pytest

from periscope import collector, i18n
from periscope.bw_client import BWError
from periscope.crypto import encrypt
from periscope.db import session_scope
from periscope.models import CertProbe, Instance, Snapshot
from periscope.tlsprobe import CertInfo


class Fake:
    def __init__(self, ping_err=None, fail=(), ping_version="1.6.0", openapi_version=None, nodes=()):
        self.nodes = list(nodes)
        self.ping_err, self.fail = ping_err, fail
        self.ping_version, self.openapi_version, self.version_calls = ping_version, openapi_version, 0

    async def version(self):
        self.version_calls += 1
        return self.openapi_version

    async def ping(self):
        if self.ping_err:
            raise self.ping_err
        return 12.0, self.ping_version

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

    async def instances(self):
        return await self._kind("instances", self.nodes)

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
        assert inst.status == "down" and i18n.render("en", inst.last_error) == "network: refused"
        assert i18n.render("fr", inst.last_error) == "network: refused"  # unknown msgid: shown as is
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
        assert inst.status == "degraded" and "bans: auth" in i18n.render("en", inst.last_error)
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


async def test_deleted_instance_mid_cycle_is_ignored(fresh_db):
    iid = add_instance()
    await collector.collect_one(iid, lambda inst: Fake())

    async def deleting_probe(host, port, domain, timeout):
        with session_scope() as s:
            s.delete(s.get(Instance, iid))
        return CertInfo(True, "X", datetime(2030, 1, 1))

    await collector.probe_one(iid, deleting_probe)
    with session_scope() as s:
        assert s.query(CertProbe).count() == 0
    collector._finish(iid, datetime(2026, 1, 1), "ok", "", 1.0, "1.0", {})  # does not raise


async def test_version_truncated(fresh_db):
    class LongVer(Fake):
        async def ping(self):
            return 1.0, "v" * 100

    iid = add_instance()
    await collector.collect_one(iid, lambda inst: LongVer())
    with session_scope() as s:
        assert s.get(Instance, iid).version == "v" * 32


@pytest.fixture(autouse=True)
def _clear_version_cache():
    collector._VERSION_CHECKED.clear()


def _version(iid):
    with session_scope() as s:
        return s.get(Instance, iid).version


async def test_openapi_version_stored_when_ping_has_none(fresh_db):
    iid = add_instance()
    await collector.collect_one(iid, lambda inst: Fake(ping_version=None, openapi_version="1.6.17"))
    assert _version(iid) == "1.6.17"


async def test_ping_version_wins_and_skips_lookup(fresh_db):
    iid = add_instance()
    f = Fake(ping_version="1.6.0", openapi_version="9.9")
    await collector.collect_one(iid, lambda inst: f)
    assert _version(iid) == "1.6.0" and f.version_calls == 0


async def test_version_not_refetched_within_the_hour(fresh_db, monkeypatch):
    iid = add_instance()
    t0 = datetime(2026, 1, 1, 12, 0)
    monkeypatch.setattr(collector, "utcnow", lambda: t0)
    f = Fake(ping_version=None, openapi_version="1.6.17")
    await collector.collect_one(iid, lambda inst: f)
    monkeypatch.setattr(collector, "utcnow", lambda: t0 + timedelta(minutes=59))
    await collector.collect_one(iid, lambda inst: f)
    assert f.version_calls == 1 and _version(iid) == "1.6.17"


async def test_version_refetched_after_an_hour(fresh_db, monkeypatch):
    iid = add_instance()
    t0 = datetime(2026, 1, 1, 12, 0)
    monkeypatch.setattr(collector, "utcnow", lambda: t0)
    await collector.collect_one(iid, lambda inst: Fake(ping_version=None, openapi_version="1.6.17"))
    monkeypatch.setattr(collector, "utcnow", lambda: t0 + timedelta(hours=1, seconds=1))
    f = Fake(ping_version=None, openapi_version="1.6.18")
    await collector.collect_one(iid, lambda inst: f)
    assert f.version_calls == 1 and _version(iid) == "1.6.18"


async def test_previous_version_kept_when_lookup_returns_none(fresh_db, monkeypatch):
    iid = add_instance()
    t0 = datetime(2026, 1, 1, 12, 0)
    monkeypatch.setattr(collector, "utcnow", lambda: t0)
    await collector.collect_one(iid, lambda inst: Fake(ping_version=None, openapi_version="1.6.17"))
    monkeypatch.setattr(collector, "utcnow", lambda: t0 + timedelta(hours=2))
    await collector.collect_one(iid, lambda inst: Fake(ping_version=None, openapi_version=None))
    assert _version(iid) == "1.6.17"


async def test_version_retried_each_cycle_while_unknown(fresh_db):
    iid = add_instance()
    f = Fake(ping_version=None, openapi_version=None)
    await collector.collect_one(iid, lambda inst: f)
    await collector.collect_one(iid, lambda inst: f)
    assert f.version_calls == 2 and not _version(iid)


async def test_failing_version_lookup_does_not_degrade(fresh_db):
    iid = add_instance()
    await collector.collect_one(iid, lambda inst: Fake(ping_version=None, openapi_version=None))
    with session_scope() as s:
        inst = s.get(Instance, iid)
        assert inst.status == "ok" and inst.last_error == ""


def add_user_instance(password="pw") -> int:
    with session_scope() as s:
        inst = Instance(name="u1", base_url="http://10.0.0.5:8888", auth_mode="user",
                        api_username="periscope", api_password_enc=encrypt(password))
        s.add(inst)
        s.flush()
        return inst.id


def test_default_client_token_mode(fresh_db):
    iid = add_instance()
    with session_scope() as s:
        c = collector.default_client(s.get(Instance, iid))
    assert c.token == "t" and c._credentials is None


def test_default_client_user_mode_caches_token_by_fingerprint(fresh_db):
    collector._TOKEN_CACHE.clear()
    iid = add_user_instance()
    with session_scope() as s:
        inst = s.get(Instance, iid)
        c = collector.default_client(inst)
        assert c._credentials == ("periscope", "pw") and c.token is None
        c.token = "bisc"
        collector.remember_token(inst, c)
        assert collector.default_client(inst).token == "bisc"
        inst.api_password_enc = encrypt("other")  # credentials changed: cache invalidated
        c2 = collector.default_client(inst)
        assert c2.token is None and c2._credentials == ("periscope", "other")


async def test_collect_one_stores_token_back_in_cache(fresh_db):
    collector._TOKEN_CACHE.clear()
    iid = add_user_instance()

    class Tok(Fake):
        token = "fresh"

    made = []

    def factory(inst):
        made.append(1)
        return Tok()

    await collector.collect_one(iid, factory)
    with session_scope() as s:
        assert collector.default_client(s.get(Instance, iid)).token == "fresh"


async def test_version_from_token_when_client_built_with_cached_token(fresh_db):
    """User mode, token coming from the in-process cache: version() (read from the token) feeds instance.version."""
    collector._TOKEN_CACHE.clear()
    collector._VERSION_CHECKED.clear()
    iid = add_user_instance()
    with session_scope() as s:
        inst = s.get(Instance, iid)
        c = collector.default_client(inst)
        c.token = "cached-biscuit"
        collector.remember_token(inst, c)

    class Cached(Fake):
        def __init__(self):
            super().__init__(ping_version=None)
            self.token = None

    seen = []

    def factory(inst):
        f = Cached()
        f.token = collector.default_client(inst).token  # token already present before any network call
        seen.append(f.token)

        async def version():
            return "1.6.17" if f.token == "cached-biscuit" else None
        f.version = version
        return f

    await collector.collect_one(iid, factory)
    assert seen == ["cached-biscuit"] and _version(iid) == "1.6.17"


def _node(host, status):
    return {"hostname": host, "name": host, "port": 5000, "type": "static", "status": status,
            "method": "scheduler", "last_seen": None, "server_name": ""}


async def test_nodes_stored_and_all_up_is_ok(fresh_db):
    iid = add_instance()
    await collector.collect_one(iid, lambda inst: Fake(nodes=[_node("w1", "up"), _node("w2", "loading")]))
    assert [n["hostname"] for n in snap(iid, "instances")] == ["w1", "w2"]
    with session_scope() as s:
        inst = s.get(Instance, iid)
        assert inst.status == "ok" and inst.last_error == ""  # loading is not an error


async def test_down_node_degrades_instance(fresh_db):
    iid = add_instance()
    await collector.collect_one(iid, lambda inst: Fake(nodes=[_node("w1", "up"), _node("w2", "down")]))
    with session_scope() as s:
        inst = s.get(Instance, iid)
        assert inst.status == "degraded" and i18n.render("en", inst.last_error) == "1 node offline: w2"
        assert i18n.render("fr", inst.last_error) == "1 nœud hors ligne : w2"
    await collector.collect_one(iid, lambda inst: Fake(nodes=[_node("a", "down"), _node("b", "failover")]))
    with session_scope() as s:
        err = s.get(Instance, iid).last_error
        assert "1 node offline: a; 1 node in failover: b" == i18n.render("en", err)
        assert "1 nœud hors ligne : a; 1 nœud en failover : b" == i18n.render("fr", err)


async def test_instances_failure_is_partial_and_keeps_snapshot(fresh_db):
    iid = add_instance()
    await collector.collect_one(iid, lambda inst: Fake(nodes=[_node("w1", "up")]))
    await collector.collect_one(iid, lambda inst: Fake(fail=("instances",)))
    with session_scope() as s:
        inst = s.get(Instance, iid)
        assert inst.status == "degraded" and i18n.render("en", inst.last_error).startswith("instances:")
    assert [n["hostname"] for n in snap(iid, "instances")] == ["w1"]
    assert len(snap(iid, "services")) == 2
