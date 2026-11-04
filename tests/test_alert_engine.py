from datetime import datetime, timedelta

import pytest

from periscope import alert_engine as eng
from periscope.db import session_scope
from periscope.i18n import pack
from periscope.models import AlertState, Instance, Tag

T0 = datetime(2026, 11, 4, 12, 0, 0)


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def make(name="bw1", status="ok", **kw) -> int:
    with session_scope() as s:
        inst = Instance(name=name, status=status, **kw)
        s.add(inst)
        s.flush()
        return inst.id


def set_status(iid: int, status: str, error: str = "", **kw) -> None:
    with session_scope() as s:
        inst = s.get(Instance, iid)
        inst.status, inst.last_error = status, error
        for k, v in kw.items():
            setattr(inst, k, v)


def state(**filt):
    with session_scope() as s:
        return s.query(AlertState).filter_by(**filt).one_or_none()


def st(notified="ok", pending="", count=0, notified_at=None) -> AlertState:
    return AlertState(kind="status", instance_id=1, subject="", notified=notified, pending=pending,
                      pending_count=count, notified_at=notified_at or T0)


# --- step() ---------------------------------------------------------------------------------

def test_step_needs_two_consecutive_observations():
    s = st()
    assert eng.step(s, "down", at(0)) is None
    assert eng.step(s, "down", at(30)) == ("change", "ok")
    assert (s.notified, s.pending, s.pending_count) == ("down", "", 0)


def test_alternating_problem_states_are_still_notified():
    s = st()
    results = [eng.step(s, o, at(30 * i)) for i, o in enumerate(["down", "degraded", "down", "degraded"])]
    assert results == [None, ("change", "ok"), None, None]  # latest observation wins, then it is stable
    assert s.notified == "degraded"
    c = st()
    zones = [eng.step(c, o, at(30 * i)) for i, o in enumerate(["orange", "none"])]
    assert zones == [None, ("change", "ok")]


def test_flapping_never_notifies():
    s = st()
    results = [eng.step(s, o, at(30 * i)) for i, o in enumerate(["down", "ok", "down", "ok", "down"])]
    assert results == [None] * 5
    assert s.notified == "ok"


def test_reminder_after_24h_only_for_a_problem():
    s = st(notified="down", notified_at=T0)
    assert eng.step(s, "down", T0 + timedelta(hours=23)) is None
    assert eng.step(s, "down", T0 + timedelta(hours=24)) == ("reminder", "down")
    assert s.notified_at == T0 + timedelta(hours=24)
    ok = st(notified="ok", notified_at=T0)
    assert eng.step(ok, "ok", T0 + timedelta(days=30)) is None


# --- evaluate_status ------------------------------------------------------------------------

def test_first_sight_is_a_silent_baseline(fresh_db):
    iid = make(status="down")
    assert eng.evaluate_status(at(0)) == []
    assert state(kind="status", instance_id=iid).notified == "down"
    unk = make("new", status="unknown")
    assert eng.evaluate_status(at(30)) == []
    assert state(kind="status", instance_id=unk).notified == "ok"
    set_status(unk, "down")
    assert eng.evaluate_status(at(60)) == []
    assert [n.type for n in eng.evaluate_status(at(90))] == ["instance_down"]


def test_status_change_types(fresh_db):
    msg = pack("1 node offline: {host}", host="n1")
    with session_scope() as s:
        t = Tag(name="customer-a")
        inst = Instance(name="bw1", status="ok")
        s.add_all([t, inst])
        inst.tags = [t]
    iid = state_free_id()
    eng.evaluate_status(at(0))
    set_status(iid, "down", msg)
    assert eng.evaluate_status(at(30)) == []
    (n,) = eng.evaluate_status(at(60))
    assert (n.type, n.event, n.instance, n.tags, n.status, n.message) == (
        "instance_down", "down", "bw1", ("customer-a",), "down", msg)
    set_status(iid, "degraded")
    eng.evaluate_status(at(90))
    assert [x.type for x in eng.evaluate_status(at(120))] == ["instance_degraded"]
    set_status(iid, "ok")
    eng.evaluate_status(at(150))
    (r,) = eng.evaluate_status(at(180))
    assert (r.type, r.event) == ("instance_resolved", "degraded")


def state_free_id() -> int:
    with session_scope() as s:
        return s.query(Instance.id).scalar()


def test_resolved_from_down_has_down_event(fresh_db):
    iid = make()
    eng.evaluate_status(at(0))
    set_status(iid, "down")
    eng.evaluate_status(at(30))
    eng.evaluate_status(at(60))
    set_status(iid, "ok")
    eng.evaluate_status(at(90))
    (r,) = eng.evaluate_status(at(120))
    assert (r.type, r.event) == ("instance_resolved", "down")


def test_reminder_notification(fresh_db):
    iid = make()
    eng.evaluate_status(at(0))
    set_status(iid, "down")
    eng.evaluate_status(at(30))
    assert [n.type for n in eng.evaluate_status(at(60))] == ["instance_down"]
    assert eng.evaluate_status(at(3600)) == []
    (n,) = eng.evaluate_status(at(60 + 24 * 3600))
    assert (n.type, n.event, n.status) == ("instance_reminder", "down", "down")


def test_unknown_status_is_ignored(fresh_db):
    iid = make()
    eng.evaluate_status(at(0))
    set_status(iid, "unknown")
    for i in range(1, 4):
        assert eng.evaluate_status(at(30 * i)) == []
    assert state(kind="status", instance_id=iid).notified == "ok"


def test_silenced_instance_is_skipped_and_resumes(fresh_db):
    iid = make()
    eng.evaluate_status(at(0))
    set_status(iid, "down", silenced_until=at(1000))
    for i in range(1, 6):
        assert eng.evaluate_status(at(30 * i)) == []
    s = state(kind="status", instance_id=iid)
    assert (s.notified, s.pending_count) == ("ok", 0)
    eng.evaluate_status(at(1001))
    assert [n.type for n in eng.evaluate_status(at(1031))] == ["instance_down"]


def test_resolved_is_sent_after_the_silence_ended(fresh_db):
    iid = make()
    eng.evaluate_status(at(0))
    set_status(iid, "down")
    eng.evaluate_status(at(30))
    eng.evaluate_status(at(60))  # notified down
    set_status(iid, "ok", silenced_until=at(500))
    assert eng.evaluate_status(at(90)) == [] and eng.evaluate_status(at(120)) == []
    eng.evaluate_status(at(501))
    assert [n.type for n in eng.evaluate_status(at(531))] == ["instance_resolved"]


def test_problem_that_came_and_went_during_silence_sends_nothing(fresh_db):
    iid = make()
    eng.evaluate_status(at(0))
    set_status(iid, "down", silenced_until=at(500))
    eng.evaluate_status(at(30))
    set_status(iid, "ok")
    out = [eng.evaluate_status(at(t)) for t in (60, 501, 531, 561)]
    assert out == [[], [], [], []]


def test_disabled_instance_state_is_dropped(fresh_db):
    iid = make()
    eng.evaluate_status(at(0))
    assert state(kind="status", instance_id=iid) is not None
    set_status(iid, "down", enabled=False)
    assert eng.evaluate_status(at(30)) == [] and eng.evaluate_status(at(60)) == []
    assert state(kind="status", instance_id=iid) is None


def test_version_change(fresh_db):
    iid = make(version="1.6.16")
    assert eng.evaluate_status(at(0)) == []  # baseline
    set_status(iid, "ok", version=None)
    assert eng.evaluate_status(at(30)) == []
    set_status(iid, "ok", version="")
    assert eng.evaluate_status(at(60)) == []
    set_status(iid, "ok", version="1.6.17")
    (n,) = eng.evaluate_status(at(90))
    assert (n.type, n.event, n.version) == ("instance_version_changed", "version", "1.6.17")
    assert eng.evaluate_status(at(120)) == []
    assert state(kind="version", instance_id=iid).notified == "1.6.17"


@pytest.mark.parametrize("name", ["a{b}%s é"])
def test_names_with_braces_are_just_data(fresh_db, name):
    iid = make(name)
    eng.evaluate_status(at(0))
    set_status(iid, "down")
    eng.evaluate_status(at(30))
    (n,) = eng.evaluate_status(at(60))
    assert n.instance == name


# --- evaluate_certs -------------------------------------------------------------------------

def probe(iid: int, domain="a.example", present=True, days=60.0, now=T0) -> None:
    from periscope.models import CertProbe
    with session_scope() as s:
        p = s.query(CertProbe).filter_by(instance_id=iid, domain=domain).one_or_none()
        if p is None:
            p = CertProbe(instance_id=iid, domain=domain)
            s.add(p)
        p.present = present
        p.not_after = now + timedelta(days=days) if present else None


def run_certs(iid_times):
    return [eng.evaluate_certs(at(t)) for t in iid_times]


def test_cert_zone_change_is_notified_once(fresh_db):
    iid = make()
    probe(iid)
    eng.evaluate_certs(at(0))  # baseline ok
    probe(iid, days=20)
    assert eng.evaluate_certs(at(30)) == []
    (n,) = eng.evaluate_certs(at(60))
    assert (n.type, n.event, n.domain, n.instance, n.days_left) == ("cert_orange", "certificate", "a.example", "bw1", 19)
    assert n.not_after == T0 + timedelta(days=20)
    assert eng.evaluate_certs(at(90)) == []
    probe(iid, days=5)
    eng.evaluate_certs(at(120))
    assert [x.type for x in eng.evaluate_certs(at(150))] == ["cert_red"]
    probe(iid, days=-1)
    eng.evaluate_certs(at(180))
    assert [x.type for x in eng.evaluate_certs(at(210))] == ["cert_expired"]


def test_cert_probe_failure_is_cert_error_not_expiry(fresh_db):
    iid = make()
    probe(iid)
    eng.evaluate_certs(at(0))
    probe(iid, present=False)
    eng.evaluate_certs(at(30))
    (n,) = eng.evaluate_certs(at(60))
    assert (n.type, n.event) == ("cert_error", "certificate")


def test_cert_renewal_resolves(fresh_db):
    iid = make()
    probe(iid, days=3)
    eng.evaluate_certs(at(0))  # silent baseline red
    probe(iid, days=90)
    eng.evaluate_certs(at(30))
    (n,) = eng.evaluate_certs(at(60))
    assert (n.type, n.event) == ("cert_resolved", "certificate")


def test_cert_has_no_reminders(fresh_db):
    iid = make()
    probe(iid)
    eng.evaluate_certs(at(0))
    probe(iid, days=20)
    sent = [eng.evaluate_certs(at(t)) for t in (30, 60, 3 * 86400, 5 * 86400)]
    assert sum(len(x) for x in sent) == 1


def test_vanished_domain_state_dropped_silently(fresh_db):
    from periscope.models import CertProbe
    iid = make()
    probe(iid, days=3)
    eng.evaluate_certs(at(0))
    assert state(kind="cert", instance_id=iid, subject="a.example") is not None
    with session_scope() as s:
        s.query(CertProbe).delete()
    assert eng.evaluate_certs(at(30)) == []
    assert state(kind="cert", instance_id=iid, subject="a.example") is None


def test_cert_silenced_and_disabled_instances_skipped(fresh_db):
    iid = make()
    probe(iid)
    eng.evaluate_certs(at(0))
    probe(iid, days=3)
    set_status(iid, "ok", silenced_until=at(1000))
    assert run_certs([30, 60, 90]) == [[], [], []]
    set_status(iid, "ok", silenced_until=None, enabled=False)
    assert run_certs([120, 150]) == [[], []]
    assert state(kind="cert", instance_id=iid, subject="a.example") is None


def test_cert_domain_with_braces_and_unicode(fresh_db):
    iid = make()
    probe(iid, domain="é{x}.example")
    eng.evaluate_certs(at(0))
    probe(iid, domain="é{x}.example", days=3)
    eng.evaluate_certs(at(30))
    (n,) = eng.evaluate_certs(at(60))
    assert n.domain == "é{x}.example" and n.type == "cert_red"


# --- run_status / run_certs and the collector hooks -------------------------------------------

async def test_run_status_dispatches_what_evaluate_returns(fresh_db, monkeypatch):
    from periscope import alert_send
    sent = []

    async def fake_dispatch(notifications, now=None):
        sent.append(notifications)

    monkeypatch.setattr(alert_send, "dispatch", fake_dispatch)
    iid = make()
    await eng.run_status()  # baseline
    set_status(iid, "down")
    await eng.run_status()
    await eng.run_status()
    await eng.drain()
    assert [[n.type for n in batch] for batch in sent if batch] == [["instance_down"]]


async def test_run_never_raises(fresh_db, monkeypatch, caplog):
    def boom(*a, **k):
        raise RuntimeError("db down")

    monkeypatch.setattr(eng, "evaluate_status", boom)
    monkeypatch.setattr(eng, "evaluate_certs", boom)
    await eng.run_status()
    await eng.run_certs()
    assert "alert" in caplog.text.lower()


async def test_collect_all_and_probe_all_call_their_own_alert_run(fresh_db, monkeypatch):
    from periscope import collector
    calls = []

    async def status():
        calls.append("status")

    async def certs():
        calls.append("certs")

    monkeypatch.setattr(collector, "_enabled_ids", lambda connection="direct": [])
    monkeypatch.setattr(eng, "run_status", status)
    monkeypatch.setattr(eng, "run_certs", certs)
    await collector.collect_all()
    assert calls == ["status"]
    await collector.probe_all()
    assert calls == ["status", "certs"]


async def test_slow_delivery_does_not_block_the_collector_loop(fresh_db, monkeypatch):
    import asyncio

    from periscope import alert_send
    release, started, finished = asyncio.Event(), asyncio.Event(), []

    async def slow_dispatch(notifications, now=None):
        started.set()
        await release.wait()
        finished.append(notifications)

    monkeypatch.setattr(alert_send, "dispatch", slow_dispatch)
    iid = make()
    await eng.run_status()
    set_status(iid, "down")
    await eng.run_status()
    await asyncio.wait_for(eng.run_status(), 1)  # confirms the change; must return while delivery is pending
    await asyncio.wait_for(started.wait(), 1)
    assert finished == []
    release.set()
    await eng.drain()
    assert len(finished) == 1
