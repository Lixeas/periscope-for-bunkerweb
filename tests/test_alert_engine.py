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
