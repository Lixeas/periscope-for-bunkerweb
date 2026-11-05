import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.exc import IntegrityError

from periscope.config import get_settings
from periscope.db import migrate, session_scope
from periscope.models import AlertChannel, AlertLog, AlertState, Instance, Tag


def test_channel_roundtrip_with_tags_and_events(fresh_db):
    with session_scope() as s:
        b, a = Tag(name="b"), Tag(name="a")
        ch = AlertChannel(name="MSP", kind="email", events="down,certificate", recipients="x@y.example")
        s.add_all([a, b, ch])
        ch.tags = [b, a]
    with session_scope() as s:
        ch = s.query(AlertChannel).one()
        assert [t.name for t in ch.tags] == ["a", "b"]
        assert ch.has_event("down") and ch.has_event("certificate")
        assert not ch.has_event("version")
        assert (ch.lang, ch.enabled) == ("en", True)


def test_channel_default_events(fresh_db):
    with session_scope() as s:
        s.add(AlertChannel(name="w", kind="webhook"))
    with session_scope() as s:
        assert s.query(AlertChannel).one().events == "down,degraded,certificate"


def test_state_unique_per_subject(fresh_db):
    with session_scope() as s:
        inst = Instance(name="bw1")
        s.add(inst)
        s.flush()
        s.add(AlertState(kind="cert", instance_id=inst.id, subject="a.example", notified="ok"))
    with pytest.raises(IntegrityError), session_scope() as s:
        iid = s.query(Instance.id).scalar()
        s.add(AlertState(kind="cert", instance_id=iid, subject="a.example", notified="ok"))


def test_instance_delete_cascades_state_and_deleting_channel_keeps_log(fresh_db):
    with session_scope() as s:
        inst = Instance(name="bw1")
        ch = AlertChannel(name="MSP", kind="email")
        s.add_all([inst, ch])
        s.flush()
        s.add(AlertState(kind="status", instance_id=inst.id, notified="ok"))
        s.add(AlertLog(channel_id=ch.id, channel_name="MSP", events="instance_down", instances="bw1", ok=True))
    with session_scope() as s:
        s.delete(s.query(Instance).one())
    with session_scope() as s:
        assert s.query(AlertState).count() == 0
        s.delete(s.query(AlertChannel).one())
    with session_scope() as s:
        log = s.query(AlertLog).one()
        assert log.channel_id is None and log.channel_name == "MSP"


def test_instance_silenced_until_defaults_to_none(fresh_db):
    with session_scope() as s:
        s.add(Instance(name="bw1"))
    with session_scope() as s:
        assert s.query(Instance).one().silenced_until is None


def test_migration_0005_from_0004(tmp_path, monkeypatch):
    from pathlib import Path

    from alembic import command
    from alembic.config import Config

    from periscope import db as mcdb
    url = f"sqlite:///{(tmp_path / 'm.db').as_posix()}"
    monkeypatch.setenv("PERISCOPE_DATABASE_URL", url)
    get_settings.cache_clear()
    try:
        cfg = Config()
        cfg.set_main_option("script_location", str(Path(mcdb.__file__).parent / "migrations"))
        cfg.set_main_option("sqlalchemy.url", url)
        command.upgrade(cfg, "0004")
        migrate()
        insp = inspect(create_engine(url))
        assert {"alert_channels", "alert_channel_tags", "alert_state", "alert_log"} <= set(insp.get_table_names())
        cols = {c["name"]: c for c in insp.get_columns("instances")}
        assert cols["silenced_until"]["nullable"] is True
    finally:
        get_settings.cache_clear()
