from datetime import datetime, timedelta

from periscope import queries
from periscope.clock import utcnow
from periscope.db import session_scope
from periscope.models import CertProbe, Instance, Snapshot


def seed():
    now = utcnow()
    with session_scope() as s:
        a = Instance(name="bw1", base_url="http://a:8888", token_enc="x", status="ok", version="1.6.0",
                     last_ok_at=now, latency_ms=12.0)
        b = Instance(name="bw2", base_url="http://b:8888", token_enc="x", status="down",
                     last_ok_at=now - timedelta(hours=1), last_error="network: timeout")
        off = Instance(name="bw3", base_url="http://c:8888", token_enc="x", enabled=False)
        s.add_all([a, b, off])
        s.flush()
        snaps = {
            (a.id, "services"): [{"name": "x.example", "draft": False, "mode": "block"},
                                 {"name": "y.example", "draft": False, "mode": "detect"},
                                 {"name": "d.example", "draft": True, "mode": None}],
            (b.id, "services"): [{"name": "x.example", "draft": False, "mode": "detect"}],
            (a.id, "bans"): [{"ip": "1.1.1.1", "reason": "bot", "service": "x.example", "exp": 60, "date": 1}],
            (b.id, "bans"): [{"ip": "1.1.1.1", "reason": "bot", "service": "x.example", "exp": 30, "date": 1},
                             {"ip": "2.2.2.2", "reason": "scan", "service": "global", "exp": 10, "date": 2}],
            (off.id, "bans"): [{"ip": "9.9.9.9", "reason": "x", "service": "global", "exp": 1, "date": 1}],
            (a.id, "jobs"): [{"name": "renew", "plugin": "letsencrypt", "every": "day", "last_run": "2020-01-01 00:00:00", "success": True}],
            (a.id, "plugins"): [{"id": "antibot", "name": "Antibot", "version": "1.0", "type": "core"}],
            (b.id, "plugins"): [{"id": "antibot", "name": "Antibot", "version": "1.1", "type": "core"}],
        }
        for (iid, kind), payload in snaps.items():
            s.add(Snapshot(instance_id=iid, kind=kind, payload=payload, collected_at=now))
        s.add_all([
            CertProbe(instance_id=a.id, domain="x.example", present=True, issuer="Let's Encrypt",
                      not_after=now + timedelta(days=3)),
            CertProbe(instance_id=a.id, domain="y.example", present=True, issuer="Other CA",
                      not_after=now + timedelta(days=90)),
            CertProbe(instance_id=b.id, domain="x.example", present=False, error="timeout"),
        ])
    return now


def test_instance_cards_flag_stale_and_disabled(fresh_db):
    now = seed()
    with session_scope() as s:
        cards = {c["name"]: c for c in queries.instance_cards(s, now)}
    assert cards["bw1"]["stale"] is False
    assert cards["bw2"]["stale"] is True and cards["bw2"]["last_error"] == "network: timeout"
    assert cards["bw3"]["enabled"] is False


def test_summary_counts_only_enabled_instances(fresh_db):
    now = seed()
    with session_scope() as s:
        out = queries.summary(s, now)
    assert out == {"instances_total": 2, "instances_ok": 1, "instances_stale": 1,
                   "bans_active": 2, "certs_warn": 1, "certs_none": 1}


def test_services_gaps_and_filters(fresh_db):
    seed()
    with session_scope() as s:
        rows, names = queries.services(s)
        assert names == ["bw1", "bw2"]
        by = {(r["instance"], r["name"]): r for r in rows}
        assert by[("bw1", "y.example")]["missing_on"] == ["bw2"]
        assert by[("bw1", "x.example")]["missing_on"] == []
        assert by[("bw1", "d.example")]["draft"] is True and by[("bw1", "d.example")]["missing_on"] == []
        assert [r["name"] for r in queries.services(s, instance="bw2")[0]] == ["x.example"]
        assert {r["instance"] for r in queries.services(s, mode="detect")[0]} == {"bw1", "bw2"}
        assert len(queries.services(s, mode="block")[0]) == 1


def test_bans_merge_gaps_search_and_ignore_disabled(fresh_db):
    seed()
    with session_scope() as s:
        rows = queries.bans(s)
        assert [(r["ip"], r["instance"]) for r in rows] == [("1.1.1.1", "bw1"), ("1.1.1.1", "bw2"), ("2.2.2.2", "bw2")]
        assert rows[2]["missing_on"] == ["bw1"] and rows[0]["missing_on"] == []
        assert [r["ip"] for r in queries.bans(s, q="2.2")] == ["2.2.2.2"]


def test_jobs_and_plugin_matrix(fresh_db):
    seed()
    with session_scope() as s:
        assert queries.jobs(s)[0]["instance"] == "bw1" and queries.jobs(s)[0]["name"] == "renew"
        assert queries.jobs(s)[0]["next_run"] == datetime(2020, 1, 2)
        names, matrix = queries.plugins(s)
    assert names == ["bw1", "bw2"]
    assert matrix[0]["id"] == "antibot" and matrix[0]["diff"] is True and matrix[0]["cells"] == {"bw1": "1.0", "bw2": "1.1"}


def test_certs_sorted_worst_first_with_status(fresh_db):
    now = seed()
    with session_scope() as s:
        rows = queries.certs(s, now)
    assert [(r["instance"], r["domain"], r["status"]) for r in rows] == [
        ("bw2", "x.example", "none"), ("bw1", "x.example", "red"), ("bw1", "y.example", "ok")]
    red = rows[1]
    assert red["letsencrypt"] is True and red["days"] in (2, 3)
    assert rows[2]["letsencrypt"] is False
