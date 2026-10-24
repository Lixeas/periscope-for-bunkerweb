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
            # normalized shape (see normalize.bans; API derived from the BunkerWeb v1.6.17 source)
            (a.id, "bans"): [{"ip": "1.1.1.1", "reason": "bot", "service": "x.example", "ban_scope": "service",
                              "exp": 60, "date": 1760000000, "permanent": False, "country": "FR", "kind": "ban"}],
            (b.id, "bans"): [{"ip": "1.1.1.1", "reason": "bot", "service": "x.example", "ban_scope": "service",
                              "exp": 30, "date": 1760000000, "permanent": False, "country": "FR", "kind": "ban"},
                             {"ip": "2.2.2.2", "reason": "scan", "service": "global", "ban_scope": "global",
                              "exp": 0, "date": 1760000000, "permanent": True, "country": "", "kind": "crowdsec_lease"}],
            (off.id, "bans"): [{"ip": "9.9.9.9", "reason": "x", "service": "global", "exp": 1, "date": 1}],
            (a.id, "jobs"): [{"name": "renew", "plugin": "letsencrypt", "every": "day", "last_run": "2020-01-01 00:00:00", "success": True}],
            (a.id, "instances"): [
                {"hostname": "w1.lan", "name": "worker1", "port": 5000, "type": "static", "status": "up",
                 "method": "scheduler", "last_seen": "2026-10-22T10:00:00+00:00", "server_name": ""},
                {"hostname": "w2.lan", "name": "<script>x</script>", "port": 5000, "type": "container",
                 "status": "down", "method": "autoconf", "last_seen": None, "server_name": ""}],
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
    assert {k: out[k] for k in ("instances_total", "instances_ok", "instances_stale",
                                "bans_active", "certs_warn", "certs_none")} == {
        "instances_total": 2, "instances_ok": 1, "instances_stale": 1,
        "bans_active": 2, "certs_warn": 1, "certs_none": 1}
    assert (out["nodes_up"], out["nodes_total"], out["certs_total"]) == (1, 2, 2)
    assert out["alerts_total"] == sum(len(c["alerts"]) for c in queries.instance_cards(s, now) if c["enabled"])


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


def test_bans_rows_have_permanent_and_numeric_sort_key(fresh_db):
    seed()
    with session_scope() as s:
        rows = {(r["ip"], r["instance"]): r for r in queries.bans(s)}
    assert rows[("1.1.1.1", "bw1")]["permanent"] is False and rows[("1.1.1.1", "bw1")]["exp_sort"] == 60
    assert rows[("2.2.2.2", "bw2")]["permanent"] is True
    assert rows[("2.2.2.2", "bw2")]["exp_sort"] > rows[("1.1.1.1", "bw1")]["exp_sort"]


def test_bans_rows_legacy_snapshot_exp_zero_is_permanent_and_hostile_exp_safe(fresh_db):
    seed()
    with session_scope() as s:
        inst = s.query(Instance).filter_by(name="bw1").one()
        snap = s.query(Snapshot).filter_by(instance_id=inst.id, kind="bans").one()
        snap.payload = [{"ip": "7.7.7.7", "exp": 0}, {"ip": "8.8.8.8", "exp": ["x"], "date": {"a": 1}},
                        {"ip": "9.9.9.9", "exp": True}]
    with session_scope() as s:
        rows = {r["ip"]: r for r in queries.bans(s) if r["instance"] == "bw1"}
    assert rows["7.7.7.7"]["permanent"] is True
    assert rows["8.8.8.8"]["permanent"] is False and rows["8.8.8.8"]["exp_sort"] == 0
    assert rows["9.9.9.9"]["permanent"] is False


def test_ban_row_survives_gigantic_numbers():
    from periscope.queries import PERMANENT_SORT, _ban_row
    row = _ban_row({"ip": "1.1.1.1", "exp": 10**400, "date": 10**400}, "bw1", {})
    assert row["exp_sort"] == PERMANENT_SORT - 1 and row["permanent"] is False


def test_instance_cards_carry_role_and_nodes(fresh_db):
    now = seed()
    with session_scope() as s:
        cards = {c["name"]: c for c in queries.instance_cards(s, now)}
    assert cards["bw1"]["role"] == "scheduler"
    assert (cards["bw1"]["nodes_up"], cards["bw1"]["nodes_total"]) == (1, 2)
    assert cards["bw1"]["nodes"][0]["last_seen"].year == 2026 and cards["bw1"]["nodes"][1]["last_seen"] is None
    assert cards["bw2"]["nodes"] is None and cards["bw2"]["nodes_total"] == 0


def test_instance_cards_alerts_are_sorted_worst_first(fresh_db):
    now = seed()
    with session_scope() as s:
        cards = queries.instance_cards(s, now)
    by = {c["name"]: c for c in cards}
    codes = [a["code"] for a in by["bw1"]["alerts"]]
    assert "cert_red" in codes                        # x.example expires in 3 days
    assert [a["level"] for a in by["bw1"]["alerts"]] == sorted(
        (a["level"] for a in by["bw1"]["alerts"]), key=queries.SEV_ORDER.get)
    assert by["bw2"]["alerts"] and by["bw3"]["alerts"] == [] and by["bw3"]["sev"] == "off"
    # the instances to check come first, disabled ones last
    assert [c["sev"] for c in cards] == sorted((c["sev"] for c in cards), key=queries.SEV_ORDER.get)
