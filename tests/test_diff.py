from datetime import datetime, timedelta

from periscope.diff import cert_status, days_left, gaps, is_stale, next_run, plugin_matrix

NOW = datetime(2026, 1, 1)


def test_cert_status_thresholds():
    d = lambda n: NOW + timedelta(days=n)
    assert cert_status(False, None, NOW) == "none"
    assert cert_status(True, d(-1), NOW) == "expired"
    assert cert_status(True, d(6), NOW) == "red"
    assert cert_status(True, d(7), NOW) == "orange"
    assert cert_status(True, d(20), NOW) == "orange"
    assert cert_status(True, d(21), NOW) == "ok"


def test_days_left():
    assert days_left(NOW + timedelta(days=10, hours=3), NOW) == 10
    assert days_left(None, NOW) is None


def test_gaps_only_lists_items_missing_somewhere():
    per = {"a": {"x", "y"}, "b": {"x"}, "c": {"x", "y"}}
    assert gaps(per) == {"y": ["b"]}
    assert gaps({}) == {}
    assert gaps({"a": {"x"}, "b": {"x"}}) == {}


def test_plugin_matrix_flags_missing_and_version_diff():
    rows = plugin_matrix({"a": {"p1": "1.0", "p2": "1.0"}, "b": {"p1": "1.1"}})
    by = {r["id"]: r for r in rows}
    assert by["p1"]["diff"] is True and by["p1"]["cells"] == {"a": "1.0", "b": "1.1"}
    assert by["p2"]["diff"] is True and by["p2"]["cells"]["b"] is None
    assert plugin_matrix({"a": {"p": "1"}, "b": {"p": "1"}})[0]["diff"] is False


def test_is_stale():
    assert is_stale(None, NOW, 30, 3)
    assert not is_stale(NOW - timedelta(seconds=90), NOW, 30, 3)
    assert is_stale(NOW - timedelta(seconds=91), NOW, 30, 3)


def test_next_run_parses_formats_and_frequencies():
    base = datetime(2026, 1, 1, 12, 0, 0)
    assert next_run("2026-01-01 12:00:00", "hour") == base + timedelta(hours=1)
    assert next_run("2026-01-01T12:00:00", "day") == base + timedelta(days=1)
    assert next_run("2026-01-01T12:00:00Z", "minute") == base + timedelta(minutes=1)
    assert next_run("2026-01-01T14:00:00+02:00", "week") == base + timedelta(weeks=1)
    epoch = (base - datetime(1970, 1, 1)).total_seconds()
    assert next_run(epoch, "hour") == base + timedelta(hours=1)
    assert next_run(int(epoch * 1000), "hour") == base + timedelta(hours=1)
    assert next_run(str(int(epoch)), "day") == base + timedelta(days=1)


def test_next_run_none_cases():
    assert next_run("2026-01-01 12:00:00", "once") is None
    assert next_run("2026-01-01 12:00:00", "fortnight") is None
    assert next_run("2026-01-01 12:00:00", None) is None
    assert next_run(None, "day") is None
    assert next_run("garbage", "day") is None
    assert next_run("", "day") is None
    assert next_run(True, "day") is None


def test_next_run_never_raises_on_hostile_values():
    from periscope.diff import next_run
    for bad in ("9999-12-31 23:59:59", "0001-01-01T00:00:00+05:00", "inf", "nan", 1e300, -1e300, 2**80):
        assert next_run(bad, "day") is None or next_run(bad, "day").year >= 1
