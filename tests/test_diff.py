from datetime import datetime, timedelta

from mc.diff import cert_status, days_left, gaps, is_stale, plugin_matrix

NOW = datetime(2026, 1, 1)


def test_cert_status_thresholds():
    d = lambda n: NOW + timedelta(days=n)  # noqa: E731
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
