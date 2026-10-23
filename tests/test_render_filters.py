from datetime import datetime, timedelta

from periscope.clock import utcnow
from periscope.web.render import _ago, _date, _dt, _duration, _epoch


def test_dt_and_ago_filters_english_and_french():
    assert _dt(datetime(2026, 3, 4, 5, 6)) == "2026-03-04 05:06 UTC"
    assert _dt(datetime(2026, 3, 4, 5, 6), "fr") == "04/03/2026 05:06 UTC"
    assert _dt(None) == "—" and _dt(None, "fr") == "—"
    assert _date(datetime(2026, 3, 4, 5, 6)) == "2026-03-04"
    assert _date(datetime(2026, 3, 4, 5, 6), "fr") == "04/03/2026"
    assert _date(None) == "—"
    assert _ago(None) == "never" and _ago(None, "fr") == "jamais"
    cases = [(timedelta(seconds=30), "30 s ago", "il y a 30 s"),
             (timedelta(minutes=5, seconds=1), "5 min ago", "il y a 5 min"),
             (timedelta(hours=3, seconds=1), "3 h ago", "il y a 3 h"),
             (timedelta(days=2, seconds=1), "2 d ago", "il y a 2 j")]
    for delta, en, fr in cases:
        assert _ago(utcnow() - delta) == en
        assert _ago(utcnow() - delta, "fr") == fr


def test_duration_filter():
    d = _duration
    assert d(45) == "45 s" and d(0) == "0 s" and d(59.9) == "59 s"
    assert d(60) == "1 min" and d(12 * 60 + 5) == "12 min"
    assert d(3 * 3600) == "3 h" and d(3 * 3600 + 20 * 60) == "3 h 20" and d(3 * 3600 + 5 * 60) == "3 h 05"
    assert d(2 * 86400) == "2 d" and d(2 * 86400 + 4 * 3600 + 59) == "2 d 4 h"
    assert d(2 * 86400, "fr") == "2 j" and d(2 * 86400 + 4 * 3600 + 59, "fr") == "2 j 4 h"


def test_duration_filter_non_numeric_negative_and_huge():
    for bad in (None, "x", "60", ["x"], {"a": 1}, True, -1, -3600.5, float("nan"), float("inf"), float("-inf")):
        assert _duration(bad) == "—", bad
    assert _duration(10**30).endswith("d") or " d" in _duration(10**30)  # does not raise


def test_epoch_filter():
    assert _epoch(1760000000) == "2025-10-09 08:53 UTC"
    assert _epoch(1760000000.9) == "2025-10-09 08:53 UTC"
    assert _epoch(1760000000, "fr") == "09/10/2025 08:53 UTC"


def test_epoch_filter_never_raises():
    for bad in (None, 0, 0.0, "x", "1760000000", ["x"], {"a": 1}, True, -1, -(10**30), 10**30, 10**18,
                float("nan"), float("inf"), 253402300800):
        assert _epoch(bad) == "—", bad


def test_duration_and_epoch_accept_gigantic_ints_without_raising():
    assert _epoch(10**400) == "—" and isinstance(_duration(10**400), str)
    assert _epoch(-(10**400)) == "—" and _duration(-(10**400)) == "—"
