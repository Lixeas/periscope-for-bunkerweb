from datetime import datetime, timedelta

from periscope.clock import utcnow
from periscope.web.render import templates


def test_dt_and_ago_filters():
    dt, ago = templates.env.filters["dt"], templates.env.filters["ago"]
    assert dt(datetime(2026, 3, 4, 5, 6)) == "04/03/2026 05:06 UTC"
    assert dt(None) == "—"
    assert ago(None) == "jamais"
    assert ago(utcnow() - timedelta(seconds=30)) == "il y a 30 s"
    assert ago(utcnow() - timedelta(minutes=5, seconds=1)) == "il y a 5 min"
    assert ago(utcnow() - timedelta(hours=3, seconds=1)) == "il y a 3 h"
    assert ago(utcnow() - timedelta(days=2, seconds=1)) == "il y a 2 j"


def test_duration_filter():
    d = templates.env.filters["duration"]
    assert d(45) == "45 s" and d(0) == "0 s" and d(59.9) == "59 s"
    assert d(60) == "1 min" and d(12 * 60 + 5) == "12 min"
    assert d(3 * 3600) == "3 h" and d(3 * 3600 + 20 * 60) == "3 h 20" and d(3 * 3600 + 5 * 60) == "3 h 05"
    assert d(2 * 86400) == "2 j" and d(2 * 86400 + 4 * 3600 + 59) == "2 j 4 h"


def test_duration_filter_non_numeric_negative_and_huge():
    d = templates.env.filters["duration"]
    for bad in (None, "x", "60", ["x"], {"a": 1}, True, -1, -3600.5, float("nan"), float("inf"), float("-inf")):
        assert d(bad) == "—", bad
    assert d(10**30).endswith("j") or " j" in d(10**30)  # does not raise


def test_epoch_filter():
    e = templates.env.filters["epoch"]
    assert e(1760000000) == "09/10/2025 08:53 UTC"
    assert e(1760000000.9) == "09/10/2025 08:53 UTC"


def test_epoch_filter_never_raises():
    e = templates.env.filters["epoch"]
    for bad in (None, 0, 0.0, "x", "1760000000", ["x"], {"a": 1}, True, -1, -(10**30), 10**30, 10**18,
                float("nan"), float("inf"), 253402300800):
        assert e(bad) == "—", bad


def test_duration_and_epoch_accept_gigantic_ints_without_raising():
    dur, ep = templates.env.filters["duration"], templates.env.filters["epoch"]
    assert ep(10**400) == "—" and isinstance(dur(10**400), str)
    assert ep(-(10**400)) == "—" and dur(-(10**400)) == "—"
