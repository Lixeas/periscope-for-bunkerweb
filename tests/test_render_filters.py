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
