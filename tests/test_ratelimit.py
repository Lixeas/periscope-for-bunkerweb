from datetime import datetime, timedelta

from mc.auth import ratelimit
from mc.models import User

NOW = datetime(2026, 1, 1)


def test_lock_seconds_progression():
    assert [ratelimit.lock_seconds(n) for n in (1, 4, 5, 6, 7, 20)] == [0, 0, 30, 60, 120, 900]


def test_account_lock_cycle():
    u = User(username="a", password_hash="x", failed_attempts=0)
    for _ in range(4):
        ratelimit.register_failure(u, NOW)
    assert not ratelimit.is_locked(u, NOW)
    ratelimit.register_failure(u, NOW)
    assert ratelimit.is_locked(u, NOW)
    assert ratelimit.is_locked(u, NOW + timedelta(seconds=29))
    assert not ratelimit.is_locked(u, NOW + timedelta(seconds=31))
    ratelimit.register_success(u)
    assert u.failed_attempts == 0 and u.locked_until is None


def test_ip_limiter_window():
    lim = ratelimit.IPLimiter(max_events=3, window=10)
    assert [lim.hit("1.1.1.1", now=t) for t in (0, 1, 2, 3)] == [True, True, True, False]
    assert lim.hit("2.2.2.2", now=3) is True  # autre IP
    assert lim.hit("1.1.1.1", now=11.5) is True  # fenêtre écoulée


def test_ip_limiter_drops_empty_entries():
    lim = ratelimit.IPLimiter(max_events=3, window=10)
    lim.hit("1.1.1.1", now=0)
    assert lim.hit("2.2.2.2", now=20) is True
    assert "1.1.1.1" not in lim._events
    lim.hit("1.1.1.1", now=40)
    assert len(lim._events["1.1.1.1"]) == 1
