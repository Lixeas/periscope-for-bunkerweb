from datetime import datetime, timedelta

from periscope.auth import ratelimit
from periscope.models import User

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
    assert lim.hit("1.1.1.1", now=11.5) is False  # still blocked (60 s after the overrun)
    assert lim.hit("1.1.1.1", now=64) is True  # block elapsed


def test_ip_limiter_sliding_window_without_violation():
    lim = ratelimit.IPLimiter(max_events=3, window=10)
    assert [lim.hit("a", now=t) for t in (0, 1, 2)] == [True] * 3
    assert lim.hit("a", now=11.5) is True  # window elapsed, never exceeded


def test_ip_limiter_escalating_block():
    lim = ratelimit.IPLimiter(max_events=1, window=10)
    assert lim.hit("a", now=0) is True
    assert lim.hit("a", now=1) is False  # 1re violation : 60 s
    assert lim.retry_after("a", now=1) == 60
    assert lim.hit("a", now=30) is False and lim.retry_after("a", now=30) == 31
    assert lim.hit("a", now=62) is True
    assert lim.hit("a", now=63) is False  # 2e violation : 120 s
    assert lim.retry_after("a", now=63) == 120
    assert lim.retry_after("b", now=63) == 0


def test_ip_limiter_block_is_capped_and_forgotten():
    lim = ratelimit.IPLimiter(max_events=1, window=1)
    t = 0.0
    for _ in range(10):
        lim.hit("a", now=t)
        lim.hit("a", now=t + 0.1)
        t += lim.retry_after("a", now=t + 0.1) + 0.2
    assert lim.retry_after("a", now=t) == 0
    lim.hit("a", now=t)
    lim.hit("a", now=t + 0.1)
    assert lim.retry_after("a", now=t + 0.1) == 3600
    lim.hit("zzz", now=t + 0.1 + 3600 + 3601)  # purge: violations forgotten
    assert "a" not in lim._violations


def test_ip_limiter_drops_empty_entries():
    lim = ratelimit.IPLimiter(max_events=3, window=10)
    lim.hit("1.1.1.1", now=0)
    assert lim.hit("2.2.2.2", now=20) is True
    assert "1.1.1.1" not in lim._events
    lim.hit("1.1.1.1", now=40)
    assert len(lim._events["1.1.1.1"]) == 1


def test_login_failures_escalation_and_cap():
    lf = ratelimit.LoginFailures()
    for i in range(4):
        lf.register_failure("a", "1.1.1.1", now=100.0)
        assert lf.retry_after("a", "1.1.1.1", now=100.0) == 0
    lf.register_failure("a", "1.1.1.1", now=100.0)
    assert lf.retry_after("a", "1.1.1.1", now=100.0) == 30
    assert lf.retry_after("a", "1.1.1.1", now=131.0) == 0
    lf.register_failure("a", "1.1.1.1", now=131.0)
    assert lf.retry_after("a", "1.1.1.1", now=131.0) == 60
    for _ in range(20):
        lf.register_failure("a", "1.1.1.1", now=200.0)
    assert lf.retry_after("a", "1.1.1.1", now=200.0) == 900


def test_login_failures_keyed_by_lowercase_user_and_ip():
    lf = ratelimit.LoginFailures()
    for _ in range(5):
        lf.register_failure("Alice", "1.1.1.1", now=0.0)
    assert lf.retry_after("alice", "1.1.1.1", now=0.0) == 30
    assert lf.retry_after("alice", "2.2.2.2", now=0.0) == 0
    assert lf.retry_after("bob", "1.1.1.1", now=0.0) == 0


def test_login_failures_success_reset():
    lf = ratelimit.LoginFailures()
    for _ in range(5):
        lf.register_failure("a", "1.1.1.1", now=0.0)
    lf.clear("A", "1.1.1.1")
    assert lf.retry_after("a", "1.1.1.1", now=0.0) == 0


def test_login_failures_sweep_bounds_memory():
    lf = ratelimit.LoginFailures()
    for i in range(50):
        lf.register_failure(f"u{i}", "1.1.1.1", now=0.0)
    assert len(lf._state) == 50
    lf.register_failure("late", "1.1.1.1", now=ratelimit.LoginFailures.FORGET + 1)
    assert len(lf._state) == 1
