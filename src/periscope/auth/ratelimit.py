import math
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

from periscope.models import User

LOCK_AFTER = 5


def lock_seconds(failures: int) -> int:
    """0 up to 4 failures, then 30 s doubling with each failure, capped at 15 min."""
    return 0 if failures < LOCK_AFTER else min(900, 30 * 2 ** (failures - LOCK_AFTER))


def is_locked(user: User, now: datetime) -> bool:
    return user.locked_until is not None and user.locked_until > now


def register_failure(user: User, now: datetime) -> None:
    user.failed_attempts += 1
    secs = lock_seconds(user.failed_attempts)
    if secs:
        user.locked_until = now + timedelta(seconds=secs)


def register_success(user: User) -> None:
    user.failed_attempts = 0
    user.locked_until = None


class IPLimiter:
    """In-memory sliding window (single process); ponytail: Redis if we move to several workers.

    Each time the window is exceeded the key is blocked for 60 s, then 120 s, 240 s… (cap 1 h).
    The overrun counter is forgotten after 1 h without a new violation."""

    BASE_BLOCK, MAX_BLOCK, FORGET = 60, 3600, 3600

    def __init__(self, max_events: int = 20, window: float = 300):
        self.max, self.window = max_events, window
        self._events: dict[str, deque] = defaultdict(deque)
        self._blocked_until: dict[str, float] = {}
        self._violations: dict[str, int] = {}

    def retry_after(self, key: str, now: float | None = None) -> int:
        """Remaining blocking seconds (0 if not blocked)."""
        now = time.monotonic() if now is None else now
        return max(0, math.ceil(self._blocked_until.get(key, 0) - now))

    def hit(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        for k in [k for k, d in self._events.items() if not d or now - d[-1] > self.window]:
            del self._events[k]  # fully expired entries: avoids unbounded growth
        for k in [k for k, t in self._blocked_until.items() if now - t > self.FORGET]:
            del self._blocked_until[k]
            self._violations.pop(k, None)
        if self.retry_after(key, now):
            return False
        q = self._events[key]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.max:
            n = self._violations[key] = self._violations.get(key, 0) + 1
            self._blocked_until[key] = now + min(self.MAX_BLOCK, self.BASE_BLOCK * 2 ** (n - 1))
            q.clear()
            return False
        q.append(now)
        return True

    def reset(self) -> None:
        self._events.clear()
        self._blocked_until.clear()
        self._violations.clear()


class LoginFailures:
    """Password failures per (lowercase username, IP), in memory (single process).

    Same escalation as the account lock (lock_seconds) but never touching the account:
    an attacker cannot lock out the real user from another IP.
    An entry is forgotten after 1 h without failure; swept on every call to bound memory."""

    FORGET = 3600

    def __init__(self):
        self._state: dict[tuple[str, str], list[float]] = {}  # key -> [failures, locked until, last failure]

    @staticmethod
    def _key(username: str, ip: str) -> tuple[str, str]:
        return username.lower(), ip

    def _sweep(self, now: float) -> None:
        for k in [k for k, v in self._state.items() if now - v[2] > self.FORGET]:
            del self._state[k]

    def retry_after(self, username: str, ip: str, now: float | None = None) -> int:
        """Remaining lock seconds for this pair (0 = free)."""
        now = time.monotonic() if now is None else now
        self._sweep(now)
        st = self._state.get(self._key(username, ip))
        return max(0, math.ceil(st[1] - now)) if st else 0

    def register_failure(self, username: str, ip: str, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        self._sweep(now)
        st = self._state.setdefault(self._key(username, ip), [0, 0.0, now])
        st[0] += 1
        st[2] = now
        if secs := lock_seconds(int(st[0])):
            st[1] = now + secs

    def clear(self, username: str, ip: str) -> None:
        self._state.pop(self._key(username, ip), None)

    def reset(self) -> None:
        self._state.clear()
