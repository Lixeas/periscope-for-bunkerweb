import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

from mc.models import User

LOCK_AFTER = 5


def lock_seconds(failures: int) -> int:
    """0 jusqu'à 4 échecs, puis 30 s doublant à chaque échec, plafonné à 15 min."""
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
    """Fenêtre glissante en mémoire (un seul processus) ; ponytail: Redis si on passe à plusieurs workers."""

    def __init__(self, max_events: int = 20, window: float = 300):
        self.max, self.window = max_events, window
        self._events: dict[str, deque] = defaultdict(deque)

    def hit(self, ip: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        q = self._events[ip]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.max:
            return False
        q.append(now)
        return True

    def reset(self) -> None:
        self._events.clear()
