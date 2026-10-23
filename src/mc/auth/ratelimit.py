import math
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
    """Fenêtre glissante en mémoire (un seul processus) ; ponytail: Redis si on passe à plusieurs workers.

    Chaque dépassement de la fenêtre bloque la clé 60 s, puis 120 s, 240 s… (plafond 1 h).
    Le compteur de dépassements est oublié après 1 h sans nouvelle violation."""

    BASE_BLOCK, MAX_BLOCK, FORGET = 60, 3600, 3600

    def __init__(self, max_events: int = 20, window: float = 300):
        self.max, self.window = max_events, window
        self._events: dict[str, deque] = defaultdict(deque)
        self._blocked_until: dict[str, float] = {}
        self._violations: dict[str, int] = {}

    def retry_after(self, key: str, now: float | None = None) -> int:
        """Secondes restantes de blocage (0 si non bloqué)."""
        now = time.monotonic() if now is None else now
        return max(0, math.ceil(self._blocked_until.get(key, 0) - now))

    def hit(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        for k in [k for k, d in self._events.items() if not d or now - d[-1] > self.window]:
            del self._events[k]  # entrées entièrement expirées : évite la croissance sans borne
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
    """Échecs de mot de passe par (identifiant en minuscules, IP), en mémoire (processus unique).

    Même escalade que le verrou de compte (lock_seconds) mais sans jamais toucher au compte :
    un attaquant ne peut pas verrouiller le vrai utilisateur depuis une autre IP.
    Une entrée est oubliée après 1 h sans échec ; balayage à chaque appel pour borner la mémoire."""

    FORGET = 3600

    def __init__(self):
        self._state: dict[tuple[str, str], list[float]] = {}  # clé -> [échecs, verrouillé jusqu'à, dernier échec]

    @staticmethod
    def _key(username: str, ip: str) -> tuple[str, str]:
        return username.lower(), ip

    def _sweep(self, now: float) -> None:
        for k in [k for k, v in self._state.items() if now - v[2] > self.FORGET]:
            del self._state[k]

    def retry_after(self, username: str, ip: str, now: float | None = None) -> int:
        """Secondes de verrouillage restantes pour cette paire (0 = libre)."""
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
