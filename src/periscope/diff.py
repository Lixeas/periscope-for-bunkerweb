from datetime import UTC, datetime, timedelta


def cert_status(present: bool, not_after: datetime | None, now: datetime,
                red_days: int = 7, orange_days: int = 21) -> str:
    """none | expired | red | orange | ok"""
    if not present or not_after is None:
        return "none"
    left = (not_after - now).total_seconds() / 86400
    if left < 0:
        return "expired"
    if left < red_days:
        return "red"
    if left < orange_days:
        return "orange"
    return "ok"


def days_left(not_after: datetime | None, now: datetime) -> int | None:
    return None if not_after is None else int((not_after - now).total_seconds() // 86400)


def gaps(per_instance: dict[str, set[str]]) -> dict[str, list[str]]:
    """élément -> instances qui ne l'ont pas ; seulement les éléments absents quelque part."""
    seen = set().union(*per_instance.values()) if per_instance else set()
    out = {}
    for item in seen:
        missing = sorted(n for n, items in per_instance.items() if item not in items)
        if missing:
            out[item] = missing
    return out


def plugin_matrix(per_instance: dict[str, dict[str, str]]) -> list[dict]:
    ids = sorted(set().union(*[set(v) for v in per_instance.values()])) if per_instance else []
    rows = []
    for pid in ids:
        cells = {n: v.get(pid) for n, v in per_instance.items()}
        versions = {c for c in cells.values() if c is not None}
        rows.append({"id": pid, "cells": cells, "diff": None in cells.values() or len(versions) > 1})
    return rows


def is_stale(last_ok_at: datetime | None, now: datetime, interval: int, cycles: int) -> bool:
    return last_ok_at is None or (now - last_ok_at) > timedelta(seconds=interval * cycles)


_EVERY = {"minute": timedelta(minutes=1), "hour": timedelta(hours=1),
          "day": timedelta(days=1), "week": timedelta(weeks=1)}


def _parse_ts(value) -> datetime | None:
    """Horodatage tolérant -> UTC naïf ; None si absent ou illisible."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, str):
        v = value.strip()
        if not v:
            return None
        try:
            value = float(v)
        except ValueError:
            try:
                d = datetime.fromisoformat(v)
                return d.astimezone(UTC).replace(tzinfo=None) if d.tzinfo else d
            except (ValueError, OverflowError, OSError):
                return None
    if isinstance(value, (int, float)):
        if value > 1e11:  # millisecondes
            value /= 1000
        try:
            return datetime.fromtimestamp(value, UTC).replace(tzinfo=None)
        except (OverflowError, OSError, ValueError):
            return None
    return None


def next_run(last_run, every) -> datetime | None:
    """Prochaine échéance estimée (naïf UTC) ; None pour 'once', fréquence inconnue ou dernière exécution illisible."""
    delta = _EVERY.get(every) if isinstance(every, str) else None
    last = _parse_ts(last_run)
    if delta is None or last is None:
        return None
    try:
        return last + delta
    except OverflowError:  # date proche de datetime.max
        return None
