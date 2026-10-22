from datetime import datetime, timezone


def utcnow() -> datetime:
    """UTC naïf : SQLite ne conserve pas le fuseau, on reste cohérent partout."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
