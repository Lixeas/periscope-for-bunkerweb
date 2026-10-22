from datetime import UTC, datetime


def utcnow() -> datetime:
    """UTC naïf : SQLite ne conserve pas le fuseau, on reste cohérent partout."""
    return datetime.now(UTC).replace(tzinfo=None)
