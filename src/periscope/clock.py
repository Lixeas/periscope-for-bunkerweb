from datetime import UTC, datetime


def utcnow() -> datetime:
    """Naive UTC: SQLite does not keep the time zone, so stay consistent everywhere."""
    return datetime.now(UTC).replace(tzinfo=None)
