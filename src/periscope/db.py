from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import StaticPool

from periscope.config import get_settings


class Base(DeclarativeBase):
    pass


_engine = None
_factory = None


def _ensure_sqlite_dir(url: str) -> None:
    if url.startswith("sqlite:///") and url not in ("sqlite://", "sqlite:///:memory:"):
        Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)


def init_engine(url: str | None = None):
    global _engine, _factory
    url = url or get_settings().database_url
    kw = {}
    if url.startswith("sqlite"):
        kw["connect_args"] = {"check_same_thread": False}
        if url in ("sqlite://", "sqlite:///:memory:"):
            kw["poolclass"] = StaticPool
    mem = url in ("sqlite://", "sqlite:///:memory:")
    if url.startswith("sqlite") and not mem:
        _ensure_sqlite_dir(url)
    _engine = create_engine(url, **kw)
    if url.startswith("sqlite"):
        @event.listens_for(_engine, "connect")
        def _pragmas(dbapi_conn, _record):
            cur = dbapi_conn.cursor()
            if not mem:
                cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA busy_timeout=3000")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()
    _factory = sessionmaker(_engine, expire_on_commit=False)
    return _engine


def engine():
    return _engine or init_engine()


@contextmanager
def session_scope():
    engine()
    s = _factory()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def get_db():
    """Dépendance FastAPI."""
    with session_scope() as s:
        yield s


def migrate() -> None:
    from alembic import command
    from alembic.config import Config

    _ensure_sqlite_dir(get_settings().database_url)
    cfg = Config()
    cfg.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
    cfg.set_main_option("sqlalchemy.url", get_settings().database_url)
    command.upgrade(cfg, "head")
