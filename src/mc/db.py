from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import StaticPool

from mc.config import get_settings


class Base(DeclarativeBase):
    pass


_engine = None
_factory = None


def init_engine(url: str | None = None):
    global _engine, _factory
    url = url or get_settings().database_url
    kw = {}
    if url.startswith("sqlite"):
        kw["connect_args"] = {"check_same_thread": False}
        if url in ("sqlite://", "sqlite:///:memory:"):
            kw["poolclass"] = StaticPool
        else:
            Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
    _engine = create_engine(url, **kw)
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

    cfg = Config()
    cfg.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
    cfg.set_main_option("sqlalchemy.url", get_settings().database_url)
    command.upgrade(cfg, "head")
