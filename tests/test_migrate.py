from sqlalchemy import create_engine, inspect

from mc.config import get_settings
from mc.db import migrate


def test_migrate_creates_tables(tmp_path, monkeypatch):
    url = f"sqlite:///{(tmp_path / 'm.db').as_posix()}"
    monkeypatch.setenv("MC_DATABASE_URL", url)
    get_settings.cache_clear()
    try:
        migrate()
        names = set(inspect(create_engine(url)).get_table_names())
    finally:
        get_settings.cache_clear()
    assert {"users", "credentials", "backup_codes", "sessions", "instances",
            "snapshots", "cert_probes", "audit_log"} <= names
