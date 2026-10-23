from pathlib import Path

from sqlalchemy import create_engine, inspect

from periscope.config import get_settings
from periscope.db import migrate


def test_migrate_creates_tables(tmp_path, monkeypatch):
    url = f"sqlite:///{(tmp_path / 'm.db').as_posix()}"
    monkeypatch.setenv("PERISCOPE_DATABASE_URL", url)
    get_settings.cache_clear()
    try:
        migrate()
        names = set(inspect(create_engine(url)).get_table_names())
    finally:
        get_settings.cache_clear()
    assert {"users", "credentials", "backup_codes", "sessions", "instances",
            "snapshots", "cert_probes", "audit_log"} <= names


def test_migrate_creates_parent_dir_and_engine_sets_pragmas(tmp_path, monkeypatch):
    from periscope import db as mcdb
    url = f"sqlite:///{(tmp_path / 'sub' / 'd' / 'm.db').as_posix()}"
    monkeypatch.setenv("PERISCOPE_DATABASE_URL", url)
    get_settings.cache_clear()
    try:
        migrate()
        eng = mcdb.init_engine(url)
        with eng.connect() as c:
            assert c.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
            assert c.exec_driver_sql("PRAGMA journal_mode").scalar() == "wal"
        eng.dispose()
    finally:
        get_settings.cache_clear()


def test_migrate_adds_api_user_columns_with_defaults(tmp_path, monkeypatch):
    url = f"sqlite:///{(tmp_path / 'm.db').as_posix()}"
    monkeypatch.setenv("PERISCOPE_DATABASE_URL", url)
    get_settings.cache_clear()
    try:
        migrate()
        cols = {c["name"]: c for c in inspect(create_engine(url)).get_columns("instances")}
    finally:
        get_settings.cache_clear()
    assert {"auth_mode", "api_username", "api_password_enc"} <= set(cols)
    assert "token" in str(cols["auth_mode"]["default"])


def test_migrate_adds_nullable_user_lang_and_existing_users_get_null(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import text

    from periscope import db as mcdb
    url = f"sqlite:///{(tmp_path / 'm.db').as_posix()}"
    monkeypatch.setenv("PERISCOPE_DATABASE_URL", url)
    get_settings.cache_clear()
    try:
        cfg = Config()
        cfg.set_main_option("script_location", str(Path(mcdb.__file__).parent / "migrations"))
        cfg.set_main_option("sqlalchemy.url", url)
        command.upgrade(cfg, "0002")
        eng = create_engine(url)
        with eng.begin() as c:
            c.execute(text("INSERT INTO users (username, password_hash, role, totp_confirmed, totp_last_step, "
                           "failed_attempts, created_at) VALUES ('old', 'x', 'reader', 0, 0, 0, '2026-01-01')"))
        assert "lang" not in {c["name"] for c in inspect(eng).get_columns("users")}
        migrate()  # from 0002 to head
        cols = {c["name"]: c for c in inspect(create_engine(url)).get_columns("users")}
        assert cols["lang"]["nullable"] is True
        with create_engine(url).connect() as c:
            assert c.execute(text("SELECT lang FROM users WHERE username='old'")).scalar() is None
    finally:
        get_settings.cache_clear()
