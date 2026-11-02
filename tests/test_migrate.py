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


def test_migrate_0004_converts_instances_and_drops_token(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import text

    from periscope import db as mcdb
    from periscope import i18n
    url = f"sqlite:///{(tmp_path / 'm.db').as_posix()}"
    monkeypatch.setenv("PERISCOPE_DATABASE_URL", url)
    get_settings.cache_clear()
    try:
        cfg = Config()
        cfg.set_main_option("script_location", str(Path(mcdb.__file__).parent / "migrations"))
        cfg.set_main_option("sqlalchemy.url", url)
        command.upgrade(cfg, "0003")
        eng = create_engine(url)
        with eng.begin() as c:
            for name, mode, user in (("tok", "token", ""), ("usr", "user", "periscope")):
                c.execute(text(
                    "INSERT INTO instances (name, base_url, token_enc, verify_tls, probe_host, tls_port, enabled, "
                    "status, last_error, auth_mode, api_username, api_password_enc) VALUES "
                    "(:n, 'http://h:8888', 'enc', 1, '', 443, 1, 'ok', '', :m, :u, :p)"),
                    {"n": name, "m": mode, "u": user, "p": "pw" if user else ""})
        migrate()  # from 0003 to head
        insp = inspect(create_engine(url))
        cols = {c["name"] for c in insp.get_columns("instances")}
        assert {"connection", "agent_cert_fp", "agent_enroll_hash"} <= cols
        assert not {"auth_mode", "token_enc"} & cols
        assert {"tags", "instance_tags", "settings"} <= set(insp.get_table_names())
        with create_engine(url).connect() as c:
            rows = {r.name: r for r in c.execute(text(
                "SELECT name, connection, enabled, status, last_error, api_username FROM instances"))}
        assert (rows["usr"].connection, rows["usr"].enabled, rows["usr"].api_username) == ("direct", 1, "periscope")
        tok = rows["tok"]
        assert (tok.connection, tok.enabled, tok.status) == ("direct", 0, "unknown")
        assert "no longer supported" in i18n.render("en", tok.last_error)
    finally:
        get_settings.cache_clear()


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
