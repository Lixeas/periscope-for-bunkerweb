"""Migrations and ORM against a real PostgreSQL. Skipped unless PERISCOPE_TEST_POSTGRES_URL is set
(CI does; locally: docker run --rm -e POSTGRES_PASSWORD=pw -p 5432:5432 postgres:16, then
PERISCOPE_TEST_POSTGRES_URL=postgresql://postgres:pw@localhost:5432/postgres). The database is wiped."""
import os
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text

from periscope import db as mcdb
from periscope import i18n
from periscope.config import Settings, get_settings
from periscope.db import migrate

RAW = os.environ.get("PERISCOPE_TEST_POSTGRES_URL", "")


def test_postgres_urls_use_the_psycopg_driver():
    for scheme in ("postgresql", "postgres"):
        assert Settings(secret_key="k", database_url=f"{scheme}://u:p@h/db").database_url == \
            "postgresql+psycopg://u:p@h/db"
    assert Settings(secret_key="k", database_url="postgresql+psycopg://u@h/db").database_url == \
        "postgresql+psycopg://u@h/db"
    assert Settings(secret_key="k", database_url="sqlite:///x.db").database_url == "sqlite:///x.db"


def test_psycopg_is_installed_with_the_postgres_extra():
    pytest.importorskip("psycopg")
    create_engine("postgresql+psycopg://u:p@localhost/db")  # resolves the dialect and driver


@pytest.fixture
def pg(monkeypatch):
    if not RAW:
        pytest.skip("PERISCOPE_TEST_POSTGRES_URL not set")
    url = Settings(secret_key="k", database_url=RAW).database_url
    eng = create_engine(url, isolation_level="AUTOCOMMIT")
    with eng.connect() as c:
        c.execute(text("DROP SCHEMA public CASCADE"))
        c.execute(text("CREATE SCHEMA public"))
    monkeypatch.setenv("PERISCOPE_DATABASE_URL", url)
    get_settings.cache_clear()
    yield url
    get_settings.cache_clear()
    mcdb._engine = None
    eng.dispose()


def test_migrations_build_the_models_schema(pg):
    migrate()
    with create_engine(pg).connect() as c:
        assert compare_metadata(MigrationContext.configure(c), mcdb.Base.metadata) == []


def test_migrate_0003_to_head_converts_token_instances(pg):
    cfg = Config()
    cfg.set_main_option("script_location", str(Path(mcdb.__file__).parent / "migrations"))
    cfg.set_main_option("sqlalchemy.url", pg.replace("%", "%%"))
    command.upgrade(cfg, "0003")
    eng = create_engine(pg)
    with eng.begin() as c:
        for name, mode, user in (("tok", "token", ""), ("usr", "user", "periscope")):
            c.execute(text(
                "INSERT INTO instances (name, base_url, token_enc, verify_tls, probe_host, tls_port, enabled, "
                "status, last_error, auth_mode, api_username, api_password_enc) VALUES "
                "(:n, 'http://h:8888', 'enc', true, '', 443, true, 'ok', '', :m, :u, :p)"),
                {"n": name, "m": mode, "u": user, "p": "pw" if user else ""})
    migrate()
    with eng.connect() as c:
        rows = {r.name: r for r in c.execute(text(
            "SELECT name, connection, enabled, status, last_error, api_username FROM instances"))}
    assert (rows["usr"].connection, rows["usr"].enabled, rows["usr"].api_username) == ("direct", True, "periscope")
    assert (rows["tok"].connection, rows["tok"].enabled, rows["tok"].status) == ("direct", False, "unknown")
    assert "no longer supported" in i18n.render("en", rows["tok"].last_error)
    assert {"tags", "instance_tags", "settings"} <= set(inspect(eng).get_table_names())


def test_orm_round_trip(pg):
    """Users, instances, JSON snapshots, binary credentials and tags work through the ORM."""
    from periscope.auth.users import create_user
    from periscope.models import Instance, Snapshot, User

    migrate()
    mcdb.init_engine(pg)
    with mcdb.session_scope() as s:
        create_user(s, "admin", "correct horse battery", "admin")
        inst = Instance(name="bw1", base_url="http://bw:8888")
        s.add(inst)
        s.flush()
        s.add(Snapshot(instance_id=inst.id, kind="services", payload=[{"id": "a.example", "é": 1}]))
    with mcdb.session_scope() as s:
        assert s.query(User).one().username == "admin"
        assert s.query(Snapshot).one().payload == [{"id": "a.example", "é": 1}]
        s.delete(s.query(Instance).one())  # ORM cascade
    with mcdb.session_scope() as s:
        assert s.query(Snapshot).count() == 0
