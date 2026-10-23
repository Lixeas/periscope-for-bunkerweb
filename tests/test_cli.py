import getpass

from periscope import cli
from periscope.db import session_scope
from periscope.models import User


def fake_migrate(monkeypatch):
    monkeypatch.setattr(cli, "migrate", lambda: None)


def test_bootstrap_admin_creates_admin_without_second_factor(fresh_db, monkeypatch):
    fake_migrate(monkeypatch)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "correct horse battery")
    assert cli.main(["bootstrap-admin", "--username", "root"]) == 0
    with session_scope() as s:
        u = s.query(User).one()
        assert (u.username, u.role, u.totp_confirmed) == ("root", "admin", False)


def test_bootstrap_admin_rejects_mismatch_and_duplicates(fresh_db, monkeypatch, capsys):
    fake_migrate(monkeypatch)
    answers = iter(["correct horse battery", "something else entirely"])
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(answers))
    assert cli.main(["bootstrap-admin", "--username", "root"]) == 1
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "correct horse battery")
    assert cli.main(["bootstrap-admin", "--username", "root"]) == 0
    assert cli.main(["bootstrap-admin", "--username", "root"]) == 1
    assert "already exists" in capsys.readouterr().err
