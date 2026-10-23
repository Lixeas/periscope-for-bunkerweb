import pytest

from tests.helpers import login_as, make_client
from tests.test_queries import seed


@pytest.fixture
def client(fresh_db):
    seed()
    with make_client() as c:
        login_as(c, "bob", "reader")
        yield c


def test_dashboard_shows_tiles_and_instance_cards(client):
    r = client.get("/dashboard")
    assert r.status_code == 200
    assert 'data-summary="instances_ok"' in r.text and "bw1" in r.text and "bw2" in r.text
    assert "Injoignable" in r.text and "network: timeout" in r.text
    assert "Désactivée" in r.text  # bw3


def test_api_summary_json(client):
    r = client.get("/api/summary")
    assert r.status_code == 200
    assert r.json()["bans_active"] == 2 and r.json()["instances_total"] == 2


def test_api_summary_requires_login(fresh_db):
    with make_client() as c:
        assert c.get("/api/summary", follow_redirects=False).status_code == 303


def test_services_page_with_gap_and_filter(client):
    r = client.get("/services")
    assert "y.example" in r.text and "absent sur : bw2" in r.text
    r = client.get("/services", params={"mode": "block"})
    assert "y.example" not in r.text and "x.example" in r.text


def test_bans_page_search(client):
    assert "2.2.2.2" in client.get("/bans").text
    r = client.get("/bans", params={"q": "2.2"})
    assert "2.2.2.2" in r.text and "1.1.1.1" not in r.text


def test_jobs_page_has_matrix_and_job(client):
    r = client.get("/jobs")
    assert "renew" in r.text and "antibot" in r.text and "1.1" in r.text
    assert "Prochaine échéance (estimée)" in r.text
    assert "02/01/2020 00:00 UTC" in r.text and "en retard" in r.text


def test_certificates_page_status_labels(client):
    r = client.get("/certificates")
    assert "Critique" in r.text and "Aucun" in r.text and "Valide" in r.text and "Let's Encrypt" in r.text


def test_bans_jobs_plugins_render_with_hostile_snapshot_values(client):
    from mc.db import session_scope
    from mc.models import Instance, Snapshot
    bad = [["x"], {"a": 1}, None, 5]
    with session_scope() as s:
        inst = s.query(Instance).filter_by(name="bw1").one()
        for kind, rows in {
            "bans": [{"ip": v, "reason": v, "service": v, "exp": v, "date": v} for v in bad],
            "jobs": [{"name": v, "plugin": v, "every": v, "last_run": v, "success": v} for v in bad],
            "plugins": [{"id": v, "name": v, "version": v, "type": v} for v in bad],
            "services": [{"name": v, "draft": False, "mode": v} for v in bad],
        }.items():
            snap = s.query(Snapshot).filter_by(instance_id=inst.id, kind=kind).one()
            snap.payload = rows
    for path in ("/bans", "/jobs", "/services", "/dashboard", "/api/summary"):
        assert client.get(path).status_code == 200, path
    assert client.get("/bans", params={"q": "x"}).status_code == 200
