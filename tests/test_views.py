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


def test_bans_page_renders_duration_permanent_and_epoch_date(client):
    t = client.get("/bans").text
    assert "09/10/2025 08:53 UTC" in t                   # date epoch -> datetime
    assert "1 min" in t and "30 s" in t                   # secondes restantes -> durée lisible
    assert "Permanent" in t                               # exp 0 / permanent
    assert 'data-v="1000000000000"' in t and 'data-v="60"' in t  # tri numérique, permanent en dernier
    assert "CrowdSec" in t and "service" in t             # badge crowdsec_lease + ban_scope
    assert "Durée restante renvoyée par BunkerWeb ; « Permanent » si le ban n'expire pas." in t
    assert "telle que renvoyée" not in t


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
    from periscope.db import session_scope
    from periscope.models import Instance, Snapshot
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


def test_bans_page_hostile_expiration_and_date_values(client):
    from periscope.db import session_scope
    from periscope.models import Instance, Snapshot
    with session_scope() as s:
        inst = s.query(Instance).filter_by(name="bw1").one()
        snap = s.query(Snapshot).filter_by(instance_id=inst.id, kind="bans").one()
        snap.payload = [{"ip": "6.6.6.6", "exp": 10**30, "date": 10**30, "permanent": ["x"], "kind": {"a": 1}},
                        {"ip": "6.6.6.7", "exp": "soon", "date": "yesterday", "ban_scope": ["y"]},
                        {"ip": "6.6.6.8", "exp": -5, "date": -10**30}]
    r = client.get("/bans")
    assert r.status_code == 200 and "6.6.6.6" in r.text and "6.6.6.8" in r.text


def test_jobs_page_with_iso_offset_last_run_and_services_mode(client):
    """last_run ISO avec décalage (forme dérivée du source BunkerWeb v1.6.17, non capturée en live)."""
    from periscope.db import session_scope
    from periscope.models import Instance, Snapshot
    with session_scope() as s:
        inst = s.query(Instance).filter_by(name="bw1").one()
        snap = s.query(Snapshot).filter_by(instance_id=inst.id, kind="jobs").one()
        snap.payload = [{"name": "j", "plugin": "p", "every": "day",
                         "last_run": "2020-05-01T03:00:00+02:00", "success": False}]
    t = client.get("/jobs").text
    assert "02/05/2020 01:00 UTC" in t and "Échec" in t and "en retard" in t


def test_dashboard_lists_scheduler_and_worker_nodes(client):
    t = client.get("/dashboard").text
    assert t.count(">scheduler<") == 3 and ">worker<" in t
    assert "1/2 en ligne" in t and "w1.lan:5000" in t and "w2.lan:5000" in t
    assert "En ligne" in t and "Hors ligne" in t  # libellé texte, pas seulement la couleur
    assert "<script>x</script>" not in t and "&lt;script&gt;x&lt;/script&gt;" in t
    assert "inconnus" in t  # bw2 : jamais collecté
