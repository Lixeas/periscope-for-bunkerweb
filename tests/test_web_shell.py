import pytest
from fastapi.testclient import TestClient

from mc.web.app import create_app


@pytest.fixture
def client(fresh_db):
    with TestClient(create_app(run_migrations=False)) as c:
        yield c


def test_unauthenticated_dashboard_redirects_to_login(client):
    r = client.get("/dashboard", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_security_headers_present(client):
    r = client.get("/dashboard", follow_redirects=False)
    csp = r.headers["content-security-policy"]
    assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp and "script-src 'self'" in csp
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["referrer-policy"] == "same-origin"


def test_static_assets_served_and_cacheable(client):
    r = client.get("/static/app.js")
    assert r.status_code == 200 and "no-store" not in r.headers.get("cache-control", "")


def test_foreign_origin_rejected_on_unsafe_methods(client):
    r = client.post("/login", headers={"origin": "https://evil.example"})
    assert r.status_code == 403
    r = client.post("/login", headers={"origin": "http://localhost:8000"})
    assert r.status_code != 403  # origine autorisée (la route n'existe pas encore : 404/405 attendu)


def test_docs_disabled(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
