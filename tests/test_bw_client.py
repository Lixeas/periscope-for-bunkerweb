import httpx
import pytest
import respx

from mc.bw_client import BWClient, BWError

BASE = "http://bw:8888"


@respx.mock
async def test_ping_returns_latency_and_version():
    respx.get(f"{BASE}/ping").respond(json={"status": "success", "version": "1.6.0"})
    latency, version = await BWClient(BASE, "tok").ping()
    assert latency >= 0 and version == "1.6.0"


@respx.mock
async def test_bearer_header_sent():
    route = respx.get(f"{BASE}/ping").respond(json={})
    await BWClient(BASE, "tok").ping()
    assert route.calls[0].request.headers["authorization"] == "Bearer tok"


@respx.mock
async def test_auth_error_kind():
    respx.get(f"{BASE}/bans").respond(status_code=401)
    with pytest.raises(BWError) as e:
        await BWClient(BASE, "bad").bans()
    assert e.value.kind == "auth"


@respx.mock
async def test_network_error_kind():
    respx.get(f"{BASE}/ping").mock(side_effect=httpx.ConnectError("refused"))
    with pytest.raises(BWError) as e:
        await BWClient(BASE, "t").ping()
    assert e.value.kind == "network"


@respx.mock
async def test_http_and_data_error_kinds():
    respx.get(f"{BASE}/jobs").respond(status_code=500)
    respx.get(f"{BASE}/plugins").respond(text="<html>")
    with pytest.raises(BWError) as e1:
        await BWClient(BASE, "t").jobs()
    with pytest.raises(BWError) as e2:
        await BWClient(BASE, "t").plugins()
    assert (e1.value.kind, e2.value.kind) == ("http", "data")


@respx.mock
async def test_services_include_mode_and_quote_names():
    respx.get(f"{BASE}/services").respond(json={"services": [{"id": "a.example"}, {"id": "b.example"}]})
    respx.get(f"{BASE}/services/a.example", params={"full": "true"}).respond(json={"SECURITY_MODE": "block"})
    respx.get(f"{BASE}/services/b.example", params={"full": "true"}).respond(status_code=404)
    out = await BWClient(BASE, "t").services()
    assert out == [{"name": "a.example", "draft": False, "mode": "block"},
                   {"name": "b.example", "draft": False, "mode": None}]


def test_client_is_read_only():
    c = BWClient(BASE, "t")
    assert not any(hasattr(c, m) for m in ("post", "put", "patch", "delete"))
