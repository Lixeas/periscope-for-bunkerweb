import httpx
import pytest
import respx

from periscope.bw_client import BWClient, BWError

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


CREDS = ("periscope", "s3cret!")


@respx.mock
async def test_user_mode_authenticates_lazily_with_basic_and_sends_bearer():
    auth = respx.post(f"{BASE}/auth").respond(json={"status": "success", "token": "bisc1"})
    ping = respx.get(f"{BASE}/ping").respond(json={"version": "1"})
    c = BWClient(BASE, credentials=CREDS)
    assert not auth.called and c.token is None
    await c.ping()
    await c.ping()
    assert auth.call_count == 1
    import base64
    assert auth.calls[0].request.headers["authorization"] == "Basic " + base64.b64encode(b"periscope:s3cret!").decode()
    assert ping.calls[0].request.headers["authorization"] == "Bearer bisc1"
    assert c.token == "bisc1"


@respx.mock
async def test_user_mode_token_under_data_and_cached_initial_token():
    auth = respx.post(f"{BASE}/auth").respond(json={"data": {"token": "nested"}})
    ping = respx.get(f"{BASE}/ping").respond(json={})
    c = BWClient(BASE, credentials=CREDS)
    await c.ping()
    assert c.token == "nested"
    c2 = BWClient(BASE, token="cached", credentials=CREDS)
    await c2.ping()
    assert auth.call_count == 1  # le jeton en cache évite /auth
    assert ping.calls[-1].request.headers["authorization"] == "Bearer cached"


@respx.mock
async def test_user_mode_reauths_once_on_401_and_retries_once():
    auth = respx.post(f"{BASE}/auth").mock(side_effect=[
        httpx.Response(200, json={"token": "t1"}), httpx.Response(200, json={"token": "t2"})])
    bans = respx.get(f"{BASE}/bans").mock(side_effect=[
        httpx.Response(401), httpx.Response(200, json={"bans": []})])
    c = BWClient(BASE, credentials=CREDS)
    assert await c.bans() == []
    assert auth.call_count == 2 and bans.call_count == 2
    assert bans.calls[1].request.headers["authorization"] == "Bearer t2" and c.token == "t2"


@respx.mock
async def test_user_mode_second_401_is_auth_error_no_loop():
    auth = respx.post(f"{BASE}/auth").respond(json={"token": "t"})
    bans = respx.get(f"{BASE}/bans").respond(status_code=401)
    with pytest.raises(BWError) as e:
        await BWClient(BASE, credentials=CREDS).bans()
    assert e.value.kind == "auth" and auth.call_count == 2 and bans.call_count == 2


@respx.mock
@pytest.mark.parametrize("status", [401, 403])
async def test_auth_endpoint_refusal_is_auth_error_without_secrets(status):
    auth = respx.post(f"{BASE}/auth").respond(status_code=status)
    ping = respx.get(f"{BASE}/ping").respond(json={})
    c = BWClient(BASE, credentials=CREDS)
    with pytest.raises(BWError) as e:
        await c.ping()
    assert e.value.kind == "auth" and auth.call_count == 1 and not ping.called
    assert "s3cret" not in str(e.value)


@respx.mock
async def test_auth_response_without_token_is_data_error():
    respx.post(f"{BASE}/auth").respond(json={"status": "success"})
    with pytest.raises(BWError) as e:
        await BWClient(BASE, credentials=CREDS).ping()
    assert e.value.kind == "data"


@respx.mock
async def test_auth_network_error_kind():
    respx.post(f"{BASE}/auth").mock(side_effect=httpx.ConnectError("refused"))
    with pytest.raises(BWError) as e:
        await BWClient(BASE, credentials=CREDS).ping()
    assert e.value.kind == "network"


def test_constructor_requires_a_secret():
    with pytest.raises(ValueError):
        BWClient(BASE)


@respx.mock
async def test_client_is_read_only():
    """Seule requête non-GET autorisée : POST /auth (échange identifiants -> jeton)."""
    respx.post(f"{BASE}/auth").respond(json={"token": "t"})
    respx.route(method="GET").respond(json={"services": [], "bans": [], "jobs": {}, "plugins": []})
    other = respx.route(method__in=["POST", "PUT", "PATCH", "DELETE"], path__regex=r"^(?!/auth$).*")
    other.respond(500)
    for c in (BWClient(BASE, "t"), BWClient(BASE, credentials=CREDS)):
        for name in ("ping", "services", "bans", "jobs", "plugins"):
            await getattr(c, name)()
        assert not [m for m in dir(c) if not m.startswith("_") and m in
                    ("post", "put", "patch", "delete", "request", "send", "authenticate")]
        assert not any(hasattr(c, m) for m in ("post", "put", "patch", "delete"))
    assert not other.called
    assert all(call.request.method in ("GET", "POST") for call in respx.calls)
    assert all(call.request.url.path == "/auth" for call in respx.calls if call.request.method != "GET")
