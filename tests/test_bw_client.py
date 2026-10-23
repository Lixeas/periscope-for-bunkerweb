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


# Shapes below: derived from the BunkerWeb v1.6.17 source, not captured from a live instance.

@respx.mock
async def test_ping_without_version_field():
    respx.get(f"{BASE}/ping").respond(json={"status": "ok", "message": "pong"})
    latency, version = await BWClient(BASE, "tok").ping()
    assert latency >= 0 and version is None


@respx.mock
async def test_services_mode_from_list_without_per_service_calls():
    respx.get(f"{BASE}/services").respond(json={"status": "success", "services": [
        {"id": "a.example", "method": "ui", "is_draft": False, "creation_date": "x", "last_update": "y",
         "template": None, "security_mode": "block"},
        {"id": "b.example", "method": "ui", "is_draft": True, "creation_date": "x", "last_update": "y",
         "template": None, "security_mode": "Detect"}]})
    out = await BWClient(BASE, "t").services()
    assert out == [{"name": "a.example", "draft": False, "mode": "block"},
                   {"name": "b.example", "draft": True, "mode": "detect"}]
    assert len(respx.calls) == 1  # aucun appel /services/{id}


@respx.mock
async def test_services_fallback_config_lookup_when_security_mode_absent_and_quote_names():
    respx.get(f"{BASE}/services").respond(json={"services": [
        {"id": "a.example"}, {"id": "b.example"}, {"id": "c d/e"}, {"id": "f.example", "security_mode": "block"}]})
    respx.get(f"{BASE}/services/a.example", params={"full": "true"}).respond(json={
        "status": "success", "service": "a.example",
        "config": {"SECURITY_MODE": {"value": "block", "global": False, "method": "ui", "default": "detect",
                                     "template": None}}})
    respx.get(f"{BASE}/services/b.example", params={"full": "true"}).respond(status_code=404)
    respx.get(f"{BASE}/services/c%20d%2Fe", params={"full": "true"}).respond(json={
        "config": {"SECURITY_MODE": "detect"}})
    out = await BWClient(BASE, "t").services()
    assert out == [{"name": "a.example", "draft": False, "mode": "block"},
                   {"name": "b.example", "draft": False, "mode": None},
                   {"name": "c d/e", "draft": False, "mode": "detect"},
                   {"name": "f.example", "draft": False, "mode": "block"}]


def _ban(**kw):
    return {"ip": "203.0.113.7", "reason": "antibot", "service": "www", "date": 1760000000, "country": "FR",
            "ban_scope": "service", "exp": 600, "permanent": False, "kind": "ban", "reason_data": {}, **kw}


@respx.mock
async def test_bans_per_instance_dict_aggregated_and_deduped():
    respx.get(f"{BASE}/bans").respond(json={
        "nginx-1": {"status": "success", "msg": "success", "data": [_ban(exp=100)]},
        "nginx-2": {"status": "success", "msg": "success", "data": [_ban(exp=500), _ban(ip="1.1.1.1")]}})
    out = await BWClient(BASE, "t").bans()
    assert [(b["ip"], b["exp"]) for b in out] == [("203.0.113.7", 500), ("1.1.1.1", 600)]


@respx.mock
async def test_bans_partial_failure_502_with_instance_dict_is_accepted():
    respx.get(f"{BASE}/bans").respond(status_code=502, json={
        "nginx-1": {"status": "success", "msg": "success", "data": [_ban()]},
        "nginx-2": {"status": "error", "msg": "timeout"}})
    out = await BWClient(BASE, "t").bans()
    assert [b["ip"] for b in out] == ["203.0.113.7"]


@respx.mock
async def test_bans_502_with_error_body_is_http_error():
    respx.get(f"{BASE}/bans").respond(status_code=502, json={"status": "error", "msg": "internal error"})
    with pytest.raises(BWError) as e:
        await BWClient(BASE, "t").bans()
    assert e.value.kind == "http"


@respx.mock
async def test_502_is_an_error_on_other_endpoints_and_other_statuses_rejected_on_bans():
    respx.get(f"{BASE}/jobs").respond(status_code=502, json={"n": {"status": "success", "data": []}})
    with pytest.raises(BWError) as e1:
        await BWClient(BASE, "t").jobs()
    respx.get(f"{BASE}/bans").respond(status_code=500, json={"n": {"status": "success", "data": []}})
    with pytest.raises(BWError) as e2:
        await BWClient(BASE, "t").bans()
    assert (e1.value.kind, e2.value.kind) == ("http", "http")


@respx.mock
async def test_jobs_real_dict_shape():
    respx.get(f"{BASE}/jobs").respond(json={"status": "success", "jobs": {
        "j1": {"plugin_id": "p", "every": "day", "reload": False, "async": False, "cache": [],
               "history": [{"start_date": "a", "end_date": "2026-10-22T03:00:05+00:00", "success": True}]}}})
    assert await BWClient(BASE, "t").jobs() == [
        {"name": "j1", "plugin": "p", "every": "day", "last_run": "2026-10-22T03:00:05+00:00", "success": True}]


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
    assert auth.call_count == 1  # the cached token avoids /auth
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
    """Only non-GET request allowed: POST /auth (credentials -> token exchange)."""
    respx.post(f"{BASE}/auth").respond(json={"token": "t"})
    respx.route(method="GET").respond(json={"services": [], "bans": [], "jobs": {}, "plugins": [], "instances": []})
    other = respx.route(method__in=["POST", "PUT", "PATCH", "DELETE"], path__regex=r"^(?!/auth$).*")
    other.respond(500)
    for c in (BWClient(BASE, "t"), BWClient(BASE, credentials=CREDS)):
        for name in ("ping", "version", "services", "bans", "jobs", "plugins", "instances"):
            await getattr(c, name)()
        assert not [m for m in dir(c) if not m.startswith("_") and m in
                    ("post", "put", "patch", "delete", "request", "send", "authenticate")]
        assert not any(hasattr(c, m) for m in ("post", "put", "patch", "delete"))
    assert not other.called
    assert all(call.request.method in ("GET", "POST") for call in respx.calls)
    assert all(call.request.url.path == "/auth" for call in respx.calls if call.request.method != "GET")


# --- version(): read from the public OpenAPI document (info.version) ---

@respx.mock
async def test_version_from_openapi_info():
    route = respx.get(f"{BASE}/openapi.json").respond(json={"info": {"title": "BunkerWeb API", "version": "1.6.17"}})
    assert await BWClient(BASE, "tok").version() == "1.6.17"
    assert route.called


@respx.mock
@pytest.mark.parametrize("kwargs", [
    {"status_code": 500}, {"status_code": 404}, {"text": "<html>"}, {"json": {}}, {"json": []},
    {"json": {"info": {}}}, {"json": {"info": "x"}}, {"json": {"info": {"version": 1}}},
    {"json": {"info": {"version": ""}}}, {"json": {"info": {"version": None}}},
])
async def test_version_none_on_any_problem(kwargs):
    respx.get(f"{BASE}/openapi.json").respond(**kwargs)
    assert await BWClient(BASE, "tok").version() is None


@respx.mock
async def test_version_none_on_network_error():
    respx.get(f"{BASE}/openapi.json").mock(side_effect=httpx.ConnectError("refused"))
    assert await BWClient(BASE, "tok").version() is None


@respx.mock
async def test_version_truncated_to_32():
    respx.get(f"{BASE}/openapi.json").respond(json={"info": {"version": "v" * 100}})
    assert await BWClient(BASE, "tok").version() == "v" * 32


@respx.mock
async def test_version_none_when_document_too_large():
    big = b'{"info":{"version":"1"},"pad":"' + b"x" * (5 * 1024 * 1024 + 10) + b'"}'
    respx.get(f"{BASE}/openapi.json").respond(content=big)
    assert await BWClient(BASE, "tok").version() is None


@respx.mock
async def test_version_under_root_path_prefix():
    route = respx.get("http://bw:8888/bwapi/openapi.json").respond(json={"info": {"version": "1.6.17"}})
    assert await BWClient("http://bw:8888/bwapi", "tok").version() == "1.6.17"
    assert route.called


@respx.mock
async def test_version_sends_no_auth_and_no_auth_roundtrip():
    auth = respx.post(f"{BASE}/auth").respond(json={"token": "t"})
    route = respx.get(f"{BASE}/openapi.json").respond(json={"info": {"version": "1.6.17"}})
    assert await BWClient(BASE, credentials=CREDS).version() == "1.6.17"
    assert not auth.called
    assert "authorization" not in route.calls[0].request.headers


# --- version(): first the `version` fact of the Biscuit token, no network request ---

def _biscuit(symbols):
    import base64
    block = b"".join(b"\x0a" + bytes([len(s)]) + s.encode() for s in symbols)
    signed = b"\x0a" + bytes([len(block)]) + block
    return base64.urlsafe_b64encode(b"\x12" + bytes([len(signed)]) + signed).decode().rstrip("=")


@respx.mock
async def test_version_from_token_makes_no_request():
    openapi = respx.get(f"{BASE}/openapi.json").respond(json={"info": {"version": "9.9.9"}})
    client = BWClient(BASE, credentials=CREDS)
    client.token = _biscuit(["periscope", "10.0.0.1", "1.6.17", "api_user"])
    assert await client.version() == "1.6.17"
    assert not openapi.called and not respx.calls


@respx.mock
async def test_version_token_without_version_falls_back_to_openapi():
    route = respx.get(f"{BASE}/openapi.json").respond(json={"info": {"version": "1.6.18"}})
    assert await BWClient(BASE, _biscuit(["periscope", "10.0.0.1"])).version() == "1.6.18"
    assert route.called


@respx.mock
async def test_version_static_token_falls_back_to_openapi():
    route = respx.get(f"{BASE}/openapi.json").respond(json={"info": {"version": "1.6.17"}})
    assert await BWClient(BASE, "static-api-token").version() == "1.6.17"
    assert route.called and "authorization" not in route.calls[0].request.headers


@respx.mock
async def test_instances_nodes_from_real_shape():
    respx.get(f"{BASE}/instances").respond(json={"status": "success", "instances": [
        {"hostname": "w1", "name": "worker1", "port": 5000, "type": "static", "status": "up",
         "method": "scheduler", "server_name": "bwapi", "last_seen": "2026-10-22T10:00:00+00:00"}]})
    out = await BWClient(BASE, "t").instances()
    assert out[0]["hostname"] == "w1" and out[0]["status"] == "up"
