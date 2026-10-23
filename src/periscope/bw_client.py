import json
import time
from urllib.parse import quote

import httpx

from periscope import normalize as N
from periscope.biscuit_version import version_from_token

_OPENAPI_MAX_BYTES = 5 * 1024 * 1024


class BWError(Exception):
    """kind : network | auth | http | data"""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


class BWClient:
    """Read-only: everything is read through `_get` (GET). The only other request sent is POST /auth,
    which exchanges the API user's username/password for a Biscuit token.
    No public write method exists. Neither password nor token in error messages."""

    def __init__(self, base_url: str, token: str | None = None, *,
                 credentials: tuple[str, str] | None = None, timeout: float = 5.0,
                 verify: bool = True, transport=None):
        if not token and not credentials:
            raise ValueError("token ou credentials requis")
        self._credentials = credentials
        self.token: str | None = token or None  # exposed so the caller can cache it
        self._http = httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=timeout,
                                       verify=verify, transport=transport)

    async def _authenticate(self) -> None:
        assert self._credentials
        try:
            r = await self._http.post("/auth", auth=self._credentials)
        except httpx.TimeoutException as e:
            raise BWError("network", "timeout on /auth") from e
        except httpx.HTTPError as e:
            raise BWError("network", f"{type(e).__name__} on /auth") from e
        if r.status_code in (401, 403):
            raise BWError("auth", f"HTTP {r.status_code} on /auth (identifiants refusés)")
        if r.status_code >= 400:
            raise BWError("http", f"HTTP {r.status_code} on /auth")
        try:
            body = r.json()
        except ValueError as e:
            raise BWError("data", "invalid JSON on /auth") from e
        data = body.get("data") if isinstance(body, dict) else None
        token = body.get("token") if isinstance(body, dict) else None
        if not token and isinstance(data, dict):
            token = data.get("token")
        if not isinstance(token, str) or not token:
            raise BWError("data", "no token in /auth response")
        self.token = token

    async def _send(self, path: str, params):
        try:
            return await self._http.get(path, params=params,
                                        headers={"Authorization": f"Bearer {self.token}"})
        except httpx.TimeoutException as e:
            raise BWError("network", f"timeout on {path}") from e
        except httpx.HTTPError as e:
            raise BWError("network", f"{type(e).__name__}: {e}") from e

    async def _get(self, path: str, *, ok_statuses: tuple[int, ...] = (200,), **params):
        return (await self._get_status(path, ok_statuses, params))[1]

    async def _get_status(self, path: str, ok_statuses: tuple[int, ...], params: dict):
        params = params or None
        if self.token is None:
            await self._authenticate()
        r = await self._send(path, params)
        if r.status_code == 401 and self._credentials:
            # expired/revoked token: a single re-authentication, a single retry
            self.token = None
            await self._authenticate()
            r = await self._send(path, params)
        if r.status_code in (401, 403):
            raise BWError("auth", f"HTTP {r.status_code} on {path}")
        if r.status_code not in ok_statuses:
            raise BWError("http", f"HTTP {r.status_code} on {path}")
        try:
            return r.status_code, r.json()
        except ValueError as e:
            raise BWError("data", f"invalid JSON on {path}") from e

    async def ping(self) -> tuple[float, str | None]:
        t = time.perf_counter()
        data = await self._get("/ping")
        version = data.get("version") if isinstance(data, dict) else None
        return (time.perf_counter() - t) * 1000, version

    async def version(self) -> str | None:
        """Version: first the `version` fact of the held Biscuit token (local read, no request),
        otherwise `info.version` of the OpenAPI document (GET /openapi.json, public: no token, so no
        /auth round trip). Never raises: any problem returns None."""
        if self.token and (from_token := version_from_token(self.token)):
            return from_token
        try:
            async with self._http.stream("GET", "/openapi.json") as r:
                if r.status_code != 200:
                    return None
                declared = r.headers.get("content-length", "")
                if declared.isdigit() and int(declared) > _OPENAPI_MAX_BYTES:
                    return None
                body = bytearray()
                async for chunk in r.aiter_bytes():
                    body += chunk
                    if len(body) > _OPENAPI_MAX_BYTES:
                        return None
            info = json.loads(bytes(body)).get("info")
            version = info.get("version") if isinstance(info, dict) else None
        except (httpx.HTTPError, ValueError, AttributeError):
            return None
        return version[:32] if isinstance(version, str) and version else None

    async def services(self) -> list[dict]:
        payload = await self._get("/services")
        items = N.services(payload)
        for s, raw in zip(items, N.service_items(payload), strict=True):
            if "security_mode" in raw:  # the mode is provided by the list (BunkerWeb falls back to the global one)
                continue
            try:  # older versions: one request per service
                s["mode"] = N.security_mode(await self._get(f"/services/{quote(s['name'], safe='')}", full="true"))
            except BWError:
                s["mode"] = None
        return items

    async def bans(self) -> list[dict]:
        # 502 = at least one nginx instance failed; the body is still the per-instance dict (partial response)
        status, body = await self._get_status("/bans", (200, 502), {})
        if status == 502 and not (isinstance(body, dict) and any(isinstance(v, dict) for v in body.values())):
            raise BWError("http", "HTTP 502 on /bans")
        return N.bans(body)

    async def jobs(self) -> list[dict]:
        return N.jobs(await self._get("/jobs"))

    async def plugins(self) -> list[dict]:
        return N.plugins(await self._get("/plugins"))

    async def instances(self) -> list[dict]:
        """Nginx nodes managed by this scheduler (GET /instances, instances_read permission)."""
        return N.nodes(await self._get("/instances"))

    async def aclose(self) -> None:
        await self._http.aclose()
