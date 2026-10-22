import time
from urllib.parse import quote

import httpx

from mc import normalize as N


class BWError(Exception):
    """kind : network | auth | http | data"""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


class BWClient:
    """Lecture seule par construction : seul GET est émis, aucune méthode d'écriture n'existe."""

    def __init__(self, base_url: str, token: str, *, timeout: float = 5.0,
                 verify: bool = True, transport=None):
        self._http = httpx.AsyncClient(
            base_url=base_url.rstrip("/"), headers={"Authorization": f"Bearer {token}"},
            timeout=timeout, verify=verify, transport=transport)

    async def _get(self, path: str, **params):
        try:
            r = await self._http.get(path, params=params or None)
        except httpx.TimeoutException as e:
            raise BWError("network", f"timeout on {path}") from e
        except httpx.HTTPError as e:
            raise BWError("network", f"{type(e).__name__}: {e}") from e
        if r.status_code in (401, 403):
            raise BWError("auth", f"HTTP {r.status_code} on {path}")
        if r.status_code >= 400:
            raise BWError("http", f"HTTP {r.status_code} on {path}")
        try:
            return r.json()
        except ValueError as e:
            raise BWError("data", f"invalid JSON on {path}") from e

    async def ping(self) -> tuple[float, str | None]:
        t = time.perf_counter()
        data = await self._get("/ping")
        version = data.get("version") if isinstance(data, dict) else None
        return (time.perf_counter() - t) * 1000, version

    async def services(self) -> list[dict]:
        items = N.services(await self._get("/services"))
        for s in items:  # ponytail: N+1 requêtes, acceptable pour <= 10 instances
            try:
                s["mode"] = N.security_mode(await self._get(f"/services/{quote(s['name'], safe='')}", full="true"))
            except BWError:
                s["mode"] = None
        return items

    async def bans(self) -> list[dict]:
        return N.bans(await self._get("/bans"))

    async def jobs(self) -> list[dict]:
        return N.jobs(await self._get("/jobs"))

    async def plugins(self) -> list[dict]:
        return N.plugins(await self._get("/plugins"))

    async def aclose(self) -> None:
        await self._http.aclose()
