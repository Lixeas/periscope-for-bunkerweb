import time
from urllib.parse import quote

import httpx

from periscope import normalize as N


class BWError(Exception):
    """kind : network | auth | http | data"""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


class BWClient:
    """Lecture seule : tout est lu par `_get` (GET). Seule autre requête émise : POST /auth,
    qui échange l'identifiant/mot de passe de l'utilisateur d'API contre un jeton Biscuit.
    Aucune méthode publique d'écriture n'existe. Ni mot de passe ni jeton dans les messages d'erreur."""

    def __init__(self, base_url: str, token: str | None = None, *,
                 credentials: tuple[str, str] | None = None, timeout: float = 5.0,
                 verify: bool = True, transport=None):
        if not token and not credentials:
            raise ValueError("token ou credentials requis")
        self._credentials = credentials
        self.token: str | None = token or None  # exposé pour que l'appelant le mette en cache
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

    async def _get(self, path: str, **params):
        params = params or None
        if self.token is None:
            await self._authenticate()
        r = await self._send(path, params)
        if r.status_code == 401 and self._credentials:
            # jeton expiré/révoqué : une seule ré-authentification, un seul nouvel essai
            self.token = None
            await self._authenticate()
            r = await self._send(path, params)
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
