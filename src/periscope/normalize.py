"""Normalisation tolérante : la doc BunkerWeb ne fige pas la forme des réponses.
Si l'API réelle diffère (cf. /openapi.json), n'ajuster que ce fichier + ses tests."""


def _pick(d: dict, *keys, default=None):
    for k in keys:
        if d.get(k) is not None:
            return d[k]
    return default


def _s(d: dict, *keys, default: str = "") -> str:
    """Champ identifiant : toujours un str (donc hashable), même si le nœud renvoie liste/dict/nombre."""
    v = _pick(d, *keys)
    return default if v is None else str(v)


def _items(payload, *keys) -> list[dict]:
    """Liste de dicts depuis [..], {"cle": [..]} ou {"cle": {nom: {..}}}."""
    if isinstance(payload, dict):
        found = next((payload[k] for k in keys if k in payload), None)
        if found is None:
            return []
        payload = found
    if isinstance(payload, dict):
        return [{"name": n, **v} if isinstance(v, dict) else {"name": n, "value": v}
                for n, v in payload.items()]
    if isinstance(payload, list):
        return [x if isinstance(x, dict) else {"name": str(x)} for x in payload]
    return []


def services(payload) -> list[dict]:
    return [
        {"name": str(_pick(i, "id", "name", "service", default="")),
         "draft": bool(_pick(i, "is_draft", "draft", default=False))}
        for i in _items(payload, "services")
    ]


def security_mode(payload) -> str | None:
    if isinstance(payload, dict):
        for k, v in payload.items():
            if str(k).upper().endswith("SECURITY_MODE"):
                return str(v.get("value") if isinstance(v, dict) else v).lower()
        for v in payload.values():
            if isinstance(v, dict) and (m := security_mode(v)):
                return m
    return None


def bans(payload) -> list[dict]:
    return [
        {"ip": _s(i, "ip", "name"),
         "reason": _s(i, "reason"),
         "service": _s(i, "service", default="global"),
         "exp": _pick(i, "exp", "ban_end", "expire"),
         "date": _pick(i, "date", "ban_start")}
        for i in _items(payload, "bans")
    ]


def jobs(payload) -> list[dict]:
    out = []
    for i in _items(payload, "jobs"):
        last_run = _pick(i, "last_run", "lastRun")
        success = _pick(i, "success", "last_success")
        history = i.get("history")
        if last_run is None and isinstance(history, list) and history and isinstance(history[-1], dict):
            h = history[-1]
            last_run = _pick(h, "end_date", "start_date")
            success = h.get("success") if success is None else success
        out.append({"name": _s(i, "name"), "plugin": _s(i, "plugin"),
                    "every": _s(i, "every"), "last_run": last_run, "success": success})
    return out


def plugins(payload) -> list[dict]:
    return [
        {"id": _s(i, "id", "name"), "name": _s(i, "name", "id"),
         "version": _s(i, "version"), "type": _s(i, "type")}
        for i in _items(payload, "plugins")
    ]
