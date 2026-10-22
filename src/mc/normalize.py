"""Normalisation tolérante : la doc BunkerWeb ne fige pas la forme des réponses.
Si l'API réelle diffère (cf. /openapi.json), n'ajuster que ce fichier + ses tests."""


def _pick(d: dict, *keys, default=None):
    for k in keys:
        if d.get(k) is not None:
            return d[k]
    return default


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
        {"ip": _pick(i, "ip", "name", default=""),
         "reason": _pick(i, "reason", default=""),
         "service": _pick(i, "service", default="global"),
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
        out.append({"name": _pick(i, "name", default=""), "plugin": _pick(i, "plugin", default=""),
                    "every": _pick(i, "every", default=""), "last_run": last_run, "success": success})
    return out


def plugins(payload) -> list[dict]:
    return [
        {"id": _pick(i, "id", "name", default=""), "name": _pick(i, "name", "id", default=""),
         "version": _pick(i, "version", default=""), "type": _pick(i, "type", default="")}
        for i in _items(payload, "plugins")
    ]
