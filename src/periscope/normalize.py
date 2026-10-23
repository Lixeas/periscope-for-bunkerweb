"""Lenient normalization. The JSON shapes of the BunkerWeb API are undocumented: they were
derived from reading the BunkerWeb v1.6.17 SOURCE (routers/*.py, Database.py, api.lua, banlease.lua),
not captured from a live instance. The historical assumed shapes remain accepted.
If the real API differs, adjust only this file + its tests."""
import math

from periscope.diff import _parse_ts


def _pick(d: dict, *keys, default=None):
    for k in keys:
        if d.get(k) is not None:
            return d[k]
    return default


def _s(d: dict, *keys, default: str = "") -> str:
    """Identifier field: always a str (hence hashable), even if the node returns a list/dict/number."""
    v = _pick(d, *keys)
    return default if v is None else str(v)


def _items(payload, *keys) -> list[dict]:
    """List of dicts from [..], {"cle": [..]} ou {"cle": {nom: {..}}}."""
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


def service_items(payload) -> list[dict]:
    """Raw items of GET /services (in the same order as `services`)."""
    return _items(payload, "services")


def services(payload) -> list[dict]:
    out = []
    for i in service_items(payload):
        mode = _pick(i, "security_mode")
        out.append({"name": str(_pick(i, "id", "name", "service", default="")),
                    "draft": bool(_pick(i, "is_draft", "draft", default=False)),
                    "mode": None if mode is None else str(mode).lower()})
    return out


def security_mode(payload) -> str | None:
    if isinstance(payload, dict):
        for k, v in payload.items():
            if str(k).upper().endswith("SECURITY_MODE"):
                val = v.get("value") if isinstance(v, dict) else v
                return None if val is None else str(val).lower()
        for v in payload.values():
            if isinstance(v, dict) and (m := security_mode(v)):
                return m
    return None


def _num(v):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def _remaining(b: dict) -> float:
    """Comparable remaining duration: permanent = infinite, unknown = -1."""
    if b["permanent"]:
        return float("inf")
    n = _num(b["exp"])
    return -1.0 if n is None or math.isnan(n) else float(n)


def _ban_items(payload) -> list[dict]:
    if isinstance(payload, dict) and "bans" not in payload:
        # real shape: {"<nginx instance>": {"status", "msg", "data": [...]}, ...} (or error body)
        return [x for v in payload.values() if isinstance(v, dict) and isinstance(v.get("data"), list)
                for x in v["data"] if isinstance(x, dict)]
    return _items(payload, "bans")


def bans(payload) -> list[dict]:
    uniq: dict[tuple, dict] = {}
    for i in _ban_items(payload):
        exp = _pick(i, "exp", "ban_end", "expire")
        b = {"ip": _s(i, "ip", "name"),
             "reason": _s(i, "reason"),
             "service": _s(i, "service", default="global"),
             "ban_scope": _s(i, "ban_scope"),
             "date": _pick(i, "date", "ban_start"),
             "exp": exp,
             "permanent": bool(i.get("permanent")) or (_num(exp) == 0),
             "country": _s(i, "country"),
             "kind": _s(i, "kind")}
        key = (b["ip"], b["service"], b["ban_scope"], b["kind"])
        # the same ban is reported once per nginx instance: keep the longest
        if key not in uniq or _remaining(b) > _remaining(uniq[key]):
            uniq[key] = b
    return list(uniq.values())


def _latest(history) -> dict | None:
    """Most recent history entry (by end_date, without assuming order); failing a readable date,
    the last one in the list (old assumed order)."""
    entries = [h for h in history if isinstance(h, dict)] if isinstance(history, list) else []
    if not entries:
        return None
    dated = [(ts, h) for h in entries if (ts := _parse_ts(_pick(h, "end_date", "start_date"))) is not None]
    if not dated:
        return entries[-1]
    return max(dated, key=lambda t: t[0])[1]


def jobs(payload) -> list[dict]:
    out = []
    for i in _items(payload, "jobs"):
        last_run = _pick(i, "last_run", "lastRun")
        success = _pick(i, "success", "last_success")
        h = _latest(i.get("history"))
        if last_run is None and h is not None:
            last_run = _pick(h, "end_date", "start_date")
            success = h.get("success") if success is None else success
        out.append({"name": _s(i, "name"), "plugin": _s(i, "plugin_id", "plugin"),
                    "every": _s(i, "every"), "last_run": last_run, "success": success})
    return out


def plugins(payload) -> list[dict]:
    return [
        {"id": _s(i, "id", "name"), "name": _s(i, "name", "id"),
         "version": _s(i, "version"), "type": _s(i, "type")}
        for i in _items(payload, "plugins")
    ]


def nodes(payload) -> list[dict]:
    """Nginx nodes of a scheduler (GET /instances). An item with neither hostname nor name is ignored;
    an unknown status is kept as is (str, lowercase)."""
    out = []
    raw = payload.get("instances") if isinstance(payload, dict) else payload
    for i in raw if isinstance(raw, list) else []:
        if not isinstance(i, dict):
            continue
        host, name = _s(i, "hostname"), _s(i, "name")
        if not (host or name):
            continue
        seen = _pick(i, "last_seen")
        out.append({"hostname": host or name, "name": name or host, "port": _int(_pick(i, "port")),
                    "type": _s(i, "type"), "status": _s(i, "status").lower(), "method": _s(i, "method"),
                    "last_seen": seen if isinstance(seen, str) and seen else None,
                    "server_name": _s(i, "server_name")})
    return out


def _int(v):
    return v if isinstance(v, int) and not isinstance(v, bool) else None
