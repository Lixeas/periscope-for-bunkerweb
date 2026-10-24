import math
from datetime import datetime

from sqlalchemy.orm import Session

from periscope import diff
from periscope.config import get_settings
from periscope.models import CertProbe, Instance, Snapshot

CERT_ORDER = {"expired": 0, "none": 1, "red": 2, "orange": 3, "ok": 4}


def _by_instance(db: Session, kind: str) -> dict[str, list]:
    """{instance name: latest snapshot} for enabled instances that have a snapshot of this type."""
    names = {i.id: i.name for i in db.query(Instance).filter_by(enabled=True)}
    return {names[s.instance_id]: s.payload
            for s in db.query(Snapshot).filter_by(kind=kind) if s.instance_id in names}


def _node_view(n: dict) -> dict:
    return {"hostname": str(n.get("hostname", "")), "name": str(n.get("name", "")), "port": n.get("port"),
            "type": str(n.get("type", "")), "status": str(n.get("status", "")),
            "last_seen": diff._parse_ts(n.get("last_seen"))}


SEV_ORDER = {"crit": 0, "warn": 1, "ok": 2, "off": 3}


def _alerts(c: dict, certs: dict[str, int]) -> list[dict]:
    """Things to check on one instance, worst first. `code` is a stable key the template translates."""
    if not c["enabled"]:
        return []
    out = []
    if c["status"] == "down":
        out.append({"level": "crit", "code": "down"})
    node_alerts = [{"level": "crit" if n["status"] == "down" else "warn",
                    "code": "node_down" if n["status"] == "down" else "node_failover",
                    "name": n["name"] or n["hostname"]}
                   for n in c["nodes"] or [] if n["status"] in ("down", "failover")]
    out += node_alerts
    if c["status"] == "degraded" and not node_alerts:
        out.append({"level": "warn", "code": "degraded"})
    if c["stale"] and c["status"] != "down":
        out.append({"level": "warn", "code": "stale"})
    for key, level, code in (("expired", "crit", "cert_expired"), ("red", "crit", "cert_red"),
                             ("orange", "warn", "cert_orange")):
        if certs.get(key):
            out.append({"level": level, "code": code, "count": certs[key]})
    out.sort(key=lambda a: SEV_ORDER[a["level"]])
    return out


def instance_cards(db: Session, now: datetime) -> list[dict]:
    cfg = get_settings()
    snaps = {s.instance_id: s.payload for s in db.query(Snapshot).filter_by(kind="instances")}
    svc_snaps = {s.instance_id: s.payload for s in db.query(Snapshot).filter_by(kind="services")}
    cert_counts: dict[int, dict[str, int]] = {}
    for p in db.query(CertProbe):
        st = diff.cert_status(p.present, p.not_after, now)
        by = cert_counts.setdefault(p.instance_id, {})
        by[st] = by.get(st, 0) + 1
    cards = [
        {"role": "scheduler",
         # None = nodes never collected (unknown); [] = the scheduler declares none
         "nodes": None if i.id not in snaps else [_node_view(n) for n in snaps[i.id] if isinstance(n, dict)],
         "id": i.id, "name": i.name, "status": i.status, "version": i.version,
         "latency_ms": i.latency_ms, "last_ok_at": i.last_ok_at, "last_error": i.last_error,
         "enabled": i.enabled,
         "stale": diff.is_stale(i.last_ok_at, now, cfg.poll_interval, cfg.stale_cycles)}
        for i in db.query(Instance).order_by(Instance.name)
    ]
    for c in cards:
        c["nodes_total"] = len(c["nodes"] or [])
        c["nodes_up"] = sum(n["status"] == "up" for n in c["nodes"] or [])
        certs = cert_counts.get(c["id"], {})
        c["certs_total"] = sum(v for k, v in certs.items() if k != "none")  # certificates actually served
        c["certs_warn"] = sum(certs.get(k, 0) for k in ("expired", "red", "orange"))
        c["services_total"] = sum(1 for s in svc_snaps.get(c["id"]) or []
                                  if isinstance(s, dict) and not s.get("draft"))
        c["alerts"] = _alerts(c, certs)
        c["sev"] = ("off" if not c["enabled"] else c["alerts"][0]["level"] if c["alerts"] else "ok")
    # instances to check first
    cards.sort(key=lambda c: (SEV_ORDER[c["sev"]], c["name"]))
    return cards


def summary(db: Session, now: datetime) -> dict:
    all_cards = instance_cards(db, now)
    active = [c for c in all_cards if c["enabled"]]
    ips = {str(b.get("ip", "")) for payload in _by_instance(db, "bans").values() for b in payload}
    statuses = [diff.cert_status(p.present, p.not_after, now)
                for p, _ in db.query(CertProbe, Instance)
                .join(Instance, CertProbe.instance_id == Instance.id).filter(Instance.enabled.is_(True))]
    return {
        "services_diff": len({r["name"] for r in services(db)[0] if r["missing_on"]}),
        "instances_total": len(active),
        "instances_ok": sum(c["status"] == "ok" for c in active),
        "instances_stale": sum(c["stale"] for c in active),
        "nodes_total": sum(c["nodes_total"] for c in active),
        "nodes_up": sum(c["nodes_up"] for c in active),
        "services_total": sum(c["services_total"] for c in active),
        "certs_total": sum(c["certs_total"] for c in active),
        "alerts_total": sum(len(c["alerts"]) for c in active),
        "bans_active": len(ips),
        "certs_warn": sum(s in ("expired", "red", "orange") for s in statuses),
        "certs_none": statuses.count("none"),
    }


def services(db: Session, instance: str = "", mode: str = "", only_diff: bool = False) -> tuple[list[dict], list[str]]:
    per = _by_instance(db, "services")
    missing = diff.gaps({n: {str(s.get("name", "")) for s in p if not s.get("draft")} for n, p in per.items()})
    rows = [{"instance": n, "name": str(s.get("name", "")), "mode": s.get("mode"), "draft": bool(s.get("draft")),
             "missing_on": [] if s.get("draft") else missing.get(str(s.get("name", "")), [])}
            for n, p in per.items() for s in p]
    if instance:
        rows = [r for r in rows if r["instance"] == instance]
    if mode:
        rows = [r for r in rows if r["mode"] == mode]
    if only_diff:
        rows = [r for r in rows if r["missing_on"]]
    rows.sort(key=lambda r: (r["name"], r["instance"]))
    return rows, sorted(per)


PERMANENT_SORT = 10**12  # sort key of permanent bans: after any remaining duration


def _finite(v) -> bool:
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return True  # math.isfinite raises OverflowError beyond ~1e308
    return isinstance(v, float) and math.isfinite(v)


def _ban_row(b: dict, n: str, missing: dict) -> dict:
    exp = b.get("exp")
    permanent = bool(b.get("permanent")) or (_finite(exp) and exp == 0)
    exp_sort = PERMANENT_SORT if permanent else (min(exp, PERMANENT_SORT - 1) if _finite(exp) else 0)
    date = b.get("date")
    return {**b, "ip": str(b.get("ip", "")), "instance": n, "permanent": permanent, "exp_sort": exp_sort,
            "date_sort": date if _finite(date) else 0,
            "missing_on": missing.get(str(b.get("ip", "")), [])}


def bans(db: Session, q: str = "") -> list[dict]:
    per = _by_instance(db, "bans")
    missing = diff.gaps({n: {str(b.get("ip", "")) for b in p} for n, p in per.items()})
    rows = [_ban_row(b, n, missing) for n, p in per.items() for b in p]
    if q.strip():
        rows = [r for r in rows if q.strip() in str(r["ip"])]
    rows.sort(key=lambda r: (str(r["ip"]), r["instance"]))
    return rows


def jobs(db: Session) -> list[dict]:
    return [{**j, "instance": n, "next_run": diff.next_run(j.get("last_run"), j.get("every"))}
            for n, p in sorted(_by_instance(db, "jobs").items()) for j in p]


def plugins(db: Session) -> tuple[list[str], list[dict]]:
    per = _by_instance(db, "plugins")
    matrix = diff.plugin_matrix({n: {str(p.get("id", "")): str(p.get("version", "")) for p in pl} for n, pl in per.items()})
    return sorted(per), matrix


def certs(db: Session, now: datetime) -> list[dict]:
    rows = []
    q = (db.query(CertProbe, Instance).join(Instance, CertProbe.instance_id == Instance.id)
         .filter(Instance.enabled.is_(True)))
    for p, i in q:
        rows.append({
            "instance": i.name, "domain": p.domain, "present": p.present, "issuer": p.issuer,
            "letsencrypt": "let's encrypt" in p.issuer.lower(), "not_after": p.not_after,
            "days": diff.days_left(p.not_after, now), "error": p.error, "probed_at": p.probed_at,
            "status": diff.cert_status(p.present, p.not_after, now),
        })
    rows.sort(key=lambda r: (CERT_ORDER[r["status"]], r["days"] if r["days"] is not None else 10**9,
                             r["domain"], r["instance"]))
    return rows
