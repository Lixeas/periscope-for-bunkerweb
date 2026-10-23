from datetime import datetime

from sqlalchemy.orm import Session

from mc import diff
from mc.config import get_settings
from mc.models import CertProbe, Instance, Snapshot

CERT_ORDER = {"expired": 0, "none": 1, "red": 2, "orange": 3, "ok": 4}


def _by_instance(db: Session, kind: str) -> dict[str, list]:
    """{nom d'instance: dernier snapshot} pour les instances activées ayant un snapshot de ce type."""
    names = {i.id: i.name for i in db.query(Instance).filter_by(enabled=True)}
    return {names[s.instance_id]: s.payload
            for s in db.query(Snapshot).filter_by(kind=kind) if s.instance_id in names}


def instance_cards(db: Session, now: datetime) -> list[dict]:
    cfg = get_settings()
    return [
        {"id": i.id, "name": i.name, "status": i.status, "version": i.version,
         "latency_ms": i.latency_ms, "last_ok_at": i.last_ok_at, "last_error": i.last_error,
         "enabled": i.enabled,
         "stale": diff.is_stale(i.last_ok_at, now, cfg.poll_interval, cfg.stale_cycles)}
        for i in db.query(Instance).order_by(Instance.name)
    ]


def summary(db: Session, now: datetime) -> dict:
    active = [c for c in instance_cards(db, now) if c["enabled"]]
    ips = {b["ip"] for payload in _by_instance(db, "bans").values() for b in payload}
    statuses = [diff.cert_status(p.present, p.not_after, now)
                for p, _ in db.query(CertProbe, Instance)
                .join(Instance, CertProbe.instance_id == Instance.id).filter(Instance.enabled.is_(True))]
    return {
        "instances_total": len(active),
        "instances_ok": sum(c["status"] == "ok" for c in active),
        "instances_stale": sum(c["stale"] for c in active),
        "bans_active": len(ips),
        "certs_warn": sum(s in ("expired", "red", "orange") for s in statuses),
        "certs_none": statuses.count("none"),
    }


def services(db: Session, instance: str = "", mode: str = "") -> tuple[list[dict], list[str]]:
    per = _by_instance(db, "services")
    missing = diff.gaps({n: {s["name"] for s in p if not s.get("draft")} for n, p in per.items()})
    rows = [{"instance": n, "name": s["name"], "mode": s.get("mode"), "draft": bool(s.get("draft")),
             "missing_on": [] if s.get("draft") else missing.get(s["name"], [])}
            for n, p in per.items() for s in p]
    if instance:
        rows = [r for r in rows if r["instance"] == instance]
    if mode:
        rows = [r for r in rows if r["mode"] == mode]
    rows.sort(key=lambda r: (r["name"], r["instance"]))
    return rows, sorted(per)


def bans(db: Session, q: str = "") -> list[dict]:
    per = _by_instance(db, "bans")
    missing = diff.gaps({n: {b["ip"] for b in p} for n, p in per.items()})
    rows = [{**b, "instance": n, "missing_on": missing.get(b["ip"], [])} for n, p in per.items() for b in p]
    if q.strip():
        rows = [r for r in rows if q.strip() in str(r["ip"])]
    rows.sort(key=lambda r: (str(r["ip"]), r["instance"]))
    return rows


def jobs(db: Session) -> list[dict]:
    return [{**j, "instance": n, "next_run": diff.next_run(j.get("last_run"), j.get("every"))}
            for n, p in sorted(_by_instance(db, "jobs").items()) for j in p]


def plugins(db: Session) -> tuple[list[str], list[dict]]:
    per = _by_instance(db, "plugins")
    matrix = diff.plugin_matrix({n: {p["id"]: p.get("version", "") for p in pl} for n, pl in per.items()})
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
