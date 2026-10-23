> Note: this document is historical. The project was called "BunkerWeb Mission Control"; it has since been renamed "Periscope for BunkerWeb" (package `periscope`, prefix `PERISCOPE_`). The names below are the original ones.

# BunkerWeb Mission Control — Plan 3/3: Views, administration, delivery

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The 5 monitoring views (health, services, bans, jobs/plugins, certificates), administration (instances, users, audit), the JSON refresh API, and delivery (Docker, README, AGPLv3 license, CI, fake BunkerWeb demo server, validation against a real instance).

**Architecture:** `mc.queries` computes the view models from the database (pure functions over the session, testable). The `routes_views` and `routes_admin` routes are thin. Tables are sorted/filtered in the browser (`table.js`); the home page refreshes via `/api/summary` (`refresh.js`), the other pages via `<meta refresh>`.

**Tech Stack:** FastAPI, Jinja2, Bootstrap (local CSS), dependency-free vanilla JS.

**Prerequisites:** Plans 1 and 2 completed.

---

## Spec coverage

| Spec | Task |
|---|---|
| §5 Home/Health, Services, Bans, Jobs+plugins, Certificates | 1, 3 |
| §5 Administration (instances, users, audit) | 4, 5 |
| §5 Account | Plan 2 Task 8 |
| §5 Cross-cutting: theme, sortable/filterable tables | 2 |
| §3 Internal JSON API | 3 (`/api/summary`) |
| §8 Delivery (Docker, compose, CLI, AGPLv3, README, CI) | 6 |
| §7 End-to-end validation | 7 (fake server), 8 (real instance) |

**Accepted deviation:** the spec called for a dev `docker-compose` with 2 real BunkerWeb instances. The plan instead provides a reproducible fake server (Task 7) for the demo/CI, and validation against your real instances is a guided manual step (Task 8): configuring a BunkerWeb instance depends on your environment.

---

## File structure

```
src/mc/queries.py                 view models
src/mc/collector.py               (modified) refresh_instance()
src/mc/web/render.py              (modified) dt / ago filters
src/mc/web/routes_views.py        dashboard, services, bans, jobs, certificates, /api/summary
src/mc/web/routes_admin.py        instances, users, audit
src/mc/web/routes_pages.py        (modified) only "/"
src/mc/web/app.py                 (modified) new routers
src/mc/web/templates/             base (modified), _macros, dashboard, services, bans, jobs,
                                  certificates, admin_instances, admin_instance_edit,
                                  admin_users, admin_audit
src/mc/web/static/                table.js, refresh.js, app.css (modified)
Dockerfile  docker-compose.yml  .env.example  README.md  LICENSE
.github/workflows/ci.yml
dev/fake_bunkerweb.py
tests/test_queries.py  tests/test_views.py  tests/test_admin_instances.py  tests/test_admin_users.py
```

---

### Task 1: View models (`queries.py`)

**Files:**
- Create: `src/mc/queries.py`
- Test: `tests/test_queries.py`

- [ ] **Step 1: Write the test**

```python
from datetime import timedelta

from mc import queries
from mc.clock import utcnow
from mc.db import session_scope
from mc.models import CertProbe, Instance, Snapshot


def seed():
    now = utcnow()
    with session_scope() as s:
        a = Instance(name="bw1", base_url="http://a:8888", token_enc="x", status="ok", version="1.6.0",
                     last_ok_at=now, latency_ms=12.0)
        b = Instance(name="bw2", base_url="http://b:8888", token_enc="x", status="down",
                     last_ok_at=now - timedelta(hours=1), last_error="network: timeout")
        off = Instance(name="bw3", base_url="http://c:8888", token_enc="x", enabled=False)
        s.add_all([a, b, off])
        s.flush()
        snaps = {
            (a.id, "services"): [{"name": "x.example", "draft": False, "mode": "block"},
                                 {"name": "y.example", "draft": False, "mode": "detect"},
                                 {"name": "d.example", "draft": True, "mode": None}],
            (b.id, "services"): [{"name": "x.example", "draft": False, "mode": "detect"}],
            (a.id, "bans"): [{"ip": "1.1.1.1", "reason": "bot", "service": "x.example", "exp": 60, "date": 1}],
            (b.id, "bans"): [{"ip": "1.1.1.1", "reason": "bot", "service": "x.example", "exp": 30, "date": 1},
                             {"ip": "2.2.2.2", "reason": "scan", "service": "global", "exp": 10, "date": 2}],
            (off.id, "bans"): [{"ip": "9.9.9.9", "reason": "x", "service": "global", "exp": 1, "date": 1}],
            (a.id, "jobs"): [{"name": "renew", "plugin": "letsencrypt", "every": "day", "last_run": "t", "success": True}],
            (a.id, "plugins"): [{"id": "antibot", "name": "Antibot", "version": "1.0", "type": "core"}],
            (b.id, "plugins"): [{"id": "antibot", "name": "Antibot", "version": "1.1", "type": "core"}],
        }
        for (iid, kind), payload in snaps.items():
            s.add(Snapshot(instance_id=iid, kind=kind, payload=payload, collected_at=now))
        s.add_all([
            CertProbe(instance_id=a.id, domain="x.example", present=True, issuer="Let's Encrypt",
                      not_after=now + timedelta(days=3)),
            CertProbe(instance_id=a.id, domain="y.example", present=True, issuer="Other CA",
                      not_after=now + timedelta(days=90)),
            CertProbe(instance_id=b.id, domain="x.example", present=False, error="timeout"),
        ])
    return now


def test_instance_cards_flag_stale_and_disabled(fresh_db):
    now = seed()
    with session_scope() as s:
        cards = {c["name"]: c for c in queries.instance_cards(s, now)}
    assert cards["bw1"]["stale"] is False
    assert cards["bw2"]["stale"] is True and cards["bw2"]["last_error"] == "network: timeout"
    assert cards["bw3"]["enabled"] is False


def test_summary_counts_only_enabled_instances(fresh_db):
    now = seed()
    with session_scope() as s:
        out = queries.summary(s, now)
    assert out == {"instances_total": 2, "instances_ok": 1, "instances_stale": 1,
                   "bans_active": 2, "certs_warn": 1, "certs_none": 1}


def test_services_gaps_and_filters(fresh_db):
    seed()
    with session_scope() as s:
        rows, names = queries.services(s)
        assert names == ["bw1", "bw2"]
        by = {(r["instance"], r["name"]): r for r in rows}
        assert by[("bw1", "y.example")]["missing_on"] == ["bw2"]
        assert by[("bw1", "x.example")]["missing_on"] == []
        assert by[("bw1", "d.example")]["draft"] is True and by[("bw1", "d.example")]["missing_on"] == []
        assert [r["name"] for r in queries.services(s, instance="bw2")[0]] == ["x.example"]
        assert {r["instance"] for r in queries.services(s, mode="detect")[0]} == {"bw1", "bw2"}
        assert len(queries.services(s, mode="block")[0]) == 1


def test_bans_merge_gaps_search_and_ignore_disabled(fresh_db):
    seed()
    with session_scope() as s:
        rows = queries.bans(s)
        assert [(r["ip"], r["instance"]) for r in rows] == [("1.1.1.1", "bw1"), ("1.1.1.1", "bw2"), ("2.2.2.2", "bw2")]
        assert rows[2]["missing_on"] == ["bw1"] and rows[0]["missing_on"] == []
        assert [r["ip"] for r in queries.bans(s, q="2.2")] == ["2.2.2.2"]


def test_jobs_and_plugin_matrix(fresh_db):
    seed()
    with session_scope() as s:
        assert queries.jobs(s)[0]["instance"] == "bw1" and queries.jobs(s)[0]["name"] == "renew"
        names, matrix = queries.plugins(s)
    assert names == ["bw1", "bw2"]
    assert matrix[0]["id"] == "antibot" and matrix[0]["diff"] is True and matrix[0]["cells"] == {"bw1": "1.0", "bw2": "1.1"}


def test_certs_sorted_worst_first_with_status(fresh_db):
    now = seed()
    with session_scope() as s:
        rows = queries.certs(s, now)
    assert [(r["instance"], r["domain"], r["status"]) for r in rows] == [
        ("bw2", "x.example", "none"), ("bw1", "x.example", "red"), ("bw1", "y.example", "ok")]
    red = rows[1]
    assert red["letsencrypt"] is True and red["days"] == 2 or red["days"] == 3
    assert rows[2]["letsencrypt"] is False
```

- [ ] **Step 2: Run, verify it fails**

Run: `python -m pytest tests/test_queries.py -v`
Expected: FAIL (`ImportError: mc.queries`).

- [ ] **Step 3: Implement `src/mc/queries.py`**

```python
from datetime import datetime

from sqlalchemy.orm import Session

from mc import diff
from mc.config import get_settings
from mc.models import CertProbe, Instance, Snapshot

CERT_ORDER = {"expired": 0, "none": 1, "red": 2, "orange": 3, "ok": 4}


def _by_instance(db: Session, kind: str) -> dict[str, list]:
    """{instance name: latest snapshot} for enabled instances that have a snapshot of this type."""
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
    return [{**j, "instance": n} for n, p in sorted(_by_instance(db, "jobs").items()) for j in p]


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
```

- [ ] **Step 4: Fix the ambiguous test assertion, run**

In `test_certs_sorted_worst_first_with_status`, replace the line `assert red["letsencrypt"] is True and red["days"] == 2 or red["days"] == 3` with:
```python
    assert red["letsencrypt"] is True and red["days"] in (2, 3)
```
Run: `python -m pytest tests/test_queries.py -v`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add src/mc/queries.py tests/test_queries.py
git commit -m "feat: view-model queries"
```

---

### Task 2: Shared layout, filters, table JS, refresh

**Files:**
- Modify: `src/mc/web/render.py`, `src/mc/web/templates/base.html`, `src/mc/web/static/app.css`
- Create: `src/mc/web/templates/_macros.html`, `src/mc/web/static/table.js`, `src/mc/web/static/refresh.js`
- Test: `tests/test_render_filters.py`

- [ ] **Step 1: Write the test**

```python
from datetime import datetime, timedelta

from mc.clock import utcnow
from mc.web.render import templates


def test_dt_and_ago_filters():
    dt, ago = templates.env.filters["dt"], templates.env.filters["ago"]
    assert dt(datetime(2026, 3, 4, 5, 6)) == "04/03/2026 05:06 UTC"
    assert dt(None) == "—"
    assert ago(None) == "jamais"
    assert ago(utcnow() - timedelta(seconds=30)) == "il y a 30 s"
    assert ago(utcnow() - timedelta(minutes=5, seconds=1)) == "il y a 5 min"
    assert ago(utcnow() - timedelta(hours=3, seconds=1)) == "il y a 3 h"
    assert ago(utcnow() - timedelta(days=2, seconds=1)) == "il y a 2 j"
```

- [ ] **Step 2: Run, verify it fails**

Run: `python -m pytest tests/test_render_filters.py -v`
Expected: FAIL (`KeyError: 'dt'`).

- [ ] **Step 3: Modify `src/mc/web/render.py`** (replace the file)

```python
from datetime import datetime
from pathlib import Path

from fastapi import Request
from fastapi.templating import Jinja2Templates

from mc.clock import utcnow

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _dt(d: datetime | None) -> str:
    return d.strftime("%d/%m/%Y %H:%M UTC") if d else "—"


def _ago(d: datetime | None) -> str:
    if d is None:
        return "jamais"
    s = int((utcnow() - d).total_seconds())
    if s < 60:
        return f"il y a {s} s"
    if s < 3600:
        return f"il y a {s // 60} min"
    if s < 86400:
        return f"il y a {s // 3600} h"
    return f"il y a {s // 86400} j"


templates.env.filters["dt"] = _dt
templates.env.filters["ago"] = _ago


def render(request: Request, name: str, status: int = 200, **ctx):
    row = getattr(request.state, "session", None)
    ctx.setdefault("user", None)
    ctx["csrf"] = row.csrf if row else ""
    return templates.TemplateResponse(request, name, ctx, status_code=status)
```

- [ ] **Step 4: Replace `src/mc/web/templates/base.html`**

```html
<!doctype html>
<html lang="fr" data-bs-theme="light">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{% block title %}Accueil{% endblock %} · BunkerWeb Mission Control</title>
  <link rel="stylesheet" href="/static/bootstrap.min.css">
  <link rel="stylesheet" href="/static/app.css">
  <script src="/static/app.js"></script>
  <script src="/static/table.js" defer></script>
  <script src="/static/refresh.js" defer></script>
  {% block head %}{% endblock %}
</head>
<body>
{% if user %}
<nav class="navbar border-bottom mb-4">
  <div class="container d-flex flex-wrap gap-3 align-items-center">
    <a class="navbar-brand fw-semibold" href="/dashboard">Mission Control</a>
    <div class="d-flex flex-wrap gap-3 me-auto" id="main-nav">
      <a href="/dashboard">Accueil</a>
      <a href="/services">Services</a>
      <a href="/bans">Bans</a>
      <a href="/jobs">Jobs &amp; plugins</a>
      <a href="/certificates">Certificats</a>
      {% if user.role == 'admin' %}
      <a href="/admin/instances">Instances</a>
      <a href="/admin/users">Utilisateurs</a>
      <a href="/admin/audit">Audit</a>
      {% endif %}
    </div>
    <button type="button" id="theme-toggle" class="btn btn-sm btn-outline-secondary">Thème</button>
    <a href="/account">{{ user.username }}</a>
    <form method="post" action="/logout" class="m-0">
      <input type="hidden" name="csrf" value="{{ csrf }}">
      <button class="btn btn-sm btn-outline-secondary">Déconnexion</button>
    </form>
  </div>
</nav>
{% endif %}
<main class="container pb-5">
{% block content %}{% endblock %}
</main>
</body>
</html>
```

- [ ] **Step 5: Write `_macros.html`, JS and CSS**

`src/mc/web/templates/_macros.html` :
```html
{% macro instance_badge(status) -%}
{%- set cls = {'ok': 'success', 'degraded': 'warning', 'down': 'danger'}[status] | default('secondary') -%}
{%- set label = {'ok': 'OK', 'degraded': 'Dégradé', 'down': 'Injoignable', 'unknown': 'Inconnu'}[status] | default(status) -%}
<span class="badge text-bg-{{ cls }}">{{ label }}</span>
{%- endmacro %}

{% macro cert_badge(status) -%}
{%- set cls = {'ok': 'success', 'orange': 'warning', 'red': 'danger', 'expired': 'danger'}[status] | default('secondary') -%}
{%- set label = {'ok': 'Valide', 'orange': 'Expire bientôt', 'red': 'Critique', 'expired': 'Expiré', 'none': 'Aucun'}[status] | default(status) -%}
<span class="badge text-bg-{{ cls }}">{{ label }}</span>
{%- endmacro %}

{% macro mode_badge(mode) -%}
{%- if mode == 'block' -%}<span class="badge text-bg-success">block</span>
{%- elif mode == 'detect' -%}<span class="badge text-bg-warning">detect</span>
{%- else -%}<span class="badge text-bg-secondary">inconnu</span>{%- endif -%}
{%- endmacro %}

{% macro missing(names) -%}
{%- if names %}<div class="small text-warning-emphasis">⚠ absent sur : {{ names | join(', ') }}</div>{% endif -%}
{%- endmacro %}
```

`src/mc/web/static/table.js` :
```js
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("table[data-table]").forEach((table) => {
    const body = table.tBodies[0];
    const headers = table.querySelectorAll("th[data-sort]");
    headers.forEach((th) => {
      th.setAttribute("tabindex", "0");
      const sort = () => {
        const dir = th.dataset.dir === "asc" ? "desc" : "asc";
        headers.forEach((o) => { delete o.dataset.dir; o.removeAttribute("aria-sort"); });
        th.dataset.dir = dir;
        th.setAttribute("aria-sort", dir === "asc" ? "ascending" : "descending");
        const val = (tr) => { const c = tr.cells[th.cellIndex]; return c.dataset.v ?? c.textContent.trim(); };
        [...body.rows].sort((a, b) => {
          const x = val(a), y = val(b), nx = parseFloat(x), ny = parseFloat(y);
          const cmp = !isNaN(nx) && !isNaN(ny) ? nx - ny : x.localeCompare(y, "fr");
          return dir === "asc" ? cmp : -cmp;
        }).forEach((r) => body.appendChild(r));
      };
      th.addEventListener("click", sort);
      th.addEventListener("keydown", (e) => { if (e.key === "Enter") sort(); });
    });
  });

  document.querySelectorAll("input[data-filter-for]").forEach((input) => {
    const table = document.getElementById(input.dataset.filterFor);
    input.addEventListener("input", () => {
      const q = input.value.toLowerCase();
      [...table.tBodies[0].rows].forEach((tr) => { tr.hidden = !tr.textContent.toLowerCase().includes(q); });
    });
  });
});
```

`src/mc/web/static/refresh.js` :
```js
(() => {
  const tick = async () => {
    const tiles = document.querySelectorAll("[data-summary]");
    if (!tiles.length) return;
    try {
      const r = await fetch("/api/summary", {credentials: "same-origin"});
      if (r.redirected || !r.ok) { location.reload(); return; }  // session expired
      const data = await r.json();
      tiles.forEach((el) => {
        const v = data[el.dataset.summary];
        if (v !== undefined) el.textContent = v;
      });
    } catch (e) { /* network unavailable: retry on the next tick */ }
  };
  setInterval(tick, 30000);
})();
```

Replace `src/mc/web/static/app.css`:
```css
body { min-height: 100vh; }
nav a { text-decoration: none; }
code.secret { word-break: break-all; }
th[data-sort] { cursor: pointer; white-space: nowrap; }
th[data-sort]::after { content: " ↕"; opacity: .35; }
th[aria-sort="ascending"]::after { content: " ↑"; opacity: 1; }
th[aria-sort="descending"]::after { content: " ↓"; opacity: 1; }
.tile .value { font-size: 2rem; font-weight: 600; line-height: 1.1; }
```

- [ ] **Step 6: Run, verify it passes**

Run: `python -m pytest tests/test_render_filters.py tests/test_web_shell.py tests/test_auth_routes.py -q`
Expected: all pass (the modified layout does not break existing pages).

- [ ] **Step 7: Commit**

```bash
git add src/mc/web tests/test_render_filters.py
git commit -m "feat: shared layout, formatting filters, sortable/filterable tables, live tiles"
```

---

### Task 3: Monitoring routes and templates

**Files:**
- Create: `src/mc/web/routes_views.py`, `templates/dashboard.html` (replaces the existing one), `services.html`, `bans.html`, `jobs.html`, `certificates.html`
- Modify: `src/mc/web/routes_pages.py`, `src/mc/web/app.py`, `tests/helpers.py`
- Test: `tests/test_views.py`

- [ ] **Step 1: Add a login helper to `tests/helpers.py`** (at the end of the file)

```python

def login_as(client, username="alice", role="admin") -> str:
    """Create the user, log in (password + TOTP); return the session's CSRF token."""
    secret = make_user(username, role)
    assert full_login(client, secret, username).status_code == 303
    return csrf_of(client.get("/dashboard").text)
```

- [ ] **Step 2: Write the test**

```python
import pytest

from tests.helpers import login_as, make_client
from tests.test_queries import seed


@pytest.fixture
def client(fresh_db):
    seed()
    with make_client() as c:
        login_as(c, "bob", "reader")
        yield c


def test_dashboard_shows_tiles_and_instance_cards(client):
    r = client.get("/dashboard")
    assert r.status_code == 200
    assert 'data-summary="instances_ok"' in r.text and "bw1" in r.text and "bw2" in r.text
    assert "Injoignable" in r.text and "network: timeout" in r.text
    assert "Désactivée" in r.text  # bw3


def test_api_summary_json(client):
    r = client.get("/api/summary")
    assert r.status_code == 200
    assert r.json()["bans_active"] == 2 and r.json()["instances_total"] == 2


def test_api_summary_requires_login(fresh_db):
    with make_client() as c:
        assert c.get("/api/summary", follow_redirects=False).status_code == 303


def test_services_page_with_gap_and_filter(client):
    r = client.get("/services")
    assert "y.example" in r.text and "absent sur : bw2" in r.text
    r = client.get("/services", params={"mode": "block"})
    assert "y.example" not in r.text and "x.example" in r.text


def test_bans_page_search(client):
    assert "2.2.2.2" in client.get("/bans").text
    r = client.get("/bans", params={"q": "2.2"})
    assert "2.2.2.2" in r.text and "1.1.1.1" not in r.text


def test_jobs_page_has_matrix_and_job(client):
    r = client.get("/jobs")
    assert "renew" in r.text and "antibot" in r.text and "1.1" in r.text


def test_certificates_page_status_labels(client):
    r = client.get("/certificates")
    assert "Critique" in r.text and "Aucun" in r.text and "Valide" in r.text and "Let's Encrypt" in r.text
```

- [ ] **Step 3: Run, verify it fails**

Run: `python -m pytest tests/test_views.py -v`
Expected: FAIL (404 on `/services`, etc.).

- [ ] **Step 4: Implement the routes**

`src/mc/web/routes_views.py` :
```python
from fastapi import APIRouter, Depends, Request

from mc import queries
from mc.clock import utcnow
from mc.db import get_db
from mc.models import User
from mc.web.deps import current_user
from mc.web.render import render

router = APIRouter()


@router.get("/dashboard")
async def dashboard(request: Request, user: User = Depends(current_user), db=Depends(get_db)):
    now = utcnow()
    return render(request, "dashboard.html", user=user,
                  cards=queries.instance_cards(db, now), s=queries.summary(db, now))


@router.get("/api/summary")
async def api_summary(user: User = Depends(current_user), db=Depends(get_db)):
    return queries.summary(db, utcnow())


@router.get("/services")
async def services(request: Request, instance: str = "", mode: str = "",
                   user: User = Depends(current_user), db=Depends(get_db)):
    rows, names = queries.services(db, instance, mode)
    return render(request, "services.html", user=user, rows=rows, names=names, instance=instance, mode=mode)


@router.get("/bans")
async def bans(request: Request, q: str = "", user: User = Depends(current_user), db=Depends(get_db)):
    return render(request, "bans.html", user=user, rows=queries.bans(db, q), q=q)


@router.get("/jobs")
async def jobs(request: Request, user: User = Depends(current_user), db=Depends(get_db)):
    names, matrix = queries.plugins(db)
    return render(request, "jobs.html", user=user, jobs=queries.jobs(db), names=names, matrix=matrix)


@router.get("/certificates")
async def certificates(request: Request, user: User = Depends(current_user), db=Depends(get_db)):
    return render(request, "certificates.html", user=user, rows=queries.certs(db, utcnow()))
```

Replace `src/mc/web/routes_pages.py`:
```python
from fastapi import APIRouter
from fastapi.responses import RedirectResponse

router = APIRouter()


@router.get("/")
async def index():
    return RedirectResponse("/dashboard", 303)
```

In `src/mc/web/app.py`, replace the router inclusion block:
```python
    from mc.web import routes_account, routes_auth, routes_pages, routes_views

    app.include_router(routes_auth.router)
    app.include_router(routes_account.router)
    app.include_router(routes_views.router)
    app.include_router(routes_pages.router)
```

- [ ] **Step 5: Write the templates**

`src/mc/web/templates/dashboard.html` (replaces the existing one):
```html
{% extends "base.html" %}
{% from "_macros.html" import instance_badge %}
{% block title %}Accueil{% endblock %}
{% block content %}
<h1 class="h4 mb-3">Vue d'ensemble</h1>
<div class="row g-3 mb-4">
  <div class="col-6 col-lg-3"><div class="card tile h-100"><div class="card-body">
    <div class="text-secondary small">Instances OK</div>
    <div class="value"><span data-summary="instances_ok">{{ s.instances_ok }}</span> / <span data-summary="instances_total">{{ s.instances_total }}</span></div>
  </div></div></div>
  <div class="col-6 col-lg-3"><div class="card tile h-100"><div class="card-body">
    <div class="text-secondary small">Bans actifs (IP uniques)</div>
    <div class="value" data-summary="bans_active">{{ s.bans_active }}</div>
  </div></div></div>
  <div class="col-6 col-lg-3"><div class="card tile h-100"><div class="card-body">
    <div class="text-secondary small">Certificats à surveiller</div>
    <div class="value"><a href="/certificates" data-summary="certs_warn" class="text-reset">{{ s.certs_warn }}</a></div>
    <div class="small text-secondary"><span data-summary="certs_none">{{ s.certs_none }}</span> sans certificat</div>
  </div></div></div>
  <div class="col-6 col-lg-3"><div class="card tile h-100"><div class="card-body">
    <div class="text-secondary small">Données périmées</div>
    <div class="value" data-summary="instances_stale">{{ s.instances_stale }}</div>
  </div></div></div>
</div>

{% if not cards %}
<div class="alert alert-info">Aucune instance enregistrée.{% if user.role == 'admin' %} <a href="/admin/instances">Ajouter une instance</a>.{% endif %}</div>
{% endif %}
<div class="row g-3">
  {% for c in cards %}
  <div class="col-md-6 col-xl-4"><div class="card h-100"><div class="card-body">
    <div class="d-flex justify-content-between align-items-start">
      <h2 class="h6 mb-0">{{ c.name }}</h2>
      {% if c.enabled %}{{ instance_badge(c.status) }}{% else %}<span class="badge text-bg-secondary">Désactivée</span>{% endif %}
    </div>
    <dl class="row small mb-0 mt-2">
      <dt class="col-5">Version</dt><dd class="col-7">{{ c.version or '—' }}</dd>
      <dt class="col-5">Latence</dt><dd class="col-7">{% if c.latency_ms is not none %}{{ '%.0f'|format(c.latency_ms) }} ms{% else %}—{% endif %}</dd>
      <dt class="col-5">Dernière collecte</dt>
      <dd class="col-7">{{ c.last_ok_at | ago }}{% if c.enabled and c.stale %} <span class="badge text-bg-warning">périmée</span>{% endif %}</dd>
    </dl>
    {% if c.last_error %}<div class="small text-danger mt-2">{{ c.last_error }}</div>{% endif %}
  </div></div></div>
  {% endfor %}
</div>
{% endblock %}
```

`src/mc/web/templates/services.html` :
```html
{% extends "base.html" %}
{% from "_macros.html" import mode_badge, missing %}
{% block title %}Services{% endblock %}
{% block head %}<meta http-equiv="refresh" content="60">{% endblock %}
{% block content %}
<h1 class="h4 mb-3">Services protégés</h1>
<form method="get" class="row g-2 mb-3">
  <div class="col-auto"><label class="visually-hidden" for="f-inst">Instance</label>
    <select class="form-select" id="f-inst" name="instance">
      <option value="">Toutes les instances</option>
      {% for n in names %}<option value="{{ n }}" {% if n == instance %}selected{% endif %}>{{ n }}</option>{% endfor %}
    </select></div>
  <div class="col-auto"><label class="visually-hidden" for="f-mode">Mode</label>
    <select class="form-select" id="f-mode" name="mode">
      <option value="">Tous les modes</option>
      <option value="block" {% if mode == 'block' %}selected{% endif %}>block</option>
      <option value="detect" {% if mode == 'detect' %}selected{% endif %}>detect</option>
    </select></div>
  <div class="col-auto"><button class="btn btn-outline-secondary">Filtrer</button></div>
  <div class="col-auto ms-auto"><input class="form-control" type="search" placeholder="Rechercher…" aria-label="Rechercher" data-filter-for="t-services"></div>
</form>
<div class="table-responsive">
<table class="table align-middle" id="t-services" data-table>
  <thead><tr><th data-sort>Domaine</th><th data-sort>Instance</th><th data-sort>Mode</th><th data-sort>Statut</th></tr></thead>
  <tbody>
  {% for r in rows %}
  <tr>
    <td>{{ r.name }}{{ missing(r.missing_on) }}</td>
    <td>{{ r.instance }}</td>
    <td data-v="{{ r.mode or '' }}">{{ mode_badge(r.mode) }}</td>
    <td>{% if r.draft %}<span class="badge text-bg-secondary">brouillon</span>{% else %}<span class="badge text-bg-success">actif</span>{% endif %}</td>
  </tr>
  {% else %}<tr><td colspan="4" class="text-secondary">Aucun service.</td></tr>
  {% endfor %}
  </tbody>
</table>
</div>
{% endblock %}
```

`src/mc/web/templates/bans.html` :
```html
{% extends "base.html" %}
{% from "_macros.html" import missing %}
{% block title %}Bans{% endblock %}
{% block head %}<meta http-equiv="refresh" content="60">{% endblock %}
{% block content %}
<h1 class="h4 mb-3">Bans actifs</h1>
<form method="get" class="row g-2 mb-3">
  <div class="col-auto"><label class="visually-hidden" for="q">IP</label>
    <input class="form-control" id="q" name="q" value="{{ q }}" placeholder="Rechercher une IP"></div>
  <div class="col-auto"><button class="btn btn-outline-secondary">Rechercher</button></div>
</form>
<div class="table-responsive">
<table class="table align-middle" data-table>
  <thead><tr><th data-sort>IP</th><th data-sort>Raison</th><th data-sort>Service</th><th data-sort>Instance</th><th data-sort>Expiration</th></tr></thead>
  <tbody>
  {% for r in rows %}
  <tr>
    <td>{{ r.ip }}{{ missing(r.missing_on) }}</td>
    <td>{{ r.reason or '—' }}</td>
    <td>{{ r.service }}</td>
    <td>{{ r.instance }}</td>
    <td>{{ r.exp if r.exp is not none else '—' }}</td>
  </tr>
  {% else %}<tr><td colspan="5" class="text-secondary">Aucun ban actif.</td></tr>
  {% endfor %}
  </tbody>
</table>
</div>
<p class="small text-secondary">L'expiration est affichée telle que renvoyée par l'API BunkerWeb.</p>
{% endblock %}
```

`src/mc/web/templates/jobs.html` :
```html
{% extends "base.html" %}
{% block title %}Jobs et plugins{% endblock %}
{% block head %}<meta http-equiv="refresh" content="60">{% endblock %}
{% block content %}
<h1 class="h4 mb-3">Jobs planifiés</h1>
<div class="table-responsive mb-5">
<table class="table align-middle" data-table>
  <thead><tr><th data-sort>Job</th><th data-sort>Plugin</th><th data-sort>Instance</th><th data-sort>Fréquence</th><th data-sort>Dernière exécution</th><th data-sort>Résultat</th></tr></thead>
  <tbody>
  {% for j in jobs %}
  <tr>
    <td>{{ j.name }}</td><td>{{ j.plugin or '—' }}</td><td>{{ j.instance }}</td><td>{{ j.every or '—' }}</td>
    <td>{{ j.last_run or '—' }}</td>
    <td>{% if j.success is true %}<span class="badge text-bg-success">Succès</span>
        {% elif j.success is false %}<span class="badge text-bg-danger">Échec</span>
        {% else %}<span class="badge text-bg-secondary">—</span>{% endif %}</td>
  </tr>
  {% else %}<tr><td colspan="6" class="text-secondary">Aucun job.</td></tr>
  {% endfor %}
  </tbody>
</table>
</div>

<h2 class="h4 mb-3">Plugins par instance</h2>
<div class="table-responsive">
<table class="table align-middle" data-table>
  <thead><tr><th data-sort>Plugin</th>{% for n in names %}<th data-sort>{{ n }}</th>{% endfor %}</tr></thead>
  <tbody>
  {% for row in matrix %}
  <tr class="{% if row.diff %}table-warning{% endif %}">
    <td>{{ row.id }}{% if row.diff %} <span class="badge text-bg-warning">écart</span>{% endif %}</td>
    {% for n in names %}<td>{{ row.cells[n] if row.cells[n] else '—' }}</td>{% endfor %}
  </tr>
  {% else %}<tr><td colspan="{{ names|length + 1 }}" class="text-secondary">Aucun plugin.</td></tr>
  {% endfor %}
  </tbody>
</table>
</div>
{% endblock %}
```

`src/mc/web/templates/certificates.html` :
```html
{% extends "base.html" %}
{% from "_macros.html" import cert_badge %}
{% block title %}Certificats{% endblock %}
{% block head %}<meta http-equiv="refresh" content="60">{% endblock %}
{% block content %}
<h1 class="h4 mb-3">Certificats</h1>
<div class="table-responsive">
<table class="table align-middle" data-table>
  <thead><tr><th data-sort>Domaine</th><th data-sort>Instance</th><th data-sort>Statut</th><th data-sort>Émetteur</th><th data-sort>Expiration</th><th data-sort>Jours restants</th></tr></thead>
  <tbody>
  {% for r in rows %}
  <tr>
    <td>{{ r.domain }}</td>
    <td>{{ r.instance }}</td>
    <td>{{ cert_badge(r.status) }}{% if r.error and not r.present %}<div class="small text-secondary">{{ r.error }}</div>{% endif %}</td>
    <td>{% if r.present %}{{ r.issuer or '—' }}{% if r.letsencrypt %} <span class="badge text-bg-info">Let's Encrypt</span>{% endif %}{% else %}—{% endif %}</td>
    <td>{{ r.not_after | dt }}</td>
    <td data-v="{{ r.days if r.days is not none else '' }}">{{ r.days if r.days is not none else '—' }}</td>
  </tr>
  {% else %}<tr><td colspan="6" class="text-secondary">Aucun certificat sondé pour l'instant.</td></tr>
  {% endfor %}
  </tbody>
</table>
</div>
<p class="small text-secondary">Certificat réellement servi par chaque instance (sonde TLS directe, SNI = domaine du service). Rouge : moins de 7 jours ou expiré ; orange : moins de 21 jours.</p>
{% endblock %}
```

- [ ] **Step 6: Run, verify it passes**

Run: `python -m pytest tests/test_views.py tests/test_auth_routes.py tests/test_web_shell.py -q`
Expected: tous passent.

- [ ] **Step 7: Commit**

```bash
git add src/mc/web tests/helpers.py tests/test_views.py
git commit -m "feat: supervision views (health, services, bans, jobs/plugins, certificates)"
```

---

### Task 4: Instance administration

**Files:**
- Modify: `src/mc/collector.py` (ajout `refresh_instance`), `src/mc/web/app.py`
- Create: `src/mc/web/routes_admin.py`, `templates/admin_instances.html`, `templates/admin_instance_edit.html`
- Test: `tests/test_admin_instances.py`

- [ ] **Step 1: Add `refresh_instance` to `src/mc/collector.py`** (after `probe_one`)

```python
async def refresh_instance(inst_id: int) -> None:
    """Immediately collect from, then probe, an instance (after it is added or modified)."""
    await collect_one(inst_id)
    await probe_one(inst_id)
```

- [ ] **Step 2: Write the test**

```python
import pytest

from mc import collector
from mc.crypto import decrypt
from mc.db import session_scope
from mc.models import AuditLog, CertProbe, Instance, Snapshot
from mc.web import routes_admin
from tests.helpers import login_as, make_client

FORM = {"name": "bw1", "base_url": "http://10.0.0.5:8888/", "token": "tok123", "tls_port": "443", "verify_tls": "on"}


@pytest.fixture
def client(fresh_db):
    with make_client() as c:
        yield c


@pytest.fixture
def admin(client, monkeypatch):
    calls = []
    state = {"error": None}

    async def check(base_url, token, verify_tls):
        return state["error"]

    async def refresh(inst_id):
        calls.append(inst_id)

    monkeypatch.setattr(routes_admin, "check_instance", check)
    monkeypatch.setattr(collector, "refresh_instance", refresh)
    csrf = login_as(client)
    return csrf, calls, state


def post(client, csrf, path="/admin/instances", **data):
    return client.post(path, data={"csrf": csrf, **data}, follow_redirects=False)


def test_add_instance_encrypts_token_and_triggers_refresh(client, admin):
    csrf, calls, _ = admin
    r = post(client, csrf, **FORM)
    assert r.status_code == 303 and r.headers["location"] == "/admin/instances?m=added"
    with session_scope() as s:
        i = s.query(Instance).one()
        assert i.base_url == "http://10.0.0.5:8888" and i.verify_tls is True
        assert i.token_enc != "tok123" and decrypt(i.token_enc) == "tok123"
        assert [e.event for e in s.query(AuditLog)][-1] == "instance_added"
        assert calls == [i.id]


def test_token_never_rendered(client, admin):
    csrf, _, _ = admin
    post(client, csrf, **FORM)
    assert "tok123" not in client.get("/admin/instances").text


def test_connection_failure_blocks_unless_forced(client, admin):
    csrf, calls, state = admin
    state["error"] = "Instance injoignable"
    r = post(client, csrf, **FORM)
    assert r.status_code == 400 and "injoignable" in client.post(
        "/admin/instances", data={"csrf": csrf, **FORM}).text
    with session_scope() as s:
        assert s.query(Instance).count() == 0
    r = post(client, csrf, force="on", **FORM)
    assert r.status_code == 303
    with session_scope() as s:
        assert s.query(Instance).count() == 1


@pytest.mark.parametrize("override,fragment", [
    ({"base_url": "ftp://x"}, "URL invalide"),
    ({"base_url": "http://user:pw@x:8888"}, "URL invalide"),
    ({"base_url": "http://x:99999"}, "URL invalide"),
    ({"name": ""}, "Nom invalide"),
    ({"tls_port": "70000"}, "Port TLS invalide"),
])
def test_validation_errors(client, admin, override, fragment):
    csrf, _, _ = admin
    r = client.post("/admin/instances", data={"csrf": csrf, **{**FORM, **override}})
    assert r.status_code == 400 and fragment in r.text
    with session_scope() as s:
        assert s.query(Instance).count() == 0


def test_duplicate_name_rejected(client, admin):
    csrf, _, _ = admin
    post(client, csrf, **FORM)
    r = client.post("/admin/instances", data={"csrf": csrf, **FORM})
    assert r.status_code == 400 and "existe déjà" in r.text


def test_edit_keeps_token_when_blank_and_replaces_when_given(client, admin):
    csrf, calls, _ = admin
    post(client, csrf, **FORM)
    with session_scope() as s:
        iid = s.query(Instance).one().id
    data = {"name": "bw1-renamed", "base_url": "http://10.0.0.6:8888", "token": "", "tls_port": "8443",
            "probe_host": "10.0.0.7", "enabled": "on"}
    r = post(client, csrf, f"/admin/instances/{iid}", **data)
    assert r.status_code == 303
    with session_scope() as s:
        i = s.get(Instance, iid)
        assert (i.name, i.base_url, i.tls_port, i.probe_host) == ("bw1-renamed", "http://10.0.0.6:8888", 8443, "10.0.0.7")
        assert decrypt(i.token_enc) == "tok123" and i.verify_tls is False
    post(client, csrf, f"/admin/instances/{iid}", **{**data, "token": "newtok"})
    with session_scope() as s:
        assert decrypt(s.get(Instance, iid).token_enc) == "newtok"
    post(client, csrf, f"/admin/instances/{iid}", **{k: v for k, v in data.items() if k != "enabled"})
    with session_scope() as s:
        assert s.get(Instance, iid).enabled is False


def test_delete_cascades(client, admin):
    csrf, _, _ = admin
    post(client, csrf, **FORM)
    with session_scope() as s:
        i = s.query(Instance).one()
        i.snapshots.append(Snapshot(kind="bans", payload=[]))
        i.probes.append(CertProbe(domain="a.example"))
        iid = i.id
    assert post(client, csrf, f"/admin/instances/{iid}/delete").status_code == 303
    with session_scope() as s:
        assert (s.query(Instance).count(), s.query(Snapshot).count(), s.query(CertProbe).count()) == (0, 0, 0)


def test_reader_forbidden_and_csrf_required(client, admin):
    csrf, _, _ = admin
    assert client.post("/admin/instances", data=FORM).status_code == 403  # without CSRF
    with make_client() as c2:
        login_as(c2, "bob", "reader")
        assert c2.get("/admin/instances").status_code == 403
```

- [ ] **Step 3: Run, verify it fails**

Run: `python -m pytest tests/test_admin_instances.py -v`
Expected: FAIL (`ImportError: routes_admin`).

- [ ] **Step 4: Implement `src/mc/web/routes_admin.py`** (instances part; the users/audit part is added in Task 5)

```python
import re
from urllib.parse import urlparse

from fastapi import APIRouter, BackgroundTasks, Depends, Form, Request
from fastapi.responses import RedirectResponse

from mc import collector
from mc.auth.audit import audit
from mc.bw_client import BWClient, BWError
from mc.config import get_settings
from mc.crypto import encrypt
from mc.db import get_db
from mc.models import Instance, User
from mc.web.deps import require_admin
from mc.web.render import render
from mc.web.routes_auth import ip_of

router = APIRouter(prefix="/admin")

MESSAGES = {
    "added": "Instance ajoutée ; première collecte en cours.",
    "saved": "Instance enregistrée.",
    "deleted": "Instance supprimée.",
}
KIND_LABEL = {"network": "Instance injoignable", "auth": "Authentification refusée (token ou droits insuffisants)",
              "http": "Réponse HTTP inattendue", "data": "Réponse non JSON (est-ce bien l'API BunkerWeb ?)"}


async def check_instance(base_url: str, token: str, verify_tls: bool) -> str | None:
    """Connection test: ping + one authenticated call. Returns an error message or None."""
    client = BWClient(base_url, token, timeout=get_settings().http_timeout, verify=verify_tls)
    try:
        await client.ping()
        await client.bans()
    except BWError as e:
        return f"{KIND_LABEL[e.kind]} — {e}"
    finally:
        await client.aclose()
    return None


def clean_url(raw: str) -> str:
    raw = raw.strip()
    try:
        u = urlparse(raw)
        ok = u.scheme in ("http", "https") and u.hostname and not u.username and not u.password
        u.port  # raises ValueError if the port is invalid
    except ValueError:
        ok = False
    if not ok:
        raise ValueError("URL invalide (attendu : http(s)://hôte[:port], sans identifiants)")
    return raw.rstrip("/")


def validate_fields(db, name: str, base_url: str, tls_port: int, exclude_id: int | None = None) -> tuple[str, str]:
    name = name.strip()
    if not re.fullmatch(r"[A-Za-z0-9._ -]{1,64}", name):
        raise ValueError("Nom invalide (1-64 caractères : lettres, chiffres, espace, . _ -)")
    clash = db.query(Instance).filter(Instance.name == name)
    if exclude_id:
        clash = clash.filter(Instance.id != exclude_id)
    if clash.first():
        raise ValueError("Une instance de ce nom existe déjà")
    if not 1 <= tls_port <= 65535:
        raise ValueError("Port TLS invalide")
    return name, clean_url(base_url)


def instances_page(request: Request, db, user: User, error=None, form=None, status=200):
    return render(request, "admin_instances.html", status=status, user=user, error=error, form=form or {},
                  msg=MESSAGES.get(request.query_params.get("m")),
                  instances=db.query(Instance).order_by(Instance.name).all())


@router.get("/instances")
async def instances_get(request: Request, user: User = Depends(require_admin), db=Depends(get_db)):
    return instances_page(request, db, user)


@router.post("/instances")
async def instances_add(request: Request, background: BackgroundTasks,
                        name: str = Form(""), base_url: str = Form(""), token: str = Form(""),
                        probe_host: str = Form(""), tls_port: int = Form(443),
                        verify_tls: bool = Form(False), force: bool = Form(False),
                        user: User = Depends(require_admin), db=Depends(get_db)):
    form = {"name": name, "base_url": base_url, "probe_host": probe_host, "tls_port": tls_port,
            "verify_tls": verify_tls}
    try:
        name, base_url = validate_fields(db, name, base_url, tls_port)
        if not token.strip():
            raise ValueError("Token requis")
    except ValueError as e:
        return instances_page(request, db, user, str(e), form, 400)
    if not force:
        err = await check_instance(base_url, token.strip(), verify_tls)
        if err:
            return instances_page(request, db, user, f"Test de connexion échoué : {err}", {**form, "failed": True}, 400)
    inst = Instance(name=name, base_url=base_url, token_enc=encrypt(token.strip()), verify_tls=verify_tls,
                    probe_host=probe_host.strip(), tls_port=tls_port)
    db.add(inst)
    db.flush()
    audit(db, "instance_added", user.username, detail=name, ip=ip_of(request))
    db.commit()
    background.add_task(collector.refresh_instance, inst.id)
    return RedirectResponse("/admin/instances?m=added", 303)


@router.get("/instances/{inst_id}")
async def instance_edit_get(request: Request, inst_id: int, user: User = Depends(require_admin), db=Depends(get_db)):
    inst = db.get(Instance, inst_id)
    if inst is None:
        return RedirectResponse("/admin/instances", 303)
    return render(request, "admin_instance_edit.html", user=user, inst=inst, error=None)


@router.post("/instances/{inst_id}")
async def instance_edit_post(request: Request, inst_id: int, background: BackgroundTasks,
                             name: str = Form(""), base_url: str = Form(""), token: str = Form(""),
                             probe_host: str = Form(""), tls_port: int = Form(443),
                             verify_tls: bool = Form(False), enabled: bool = Form(False),
                             user: User = Depends(require_admin), db=Depends(get_db)):
    inst = db.get(Instance, inst_id)
    if inst is None:
        return RedirectResponse("/admin/instances", 303)
    try:
        name, base_url = validate_fields(db, name, base_url, tls_port, exclude_id=inst_id)
    except ValueError as e:
        return render(request, "admin_instance_edit.html", status=400, user=user, inst=inst, error=str(e))
    inst.name, inst.base_url, inst.probe_host = name, base_url, probe_host.strip()
    inst.tls_port, inst.verify_tls, inst.enabled = tls_port, verify_tls, enabled
    if token.strip():
        inst.token_enc = encrypt(token.strip())
    audit(db, "instance_edited", user.username, detail=name, ip=ip_of(request))
    db.commit()
    if inst.enabled:
        background.add_task(collector.refresh_instance, inst.id)
    return RedirectResponse("/admin/instances?m=saved", 303)


@router.post("/instances/{inst_id}/delete")
async def instance_delete(request: Request, inst_id: int, user: User = Depends(require_admin), db=Depends(get_db)):
    inst = db.get(Instance, inst_id)
    if inst:
        audit(db, "instance_deleted", user.username, detail=inst.name, ip=ip_of(request))
        db.delete(inst)
        db.commit()
    return RedirectResponse("/admin/instances?m=deleted", 303)
```

- [ ] **Step 5: Templates**

`src/mc/web/templates/admin_instances.html` :
```html
{% extends "base.html" %}
{% from "_macros.html" import instance_badge %}
{% block title %}Instances{% endblock %}
{% block content %}
<h1 class="h4 mb-3">Instances BunkerWeb</h1>
{% if msg %}<div class="alert alert-info" role="status">{{ msg }}</div>{% endif %}
{% if error %}<div class="alert alert-danger" role="alert">{{ error }}</div>{% endif %}

<div class="table-responsive mb-5">
<table class="table align-middle">
  <thead><tr><th>Nom</th><th>URL de l'API</th><th>Sonde TLS</th><th>État</th><th>Dernière collecte</th><th></th></tr></thead>
  <tbody>
  {% for i in instances %}
  <tr>
    <td>{{ i.name }}</td>
    <td>{{ i.base_url }}</td>
    <td>{{ i.probe_target }}:{{ i.tls_port }}</td>
    <td>{% if i.enabled %}{{ instance_badge(i.status) }}{% else %}<span class="badge text-bg-secondary">Désactivée</span>{% endif %}
        {% if i.last_error %}<div class="small text-danger">{{ i.last_error }}</div>{% endif %}</td>
    <td>{{ i.last_ok_at | ago }}</td>
    <td class="text-nowrap">
      <a class="btn btn-sm btn-outline-secondary" href="/admin/instances/{{ i.id }}">Modifier</a>
      <form method="post" action="/admin/instances/{{ i.id }}/delete" class="d-inline">
        <input type="hidden" name="csrf" value="{{ csrf }}">
        <button class="btn btn-sm btn-outline-danger">Supprimer</button>
      </form>
    </td>
  </tr>
  {% else %}<tr><td colspan="6" class="text-secondary">Aucune instance.</td></tr>
  {% endfor %}
  </tbody>
</table>
</div>

<h2 class="h5">Ajouter une instance</h2>
<form method="post" action="/admin/instances" class="col-lg-6">
  <input type="hidden" name="csrf" value="{{ csrf }}">
  <div class="mb-3"><label class="form-label" for="name">Nom</label>
    <input class="form-control" id="name" name="name" value="{{ form.name or '' }}" required></div>
  <div class="mb-3"><label class="form-label" for="base_url">URL de l'API BunkerWeb</label>
    <input class="form-control" id="base_url" name="base_url" placeholder="http://10.0.0.5:8888" value="{{ form.base_url or '' }}" required></div>
  <div class="mb-3"><label class="form-label" for="token">Token d'API (lecture seule recommandé)</label>
    <input class="form-control" id="token" name="token" type="password" autocomplete="off" required>
    <div class="form-text">Chiffré en base, jamais réaffiché.</div></div>
  <div class="row">
    <div class="col-8 mb-3"><label class="form-label" for="probe_host">Hôte de la sonde TLS</label>
      <input class="form-control" id="probe_host" name="probe_host" placeholder="vide = hôte de l'API" value="{{ form.probe_host or '' }}"></div>
    <div class="col-4 mb-3"><label class="form-label" for="tls_port">Port TLS</label>
      <input class="form-control" id="tls_port" name="tls_port" type="number" min="1" max="65535" value="{{ form.tls_port or 443 }}"></div>
  </div>
  <div class="form-check mb-3"><input class="form-check-input" type="checkbox" id="verify_tls" name="verify_tls" checked>
    <label class="form-check-label" for="verify_tls">Vérifier le certificat de l'API (si HTTPS)</label></div>
  {% if form.failed %}
  <div class="form-check mb-3"><input class="form-check-input" type="checkbox" id="force" name="force">
    <label class="form-check-label" for="force">Enregistrer malgré l'échec du test</label></div>
  {% endif %}
  <button class="btn btn-primary">Tester et ajouter</button>
</form>
{% endblock %}
```

`src/mc/web/templates/admin_instance_edit.html` :
```html
{% extends "base.html" %}
{% block title %}Modifier {{ inst.name }}{% endblock %}
{% block content %}
<h1 class="h4 mb-3">Modifier « {{ inst.name }} »</h1>
{% if error %}<div class="alert alert-danger" role="alert">{{ error }}</div>{% endif %}
<form method="post" action="/admin/instances/{{ inst.id }}" class="col-lg-6">
  <input type="hidden" name="csrf" value="{{ csrf }}">
  <div class="mb-3"><label class="form-label" for="name">Nom</label>
    <input class="form-control" id="name" name="name" value="{{ inst.name }}" required></div>
  <div class="mb-3"><label class="form-label" for="base_url">URL de l'API BunkerWeb</label>
    <input class="form-control" id="base_url" name="base_url" value="{{ inst.base_url }}" required></div>
  <div class="mb-3"><label class="form-label" for="token">Nouveau token (laisser vide pour conserver)</label>
    <input class="form-control" id="token" name="token" type="password" autocomplete="off"></div>
  <div class="row">
    <div class="col-8 mb-3"><label class="form-label" for="probe_host">Hôte de la sonde TLS</label>
      <input class="form-control" id="probe_host" name="probe_host" value="{{ inst.probe_host }}"></div>
    <div class="col-4 mb-3"><label class="form-label" for="tls_port">Port TLS</label>
      <input class="form-control" id="tls_port" name="tls_port" type="number" min="1" max="65535" value="{{ inst.tls_port }}"></div>
  </div>
  <div class="form-check mb-2"><input class="form-check-input" type="checkbox" id="verify_tls" name="verify_tls" {% if inst.verify_tls %}checked{% endif %}>
    <label class="form-check-label" for="verify_tls">Vérifier le certificat de l'API (si HTTPS)</label></div>
  <div class="form-check mb-3"><input class="form-check-input" type="checkbox" id="enabled" name="enabled" {% if inst.enabled %}checked{% endif %}>
    <label class="form-check-label" for="enabled">Instance activée (collectée)</label></div>
  <button class="btn btn-primary">Enregistrer</button>
  <a class="btn btn-link" href="/admin/instances">Annuler</a>
</form>
{% endblock %}
```

- [ ] **Step 6: Include the router** — in `src/mc/web/app.py`:

```python
    from mc.web import routes_account, routes_admin, routes_auth, routes_pages, routes_views

    app.include_router(routes_auth.router)
    app.include_router(routes_account.router)
    app.include_router(routes_admin.router)
    app.include_router(routes_views.router)
    app.include_router(routes_pages.router)
```

- [ ] **Step 7: Run, verify it passes**

Run: `python -m pytest tests/test_admin_instances.py -v`
Expected: all pass (12: 4 simple + 5 parametrized + others).

- [ ] **Step 8: Commit**

```bash
git add src/mc tests/test_admin_instances.py
git commit -m "feat: instance administration with connection test"
```

---

### Task 5: User administration and audit

**Files:**
- Modify: `src/mc/web/routes_admin.py`
- Create: `templates/admin_users.html`, `templates/admin_audit.html`
- Test: `tests/test_admin_users.py`

- [ ] **Step 1: Write the test**

```python
import pytest

from mc.auth import mfa
from mc.auth.passwords import verify_password
from mc.auth.users import create_user
from mc.clock import utcnow
from mc.db import session_scope
from mc.models import AuditLog, Credential, Session, User
from tests.helpers import PW, login_as, make_client


@pytest.fixture
def client(fresh_db):
    with make_client() as c:
        yield c


@pytest.fixture
def csrf(client):
    return login_as(client)  # alice, admin


def post(client, csrf, path, **data):
    return client.post(path, data={"csrf": csrf, **data}, follow_redirects=False)


def uid(name):
    with session_scope() as s:
        return s.query(User).filter_by(username=name).one().id


def test_create_user_and_listing(client, csrf):
    r = post(client, csrf, "/admin/users", username="bob", role="reader", password="temporary password 1")
    assert r.status_code == 303 and r.headers["location"] == "/admin/users?m=created"
    with session_scope() as s:
        bob = s.query(User).filter_by(username="bob").one()
        assert bob.role == "reader" and not bob.totp_confirmed
    page = client.get("/admin/users")
    assert "bob" in page.text and "temporary password 1" not in page.text


def test_create_user_errors(client, csrf):
    r = client.post("/admin/users", data={"csrf": csrf, "username": "bob", "role": "reader", "password": "short"})
    assert r.status_code == 400 and "trop court" in r.text
    r = client.post("/admin/users", data={"csrf": csrf, "username": "alice", "role": "reader", "password": PW})
    assert r.status_code == 400 and "existant" in r.text


def test_cannot_delete_self_or_last_admin_or_demote_last_admin(client, csrf):
    me = uid("alice")
    assert post(client, csrf, f"/admin/users/{me}/delete").headers["location"] == "/admin/users?m=self"
    assert post(client, csrf, f"/admin/users/{me}/role", role="reader").headers["location"] == "/admin/users?m=last_admin"
    with session_scope() as s:
        create_user(s, "carol", PW, "admin")
    carol = uid("carol")
    assert post(client, csrf, f"/admin/users/{carol}/role", role="reader").headers["location"] == "/admin/users?m=role_ok"
    # alice is the only admin again: can no longer demote herself
    assert post(client, csrf, f"/admin/users/{me}/role", role="reader").headers["location"] == "/admin/users?m=last_admin"


def test_delete_other_user(client, csrf):
    with session_scope() as s:
        create_user(s, "bob", PW)
    assert post(client, csrf, f"/admin/users/{uid('bob')}/delete").headers["location"] == "/admin/users?m=deleted"
    with session_scope() as s:
        assert s.query(User).filter_by(username="bob").count() == 0


def test_reset_2fa_clears_factors_and_sessions(client, csrf):
    with session_scope() as s:
        bob = create_user(s, "bob", PW)
        bob.totp_secret_enc, bob.totp_confirmed = mfa.new_secret_enc(), True
        bob.credentials.append(Credential(credential_id=b"c", public_key=b"k"))
        mfa.reset_backup_codes(s, bob)
        s.flush()
        from mc.auth import sessions
        sessions.create(s, bob, True, utcnow())
    r = post(client, csrf, f"/admin/users/{uid('bob')}/reset-2fa")
    assert r.headers["location"] == "/admin/users?m=reset_ok"
    with session_scope() as s:
        bob = s.query(User).filter_by(username="bob").one()
        assert not bob.totp_confirmed and bob.totp_secret_enc is None
        assert not bob.credentials and not bob.backup_codes
        assert s.query(Session).filter_by(user_id=bob.id).count() == 0
        assert not mfa.has_second_factor(bob)


def test_reset_password_unlocks_and_revokes_sessions(client, csrf):
    with session_scope() as s:
        bob = create_user(s, "bob", PW)
        bob.failed_attempts, bob.locked_until = 7, utcnow()
    r = post(client, csrf, f"/admin/users/{uid('bob')}/password", password="brand new passphrase")
    assert r.headers["location"] == "/admin/users?m=pwd_ok"
    with session_scope() as s:
        bob = s.query(User).filter_by(username="bob").one()
        assert verify_password(bob.password_hash, "brand new passphrase")
        assert bob.failed_attempts == 0 and bob.locked_until is None
    r = post(client, csrf, f"/admin/users/{uid('bob')}/password", password="short")
    assert r.headers["location"] == "/admin/users?m=pwd_short"


def test_self_reset_goes_through_account_page(client, csrf):
    me = uid("alice")
    assert post(client, csrf, f"/admin/users/{me}/reset-2fa").headers["location"] == "/admin/users?m=self"
    assert post(client, csrf, f"/admin/users/{me}/password", password="brand new passphrase"
                ).headers["location"] == "/admin/users?m=self"


def test_audit_page_lists_admin_actions_and_is_admin_only(client, csrf):
    post(client, csrf, "/admin/users", username="bob", role="reader", password="temporary password 1")
    page = client.get("/admin/audit")
    assert page.status_code == 200 and "user_created" in page.text and "alice" in page.text
    with make_client() as c2:
        login_as(c2, "reader1", "reader")
        assert c2.get("/admin/audit").status_code == 403
        assert c2.get("/admin/users").status_code == 403
```

- [ ] **Step 2: Run, verify it fails**

Run: `python -m pytest tests/test_admin_users.py -v`
Expected: FAIL (404 on `/admin/users`).

- [ ] **Step 3: Complete `src/mc/web/routes_admin.py`**

Add to the imports at the top of the file:
```python
from mc.auth.passwords import MIN_LENGTH, hash_password
from mc.auth.users import create_user
from mc.models import AuditLog, Session
```
(and merge `from mc.models import Instance, User` into `from mc.models import AuditLog, Instance, Session, User`.)

Add at the end of the file:
```python
# --- users -----------------------------------------------------------------

USER_MESSAGES = {
    "created": "Utilisateur créé. Il devra enregistrer un second facteur à sa première connexion.",
    "deleted": "Utilisateur supprimé.",
    "role_ok": "Rôle modifié.",
    "reset_ok": "Second facteur réinitialisé : réenrôlement exigé à la prochaine connexion.",
    "pwd_ok": "Mot de passe réinitialisé ; compte déverrouillé, sessions fermées.",
    "pwd_short": f"Mot de passe trop court ({MIN_LENGTH} caractères minimum).",
    "self": "Action impossible sur votre propre compte (utilisez la page Compte).",
    "last_admin": "Il doit rester au moins un administrateur.",
}


def users_back(code: str) -> RedirectResponse:
    return RedirectResponse(f"/admin/users?m={code}", 303)


def users_page(request: Request, db, user: User, error=None, status=200):
    return render(request, "admin_users.html", status=status, user=user, error=error,
                  msg=USER_MESSAGES.get(request.query_params.get("m")),
                  users=db.query(User).order_by(User.username).all())


def admin_count(db) -> int:
    return db.query(User).filter_by(role="admin").count()


@router.get("/users")
async def users_get(request: Request, user: User = Depends(require_admin), db=Depends(get_db)):
    return users_page(request, db, user)


@router.post("/users")
async def users_create(request: Request, username: str = Form(""), role: str = Form("reader"),
                       password: str = Form(""), user: User = Depends(require_admin), db=Depends(get_db)):
    try:
        create_user(db, username, password, role)
    except ValueError as e:
        return users_page(request, db, user, str(e).capitalize(), 400)
    audit(db, "user_created", user.username, detail=f"{username} ({role})", ip=ip_of(request))
    db.commit()
    return users_back("created")


@router.post("/users/{uid}/role")
async def users_role(request: Request, uid: int, role: str = Form(...),
                     user: User = Depends(require_admin), db=Depends(get_db)):
    target = db.get(User, uid)
    if target is None or role not in ("admin", "reader"):
        return users_back("self")
    if target.role == "admin" and role != "admin" and admin_count(db) <= 1:
        return users_back("last_admin")
    target.role = role
    audit(db, "user_role_changed", user.username, detail=f"{target.username} -> {role}", ip=ip_of(request))
    db.commit()
    return users_back("role_ok")


@router.post("/users/{uid}/delete")
async def users_delete(request: Request, uid: int, user: User = Depends(require_admin), db=Depends(get_db)):
    target = db.get(User, uid)
    if target is None:
        return users_back("deleted")
    if target.id == user.id:
        return users_back("self")
    if target.role == "admin" and admin_count(db) <= 1:
        return users_back("last_admin")
    db.query(Session).filter_by(user_id=target.id).delete()
    audit(db, "user_deleted", user.username, detail=target.username, ip=ip_of(request))
    db.delete(target)
    db.commit()
    return users_back("deleted")


@router.post("/users/{uid}/reset-2fa")
async def users_reset_2fa(request: Request, uid: int, user: User = Depends(require_admin), db=Depends(get_db)):
    target = db.get(User, uid)
    if target is None or target.id == user.id:
        return users_back("self")
    target.totp_confirmed, target.totp_secret_enc, target.totp_last_step = False, None, 0
    target.credentials.clear()
    target.backup_codes.clear()
    db.query(Session).filter_by(user_id=target.id).delete()
    audit(db, "user_2fa_reset", user.username, detail=target.username, ip=ip_of(request))
    db.commit()
    return users_back("reset_ok")


@router.post("/users/{uid}/password")
async def users_password(request: Request, uid: int, password: str = Form(...),
                         user: User = Depends(require_admin), db=Depends(get_db)):
    target = db.get(User, uid)
    if target is None or target.id == user.id:
        return users_back("self")
    try:
        target.password_hash = hash_password(password)
    except ValueError:
        return users_back("pwd_short")
    target.failed_attempts, target.locked_until = 0, None
    db.query(Session).filter_by(user_id=target.id).delete()
    audit(db, "user_password_reset", user.username, detail=target.username, ip=ip_of(request))
    db.commit()
    return users_back("pwd_ok")


# --- audit -----------------------------------------------------------------

@router.get("/audit")
async def audit_get(request: Request, user: User = Depends(require_admin), db=Depends(get_db)):
    rows = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(200).all()
    return render(request, "admin_audit.html", user=user, rows=rows)
```

- [ ] **Step 4: Templates**

`src/mc/web/templates/admin_users.html` :
```html
{% extends "base.html" %}
{% block title %}Utilisateurs{% endblock %}
{% block content %}
<h1 class="h4 mb-3">Utilisateurs</h1>
{% if msg %}<div class="alert alert-info" role="status">{{ msg }}</div>{% endif %}
{% if error %}<div class="alert alert-danger" role="alert">{{ error }}</div>{% endif %}

<div class="table-responsive mb-5">
<table class="table align-middle">
  <thead><tr><th>Utilisateur</th><th>Rôle</th><th>2FA</th><th>Actions</th></tr></thead>
  <tbody>
  {% for u in users %}
  <tr>
    <td>{{ u.username }}{% if u.id == user.id %} <span class="badge text-bg-secondary">vous</span>{% endif %}</td>
    <td>
      <form method="post" action="/admin/users/{{ u.id }}/role" class="d-flex gap-2 m-0">
        <input type="hidden" name="csrf" value="{{ csrf }}">
        <label class="visually-hidden" for="role-{{ u.id }}">Rôle de {{ u.username }}</label>
        <select class="form-select form-select-sm" id="role-{{ u.id }}" name="role">
          <option value="reader" {% if u.role == 'reader' %}selected{% endif %}>lecteur</option>
          <option value="admin" {% if u.role == 'admin' %}selected{% endif %}>admin</option>
        </select>
        <button class="btn btn-sm btn-outline-secondary">OK</button>
      </form>
    </td>
    <td>{% if u.totp_confirmed or u.credentials %}<span class="badge text-bg-success">actif</span>{% else %}<span class="badge text-bg-warning">à enrôler</span>{% endif %}</td>
    <td>
      {% if u.id != user.id %}
      <div class="d-flex flex-wrap gap-2">
        <form method="post" action="/admin/users/{{ u.id }}/reset-2fa" class="m-0">
          <input type="hidden" name="csrf" value="{{ csrf }}"><button class="btn btn-sm btn-outline-warning">Réinitialiser le 2FA</button></form>
        <form method="post" action="/admin/users/{{ u.id }}/password" class="d-flex gap-1 m-0">
          <input type="hidden" name="csrf" value="{{ csrf }}">
          <label class="visually-hidden" for="pw-{{ u.id }}">Nouveau mot de passe pour {{ u.username }}</label>
          <input class="form-control form-control-sm" id="pw-{{ u.id }}" name="password" type="password" autocomplete="new-password" placeholder="Nouveau mot de passe" minlength="12" required>
          <button class="btn btn-sm btn-outline-secondary">Réinitialiser</button></form>
        <form method="post" action="/admin/users/{{ u.id }}/delete" class="m-0">
          <input type="hidden" name="csrf" value="{{ csrf }}"><button class="btn btn-sm btn-outline-danger">Supprimer</button></form>
      </div>
      {% endif %}
    </td>
  </tr>
  {% endfor %}
  </tbody>
</table>
</div>

<h2 class="h5">Créer un utilisateur</h2>
<form method="post" action="/admin/users" class="col-lg-5">
  <input type="hidden" name="csrf" value="{{ csrf }}">
  <div class="mb-3"><label class="form-label" for="username">Nom d'utilisateur</label>
    <input class="form-control" id="username" name="username" autocomplete="off" required></div>
  <div class="mb-3"><label class="form-label" for="role">Rôle</label>
    <select class="form-select" id="role" name="role"><option value="reader">lecteur</option><option value="admin">admin</option></select></div>
  <div class="mb-3"><label class="form-label" for="password">Mot de passe initial (12 caractères minimum)</label>
    <input class="form-control" id="password" name="password" type="password" autocomplete="new-password" minlength="12" required>
    <div class="form-text">Communiquez-le par un canal sûr ; le second facteur sera exigé à la première connexion.</div></div>
  <button class="btn btn-primary">Créer</button>
</form>
{% endblock %}
```

`src/mc/web/templates/admin_audit.html` :
```html
{% extends "base.html" %}
{% block title %}Audit{% endblock %}
{% block content %}
<h1 class="h4 mb-3">Journal d'audit <small class="text-secondary fs-6">(200 derniers événements)</small></h1>
<div class="mb-3"><input class="form-control" type="search" placeholder="Filtrer…" aria-label="Filtrer" data-filter-for="t-audit"></div>
<div class="table-responsive">
<table class="table table-sm align-middle" id="t-audit" data-table>
  <thead><tr><th data-sort>Date</th><th data-sort>Utilisateur</th><th data-sort>Événement</th><th data-sort>Détail</th><th data-sort>IP</th></tr></thead>
  <tbody>
  {% for e in rows %}
  <tr><td data-v="{{ e.id }}">{{ e.at | dt }}</td><td>{{ e.username or '—' }}</td><td>{{ e.event }}</td><td>{{ e.detail or '—' }}</td><td>{{ e.ip or '—' }}</td></tr>
  {% else %}<tr><td colspan="5" class="text-secondary">Aucun événement.</td></tr>
  {% endfor %}
  </tbody>
</table>
</div>
{% endblock %}
```

- [ ] **Step 5: Run, verify it passes**

Run: `python -m pytest tests/test_admin_users.py -v`
Expected: 8 passed.

- [ ] **Step 6: Full suite**

Run: `python -m pytest -q && ruff check src tests`
Expected: all green.

- [ ] **Step 7: Commit**

```bash
git add src/mc tests/test_admin_users.py
git commit -m "feat: user administration and audit log"
```

---

### Task 6: Delivery (Docker, compose, README, license, CI)

**Files:**
- Create: `Dockerfile`, `docker-compose.yml`, `.env.example`, `README.md`, `LICENSE`, `.dockerignore`, `.github/workflows/ci.yml`

- [ ] **Step 1: `Dockerfile`**

```dockerfile
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    MC_DATABASE_URL=sqlite:////data/mc.db

RUN useradd --create-home --uid 10001 mc && mkdir /data && chown mc /data
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

USER mc
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/login').status == 200 else 1)"

# FORWARDED_ALLOW_IPS (read by uvicorn): IP of the reverse proxy allowed to set X-Forwarded-For.
CMD ["uvicorn", "mc.web.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
```

`.dockerignore` :
```
.git
.venv
data
docs
tests
dev
__pycache__
.env
```

- [ ] **Step 2: `docker-compose.yml`**

```yaml
services:
  mission-control:
    build: .
    restart: unless-stopped
    env_file: .env
    environment:
      FORWARDED_ALLOW_IPS: "${MC_TRUSTED_PROXY:-127.0.0.1}"
    volumes:
      - mc-data:/data
    # Local access only by default. To expose via BunkerWeb: remove "ports" and
    # attach this service to BunkerWeb's Docker network (see README).
    ports:
      - "127.0.0.1:8000:8000"
    read_only: true
    tmpfs:
      - /tmp
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true

volumes:
  mc-data: {}
```

`.env.example` :
```
# Encryption key for BunkerWeb tokens (REQUIRED). Generate with:
#   python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())"
# Back it up off the server: without it, stored tokens are lost.
MC_SECRET_KEY=

# WebAuthn domain (passkeys) and allowed origins (JSON). Put ALL access URLs.
MC_RP_ID=mc.example.com
MC_ORIGINS=["https://mc.example.com","http://localhost:8000"]

# true behind HTTPS (Secure cookies + HSTS). false only for a local HTTP trial.
MC_COOKIE_SECURE=true

# IP of the trusted reverse proxy (for the client IP in the audit log and brute-force protection)
MC_TRUSTED_PROXY=127.0.0.1

# Optional
# MC_POLL_INTERVAL=30
# MC_PROBE_INTERVAL=900
# MC_HTTP_TIMEOUT=5
```

- [ ] **Step 3: AGPLv3 license**

Run:
```bash
curl -fsSL -o LICENSE https://www.gnu.org/licenses/agpl-3.0.txt
head -3 LICENSE
```
Expected: `GNU AFFERO GENERAL PUBLIC LICENSE` / `Version 3, 19 November 2007`.

- [ ] **Step 4: `README.md`**

````markdown
# BunkerWeb Mission Control

**Read-only** monitoring of several [BunkerWeb](https://www.bunkerweb.io/) instances (2 to 10, same network) from a single interface, via the BunkerWeb API.

- Instance health, protected services, active bans, jobs and plugins (with differences between instances)
- Status of the certificates actually served (direct TLS probe: presence, issuer, expiry)
- Strong authentication: password (argon2id) + **mandatory** second factor (TOTP or WebAuthn passkey), recovery codes, brute-force protection, audit log
- Roles `admin` / `reader`
- No write access to BunkerWeb: the client only issues `GET` requests

License: AGPL-3.0-or-later.

## Quick start (Docker)

```bash
cp .env.example .env
# fill in MC_SECRET_KEY (see the file), MC_RP_ID and MC_ORIGINS
docker compose up -d --build
docker compose exec -it mission-control mc bootstrap-admin --username admin
```

Open `http://localhost:8000` and log in: enrolling a second factor (TOTP) is required before any access. Then add your instances under **Instances**.

## BunkerWeb API token (read-only)

On the BunkerWeb side (see the API section of its documentation), create a dedicated identity with read permissions only: `instances_read`, `service_read`, `global_config_read`, `ban_read`, `job_read`, `plugin_read`. Paste its token into Mission Control; it is encrypted in the database and never displayed again.

## Local and domain access

- Same application for both accesses. List all URLs in `MC_ORIGINS` (cross-origin request protection).
- **Passkeys are bound to the domain** (`MC_RP_ID`): they work through the domain, not through `localhost`/IP. Locally, use TOTP.
- Behind BunkerWeb: remove `ports` from `docker-compose.yml`, attach the service to BunkerWeb's network, declare the service in BunkerWeb with `USE_REVERSE_PROXY=yes` and the internal URL `http://mission-control:8000`, and set `MC_TRUSTED_PROXY` to BunkerWeb's IP on that network.

## Security

- `HttpOnly`, `Secure`, `SameSite=Strict` cookies, server-side sessions (8 h idle, 24 h max), CSRF, strict CSP, HSTS.
- Back up `MC_SECRET_KEY`: it encrypts the BunkerWeb tokens. If lost, they must be re-entered.
- Back up the `/data` volume (SQLite).

## Development

```bash
python -m venv .venv && source .venv/Scripts/activate   # Windows (Git Bash); .venv/bin/activate on Linux
pip install -e ".[dev]"
python -m pytest
ruff check src tests
```

Demo without a real instance: see `dev/fake_bunkerweb.py`.
````

- [ ] **Step 5: CI** — `.github/workflows/ci.yml`

```yaml
name: ci
on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -e ".[dev]"
      - run: ruff check src tests
      - run: python -m pytest -q
```

- [ ] **Step 6: Verify the Docker build (if Docker is available)**

Run: `docker build -t bunkerweb-mission-control .`
Expected: build succeeds. If Docker is not installed, note the step as unverified.

- [ ] **Step 7: Commit**

```bash
git add Dockerfile .dockerignore docker-compose.yml .env.example LICENSE README.md .github
git commit -m "chore: Docker, compose, README, AGPLv3 license, CI"
```
Note: if `git push` rejects the workflow file ("refusing to allow an OAuth App to create or update workflow"), run `gh auth refresh -s workflow` and push again.

---

### Task 7: Fake BunkerWeb server (demo and manual testing)

**Files:**
- Create: `dev/fake_bunkerweb.py`

Mimics the BunkerWeb API (assumed shapes, see `normalize.py`) and a self-signed "Let's Encrypt" TLS server for the probe. Used to explore the interface without a real instance.

- [ ] **Step 1: Write `dev/fake_bunkerweb.py`**

```python
"""Fake BunkerWeb for the demo. Start two instances:

  FAKE_DAYS=15 FAKE_TLS_PORT=9443 uvicorn --app-dir dev fake_bunkerweb:app --port 9001
  FAKE_DAYS=60 FAKE_TLS_PORT=9444 FAKE_EXTRA=1 uvicorn --app-dir dev fake_bunkerweb:app --port 9002

In Mission Control: URL http://127.0.0.1:9001 (any token), empty probe host, TLS port 9443.
"""
import asyncio
import os
import ssl
import tempfile
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import FastAPI

DAYS = int(os.environ.get("FAKE_DAYS", "30"))
TLS_PORT = int(os.environ.get("FAKE_TLS_PORT", "0"))
EXTRA = os.environ.get("FAKE_EXTRA") == "1"

SERVICES = {"www.example.test": "block", "api.example.test": "detect"}
if EXTRA:
    SERVICES["blog.example.test"] = "block"


def _write_cert(directory: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Let's Encrypt"),
                      x509.NameAttribute(NameOID.COMMON_NAME, "R11")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=DAYS)).sign(key, hashes.SHA256()))
    cf, kf = directory / "cert.pem", directory / "key.pem"
    cf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kf.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    return cf, kf


@asynccontextmanager
async def lifespan(_: FastAPI):
    server = None
    if TLS_PORT:
        cf, kf = _write_cert(Path(tempfile.mkdtemp()))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cf, kf)

        async def handle(_r, w):
            w.close()

        server = await asyncio.start_server(handle, "127.0.0.1", TLS_PORT, ssl=ctx)
    yield
    if server:
        server.close()


app = FastAPI(lifespan=lifespan)


@app.get("/ping")
def ping():
    return {"status": "success", "message": "pong", "version": "1.6.0-fake"}


@app.get("/services")
def services():
    return {"status": "success", "services": [{"id": s, "is_draft": False} for s in SERVICES]}


@app.get("/services/{service}")
def service(service: str, full: bool = False):
    return {f"{service}_SECURITY_MODE": SERVICES.get(service, "detect")}


@app.get("/bans")
def bans():
    out = [{"ip": "203.0.113.7", "reason": "antibot", "service": "www.example.test", "exp": 3600, "date": 1}]
    if EXTRA:
        out.append({"ip": "198.51.100.9", "reason": "modsecurity", "service": "global", "exp": 600, "date": 2})
    return {"status": "success", "bans": out}


@app.get("/jobs")
def jobs():
    return {"status": "success", "jobs": {
        "certbot-renew": {"plugin": "letsencrypt", "every": "day",
                          "history": [{"success": True, "end_date": "2026-10-22 03:00:00"}]},
        "blacklist-download": {"plugin": "blacklist", "every": "hour",
                               "history": [{"success": not EXTRA, "end_date": "2026-10-22 10:00:00"}]}}}


@app.get("/plugins")
def plugins():
    return {"status": "success", "plugins": [
        {"id": "antibot", "name": "Antibot", "version": "1.9" if EXTRA else "1.8", "type": "core"},
        {"id": "letsencrypt", "name": "Let's Encrypt", "version": "1.8", "type": "core"}]}
```

- [ ] **Step 2: Manual verification**

Run (3 terminals, venv activated, `MC_*` variables from Plan 2 Task 10):
```bash
FAKE_DAYS=15 FAKE_TLS_PORT=9443 uvicorn --app-dir dev fake_bunkerweb:app --port 9001
FAKE_DAYS=60 FAKE_TLS_PORT=9444 FAKE_EXTRA=1 uvicorn --app-dir dev fake_bunkerweb:app --port 9002
MC_COLLECTOR_ENABLED=true uvicorn mc.web.app:create_app --factory --port 8000
```
In the interface, add `bw1` (`http://127.0.0.1:9001`, token `x`, TLS port 9443) and `bw2` (`http://127.0.0.1:9002`, token `x`, TLS port 9444).
Expected after ~20 s: 2 instances "OK"; Services: `blog.example.test` flagged "absent sur : bw1"; Bans: `198.51.100.9` "absent sur : bw1"; Plugins: `antibot` shown as "écart"; Certificates: bw1 orange (15 d), bw2 valid (60 d), Let's Encrypt badge.

- [ ] **Step 3: Commit**

```bash
git add dev/fake_bunkerweb.py
git commit -m "chore: fake BunkerWeb server for demo"
```

---

### Task 8: Validation against a real BunkerWeb instance and wrap-up

The JSON shapes of the BunkerWeb API are undocumented: this task aligns the normalizers with reality.

- [ ] **Step 1: Fetch the schema and real responses**

Run (replace `HOST`, `PORT`, `TOKEN`):
```bash
mkdir -p tests/fixtures
B=http://HOST:PORT; H="Authorization: Bearer TOKEN"
curl -s $B/openapi.json -o tests/fixtures/openapi.json
for p in ping services bans jobs plugins instances; do
  curl -s -H "$H" $B/$p | python -m json.tool > tests/fixtures/real_$p.json
done
S=$(python -c "import json;d=json.load(open('tests/fixtures/real_services.json'));print((d.get('services') or d)[0]['id'])" 2>/dev/null)
curl -s -H "$H" "$B/services/$S?full=true" | python -m json.tool > tests/fixtures/real_service_full.json
```
Expected: readable JSON files. **Do not commit secrets**: review the fixtures and mask sensitive IPs/domains before any commit.

- [ ] **Step 2: Compare against the assumptions**

For each fixture, check that `normalize` produces a consistent result:
```bash
python - <<'EOF'
import json
from mc import normalize as N
load = lambda n: json.load(open(f"tests/fixtures/real_{n}.json"))
print("services", N.services(load("services")))
print("mode", N.security_mode(load("service_full")))
print("bans", N.bans(load("bans")))
print("jobs", N.jobs(load("jobs")))
print("plugins", N.plugins(load("plugins")))
print("ping", load("ping"))
EOF
```
Check: correct domain names, `mode` ∈ {block, detect}, bans with IP and duration, jobs with last result, plugins with version, whether `ping` contains `version` or not.

- [ ] **Step 3: Adjust `normalize.py` if needed (TDD)**

For each discrepancy: add to `tests/test_normalize.py` a test that loads the real (anonymized) fixture and asserts the expected result; watch it fail; adapt `src/mc/normalize.py` (new field names in `_pick`, new shape in `_items`); rerun `python -m pytest tests/test_normalize.py -v` until green. Also check the **semantics of the bans expiry field** (remaining seconds or a date) and adjust `bans.html` (readable formatting) accordingly; if the BunkerWeb version is exposed somewhere other than `/ping` (e.g. `/instances`), adapt `BWClient.ping`.

- [ ] **Step 4: Validate end to end with 2 real instances**

Start the application (Task 7 Step 2, without the fake servers), add the 2 instances (read-only token), then check: OK status, correct services and modes, bans consistent with the BunkerWeb UI, jobs/plugins, certificates (compare the expiry date with `openssl s_client -connect IP:443 -servername DOMAINE </dev/null 2>/dev/null | openssl x509 -noout -enddate`).

- [ ] **Step 5: Final verification and publication**

Run:
```bash
python -m pytest -q
ruff check src tests
git add -A
git commit -m "test: align normalizers with real BunkerWeb API responses"
git push
```
Expected: all green, `main` branch up to date on GitHub.
