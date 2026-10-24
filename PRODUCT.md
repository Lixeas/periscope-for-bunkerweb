# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Admins and readers of a small BunkerWeb fleet (2 to 10 instances on the same network). Two usage situations, both confirmed: occasional consultation at a workstation (check fleet health, investigate a ban or an expiring certificate), and permanent display on a dedicated screen. Roles: `admin` (manages users, instances, audit) and `reader` (read-only dashboards).

## Product Purpose

Periscope for BunkerWeb is a self-hosted, read-only web console giving a single view over several BunkerWeb instances, so nobody has to open each instance's own UI one by one. Success: the state of the whole fleet (health, services, bans, jobs and plugins, certificates) is readable at a glance, and differences between instances are visible without manual comparison.

## Positioning

Cross-instance view built on differences: services missing on some instances, IPs banned on only some, plugin version drift, certificates actually served (direct TLS probe, inspected not validated). Strictly read-only by design (GET only, plus one `POST /auth`). Independent community project, not affiliated with Bunkerity.

## Operating Context

One process (FastAPI + Jinja2) with a background collector (30 s) and a slower TLS probe (15 min); the web layer only reads the database. Reached locally or behind a domain name, always behind HTTPS in production. Data freshness matters: stale and unreachable instances are first-class states. Sign-in uses a password plus a mandatory second factor (TOTP or passkey).

## Capabilities and Constraints

- Views: Home (instance cards, scheduler and worker nodes, global counters), Services, Bans, Jobs and plugins, Certificates, Administration (instances, users, audit), Account.
- Bilingual UI: English (source, default) and French, with a language switch; light and dark themes; sortable and filterable tables.
- Technical constraints: no CDN, local assets only, vanilla JS, strict CSP (`script-src 'self'`, no inline JS or style). Server-rendered Jinja2 templates; Bootstrap is the current base and is replaceable.
- Statuses to express: ok, degraded, down/unreachable, stale, disabled; node states up, loading, down, failover; certificate states valid, expires soon (under 21 d), critical (under 7 d), expired, none; mode block or detect.
- Open decision: long-term adoption by the BunkerWeb team is not a binding constraint on the visual identity.

## Brand Commitments

Name: "Periscope for BunkerWeb", short name "Periscope". Independent identity, distinct from BunkerWeb: no Bunkerity logo or brand colors. The footer disclaimer "Independent project, not affiliated with Bunkerity" stays. A full visual rework is requested; no existing visual element is binding.

## Evidence on Hand

No logo or brand assets exist. The project has not yet been validated against real BunkerWeb instances; the UI must not imply production data that does not exist. No testimonials, customers or benchmarks exist; do not fabricate any.

## Product Principles

- Differences between instances are the point: surface them before raw data.
- Status must be unambiguous at a distance and never carried by color alone.
- Read-only trust: the interface never suggests it can act on BunkerWeb.
- Stale or missing data is shown honestly, never hidden.
- Equally usable for a quick lookup and for permanent display.

## Accessibility & Inclusion

WCAG 2.2 AA minimum on every page. The light theme is the default; the dark theme is a reader choice and must stay fully supported. Keyboard operation and screen readers are required for tables, navigation and live-updating values.
