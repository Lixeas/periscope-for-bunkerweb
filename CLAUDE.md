# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Application web de supervision **en lecture seule** de 2 à 10 instances BunkerWeb (même réseau) via leur API. Python 3.11+, FastAPI, SQLAlchemy, Jinja2. Spec : `docs/superpowers/specs/`, plans d'implémentation : `docs/superpowers/plans/`. Interface et messages en français.

## Commandes

```bash
python -m venv .venv && source .venv/Scripts/activate   # Git Bash sous Windows
pip install -e ".[dev]"
python -m pytest -q                                      # suite complète
python -m pytest tests/test_collector.py::test_collect_ok_stores_snapshots -v   # un seul test
ruff check src tests dev                                 # lint (doit rester propre)
```

Lancer l'app en local (variables `MC_*` lues par `mc.config.Settings`, `MC_SECRET_KEY` obligatoire) :

```bash
export MC_SECRET_KEY=$(python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())")
export MC_COOKIE_SECURE=false          # HTTP local uniquement
mc bootstrap-admin --username admin    # crée le 1er admin (+ applique les migrations)
uvicorn mc.web.app:create_app --factory --port 8000
```

Démo sans vraie instance : `dev/fake_bunkerweb.py` (voir son en-tête pour les 2 commandes uvicorn, ports 9001/9002, TLS 9443/9444).

Migration : `alembic revision --autogenerate -m "..."` (utilise `alembic.ini`, SQLite jetable `data/autogen.db`) ; l'app applique `alembic upgrade head` au démarrage via `mc.db.migrate()`. Les migrations vivent dans `src/mc/migrations/` (dans le package).

## Architecture

Un seul processus : `mc.web.app.create_app()` lance le serveur FastAPI **et**, dans le `lifespan`, la tâche `mc.collector.run_forever()` (désactivable avec `MC_COLLECTOR_ENABLED=false`, ce que font les tests).

Flux de données — **le web ne lit jamais BunkerWeb**, uniquement la base :
1. `collector` : toutes les `MC_POLL_INTERVAL` s, une tâche par instance → `BWClient` (`bw_client.py`, GET uniquement, aucune méthode d'écriture par construction) → `normalize.py` → upsert d'un `Snapshot` par (instance, type : services/bans/jobs/plugins). Échec réseau = statut `down`, dernier snapshot conservé ; échec partiel = `degraded`.
2. Sonde TLS (`tlsprobe.py`, boucle plus lente `MC_PROBE_INTERVAL`) : handshake vers `IP_instance:port` avec SNI = domaine de chaque service non-brouillon ; lit le certificat sans le valider (volontaire : détecter expirés/auto-signés). Résultats dans `CertProbe`.
3. `queries.py` transforme les snapshots en modèles de vue (écarts entre instances via `diff.py`, statuts de certificat 7 j rouge / 21 j orange). `web/routes_views.py` est mince.

`normalize.py` est le **seul point couplé à la forme JSON de l'API BunkerWeb**, qui n'est pas documentée : parseurs volontairement tolérants (plusieurs noms de champs). Si l'API réelle diffère (`/openapi.json` de l'instance), n'ajuster que ce fichier et ses tests. La validation sur une vraie instance reste à faire (Plan 3, tâche 8).

Authentification (`src/mc/auth/` logique, `src/mc/web/routes_auth.py` + `routes_account.py` routes) :
- Connexion en 2 temps : le mot de passe crée une session `mfa_ok=False` (TTL 5 min) ; le second facteur la remplace par une session pleine avec **rotation du jeton** (`sessions.promote`). Les sessions sont côté serveur (table `sessions`, jeton stocké haché).
- Second facteur obligatoire : un utilisateur sans facteur est forcé vers `/enroll` (TOTP). Passkeys WebAuthn ajoutables ensuite depuis `/account`. TOTP anti-rejeu via `User.totp_last_step`.
- `web/deps.py` : `current_user` / `pending_user` / `require_admin` valident la session **et le CSRF** (champ `csrf` ou en-tête `X-CSRF-Token`) pour toute méthode non-GET ; un middleware refuse les `Origin` hors `MC_ORIGINS`. Toute nouvelle route d'écriture authentifiée doit passer par ces dépendances.
- Verrouillage par compte (`ratelimit.py`, compteur partagé mot de passe / 2FA / ré-authentification) + limiteur par IP en mémoire (processus unique). Les actions sensibles du compte passent par `reauth()` / `revoke_other_sessions()` (`web/reauth.py`).
- Les tokens API BunkerWeb sont chiffrés en base (Fernet, clé `MC_SECRET_KEY`, `crypto.py`) et jamais réaffichés.

Conventions utiles :
- Datetimes en **UTC naïf** partout (`clock.utcnow()`), car SQLite ne garde pas le fuseau.
- Accès DB synchrones dans le code async (assumé, ≤ 10 instances) ; en tests, utiliser la fixture `fresh_db` (SQLite mémoire) et `session_scope()`, jamais de session ouverte pendant l'appel au collecteur.
- Front sans CDN : Bootstrap en copie locale, JS vanilla dans `web/static/`, CSP stricte (`script-src 'self'`, pas de JS ni de style inline).
- Les passkeys sont liées à `MC_RP_ID` (domaine) : inutilisables via IP/localhost, où le TOTP sert de repli.
- Tests web : helpers dans `tests/helpers.py` (`login_as`, `make_user`, `csrf_of`) ; dans les tests SQLAlchemy, lier l'objet à une variable avant `x.relation.append(...)` (sinon `ObjectDereferencedError`).
