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

Lancer l'app en local (variables `PERISCOPE_*` lues par `periscope.config.Settings`, `PERISCOPE_SECRET_KEY` obligatoire) :

```bash
export PERISCOPE_SECRET_KEY=$(python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())")
export PERISCOPE_COOKIE_SECURE=false          # HTTP local uniquement
periscope bootstrap-admin --username admin    # crée le 1er admin (+ applique les migrations)
uvicorn periscope.web.app:create_app --factory --port 8000
```

Démo sans vraie instance : `dev/fake_bunkerweb.py` (voir son en-tête pour les 2 commandes uvicorn, ports 9001/9002, TLS 9443/9444). `FAKE_AUTH=1 FAKE_TTL=<s>` active `POST /auth` (utilisateur `periscope`, mot de passe `FAKE_PASSWORD`, défaut `secret`) et exige un Bearer expirant sur les endpoints de données.

Migration : `alembic revision --autogenerate -m "..."` (utilise `alembic.ini`, SQLite jetable `data/autogen.db`) ; l'app applique `alembic upgrade head` au démarrage via `periscope.db.migrate()`. Les migrations vivent dans `src/periscope/migrations/` (dans le package).

## Architecture

Un seul processus : `periscope.web.app.create_app()` lance le serveur FastAPI **et**, dans le `lifespan`, la tâche `periscope.collector.run_forever()` (désactivable avec `PERISCOPE_COLLECTOR_ENABLED=false`, ce que font les tests).

Flux de données — **le web ne lit jamais BunkerWeb**, uniquement la base :
1. `collector` : toutes les `PERISCOPE_POLL_INTERVAL` s, une tâche par instance → `BWClient` (`bw_client.py` : toutes les données via `_get`, GET uniquement ; seule autre requête permise : `POST /auth`, aucune méthode publique d'écriture ; deux modes d'authentification, voir plus bas) → `normalize.py` → upsert d'un `Snapshot` par (instance, type : services/bans/jobs/plugins). Échec réseau = statut `down`, dernier snapshot conservé ; échec partiel = `degraded`.
2. Sonde TLS (`tlsprobe.py`, boucle plus lente `PERISCOPE_PROBE_INTERVAL`) : handshake vers `IP_instance:port` avec SNI = domaine de chaque service non-brouillon ; lit le certificat sans le valider (volontaire : détecter expirés/auto-signés). Résultats dans `CertProbe`.
3. `queries.py` transforme les snapshots en modèles de vue (écarts entre instances via `diff.py`, statuts de certificat 7 j rouge / 21 j orange). `web/routes_views.py` est mince.

`normalize.py` est le **seul point couplé à la forme JSON de l'API BunkerWeb**, qui n'est pas documentée. Les formes sont désormais **dérivées de la lecture du source de BunkerWeb v1.6.17** (routers/*.py, Database.py, api.lua, banlease.lua), pas capturées sur une instance vivante : `/services` fournit `security_mode` par service (repli sur `/services/{id}?full=true` → `config` seulement s'il manque), `/bans` est un dict par instance nginx (dédupliqué par (ip, service, ban_scope, kind), `exp` = secondes restantes, 0 = permanent ; HTTP 502 accepté si le corps est ce dict), `/jobs` est un dict indexé par nom (`plugin_id`, `history` par `end_date` décroissante), `/ping` n'a pas de `version` : elle est lue par `BWClient.version()` : d'abord dans le fait `version` du jeton Biscuit détenu (mode `user` ; `biscuit_version.py`, extracteur protobuf sans dépendance lisant la table de symboles du bloc d'autorité, sans clé ni requête), sinon dans `info.version` du document public `GET /openapi.json` (qui renvoie un 500 sur au moins une vraie instance 1.6.17 ; le fake le imite sauf `FAKE_OPENAPI=1`) (sous le préfixe racine de l'API, déjà inclus dans `base_url` ; jamais fatal, renvoie None au moindre problème ; le collecteur ne la demande que si inconnue ou datée de plus d'1 h, `collector._VERSION_CHECKED`). Un 500 y a été observé sur une vraie instance sans le préfixe racine ; non confirmé en réel. Les formes historiques supposées restent acceptées. Si l'API réelle diffère, n'ajuster que ce fichier et ses tests. La validation sur une vraie instance reste à faire (Plan 3, tâche 8).

Authentification (`src/periscope/auth/` logique, `src/periscope/web/routes_auth.py` + `routes_account.py` routes) :
- Connexion en 2 temps : le mot de passe crée une session `mfa_ok=False` (TTL 5 min) ; le second facteur la remplace par une session pleine avec **rotation du jeton** (`sessions.promote`). Les sessions sont côté serveur (table `sessions`, jeton stocké haché).
- Second facteur obligatoire : un utilisateur sans facteur est forcé vers `/enroll` (TOTP). Passkeys WebAuthn ajoutables ensuite depuis `/account`. TOTP anti-rejeu via `User.totp_last_step`.
- `web/deps.py` : `current_user` / `pending_user` / `require_admin` valident la session **et le CSRF** (champ `csrf` ou en-tête `X-CSRF-Token`) pour toute méthode non-GET ; un middleware refuse les `Origin` hors `PERISCOPE_ORIGINS`. Toute nouvelle route d'écriture authentifiée doit passer par ces dépendances.
- Verrouillage : à l'étape mot de passe, par (identifiant, IP) en mémoire (`ratelimit.LoginFailures`, jamais sur le compte réel, anti-DoS) ; le verrou de compte (`User.failed_attempts`, `ratelimit.register_failure`) ne s'applique qu'à partir du 2FA/enrôlement/passkey et à la ré-authentification. + limiteur par IP en mémoire (processus unique). Les actions sensibles du compte passent par `reauth()` / `revoke_other_sessions()` (`web/reauth.py`).
- Authentification BunkerWeb (`Instance.auth_mode`) : `user` (recommandé) = utilisateur d'API restreint, `api_username` + `api_password_enc` ; `BWClient(credentials=...)` obtient un jeton Biscuit via `POST /auth` (Basic), l'envoie en Bearer, et sur 401 se ré-authentifie une fois et rejoue une fois (échec de `/auth` = `BWError('auth')`, pas de boucle). `token` = `API_TOKEN` statique (`token_enc`, admin, déconseillé). Le collecteur garde les jetons dans `collector._TOKEN_CACHE` (en mémoire, clé = id instance + empreinte sha256 des identifiants chiffrés, donc invalidé à l'édition). Jamais de mot de passe/jeton dans les messages d'erreur ni les logs.
- Mots de passe et tokens API BunkerWeb sont chiffrés en base (Fernet, clé `PERISCOPE_SECRET_KEY`, `crypto.py`) et jamais réaffichés.

Conventions utiles :
- Datetimes en **UTC naïf** partout (`clock.utcnow()`), car SQLite ne garde pas le fuseau.
- Accès DB synchrones dans le code async (assumé, ≤ 10 instances) ; en tests, utiliser la fixture `fresh_db` (SQLite mémoire) et `session_scope()`, jamais de session ouverte pendant l'appel au collecteur.
- Front sans CDN : Bootstrap en copie locale, JS vanilla dans `web/static/`, CSP stricte (`script-src 'self'`, pas de JS ni de style inline).
- Les passkeys sont liées à `PERISCOPE_RP_ID` (domaine) : inutilisables via IP/localhost, où le TOTP sert de repli.
- Tests web : helpers dans `tests/helpers.py` (`login_as`, `make_user`, `csrf_of`) ; dans les tests SQLAlchemy, lier l'objet à une variable avant `x.relation.append(...)` (sinon `ObjectDereferencedError`).
