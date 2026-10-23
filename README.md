# BunkerWeb Mission Control

Supervision **en lecture seule** de plusieurs instances [BunkerWeb](https://www.bunkerweb.io/) (2 à 10, même réseau) depuis une seule interface, via l'API BunkerWeb.

- Santé des instances, services protégés, bans actifs, jobs et plugins (avec écarts entre instances)
- État des certificats réellement servis (sonde TLS directe : existence, émetteur, expiration)
- Authentification forte : mot de passe (argon2id) + second facteur **obligatoire** (TOTP ou passkey WebAuthn), codes de secours, anti-bruteforce, audit
- Rôles `admin` / `lecteur`
- Aucun accès en écriture à BunkerWeb : le client n'émet que des `GET`

Licence : AGPL-3.0-or-later.

## Démarrage rapide (Docker)

```bash
cp .env.example .env
# renseigner MC_SECRET_KEY (voir le fichier), MC_RP_ID et MC_ORIGINS
docker compose up -d --build
docker compose exec -it mission-control mc bootstrap-admin --username admin
```

Ouvrez `http://localhost:8000`, connectez-vous : l'enrôlement d'un second facteur (TOTP) est exigé avant tout accès. Ajoutez ensuite vos instances dans **Instances**.

## Token d'API BunkerWeb

Mission Control envoie un en-tête fixe `Authorization: Bearer <token>`. D'après la documentation BunkerWeb, le seul jeton statique documenté est `API_TOKEN` (accès **administrateur** complet). Les jetons à droits restreints (Biscuit, permissions `instances_read`, `service_read`, `global_config_read`, `ban_read`, `job_read`, `plugin_read`) s'obtiennent via `POST /auth` ; leur durée de vie n'est pas documentée et Mission Control ne se ré-authentifie pas encore.

Conséquence : l'application ne fait que des `GET` (garanti par le code du client), mais si vous lui donnez `API_TOKEN`, ce token reste un secret d'administration BunkerWeb. Il est chiffré en base et jamais réaffiché ; restreignez par ailleurs l'accès réseau à l'API (liste d'IP autorisées). Si vous utilisez un jeton Biscuit restreint, ressaisissez-le à son expiration.

## Accès local et par domaine

- Même application pour les deux accès. Listez toutes les URLs dans `MC_ORIGINS` (protection contre les requêtes inter-origines).
- Les **passkeys sont liées au domaine** (`MC_RP_ID`) : elles fonctionnent via le domaine, pas via `localhost`/IP. En local, utilisez le TOTP.
- **Attention** : un `MC_TRUSTED_PROXY` incorrect fait partager un seul compteur d'IP (limitation de débit) à tous les clients.
- Derrière BunkerWeb : retirez `ports` du `docker-compose.yml`, rattachez le service au réseau de BunkerWeb, déclarez le service dans BunkerWeb avec `USE_REVERSE_PROXY=yes` et l'URL interne `http://mission-control:8000`, et renseignez `MC_TRUSTED_PROXY` avec l'IP de BunkerWeb sur ce réseau.

## Sécurité

- Cookies `HttpOnly`, `Secure`, `SameSite=Strict`, sessions serveur (8 h d'inactivité, 24 h max), CSRF, CSP stricte, HSTS.
- Sauvegardez `MC_SECRET_KEY` : elle chiffre les tokens BunkerWeb. Perdue, il faut les ressaisir.
- Sauvegardez le volume `/data` (SQLite).

## Validation de bout en bout avec de vraies instances

`dev/docker-compose.bunkerweb.yml` définit deux piles BunkerWeb indépendantes (bw1 : API sur 8081, TLS 8443 ; bw2 : API sur 8082, TLS 9443) avec un upstream trivial. **Ce fichier n'a jamais été exécuté** (Docker absent de la machine de rédaction) : il suit la documentation officielle mais doit être validé ; les points incertains y sont commentés (notamment le token : seul `API_TOKEN`, accès admin, est documenté comme Bearer statique). L'en-tête du fichier explique comment enregistrer les instances dans Mission Control. Ensuite, alignez `src/mc/normalize.py` sur les réponses réelles : voir Plan 3, Task 8 (`docs/superpowers/plans/2026-10-22-plan-3-views-delivery.md`).

## Développement

```bash
python -m venv .venv && source .venv/Scripts/activate   # Windows (Git Bash) ; .venv/bin/activate sous Linux
pip install -e ".[dev]"
python -m pytest
ruff check src tests
```

Démo sans vraie instance : voir `dev/fake_bunkerweb.py`.
