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

## Token d'API BunkerWeb (lecture seule)

Créez, côté BunkerWeb (voir la section API de la documentation), une identité dédiée n'ayant que les permissions de lecture : `instances_read`, `service_read`, `global_config_read`, `ban_read`, `job_read`, `plugin_read`. Collez son token dans Mission Control ; il est chiffré en base et n'est jamais réaffiché.

## Accès local et par domaine

- Même application pour les deux accès. Listez toutes les URLs dans `MC_ORIGINS` (protection contre les requêtes inter-origines).
- Les **passkeys sont liées au domaine** (`MC_RP_ID`) : elles fonctionnent via le domaine, pas via `localhost`/IP. En local, utilisez le TOTP.
- **Attention** : un `MC_TRUSTED_PROXY` incorrect fait partager un seul compteur d'IP (limitation de débit) à tous les clients.
- Derrière BunkerWeb : retirez `ports` du `docker-compose.yml`, rattachez le service au réseau de BunkerWeb, déclarez le service dans BunkerWeb avec `USE_REVERSE_PROXY=yes` et l'URL interne `http://mission-control:8000`, et renseignez `MC_TRUSTED_PROXY` avec l'IP de BunkerWeb sur ce réseau.

## Sécurité

- Cookies `HttpOnly`, `Secure`, `SameSite=Strict`, sessions serveur (8 h d'inactivité, 24 h max), CSRF, CSP stricte, HSTS.
- Sauvegardez `MC_SECRET_KEY` : elle chiffre les tokens BunkerWeb. Perdue, il faut les ressaisir.
- Sauvegardez le volume `/data` (SQLite).

## Développement

```bash
python -m venv .venv && source .venv/Scripts/activate   # Windows (Git Bash) ; .venv/bin/activate sous Linux
pip install -e ".[dev]"
python -m pytest
ruff check src tests
```

Démo sans vraie instance : voir `dev/fake_bunkerweb.py`.
