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

## Authentification auprès de l'API BunkerWeb

**Recommandé : un utilisateur d'API dédié et restreint** (non administrateur, droits de lecture uniquement). Dans **Instances**, choisissez le mode « Utilisateur API » et saisissez son nom et son mot de passe. Mission Control les stocke **chiffrés** (Fernet, `MC_SECRET_KEY`), ne les réaffiche jamais, échange ces identifiants contre un jeton via `POST /auth` (HTTP Basic), l'envoie en `Authorization: Bearer <jeton>` et **le renouvelle automatiquement** : le jeton est gardé en mémoire, et sur une réponse 401 (expiration ; par défaut `API_BISCUIT_TTL_SECONDS=3600` s) l'application se ré-authentifie une fois et rejoue la requête. Le test de connexion de l'écran d'ajout exerce `/auth` : un mauvais mot de passe donne « Authentification refusée ».

L'application n'émet que des `GET`, plus ce seul `POST /auth` (garanti par le code du client).

Déclaration de l'utilisateur côté BunkerWeb : fichier JSON référencé par `API_ACL_BOOTSTRAP_FILE` (par ex. monté sur `/var/lib/bunkerweb/api_acl_bootstrap.json`). Schéma d'après la documentation (<https://docs.bunkerweb.io/latest/api/>) : objet `users` indexé par nom ; chaque entrée a `admin` (booléen), un mot de passe (`password` en clair, 8+ caractères avec majuscule, minuscule, chiffre et caractère spécial, ou hash bcrypt `password_hash` / `password_bcrypt`, coût >= 10, à préférer) et `permissions` : type de ressource, puis identifiant (ou `"*"`), puis nom de permission à `true`.

```json
{
  "users": {
    "mission-control": {
      "admin": false,
      "password_hash": "$2b$13$<hash bcrypt>",
      "permissions": {
        "instances": { "*": { "instances_read": true } },
        "global_config": { "*": { "global_config_read": true } },
        "services": { "*": { "service_read": true } },
        "bans": { "*": { "ban_read": true } },
        "jobs": { "*": { "job_read": true } },
        "plugins": { "*": { "plugin_read": true } }
      }
    }
  }
}
```

Permissions de lecture nécessaires (noms confirmés dans la documentation) : `instances_read`, `service_read`, `global_config_read`, `ban_read`, `job_read`, `plugin_read`. **Non confirmé** : les noms des types de ressource servant de clés (`instances`, `global_config`, `bans`, `jobs`, `plugins` ci-dessus sont déduits ; seuls `services` et `configs` figurent dans l'exemple de la documentation), les champs exacts de `/auth` (formulaire/JSON) et ses codes d'erreur. Vérifiez avec le `/openapi.json` de votre instance et ajustez ; n'accordez jamais de permission `*_update`, `*_create`, `*_delete` ni `config_update`.

**Mode « Token d'API » (déconseillé)** : un `API_TOKEN` statique est envoyé tel quel en Bearer. Il donne un accès **administrateur** complet à BunkerWeb ; il reste chiffré en base et jamais réaffiché. À réserver à un dépannage ; restreignez par ailleurs l'accès réseau à l'API (liste d'IP autorisées).

Migration d'une instance existante : modifier l'instance, passer en « Utilisateur API » et saisir les nouveaux identifiants (le token est alors effacé).

## Accès local et par domaine

- Même application pour les deux accès. Listez toutes les URLs dans `MC_ORIGINS` (protection contre les requêtes inter-origines).
- Les **passkeys sont liées au domaine** (`MC_RP_ID`) : elles fonctionnent via le domaine, pas via `localhost`/IP. En local, utilisez le TOTP.
- **Attention** : un `MC_TRUSTED_PROXY` incorrect fait partager un seul compteur d'IP (limitation de débit) à tous les clients.
- Derrière BunkerWeb : retirez `ports` du `docker-compose.yml`, rattachez le service au réseau de BunkerWeb, déclarez le service dans BunkerWeb avec `USE_REVERSE_PROXY=yes` et l'URL interne `http://mission-control:8000`, et renseignez `MC_TRUSTED_PROXY` avec l'IP de BunkerWeb sur ce réseau.

## Sécurité

- Cookies `HttpOnly`, `Secure`, `SameSite=Strict`, sessions serveur (8 h d'inactivité, 24 h max), CSRF, CSP stricte, HSTS.
- Sauvegardez `MC_SECRET_KEY` : elle chiffre les identifiants et tokens BunkerWeb. Perdue, il faut les ressaisir.
- Sauvegardez le volume `/data` (SQLite).

## Validation de bout en bout avec de vraies instances

`dev/docker-compose.bunkerweb.yml` définit deux piles BunkerWeb indépendantes (bw1 : API sur 8081, TLS 8443 ; bw2 : API sur 8082, TLS 9443) avec un upstream trivial. **Ce fichier n'a jamais été exécuté** (Docker absent de la machine de rédaction) : il suit la documentation officielle mais doit être validé ; les points incertains y sont commentés (notamment le fichier d'utilisateur ACL `API_ACL_BOOTSTRAP_FILE`, bloc commenté sous bw1-api). L'en-tête du fichier explique comment enregistrer les instances dans Mission Control. Ensuite, alignez `src/mc/normalize.py` sur les réponses réelles : voir Plan 3, Task 8 (`docs/superpowers/plans/2026-10-22-plan-3-views-delivery.md`).

## Développement

```bash
python -m venv .venv && source .venv/Scripts/activate   # Windows (Git Bash) ; .venv/bin/activate sous Linux
pip install -e ".[dev]"
python -m pytest
ruff check src tests
```

Démo sans vraie instance : voir `dev/fake_bunkerweb.py`.
