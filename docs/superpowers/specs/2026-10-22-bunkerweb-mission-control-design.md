# BunkerWeb Mission Control — Design

Date : 2026-10-22
Statut : validé par l'utilisateur, en attente de relecture de la spec écrite.

## 1. Objectif

Application web unique de supervision de plusieurs instances BunkerWeb (2 à 10, même réseau) via l'API BunkerWeb. Sécurisée, accessible en local et via un domaine, avec authentification forte. Vision à terme : proposer l'outil à l'équipe BunkerWeb pour reprise ou officialisation, d'où l'alignement sur leur stack (Python, FastAPI, SQLAlchemy, Jinja2, Bootstrap, Docker) et leur licence (AGPLv3).

## 2. Périmètre v1

Supervision en lecture seule. Aucune écriture sur BunkerWeb.

Vues : santé des instances, services protégés, bans actifs, jobs et plugins, certificats Let's Encrypt (existence, émetteur, expiration).

## 3. Architecture

Un seul conteneur Python (FastAPI), deux composants dans le même processus :

- **Collecteur** : tâche périodique (30 s par défaut). Pour chaque instance enregistrée, appelle l'API BunkerWeb avec le token de l'instance (ping/santé, services, bans, jobs, plugins) et stocke des snapshots en base. La sonde TLS tourne à cadence plus lente (15 min par défaut). Les instances sont traitées en parallèle. Un échec marque l'instance « injoignable » en conservant le dernier snapshot valide.
- **Web/API** : FastAPI sert des pages Jinja2 + Bootstrap et une API JSON interne pour les rafraîchissements. Elle lit uniquement la base, jamais BunkerWeb directement.

Approche retenue : collecteur + cache en base (rejetés : proxy live sans stockage ; agent par instance).

### Données

SQLAlchemy + Alembic. SQLite par défaut, PostgreSQL/MariaDB en option. Tables : `users`, `credentials` (TOTP, passkeys, codes de secours hachés), `instances` (URL, token chiffré), `snapshots` par type, `cert_probes`, `audit_log`.

### Sonde TLS

Connexion TLS directe à `IP_instance:443` avec SNI = domaine du service. Reste dans le réseau interne, teste le certificat réellement servi par chaque instance, sans accès internet. Aucune requête HTTP. Lit l'émetteur (badge Let's Encrypt ou autre) et la date d'expiration. Sonde via le domaine public : hors v1.

## 4. Authentification et accès

- Mot de passe : argon2id, 12 caractères minimum.
- Second facteur obligatoire pour tous les comptes : TOTP ou passkey WebAuthn. Le premier admin est créé via une commande CLI de bootstrap et doit enregistrer un second facteur avant tout accès.
- 10 codes de secours à usage unique, affichés une fois, stockés hachés.
- Session : cookie `HttpOnly`, `Secure`, `SameSite=Strict`, expiration 8 h d'inactivité, 24 h maximum. CSRF sur toutes les requêtes d'écriture.
- Anti-bruteforce par compte et par IP : délai croissant, verrouillage temporaire.
- Rôles : `admin` (utilisateurs, instances, audit) et `lecteur` (consultation).
- Audit : connexions, échecs, changements de 2FA, ajout/suppression d'instance et d'utilisateur. Consultable par les admins.
- En-têtes : CSP stricte, HSTS, `X-Frame-Options: DENY`.
- Accès local et domaine : les passkeys sont liées au domaine (RP ID et origines autorisées configurables par variable d'environnement). L'accès local (IP, localhost) se fait en mot de passe + TOTP.
- Tokens BunkerWeb chiffrés au repos avec une clé hors base. Client BunkerWeb limité aux requêtes GET.
- L'application tourne derrière HTTPS (BunkerWeb ou reverse proxy).

## 5. Vues

1. **Accueil / Santé** : une carte par instance (OK, dégradé, injoignable), version, latence, dernière collecte. Compteurs globaux : instances OK, bans actifs, certificats proches de l'expiration. Indicateur de donnée périmée si la collecte a plus de 3 cycles.
2. **Services** : tableau consolidé (domaine, instance, mode detect/block, statut), filtres par instance et mode. Signale les services absents de certaines instances.
3. **Bans** : liste fusionnée (IP, raison, instance, date, expiration), recherche par IP. Signale une IP bannie sur une instance mais pas sur les autres.
4. **Jobs et plugins** : jobs (dernière exécution, succès/échec, prochaine échéance). Matrice instance × plugin pour les écarts de présence ou de version.
5. **Certificats** : une ligne par service sondé (présent ou non, émetteur, expiration, jours restants). Rouge à moins de 7 jours ou expiré, orange à moins de 21 jours, « Aucun » si aucun certificat servi.
6. **Administration** (admin) : instances (ajout avec test de connexion, édition, suppression), utilisateurs, audit.
7. **Compte** : TOTP, passkeys, codes de secours.

Transverse : interface en français, thème clair/sombre, tableaux triables et filtrables.

## 6. Gestion d'erreurs

- Timeout de 5 s par appel BunkerWeb et par sonde TLS ; une instance lente ne bloque pas les autres.
- Un échec de collecte enregistre le type et le message d'erreur dans l'état de l'instance ; l'UI affiche l'âge de la donnée.
- Les erreurs d'authentification BunkerWeb (token invalide/expiré) sont distinguées des erreurs réseau, avec un message clair dans l'administration.
- Aucun secret (tokens, codes, clés) ni donnée de session dans les logs.

## 7. Tests

- Unitaires (`pytest`) : parsing des réponses BunkerWeb, calcul des écarts entre instances, seuils de certificats, chiffrement des tokens, anti-bruteforce.
- Intégration : faux serveur BunkerWeb (réponses enregistrées) pour le collecteur ; sonde TLS contre un serveur local à certificat auto-signé.
- Authentification : parcours complet mot de passe, 2FA, session, CSRF, verrouillage.
- `docker-compose` de dev avec 2 vraies instances BunkerWeb pour la validation de bout en bout.

## 8. Livraison

- Image Docker unique et `docker-compose.yml` d'exemple, configuration par variables d'environnement.
- Commande CLI de bootstrap du premier admin.
- Dépôt aligné sur les conventions BunkerWeb : licence AGPLv3, README, docs, CI (tests + lint `ruff`).

## 9. Hors périmètre v1 (évolutions possibles)

- Écriture sur BunkerWeb : ban/unban, reload, gestion des services et des settings, déploiement de configuration en masse entre instances.
- SSO/OIDC (Keycloak, Authentik, Entra…), éventuellement en complément de l'authentification locale.
- RBAC fin : rôles personnalisables, permissions par instance ou par service.
- Historique long des métriques et graphes de tendance.
- Alertes par e-mail ou webhook (instance injoignable, certificat proche de l'expiration, écarts entre instances).
- Sonde TLS via le domaine public (vue visiteur).
- Passage à plus de 10 instances (collecteur distribué, base PostgreSQL dédiée).
