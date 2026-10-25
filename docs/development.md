# Development

```bash
python -m venv .venv
source .venv/Scripts/activate        # Windows (Git Bash); use .venv/bin/activate on Linux/macOS
pip install -e ".[dev]"

python -m pytest -q                  # full test suite
python -m pytest tests/test_collector.py -v      # one file
ruff check src tests dev             # lint (kept clean)
```

Run the app locally:

```bash
export PERISCOPE_SECRET_KEY=$(python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())")
export PERISCOPE_COOKIE_SECURE=false           # plain HTTP, local only
periscope bootstrap-admin --username admin     # creates the first admin and applies migrations
uvicorn periscope.web.app:create_app --factory --port 8000
```

Project layout:

```
src/periscope/
  auth/        passwords, MFA (TOTP, backup codes), sessions, rate limiting, WebAuthn wrapper
  web/         FastAPI app, routes, dependencies (session + CSRF), Jinja2 templates, static assets
  collector.py, bw_client.py, tlsprobe.py, normalize.py, diff.py, queries.py
  models.py, db.py, migrations/   SQLAlchemy models and Alembic migrations
tests/         pytest suite (in-memory SQLite, respx for the BunkerWeb API)
dev/           fake BunkerWeb server and a dev compose file for real instances
```

Database migrations: edit `src/periscope/models.py`, then run `alembic revision --autogenerate -m "describe change"` (uses `alembic.ini` and a throw-away SQLite file). The app applies `alembic upgrade head` at start-up.

## Trying it without real instances

`dev/fake_bunkerweb.py` mimics the BunkerWeb API and serves a self-signed "Let's Encrypt" certificate for the TLS probe. Its header explains how to start two fake instances (ports 9001 and 9002, TLS ports 9443 and 9444); it can also simulate token expiry to exercise the automatic re-authentication.

## Validating against real instances

`dev/docker-compose.bunkerweb.yml` defines two independent BunkerWeb stacks (bw1: API on 8081, TLS on 8443; bw2: API on 8082, TLS on 9443). **This file has never been run** (Docker was not available where it was written). It follows the official documentation but must be validated; uncertain points are commented in the file, notably the ACL bootstrap file for the API user. Its header explains how to register the instances in Periscope. The parsers were derived by reading the BunkerWeb v1.6.17 source and have never been run against a live instance: compare the real API responses (`/services`, `/bans`, `/jobs`, `/plugins`) with `src/periscope/normalize.py` and adjust the parsers and their tests.
