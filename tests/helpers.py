import re

import pyotp
from fastapi.testclient import TestClient

from mc.auth import mfa
from mc.auth.users import create_user
from mc.db import session_scope
from mc.web import routes_auth
from mc.web.app import create_app

PW = "correct horse battery"


def make_client() -> TestClient:
    routes_auth.limiter.reset()
    return TestClient(create_app(run_migrations=False))


def make_user(username="alice", role="admin", totp=True) -> str | None:
    """Crée un utilisateur ; retourne le secret TOTP en clair (ou None)."""
    with session_scope() as s:
        user = create_user(s, username, PW, role)
        if not totp:
            return None
        user.totp_secret_enc = mfa.new_secret_enc()
        user.totp_confirmed = True
        return mfa.secret_plain(user.totp_secret_enc)


def csrf_of(html: str) -> str:
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def post_login(client, username="alice", password=PW):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=False)


def full_login(client, secret: str, username="alice"):
    """Mot de passe + code TOTP ; retourne la réponse du POST /login/2fa."""
    post_login(client, username)
    page = client.get("/login/2fa")
    return client.post("/login/2fa", data={"code": pyotp.TOTP(secret).now(), "csrf": csrf_of(page.text)},
                       follow_redirects=False)
