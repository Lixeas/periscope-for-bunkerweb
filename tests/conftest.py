import os

from cryptography.fernet import Fernet

os.environ.setdefault("MC_SECRET_KEY", Fernet.generate_key().decode())
os.environ.setdefault("MC_COOKIE_SECURE", "false")
os.environ.setdefault("MC_COLLECTOR_ENABLED", "false")

import pytest  # noqa: E402

from mc import db as mcdb  # noqa: E402
from mc import models  # noqa: E402,F401


@pytest.fixture
def fresh_db():
    """Base SQLite en mémoire vierge ; les tests ouvrent leurs sessions avec session_scope()."""
    mcdb.init_engine("sqlite://")
    mcdb.Base.metadata.create_all(mcdb.engine())
    yield
    mcdb.Base.metadata.drop_all(mcdb.engine())
