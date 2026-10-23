import os

from cryptography.fernet import Fernet

os.environ.setdefault("PERISCOPE_SECRET_KEY", Fernet.generate_key().decode())
os.environ.setdefault("PERISCOPE_COOKIE_SECURE", "false")
os.environ.setdefault("PERISCOPE_COLLECTOR_ENABLED", "false")

import pytest

from periscope import db as mcdb
from periscope import models  # noqa: F401


@pytest.fixture
def fresh_db():
    """Base SQLite en mémoire vierge ; les tests ouvrent leurs sessions avec session_scope()."""
    mcdb.init_engine("sqlite://")
    mcdb.Base.metadata.create_all(mcdb.engine())
    yield
    mcdb.Base.metadata.drop_all(mcdb.engine())
