from alembic import context
from sqlalchemy import create_engine

from mc import models  # noqa: F401  (enregistre les tables)
from mc.db import Base

url = context.config.get_main_option("sqlalchemy.url")


def run() -> None:
    eng = create_engine(url)
    with eng.connect() as conn:
        context.configure(connection=conn, target_metadata=Base.metadata, render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()


run()
