from __future__ import annotations

import os

from alembic import context
from sqlalchemy import create_engine, pool

import app.models  # noqa: F401  (registers tables)
from app.db.base import Base

target_metadata = Base.metadata


def _url() -> str:
    url = os.environ.get("AIC_MIGRATION_DATABASE_URL") or os.environ.get("AIC_DATABASE_URL")
    if not url:
        raise RuntimeError("Set AIC_MIGRATION_DATABASE_URL (migration role) or AIC_DATABASE_URL")
    return url


def run_offline() -> None:
    context.configure(url=_url(), target_metadata=target_metadata, literal_binds=True, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def run_online() -> None:
    engine = create_engine(_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True,
                          render_as_batch=connection.dialect.name == "sqlite")
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_offline()
else:
    run_online()
