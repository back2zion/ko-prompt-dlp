"""Alembic environment wired to axfilter's SQLAlchemy metadata and Settings."""
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from axfilter.settings import Settings
from axfilter.store import metadata

config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)

target_metadata = metadata
_url = Settings().database_url or "sqlite:///data/axfilter.db"
config.set_main_option("sqlalchemy.url", _url)


def run_migrations_offline() -> None:
    context.configure(url=_url, target_metadata=target_metadata, literal_binds=True,
                      render_as_batch=_url.startswith("sqlite"))
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(config.get_section(config.config_ini_section, {}),
                                     prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata,
                          render_as_batch=_url.startswith("sqlite"))
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
