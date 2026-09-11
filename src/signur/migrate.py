"""Programmatic Alembic access so a fresh install can start without extra commands."""

from pathlib import Path

from alembic import command
from alembic.config import Config

from signur.config import Settings

MIGRATIONS_ROOT = Path(__file__).resolve().parent / "migrations"


def build_alembic_config(settings: Settings) -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_ROOT))
    config.set_main_option("sqlalchemy.url", settings.database_url)
    return config


def upgrade_to_head(settings: Settings) -> None:
    """Bring the configured database up to the latest revision."""
    _prepare_sqlite_directory(settings)
    command.upgrade(build_alembic_config(settings), "head")


def _prepare_sqlite_directory(settings: Settings) -> None:
    url = settings.database_url
    prefix = "sqlite"
    if not url.startswith(prefix):
        return
    _, _, location = url.partition(":///")
    if not location or location.startswith(":memory:"):
        return
    Path(location).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
