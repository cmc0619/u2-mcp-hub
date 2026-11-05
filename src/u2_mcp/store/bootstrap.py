"""Team mode startup: open the settings database.

Team mode is --streamable-http with U2_SECRET_KEY. The first start creates the
database and seeds the built-in roles; the setup wizard in the admin site adds
the first admin and connection.
"""

from __future__ import annotations

from pathlib import Path

from ..config import U2Config
from .crypto import SecretBox
from .db import DATABASE_FILENAME, open_database
from .repo import Store


class TeamModeError(Exception):
    """Raised when team mode cannot start safely."""

    pass


def _open(config: U2Config, db_path: Path) -> Store:
    secret = config.secret_key.get_secret_value() if config.secret_key else ""
    if not secret:
        raise TeamModeError("U2_SECRET_KEY is not set. Use the key the server runs with.")
    try:
        box = SecretBox(secret)
    except ValueError as exc:
        raise TeamModeError(str(exc)) from exc
    return Store(open_database(db_path), box, db_path.parent)


def open_team_store(config: U2Config) -> Store:
    """Open (creating if needed) the settings database in U2_DATA_DIR.

    Raises:
        TeamModeError: If U2_SECRET_KEY is missing or too short
    """
    store = _open(config, Path(config.data_dir).expanduser() / DATABASE_FILENAME)
    store.seed_builtin_roles()
    return store


def open_store_for_cli(config: U2Config) -> Store:
    """Open the existing settings database for an admin command.

    Unlike open_team_store, this never creates a database: a command run with the
    wrong U2_DATA_DIR must say so, not start a second, empty deployment.

    Raises:
        TeamModeError: If U2_SECRET_KEY is missing or there is no database
    """
    db_path = Path(config.data_dir).expanduser() / DATABASE_FILENAME
    if not db_path.exists():
        raise TeamModeError(
            f"No settings database at {db_path}. Start the server with U2_SECRET_KEY "
            "set first, and run this command with the same U2_DATA_DIR."
        )
    return _open(config, db_path)
