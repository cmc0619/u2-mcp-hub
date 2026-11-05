"""Open the settings database, creating its schema on first use.

A database made by a different schema version is refused, not upgraded: there
is one schema version, and no upgrade path until a real deployment needs one.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path

from .schema import SCHEMA

DATABASE_FILENAME = "u2-mcp.db"
# 3, the schema existing databases already record; no upgrade code goes with it.
SCHEMA_VERSION = 3

# Yields a connection under its lock, as Store.locked does.
Locked = Callable[[], AbstractContextManager[sqlite3.Connection]]


class SchemaVersionError(Exception):
    """Raised when the settings database was made by a different schema version."""

    pass


def connect(path: Path) -> sqlite3.Connection:
    """Open (creating if needed) a SQLite file the way this server uses it.

    Autocommit mode (transactions are explicit), rows addressable by column name,
    foreign keys on, WAL journal and a busy timeout.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def open_database(path: Path) -> sqlite3.Connection:
    """Open the settings database, creating its schema if it is new.

    Raises:
        SchemaVersionError: If the database has a different schema version
    """
    conn = connect(path)
    version = current_version(conn)
    if version == 0:
        conn.executescript(
            f"BEGIN;\n{SCHEMA}\n"
            f"INSERT INTO schema_version (version) VALUES ({SCHEMA_VERSION});\nCOMMIT;"
        )
    elif version != SCHEMA_VERSION:
        conn.close()
        raise SchemaVersionError(
            f"The settings database at {path} is at schema version {version}; this "
            f"server uses version {SCHEMA_VERSION}."
        )
    return conn


def current_version(conn: sqlite3.Connection) -> int:
    """Return the schema version recorded in the database, 0 when new."""
    conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
    row = conn.execute("SELECT version FROM schema_version").fetchone()
    return int(row[0]) if row else 0
