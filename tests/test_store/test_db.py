"""The settings database opens with the one current schema."""

import sqlite3
from pathlib import Path

import pytest

from u2_mcp.store.db import (
    DATABASE_FILENAME,
    SCHEMA_VERSION,
    SchemaVersionError,
    current_version,
    open_database,
)

EXPECTED_TABLES = {
    "connections",
    "users",
    "groups",
    "user_groups",
    "roles",
    "grants",
    "user_u2_logins",
    "tokens",
    "admin_sessions",
    "audit",
    "settings",
    "oauth_clients",
    "oauth_codes",
    "oauth_tokens",
    "oauth_pending",
    "knowledge",
    "knowledge_namespaces",
    "schema_version",
}


def _tables(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    return {row["name"] for row in rows}


def test_a_new_database_is_created_at_the_current_version(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "data" / DATABASE_FILENAME)
    assert current_version(conn) == SCHEMA_VERSION
    assert _tables(conn) == EXPECTED_TABLES


def test_reopening_keeps_the_data(tmp_path: Path) -> None:
    path = tmp_path / DATABASE_FILENAME
    conn = open_database(path)
    conn.execute("INSERT INTO settings (key, value) VALUES ('k', '1')")
    conn.close()

    conn = open_database(path)
    assert conn.execute("SELECT value FROM settings WHERE key = 'k'").fetchone()[0] == "1"


def test_foreign_keys_are_enforced(tmp_path: Path) -> None:
    conn = open_database(tmp_path / DATABASE_FILENAME)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO tokens (user_id, name, token_hash, created_at, expires_at) "
            "VALUES (999, 'x', 'h', 0, 1)"
        )


def test_a_database_from_another_schema_version_is_refused(tmp_path: Path) -> None:
    path = tmp_path / DATABASE_FILENAME
    conn = open_database(path)
    conn.execute("UPDATE schema_version SET version = 99")
    conn.close()

    with pytest.raises(SchemaVersionError, match="version 99"):
        open_database(path)


def test_the_same_subject_from_two_issuers_is_two_people(tmp_path: Path) -> None:
    conn = open_database(tmp_path / DATABASE_FILENAME)
    for issuer in ("https://a.example", "https://b.example"):
        conn.execute(
            "INSERT INTO users (kind, sso_issuer, sso_subject, created_at) "
            "VALUES ('sso', ?, 'sub', 0)",
            (issuer,),
        )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO users (kind, sso_issuer, sso_subject, created_at) "
            "VALUES ('sso', 'https://a.example', 'sub', 0)"
        )
