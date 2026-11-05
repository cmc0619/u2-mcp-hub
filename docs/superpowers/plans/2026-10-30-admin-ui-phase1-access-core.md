# Admin UI Phase 1: Access Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give u2-mcp a settings database, granular per-connection access control, multiple U2 connections and personal access tokens, enforced on every tool, without changing how existing deployments behave.

**Architecture:** A SQLite settings store (`store/`) holds connections, users, groups, roles, grants, tokens and audit rows, with secrets encrypted under `U2_SECRET_KEY`. `access.decide()` is the single authority on who may do what on which connection. A `@guarded()` decorator on every tool runs that decision, picks the connection, and installs a route that the connection registry uses to hand out the right session. Team mode switches on only when `U2_SECRET_KEY` is set. Stdio mode and HTTP mode without that key behave exactly as they do today.

**Tech Stack:** Python 3.10+, sqlite3 (stdlib), `cryptography` (Fernet + HKDF), MCP Python SDK 1.30 (FastMCP, `TokenVerifier`), pydantic-settings, pytest, httpx.

Spec: `docs/superpowers/specs/2026-10-30-admin-ui-design.md`. Roadmap: `docs/superpowers/plans/2026-10-30-admin-ui-roadmap.md`.

## Global Constraints

- Python floor is 3.10 (`requires-python` in `pyproject.toml`). Do not use `match` statements in hot paths or 3.11-only syntax such as `ExceptionGroup` or `typing.Self`.
- Line length is 100. Ruff rules: `E, F, I, UP, B, SIM`. mypy has `disallow_untyped_defs = true`. Every function is fully typed.
- Use Google-style docstrings on public functions. Module docstrings explain *why*, in the voice of the existing modules.
- Use `ruff==0.16.5` for formatting (pinned in CI). Run `ruff check . && ruff format --check . && mypy src/` before every commit.
- Tests never need a real database. Use `tests/mocks/mock_uopy.py` through the `mock_uopy` fixture.
- The existing 503 tests must keep passing after every task.
- The settings database file is `<U2_DATA_DIR>/u2-mcp.db`, and `U2_DATA_DIR` defaults to `/data`.
- The personal access token prefix is `u2pat_`, followed by `secrets.token_urlsafe(32)` (43 characters).
- The default token lifetime is 90 days, and the token SSO freshness window defaults to 30 days.
- Refusal messages must be exactly:
  - `account disabled`
  - `unknown connection '<name>'`
  - `you need <permission> on <name>; ask an admin`
  - `<name> is read-only`
  - `no U2 login set for you on <name>; ask an admin`
- Built-in roles are Viewer, Analyst, Developer and Owner, with the permission sets in `permissions.py` (Task 2).
- The MCP endpoint stays at path `/`.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## File Structure

| File | Status | Responsibility |
|---|---|---|
| `pyproject.toml` | modify | add `cryptography` |
| `src/u2_mcp/store/__init__.py` | create | the process-wide `Store` singleton: `install_store`, `get_store`, `reset_store` |
| `src/u2_mcp/store/crypto.py` | create | `SecretBox`: encrypt/decrypt secrets under `U2_SECRET_KEY` |
| `src/u2_mcp/store/schema.py` | create | schema v1 DDL |
| `src/u2_mcp/store/db.py` | create | open the SQLite file, run migrations, back up before migrating |
| `src/u2_mcp/store/models.py` | create | frozen dataclasses for rows |
| `src/u2_mcp/store/repo.py` | create | `Store`: every read and write of the settings database |
| `src/u2_mcp/store/bootstrap.py` | create | team-mode startup: open the store, seed roles, import today's env configuration |
| `src/u2_mcp/permissions.py` | create | permission names, tool→permission map, built-in roles |
| `src/u2_mcp/access.py` | create | `decide()`, `visible_connections()`, `effective_access()` |
| `src/u2_mcp/tokens.py` | create | create, verify and revoke personal access tokens |
| `src/u2_mcp/routing.py` | create | the per-request route (connection plus credentials), and per-connection `U2Config` |
| `src/u2_mcp/guard.py` | create | `@guarded()` decorator and startup coverage check |
| `src/u2_mcp/team_auth.py` | create | PAT verifier, identity resolver and `on_sign_in` handler for team mode |
| `src/u2_mcp/identity.py` | modify | add `user_id`, `auth_method`, `caller_for_user()` |
| `src/u2_mcp/registry.py` | modify | key sessions by route when one is installed |
| `src/u2_mcp/auth/provider.py` | modify | `on_sign_in` hook, `u2pat_` dispatch in `load_access_token` |
| `src/u2_mcp/config.py` | modify | `U2_SECRET_KEY`, `U2_DATA_DIR`, `U2_PUBLIC_URL`, `U2_SSO_GROUPS_CLAIM` |
| `src/u2_mcp/server.py` | modify | rename `list_connections`→`list_sessions`, new `list_connections`, team-mode wiring |
| `src/u2_mcp/tools/*.py` | modify | `@guarded()` and a `connection` argument on every tool |
| `src/u2_mcp/utils/knowledge.py` | modify | one knowledge file per connection in team mode |
| `tests/test_store/*`, `tests/test_access.py`, `tests/test_tokens.py`, `tests/test_routing.py`, `tests/test_guard.py`, `tests/test_team_auth.py`, `tests/test_team_mode_e2e.py` | create | tests |

---

### Task 1: Settings database foundation

**Files:**
- Modify: `pyproject.toml` (the `dependencies` list)
- Create: `src/u2_mcp/store/__init__.py`, `src/u2_mcp/store/crypto.py`, `src/u2_mcp/store/schema.py`, `src/u2_mcp/store/db.py`
- Test: `tests/test_store/__init__.py`, `tests/test_store/test_crypto.py`, `tests/test_store/test_db.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `SecretBox(secret_key: str)` with `.encrypt(plaintext: str) -> str` and `.decrypt(token: str) -> str`
  - `SecretUnreadable(Exception)`
  - `open_database(path: Path) -> sqlite3.Connection`
  - `migrate(conn, path, *, now=time.time, migrations=MIGRATIONS) -> None`
  - `current_version(conn) -> int`
  - `MigrationError(Exception)`
  - `SCHEMA_VERSION = 1`, `DATABASE_FILENAME = "u2-mcp.db"`

- [ ] **Step 1: Add the dependency**

In `pyproject.toml`, add `cryptography` to `dependencies` so the list reads:

```toml
dependencies = [
    "mcp>=1.24.0,<2",
    "uopy>=1.0.0",
    "pydantic-settings>=2.0.0",
    "uvicorn>=0.30.0",
    "httpx>=0.25.0",
    "starlette>=0.27.0",
    "cryptography>=42.0.0",
]
```

Run: `uv pip install --python .venv -e ".[dev]"`
Expected: installs `cryptography` (it may already be present through `mcp`).

- [ ] **Step 2: Write the failing tests**

`tests/test_store/__init__.py`: empty file.

`tests/test_store/test_crypto.py`:

```python
"""Secrets in the settings database must be useless without U2_SECRET_KEY."""

import pytest

from u2_mcp.store.crypto import SecretBox, SecretUnreadable

KEY = "k" * 40
OTHER_KEY = "o" * 40


def test_a_secret_round_trips() -> None:
    box = SecretBox(KEY)
    assert box.decrypt(box.encrypt("hunter2")) == "hunter2"


def test_ciphertext_does_not_contain_the_secret() -> None:
    assert "hunter2" not in SecretBox(KEY).encrypt("hunter2")


def test_a_different_key_cannot_read_the_secret() -> None:
    stored = SecretBox(KEY).encrypt("hunter2")
    with pytest.raises(SecretUnreadable, match="re-enter"):
        SecretBox(OTHER_KEY).decrypt(stored)


def test_a_short_key_is_refused() -> None:
    with pytest.raises(ValueError, match="at least 32"):
        SecretBox("short")


def test_unicode_secrets_survive() -> None:
    box = SecretBox(KEY)
    assert box.decrypt(box.encrypt("pässwörd€")) == "pässwörd€"
```

`tests/test_store/test_db.py`:

```python
"""The settings database opens, migrates forward, and backs itself up first."""

import sqlite3
from pathlib import Path

import pytest

from u2_mcp.store.db import (
    DATABASE_FILENAME,
    SCHEMA_VERSION,
    MigrationError,
    current_version,
    migrate,
    open_database,
)

EXPECTED_TABLES = {
    "connections",
    "users",
    "groups",
    "user_groups",
    "roles",
    "grants",
    "tokens",
    "audit",
    "settings",
    "schema_version",
}


def _tables(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    return {row["name"] for row in rows}


def test_a_new_database_is_created_at_the_current_version(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "data" / DATABASE_FILENAME)
    assert current_version(conn) == SCHEMA_VERSION
    assert EXPECTED_TABLES <= _tables(conn)


def test_foreign_keys_are_enforced(tmp_path: Path) -> None:
    conn = open_database(tmp_path / DATABASE_FILENAME)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO tokens (user_id, name, token_hash, created_at, expires_at) "
            "VALUES (999, 'x', 'h', 0, 1)"
        )


def test_reopening_an_up_to_date_database_makes_no_backup(tmp_path: Path) -> None:
    path = tmp_path / DATABASE_FILENAME
    open_database(path).close()
    open_database(path).close()
    assert list(tmp_path.glob("*.bak-*")) == []


def test_migrating_forward_backs_up_first(tmp_path: Path) -> None:
    path = tmp_path / DATABASE_FILENAME
    conn = open_database(path)
    conn.execute("INSERT INTO settings (key, value) VALUES ('marker', '\"kept\"')")

    migrations = {1: "SELECT 1;", 2: "CREATE TABLE extra (id INTEGER PRIMARY KEY);"}
    migrate(conn, path, now=lambda: 0.0, migrations=migrations)

    assert current_version(conn) == 2
    assert "extra" in _tables(conn)
    backups = list(tmp_path.glob(f"{DATABASE_FILENAME}.bak-1-*"))
    assert len(backups) == 1
    with sqlite3.connect(backups[0]) as old:
        assert old.execute("SELECT value FROM settings WHERE key='marker'").fetchone()


def test_a_failed_migration_leaves_the_old_version_and_the_backup(tmp_path: Path) -> None:
    path = tmp_path / DATABASE_FILENAME
    conn = open_database(path)

    broken = {1: "SELECT 1;", 2: "CREATE TABLE ok (id INTEGER); THIS IS NOT SQL;"}
    with pytest.raises(MigrationError, match="version 2"):
        migrate(conn, path, now=lambda: 0.0, migrations=broken)

    assert current_version(conn) == 1
    assert "ok" not in _tables(conn)
    assert len(list(tmp_path.glob("*.bak-1-*"))) == 1


def test_a_database_from_a_newer_server_is_refused(tmp_path: Path) -> None:
    path = tmp_path / DATABASE_FILENAME
    conn = open_database(path)
    conn.execute("UPDATE schema_version SET version = 99")
    with pytest.raises(MigrationError, match="newer"):
        migrate(conn, path)
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/test_store -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'u2_mcp.store'`.

- [ ] **Step 4: Write the implementation**

`src/u2_mcp/store/__init__.py` (the singleton functions are added in Task 3):

```python
"""The settings database: connections, people, roles, grants, tokens and audit."""
```

`src/u2_mcp/store/crypto.py`:

```python
"""Encryption for the secrets kept in the settings database.

The database holds U2 passwords and the SSO client secret. Anyone who can copy
the file -- a backup, a mis-mounted volume, a support bundle -- would otherwise
hold every database login the team uses. Encrypting those columns under a key
that lives only in the environment means the file alone is not enough.

The key is derived with HKDF so an operator can supply any long random string
rather than a correctly formatted Fernet key.
"""

from __future__ import annotations

import base64

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_SALT = b"u2-mcp settings database"
_INFO = b"fernet key v1"
_MIN_KEY_LENGTH = 32


class SecretUnreadable(Exception):
    """Raised when a stored secret cannot be decrypted with the current key."""

    pass


class SecretBox:
    """Encrypts and decrypts short secrets under U2_SECRET_KEY.

    Args:
        secret_key: The operator's secret, at least 32 characters

    Raises:
        ValueError: If the key is too short to be a credible secret
    """

    def __init__(self, secret_key: str) -> None:
        if len(secret_key) < _MIN_KEY_LENGTH:
            raise ValueError(f"U2_SECRET_KEY must be at least {_MIN_KEY_LENGTH} characters")
        derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=_SALT, info=_INFO).derive(
            secret_key.encode("utf-8")
        )
        self._fernet = Fernet(base64.urlsafe_b64encode(derived))

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a secret for storage.

        Args:
            plaintext: The secret

        Returns:
            An opaque ASCII token safe to store in a TEXT column
        """
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, token: str) -> str:
        """Decrypt a stored secret.

        Args:
            token: A value produced by encrypt()

        Returns:
            The original secret

        Raises:
            SecretUnreadable: If the token was made under a different key or is corrupt
        """
        try:
            return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except InvalidToken as exc:
            raise SecretUnreadable(
                "This secret was stored under a different U2_SECRET_KEY; re-enter it"
            ) from exc
```

`src/u2_mcp/store/schema.py`:

```python
"""Schema version 1 of the settings database.

Timestamps are REAL seconds since the epoch, which compare and subtract without
parsing. Booleans are INTEGER 0/1. Secrets live only in *_enc columns, encrypted
by SecretBox.
"""

SCHEMA_V1 = """
CREATE TABLE connections (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    service TEXT NOT NULL CHECK (service IN ('uvcs', 'udcs')),
    account TEXT NOT NULL,
    ssl INTEGER NOT NULL DEFAULT 0,
    login_mode TEXT NOT NULL CHECK (login_mode IN ('shared', 'per_user')),
    shared_user TEXT,
    shared_password_enc TEXT,
    read_only INTEGER NOT NULL DEFAULT 1,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL,
    created_by TEXT,
    updated_at REAL NOT NULL,
    updated_by TEXT
);

CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('sso', 'local')),
    username TEXT UNIQUE,
    sso_subject TEXT UNIQUE,
    email TEXT,
    display_name TEXT,
    password_hash TEXT,
    is_admin INTEGER NOT NULL DEFAULT 0,
    disabled INTEGER NOT NULL DEFAULT 0,
    last_sso_login_at REAL,
    groups_unavailable INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    CHECK (
        (kind = 'sso' AND sso_subject IS NOT NULL)
        OR (kind = 'local' AND username IS NOT NULL)
    )
);

CREATE TABLE groups (
    id INTEGER PRIMARY KEY,
    external_id TEXT NOT NULL UNIQUE,
    label TEXT,
    first_seen_at REAL NOT NULL,
    last_seen_at REAL NOT NULL
);

CREATE TABLE user_groups (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    recorded_at REAL NOT NULL,
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE roles (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    builtin INTEGER NOT NULL DEFAULT 0,
    permissions TEXT NOT NULL
);

CREATE TABLE grants (
    id INTEGER PRIMARY KEY,
    connection_id INTEGER NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
    subject_type TEXT NOT NULL CHECK (subject_type IN ('user', 'group', 'everyone')),
    subject_id INTEGER,
    role_id INTEGER NOT NULL REFERENCES roles(id),
    per_user_u2_user TEXT,
    per_user_u2_password_enc TEXT,
    created_at REAL NOT NULL,
    CHECK ((subject_type = 'everyone') = (subject_id IS NULL)),
    CHECK (subject_type = 'user' OR per_user_u2_user IS NULL)
);

CREATE UNIQUE INDEX grants_one_per_subject
    ON grants (connection_id, subject_type, COALESCE(subject_id, 0));

CREATE TABLE tokens (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    last_used_at REAL,
    last_used_ip TEXT,
    revoked_at REAL
);

CREATE TABLE audit (
    id INTEGER PRIMARY KEY,
    at REAL NOT NULL,
    actor_user_id INTEGER,
    actor_label TEXT,
    kind TEXT NOT NULL CHECK (kind IN ('tool', 'admin', 'auth')),
    connection_id INTEGER,
    action TEXT NOT NULL,
    params TEXT,
    outcome TEXT NOT NULL,
    duration_ms REAL
);

CREATE INDEX audit_at ON audit (at);

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""
```

`src/u2_mcp/store/db.py`:

```python
"""Open the settings database and bring its schema up to date.

Every migration runs inside one transaction, so a failure leaves the previous
version intact. Before any migration of an existing database a full copy is
written beside it -- an upgrade that goes wrong in a way the transaction cannot
catch (a bug in the new code, not the SQL) still has a way back.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from collections.abc import Callable
from pathlib import Path

from .schema import SCHEMA_V1

logger = logging.getLogger(__name__)

DATABASE_FILENAME = "u2-mcp.db"
MIGRATIONS: dict[int, str] = {1: SCHEMA_V1}
SCHEMA_VERSION = max(MIGRATIONS)


class MigrationError(Exception):
    """Raised when the settings database cannot be brought to the current schema."""

    pass


def open_database(path: Path) -> sqlite3.Connection:
    """Open (creating if needed) the settings database and migrate it.

    Args:
        path: Location of the database file

    Returns:
        A connection in autocommit mode with rows addressable by column name

    Raises:
        MigrationError: If the schema cannot be brought up to date
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    migrate(conn, path)
    return conn


def current_version(conn: sqlite3.Connection) -> int:
    """Return the schema version recorded in the database, 0 when new."""
    conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
    row = conn.execute("SELECT version FROM schema_version").fetchone()
    return int(row[0]) if row else 0


def migrate(
    conn: sqlite3.Connection,
    path: Path,
    *,
    now: Callable[[], float] = time.time,
    migrations: dict[int, str] | None = None,
) -> None:
    """Apply every migration between the recorded version and the newest.

    Args:
        conn: Open database connection
        path: The database file, so a backup can be written beside it
        now: Clock, for naming the backup
        migrations: Version -> SQL script; defaults to this server's migrations

    Raises:
        MigrationError: If the database is newer than this server, or a step fails
    """
    steps = migrations if migrations is not None else MIGRATIONS
    target = max(steps)
    version = current_version(conn)

    if version > target:
        raise MigrationError(
            f"The settings database is at version {version}, newer than this server "
            f"supports ({target}). Upgrade u2-mcp rather than downgrading the database."
        )
    if version == target:
        return

    if version > 0:
        backup = _backup(conn, path, version, now())
        logger.info(f"Backed up settings database to {backup.name} before migrating")

    for step in range(version + 1, target + 1):
        script = (
            f"BEGIN;\n{steps[step]}\n"
            f"DELETE FROM schema_version;\n"
            f"INSERT INTO schema_version (version) VALUES ({step});\n"
            f"COMMIT;"
        )
        try:
            conn.executescript(script)
        except sqlite3.Error as exc:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise MigrationError(
                f"Migrating the settings database to version {step} failed: {exc}. "
                f"A copy taken before the attempt is beside {path.name}."
            ) from exc
        logger.info(f"Settings database migrated to version {step}")


def _backup(conn: sqlite3.Connection, path: Path, version: int, at: float) -> Path:
    """Copy the whole database beside itself, named for its version and the time."""
    stamp = time.strftime("%Y%m%d%H%M%S", time.gmtime(at))
    target = path.with_name(f"{path.name}.bak-{version}-{stamp}")
    dest = sqlite3.connect(str(target))
    try:
        conn.backup(dest)
    finally:
        dest.close()
    return target
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/test_store -q`
Expected: 11 passed.

- [ ] **Step 6: Run the full suite and the checks**

Run: `.venv/Scripts/python -m pytest -q && .venv/Scripts/ruff check . && .venv/Scripts/ruff format --check . && .venv/Scripts/mypy src/`
Expected: all pass (514 passed, 4 skipped on Windows).

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml src/u2_mcp/store tests/test_store
git commit -m "feat: settings database with encrypted secrets and backed-up migrations" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Permission catalog and built-in roles

**Files:**
- Create: `src/u2_mcp/permissions.py`
- Test: `tests/test_permissions.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `PERMISSIONS: tuple[str, ...]`
  - `WRITE_PERMISSIONS: frozenset[str]`
  - `ANY_GRANT = "connection.use"`
  - `TOOL_PERMISSIONS: dict[str, str]` (tool name → permission, or `ANY_GRANT`)
  - `UNSCOPED_TOOLS: frozenset[str]` (`{"list_connections"}`)
  - `BUILTIN_ROLES: dict[str, tuple[str, ...]]`
  - `unmapped_tools(tool_names: Iterable[str]) -> list[str]`
  - `is_write(permission: str) -> bool`

- [ ] **Step 1: Write the failing test**

`tests/test_permissions.py`:

```python
"""The permission catalog is the vocabulary every access decision is made in."""

from u2_mcp.permissions import (
    ANY_GRANT,
    BUILTIN_ROLES,
    PERMISSIONS,
    TOOL_PERMISSIONS,
    UNSCOPED_TOOLS,
    WRITE_PERMISSIONS,
    is_write,
    unmapped_tools,
)


def test_every_mapped_permission_exists() -> None:
    for tool, permission in TOOL_PERMISSIONS.items():
        assert permission == ANY_GRANT or permission in PERMISSIONS, tool


def test_write_permissions_are_real_permissions() -> None:
    assert WRITE_PERMISSIONS <= set(PERMISSIONS)


def test_reading_is_not_writing() -> None:
    for permission in ("schema.read", "records.read", "query.run", ANY_GRANT):
        assert not is_write(permission)
    for permission in ("records.write", "records.delete", "tcl.run", "basic.compile"):
        assert is_write(permission)


def test_builtin_roles_only_use_known_permissions() -> None:
    for role, permissions in BUILTIN_ROLES.items():
        assert set(permissions) <= set(PERMISSIONS), role


def test_builtin_roles_each_extend_the_one_before() -> None:
    viewer, analyst, developer, owner = (
        set(BUILTIN_ROLES[name]) for name in ("Viewer", "Analyst", "Developer", "Owner")
    )
    assert viewer == analyst
    assert analyst < developer < owner


def test_viewer_cannot_write_anything() -> None:
    assert not set(BUILTIN_ROLES["Viewer"]) & WRITE_PERMISSIONS


def test_only_owner_can_catalog_basic() -> None:
    holders = [name for name, perms in BUILTIN_ROLES.items() if "basic.catalog" in perms]
    assert holders == ["Owner"]


def test_unmapped_tools_names_strays() -> None:
    assert unmapped_tools(["read_record", "list_connections", "brand_new_tool"]) == [
        "brand_new_tool"
    ]


def test_list_connections_is_the_only_unscoped_tool() -> None:
    assert frozenset({"list_connections"}) == UNSCOPED_TOOLS
    assert "list_connections" not in TOOL_PERMISSIONS
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/test_permissions.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'u2_mcp.permissions'`.

- [ ] **Step 3: Write the implementation**

`src/u2_mcp/permissions.py`:

```python
"""What a person can be allowed to do, and which tool needs which permission.

Every tool maps to exactly one permission. That one-to-one rule is what makes the
admin UI's checkboxes honest: ticking "records.read" grants precisely the tools
listed against it, and a new tool cannot appear without someone deciding which
box it belongs under -- the server refuses to start otherwise (see guard.py).
"""

from __future__ import annotations

from collections.abc import Iterable

PERMISSIONS: tuple[str, ...] = (
    "schema.read",
    "records.read",
    "query.run",
    "records.write",
    "records.delete",
    "tcl.run",
    "subroutine.call",
    "basic.read",
    "basic.write",
    "basic.compile",
    "basic.catalog",
)

# Refused on a read-only connection and under U2_READ_ONLY, whatever the role says.
WRITE_PERMISSIONS: frozenset[str] = frozenset(
    {
        "records.write",
        "records.delete",
        "tcl.run",
        "subroutine.call",
        "basic.write",
        "basic.compile",
        "basic.catalog",
    }
)

# Session housekeeping needs a grant of any kind on the connection, nothing more.
ANY_GRANT = "connection.use"

TOOL_PERMISSIONS: dict[str, str] = {
    # schema.read
    "list_files": "schema.read",
    "get_file_info": "schema.read",
    "list_dictionary": "schema.read",
    "get_field_definition": "schema.read",
    "describe_file": "schema.read",
    "analyze_file_structure": "schema.read",
    "get_account_info": "schema.read",
    # records.read
    "read_record": "records.read",
    "read_records": "records.read",
    "export_to_json": "records.read",
    "export_to_csv": "records.read",
    # query.run
    "execute_query": "query.run",
    "get_select_list": "query.run",
    "validate_query": "query.run",
    # records.write
    "write_record": "records.write",
    "update_value": "records.write",
    "begin_transaction": "records.write",
    "commit_transaction": "records.write",
    "rollback_transaction": "records.write",
    "get_transaction_status": ANY_GRANT,
    # records.delete
    "delete_record": "records.delete",
    # tcl.run
    "execute_tcl": "tcl.run",
    # subroutine.call. list_catalog lives here, not under schema.read, because it
    # runs the CATALOG verb itself -- the verb that makes BASIC code live.
    "call_subroutine": "subroutine.call",
    "list_catalog": "subroutine.call",
    # knowledge
    "list_knowledge": ANY_GRANT,
    "get_all_knowledge": ANY_GRANT,
    "get_knowledge_topic": ANY_GRANT,
    "search_knowledge": ANY_GRANT,
    "save_knowledge": ANY_GRANT,
    "delete_knowledge": ANY_GRANT,
    # session housekeeping
    "connect": ANY_GRANT,
    "disconnect": ANY_GRANT,
    "list_sessions": ANY_GRANT,
    "watchdog_status": ANY_GRANT,
}

# Tools that are not about one connection. list_connections is how a caller
# learns which connections exist for them, so it needs only authentication.
UNSCOPED_TOOLS: frozenset[str] = frozenset({"list_connections"})

_VIEWER = ("schema.read", "records.read", "query.run")
_ANALYST = _VIEWER
_DEVELOPER = (
    *_ANALYST,
    "records.write",
    "records.delete",
    "tcl.run",
    "subroutine.call",
    "basic.read",
    "basic.write",
    "basic.compile",
)
_OWNER = (*_DEVELOPER, "basic.catalog")

BUILTIN_ROLES: dict[str, tuple[str, ...]] = {
    "Viewer": _VIEWER,
    "Analyst": _ANALYST,
    "Developer": _DEVELOPER,
    "Owner": _OWNER,
}


def is_write(permission: str) -> bool:
    """Return whether a permission changes data or runs code."""
    return permission in WRITE_PERMISSIONS


def unmapped_tools(tool_names: Iterable[str]) -> list[str]:
    """Return the tools that have no permission assigned, sorted.

    Args:
        tool_names: Names of every registered tool

    Returns:
        Tools missing from both TOOL_PERMISSIONS and UNSCOPED_TOOLS
    """
    return sorted(
        name for name in tool_names if name not in TOOL_PERMISSIONS and name not in UNSCOPED_TOOLS
    )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `.venv/Scripts/python -m pytest tests/test_permissions.py -q`
Expected: 9 passed.

- [ ] **Step 5: Run the checks and commit**

Run: `.venv/Scripts/ruff check . && .venv/Scripts/ruff format --check . && .venv/Scripts/mypy src/`
Expected: no errors.

```bash
git add src/u2_mcp/permissions.py tests/test_permissions.py
git commit -m "feat: permission catalog, tool-to-permission map and built-in roles" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Settings store (rows, repository, singleton)

**Files:**
- Create: `src/u2_mcp/store/models.py`, `src/u2_mcp/store/repo.py`
- Modify: `src/u2_mcp/store/__init__.py`, `tests/conftest.py` (append a `store` fixture)
- Test: `tests/test_store/test_repo.py`

**Interfaces:**
- Consumes: `SecretBox`, `open_database`, `DATABASE_FILENAME` (Task 1); `BUILTIN_ROLES`, `PERMISSIONS` (Task 2).
- Produces:
  - Dataclasses `Connection`, `User`, `Group`, `Role`, `Grant`, `TokenRecord` (fields in Step 4).
  - `StoreError(Exception)`.
  - `Store(conn, box, data_dir, *, clock=time.time)`. Later tasks use exactly these method names: `add_connection`, `get_connection`, `get_connection_by_name`, `list_connections`, `set_connection_flags`, `shared_password`, `has_connections`, `add_local_user`, `get_or_create_sso_user`, `get_user`, `get_user_by_subject`, `set_user_disabled`, `record_sso_login`, `group_ids_for_user`, `list_groups`, `seed_builtin_roles`, `get_role`, `get_role_by_name`, `add_role`, `add_grant`, `grants_on_connection`, `grants_for`, `grant_u2_password`, `add_token`, `get_token_by_hash`, `touch_token`, `revoke_token`, `list_tokens`, `add_audit`, `recent_audit`, `get_setting`, `set_setting`.
  - Attributes `store.data_dir: Path` and `store.clock: Callable[[], float]`.
  - From `u2_mcp.store`: `install_store(store: Store | None, *, global_read_only: bool = False) -> None`, `get_store() -> Store | None` and `is_global_read_only() -> bool`.
  - A pytest fixture `store` in `tests/conftest.py`: a fresh `Store` in `tmp_path`, with built-in roles seeded.

- [ ] **Step 1: Add the shared fixture**

Append to `tests/conftest.py`. Add `from pathlib import Path` and `from collections.abc import Iterator` to its imports if they are not already there.

```python
@pytest.fixture
def store(tmp_path: Path) -> Iterator["Store"]:
    """Provide an empty settings store in a temporary directory, roles seeded."""
    from u2_mcp.store.crypto import SecretBox
    from u2_mcp.store.db import DATABASE_FILENAME, open_database
    from u2_mcp.store.repo import Store

    conn = open_database(tmp_path / DATABASE_FILENAME)
    settings_store = Store(conn, SecretBox("t" * 40), tmp_path)
    settings_store.seed_builtin_roles()
    try:
        yield settings_store
    finally:
        conn.close()
```

Make `Store` available for the string annotation. If `tests/conftest.py` already has an `if TYPE_CHECKING:` block, add `from u2_mcp.store.repo import Store` to it. Otherwise add:

```python
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from u2_mcp.store.repo import Store
```

- [ ] **Step 2: Write the failing tests**

`tests/test_store/test_repo.py`:

```python
"""The repository is the only code that reads or writes the settings database."""

import sqlite3
import threading

import pytest

from u2_mcp.store import get_store, install_store
from u2_mcp.store.repo import Store, StoreError


def _prod(store: Store, **overrides: object) -> int:
    fields: dict[str, object] = {
        "name": "Prod",
        "host": "u2.example.com",
        "port": 31438,
        "service": "uvcs",
        "account": "DEMO",
        "shared_user": "svc",
        "shared_password": "s3cret",
    }
    fields.update(overrides)
    return store.add_connection(**fields).id  # type: ignore[arg-type]


class TestConnections:
    def test_a_connection_round_trips_without_exposing_its_password(self, store: Store) -> None:
        conn_id = _prod(store)
        connection = store.get_connection(conn_id)
        assert connection is not None
        assert connection.name == "Prod"
        assert connection.has_shared_password
        assert not hasattr(connection, "shared_password")
        assert store.shared_password(conn_id) == "s3cret"

    def test_the_password_is_encrypted_at_rest(self, store: Store) -> None:
        _prod(store)
        raw = store._conn.execute("SELECT shared_password_enc FROM connections").fetchone()[0]
        assert "s3cret" not in raw

    def test_connections_default_to_read_only(self, store: Store) -> None:
        connection = store.get_connection(_prod(store))
        assert connection is not None and connection.read_only

    def test_names_are_unique(self, store: Store) -> None:
        _prod(store)
        with pytest.raises(StoreError, match="already exists"):
            _prod(store)

    def test_lookup_by_name_and_listing(self, store: Store) -> None:
        _prod(store)
        _prod(store, name="Test")
        assert store.get_connection_by_name("Test") is not None
        assert store.get_connection_by_name("Nope") is None
        assert [c.name for c in store.list_connections()] == ["Prod", "Test"]
        assert store.has_connections()

    def test_flags_can_be_changed(self, store: Store) -> None:
        conn_id = _prod(store)
        store.set_connection_flags(conn_id, read_only=False, enabled=False)
        connection = store.get_connection(conn_id)
        assert connection is not None
        assert not connection.read_only and not connection.enabled


class TestUsersAndGroups:
    def test_sso_users_are_created_once_and_kept_up_to_date(self, store: Store) -> None:
        first = store.get_or_create_sso_user("sub-1", email="a@x.com", display_name="A")
        again = store.get_or_create_sso_user("sub-1", email="new@x.com", display_name="A")
        assert first.id == again.id
        assert again.email == "new@x.com"
        assert again.kind == "sso" and not again.is_admin and not again.disabled

    def test_local_users_need_a_unique_username(self, store: Store) -> None:
        store.add_local_user("admin", is_admin=True)
        with pytest.raises(StoreError, match="already exists"):
            store.add_local_user("admin")

    def test_sign_in_replaces_group_membership(self, store: Store) -> None:
        user = store.get_or_create_sso_user("sub-1")
        store.record_sso_login(user.id, ["g-dev", "g-ops"])
        store.record_sso_login(user.id, ["g-dev"])
        groups = {g.id: g.external_id for g in store.list_groups()}
        assert sorted(groups[i] for i in store.group_ids_for_user(user.id)) == ["g-dev"]
        assert set(groups.values()) == {"g-dev", "g-ops"}  # groups seen once are remembered

    def test_sign_in_records_the_time(self, store: Store) -> None:
        user = store.get_or_create_sso_user("sub-1")
        store.record_sso_login(user.id, [])
        refreshed = store.get_user(user.id)
        assert refreshed is not None and refreshed.last_sso_login_at is not None

    def test_missing_groups_flag_the_user_and_clear_membership(self, store: Store) -> None:
        user = store.get_or_create_sso_user("sub-1")
        store.record_sso_login(user.id, ["g-dev"])
        store.record_sso_login(user.id, None)
        refreshed = store.get_user(user.id)
        assert refreshed is not None and refreshed.groups_unavailable
        assert store.group_ids_for_user(user.id) == []

    def test_users_can_be_disabled(self, store: Store) -> None:
        user = store.get_or_create_sso_user("sub-1")
        store.set_user_disabled(user.id, True)
        refreshed = store.get_user(user.id)
        assert refreshed is not None and refreshed.disabled


class TestRolesAndGrants:
    def test_builtin_roles_are_seeded_once(self, store: Store) -> None:
        store.seed_builtin_roles()
        viewer = store.get_role_by_name("Viewer")
        assert viewer is not None and viewer.builtin
        assert "records.read" in viewer.permissions

    def test_custom_roles_reject_unknown_permissions(self, store: Store) -> None:
        with pytest.raises(StoreError, match="unknown permission"):
            store.add_role("Weird", ["records.read", "make.coffee"])

    def test_grants_for_combines_user_group_and_everyone(self, store: Store) -> None:
        prod = _prod(store)
        test = _prod(store, name="Test")
        viewer = store.get_role_by_name("Viewer")
        developer = store.get_role_by_name("Developer")
        assert viewer is not None and developer is not None
        user = store.get_or_create_sso_user("sub-1")
        other = store.get_or_create_sso_user("sub-2")
        store.record_sso_login(user.id, ["g-dev"])
        group_id = store.group_ids_for_user(user.id)[0]

        store.add_grant(
            connection_id=prod, subject_type="user", subject_id=user.id, role_id=viewer.id
        )
        store.add_grant(
            connection_id=prod, subject_type="group", subject_id=group_id, role_id=developer.id
        )
        store.add_grant(connection_id=test, subject_type="everyone", role_id=viewer.id)
        store.add_grant(
            connection_id=prod, subject_type="user", subject_id=other.id, role_id=developer.id
        )

        mine = store.grants_for(user.id, [group_id])
        assert sorted((g.connection_id, g.subject_type) for g in mine) == [
            (prod, "group"),
            (prod, "user"),
            (test, "everyone"),
        ]
        assert len(store.grants_for(user.id, [group_id], connection_id=test)) == 1

    def test_one_grant_per_subject_per_connection(self, store: Store) -> None:
        prod = _prod(store)
        viewer = store.get_role_by_name("Viewer")
        assert viewer is not None
        store.add_grant(connection_id=prod, subject_type="everyone", role_id=viewer.id)
        with pytest.raises(StoreError, match="already has a grant"):
            store.add_grant(connection_id=prod, subject_type="everyone", role_id=viewer.id)

    def test_per_user_logins_are_encrypted_and_only_on_user_grants(self, store: Store) -> None:
        prod = _prod(store, login_mode="per_user", shared_user=None, shared_password=None)
        viewer = store.get_role_by_name("Viewer")
        assert viewer is not None
        user = store.get_or_create_sso_user("sub-1")
        grant = store.add_grant(
            connection_id=prod,
            subject_type="user",
            subject_id=user.id,
            role_id=viewer.id,
            per_user_u2_user="bob",
            per_user_u2_password="pw",
        )
        assert grant.per_user_u2_user == "bob" and grant.has_per_user_password
        assert store.grant_u2_password(grant.id) == "pw"
        with pytest.raises(StoreError):
            store.add_grant(
                connection_id=prod,
                subject_type="everyone",
                role_id=viewer.id,
                per_user_u2_user="bob",
                per_user_u2_password="pw",
            )


class TestTokensAuditSettings:
    def test_tokens_are_found_by_hash_touched_and_revoked(self, store: Store) -> None:
        user = store.get_or_create_sso_user("sub-1")
        token = store.add_token(user_id=user.id, name="laptop", token_hash="h1", expires_at=9e9)
        assert store.get_token_by_hash("h1") == token
        store.touch_token(token.id, at=100.0, ip="10.0.0.5")
        store.revoke_token(token.id, at=200.0)
        found = store.get_token_by_hash("h1")
        assert found is not None
        assert found.last_used_at == 100.0 and found.revoked_at == 200.0
        assert [t.name for t in store.list_tokens(user.id)] == ["laptop"]

    def test_audit_rows_redact_secrets(self, store: Store) -> None:
        store.add_audit(
            kind="tool",
            action="read_record",
            outcome="ok",
            params={"file_name": "X", "password": "pw"},
        )
        row = store.recent_audit(1)[0]
        assert row["action"] == "read_record"
        assert row["params"]["password"] == "[redacted]"

    def test_settings_hold_json_values(self, store: Store) -> None:
        assert store.get_setting("missing", 5) == 5
        store.set_setting("token_policy", {"max_days": 90})
        assert store.get_setting("token_policy") == {"max_days": 90}


def test_the_store_singleton(store: Store) -> None:
    assert get_store() is None
    install_store(store)
    try:
        assert get_store() is store
    finally:
        install_store(None)


def test_the_store_survives_concurrent_threads(store: Store) -> None:
    _prod(store)
    errors: list[BaseException] = []

    def work() -> None:
        try:
            for _ in range(50):
                store.list_connections()
                store.add_audit(kind="tool", action="x", outcome="ok")
        except (sqlite3.Error, StoreError) as exc:
            errors.append(exc)

    threads = [threading.Thread(target=work) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(store.recent_audit(500)) == 200
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/test_store/test_repo.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'u2_mcp.store.repo'`.

- [ ] **Step 4: Write the row models**

`src/u2_mcp/store/models.py`:

```python
"""Rows of the settings database, as read by the rest of the server.

Secrets never appear on these objects. A Connection says *whether* it has a
shared password; reading the password is a separate, deliberate call on the
Store, so a row can be logged, rendered or compared without leaking it.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Connection:
    """A U2 server and account this deployment can reach."""

    id: int
    name: str
    host: str
    port: int
    service: str
    account: str
    ssl: bool
    login_mode: str  # "shared" or "per_user"
    shared_user: str | None
    has_shared_password: bool
    read_only: bool
    enabled: bool


@dataclass(frozen=True)
class User:
    """A person who can sign in, through SSO or with a local password."""

    id: int
    kind: str  # "sso" or "local"
    username: str | None
    sso_subject: str | None
    email: str | None
    display_name: str | None
    is_admin: bool
    disabled: bool
    last_sso_login_at: float | None
    groups_unavailable: bool
    created_at: float

    @property
    def label(self) -> str:
        """Return the most human-readable name available."""
        return self.display_name or self.email or self.username or self.sso_subject or str(self.id)


@dataclass(frozen=True)
class Group:
    """An SSO group, as named by the identity provider's groups claim."""

    id: int
    external_id: str
    label: str | None


@dataclass(frozen=True)
class Role:
    """A named set of permissions."""

    id: int
    name: str
    builtin: bool
    permissions: frozenset[str]


@dataclass(frozen=True)
class Grant:
    """A role on one connection, given to a user, a group or everyone."""

    id: int
    connection_id: int
    subject_type: str  # "user", "group" or "everyone"
    subject_id: int | None
    role_id: int
    per_user_u2_user: str | None
    has_per_user_password: bool


@dataclass(frozen=True)
class TokenRecord:
    """A personal access token, as stored: the hash, never the token."""

    id: int
    user_id: int
    name: str
    token_hash: str
    created_at: float
    expires_at: float
    last_used_at: float | None
    last_used_ip: str | None
    revoked_at: float | None
```

- [ ] **Step 5: Write the repository**

`src/u2_mcp/store/repo.py`:

```python
"""Every read and write of the settings database.

One connection is shared by the whole process and guarded by a lock. SQLite in
WAL mode handles this load easily -- the server makes a handful of small queries
per tool call -- and one lock means no caller ever sees half of another's write.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import Any

from ..permissions import BUILTIN_ROLES, PERMISSIONS
from .crypto import SecretBox
from .models import Connection, Grant, Group, Role, TokenRecord, User

_SECRET_PARAM_WORDS = ("password", "secret", "token")


class StoreError(Exception):
    """Raised when a write would break a rule of the settings database."""

    pass


def _redact(params: dict[str, Any] | None) -> dict[str, Any] | None:
    """Replace values whose parameter names suggest a secret."""
    if params is None:
        return None
    return {
        key: "[redacted]" if any(word in key.lower() for word in _SECRET_PARAM_WORDS) else value
        for key, value in params.items()
    }


class Store:
    """The settings database.

    Args:
        conn: Connection from open_database()
        box: Encrypts the secret columns
        data_dir: Directory holding the database and per-connection files
        clock: Source of the current time, replaceable in tests
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        box: SecretBox,
        data_dir: Path,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._conn = conn
        self._box = box
        self._lock = threading.RLock()
        self.data_dir = Path(data_dir)
        self.clock = clock

    # ------------------------------------------------------------------ helpers

    @contextlib.contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        """Run a block as one transaction under the store lock."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    def _one(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Row | None:
        with self._lock:
            row: sqlite3.Row | None = self._conn.execute(sql, tuple(params)).fetchone()
            return row

    def _all(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(sql, tuple(params)).fetchall())

    def _encrypt(self, value: str | None) -> str | None:
        return None if value is None else self._box.encrypt(value)

    # -------------------------------------------------------------- connections

    @staticmethod
    def _connection(row: sqlite3.Row) -> Connection:
        return Connection(
            id=row["id"],
            name=row["name"],
            host=row["host"],
            port=row["port"],
            service=row["service"],
            account=row["account"],
            ssl=bool(row["ssl"]),
            login_mode=row["login_mode"],
            shared_user=row["shared_user"],
            has_shared_password=row["shared_password_enc"] is not None,
            read_only=bool(row["read_only"]),
            enabled=bool(row["enabled"]),
        )

    def add_connection(
        self,
        *,
        name: str,
        host: str,
        port: int,
        service: str,
        account: str,
        ssl: bool = False,
        login_mode: str = "shared",
        shared_user: str | None = None,
        shared_password: str | None = None,
        read_only: bool = True,
        enabled: bool = True,
        actor: str | None = None,
    ) -> Connection:
        """Add a U2 connection. New connections are read-only unless stated otherwise.

        Raises:
            StoreError: If the name is taken or the values break a schema rule
        """
        now = self.clock()
        try:
            with self._tx() as conn:
                cursor = conn.execute(
                    "INSERT INTO connections (name, host, port, service, account, ssl, "
                    "login_mode, shared_user, shared_password_enc, read_only, enabled, "
                    "created_at, created_by, updated_at, updated_by) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        name,
                        host,
                        port,
                        service,
                        account,
                        int(ssl),
                        login_mode,
                        shared_user,
                        self._encrypt(shared_password),
                        int(read_only),
                        int(enabled),
                        now,
                        actor,
                        now,
                        actor,
                    ),
                )
                new_id = int(cursor.lastrowid or 0)
        except sqlite3.IntegrityError as exc:
            if "UNIQUE" in str(exc):
                raise StoreError(f"A connection named '{name}' already exists") from exc
            raise StoreError(f"Invalid connection settings: {exc}") from exc
        created = self.get_connection(new_id)
        assert created is not None
        return created

    def get_connection(self, connection_id: int) -> Connection | None:
        """Return a connection by id, or None."""
        row = self._one("SELECT * FROM connections WHERE id = ?", (connection_id,))
        return self._connection(row) if row else None

    def get_connection_by_name(self, name: str) -> Connection | None:
        """Return a connection by its exact name, or None."""
        row = self._one("SELECT * FROM connections WHERE name = ?", (name,))
        return self._connection(row) if row else None

    def list_connections(self) -> list[Connection]:
        """Return every connection, ordered by name."""
        rows = self._all("SELECT * FROM connections ORDER BY name")
        return [self._connection(row) for row in rows]

    def has_connections(self) -> bool:
        """Return whether any connection exists."""
        return self._one("SELECT 1 FROM connections LIMIT 1") is not None

    def set_connection_flags(
        self,
        connection_id: int,
        *,
        read_only: bool | None = None,
        enabled: bool | None = None,
        actor: str | None = None,
    ) -> None:
        """Change a connection's read-only or enabled switch."""
        with self._tx() as conn:
            if read_only is not None:
                conn.execute(
                    "UPDATE connections SET read_only = ? WHERE id = ?",
                    (int(read_only), connection_id),
                )
            if enabled is not None:
                conn.execute(
                    "UPDATE connections SET enabled = ? WHERE id = ?",
                    (int(enabled), connection_id),
                )
            conn.execute(
                "UPDATE connections SET updated_at = ?, updated_by = ? WHERE id = ?",
                (self.clock(), actor, connection_id),
            )

    def shared_password(self, connection_id: int) -> str | None:
        """Decrypt a connection's shared U2 password.

        Raises:
            SecretUnreadable: If it was stored under a different U2_SECRET_KEY
        """
        row = self._one(
            "SELECT shared_password_enc FROM connections WHERE id = ?", (connection_id,)
        )
        if row is None or row[0] is None:
            return None
        return self._box.decrypt(row[0])

    # -------------------------------------------------------------------- users

    @staticmethod
    def _user(row: sqlite3.Row) -> User:
        return User(
            id=row["id"],
            kind=row["kind"],
            username=row["username"],
            sso_subject=row["sso_subject"],
            email=row["email"],
            display_name=row["display_name"],
            is_admin=bool(row["is_admin"]),
            disabled=bool(row["disabled"]),
            last_sso_login_at=row["last_sso_login_at"],
            groups_unavailable=bool(row["groups_unavailable"]),
            created_at=row["created_at"],
        )

    def add_local_user(
        self,
        username: str,
        *,
        display_name: str | None = None,
        email: str | None = None,
        password_hash: str | None = None,
        is_admin: bool = False,
    ) -> User:
        """Create a local (password) user.

        Raises:
            StoreError: If the username is taken
        """
        try:
            with self._tx() as conn:
                cursor = conn.execute(
                    "INSERT INTO users (kind, username, display_name, email, password_hash, "
                    "is_admin, created_at) VALUES ('local', ?, ?, ?, ?, ?, ?)",
                    (username, display_name, email, password_hash, int(is_admin), self.clock()),
                )
                new_id = int(cursor.lastrowid or 0)
        except sqlite3.IntegrityError as exc:
            raise StoreError(f"A user named '{username}' already exists") from exc
        created = self.get_user(new_id)
        assert created is not None
        return created

    def get_or_create_sso_user(
        self, subject: str, *, email: str | None = None, display_name: str | None = None
    ) -> User:
        """Return the SSO user with this subject, creating them with no access if new.

        Email and display name are refreshed from the identity provider when given.
        """
        with self._tx() as conn:
            row = conn.execute("SELECT id FROM users WHERE sso_subject = ?", (subject,)).fetchone()
            if row is None:
                cursor = conn.execute(
                    "INSERT INTO users (kind, sso_subject, email, display_name, created_at) "
                    "VALUES ('sso', ?, ?, ?, ?)",
                    (subject, email, display_name, self.clock()),
                )
                user_id = int(cursor.lastrowid or 0)
            else:
                user_id = int(row["id"])
                conn.execute(
                    "UPDATE users SET email = COALESCE(?, email), "
                    "display_name = COALESCE(?, display_name) WHERE id = ?",
                    (email, display_name, user_id),
                )
        user = self.get_user(user_id)
        assert user is not None
        return user

    def get_user(self, user_id: int) -> User | None:
        """Return a user by id, or None."""
        row = self._one("SELECT * FROM users WHERE id = ?", (user_id,))
        return self._user(row) if row else None

    def get_user_by_subject(self, subject: str) -> User | None:
        """Return the SSO user with this subject, or None."""
        row = self._one("SELECT * FROM users WHERE sso_subject = ?", (subject,))
        return self._user(row) if row else None

    def set_user_disabled(self, user_id: int, disabled: bool) -> None:
        """Disable or re-enable a user."""
        with self._tx() as conn:
            conn.execute("UPDATE users SET disabled = ? WHERE id = ?", (int(disabled), user_id))

    def record_sso_login(self, user_id: int, group_external_ids: list[str] | None) -> None:
        """Record a completed SSO sign-in and replace the user's group membership.

        Args:
            user_id: The user who signed in
            group_external_ids: Groups from the identity provider's claim, or None
                when the provider did not supply them (for example an Entra group
                overage). None clears membership and flags the user, so stale groups
                never keep granting access.
        """
        now = self.clock()
        with self._tx() as conn:
            conn.execute(
                "UPDATE users SET last_sso_login_at = ?, groups_unavailable = ? WHERE id = ?",
                (now, int(group_external_ids is None), user_id),
            )
            conn.execute("DELETE FROM user_groups WHERE user_id = ?", (user_id,))
            for external_id in sorted(set(group_external_ids or [])):
                conn.execute(
                    "INSERT INTO groups (external_id, first_seen_at, last_seen_at) "
                    "VALUES (?, ?, ?) ON CONFLICT (external_id) "
                    "DO UPDATE SET last_seen_at = excluded.last_seen_at",
                    (external_id, now, now),
                )
                group_id = conn.execute(
                    "SELECT id FROM groups WHERE external_id = ?", (external_id,)
                ).fetchone()[0]
                conn.execute(
                    "INSERT INTO user_groups (user_id, group_id, recorded_at) VALUES (?, ?, ?)",
                    (user_id, group_id, now),
                )

    # ------------------------------------------------------------------- groups

    def group_ids_for_user(self, user_id: int) -> list[int]:
        """Return the ids of the groups recorded at the user's last SSO sign-in."""
        rows = self._all(
            "SELECT group_id FROM user_groups WHERE user_id = ? ORDER BY group_id", (user_id,)
        )
        return [int(row[0]) for row in rows]

    def list_groups(self) -> list[Group]:
        """Return every group ever seen at sign-in."""
        rows = self._all("SELECT id, external_id, label FROM groups ORDER BY external_id")
        return [
            Group(id=row["id"], external_id=row["external_id"], label=row["label"])
            for row in rows
        ]

    # -------------------------------------------------------------------- roles

    @staticmethod
    def _role(row: sqlite3.Row) -> Role:
        return Role(
            id=row["id"],
            name=row["name"],
            builtin=bool(row["builtin"]),
            permissions=frozenset(json.loads(row["permissions"])),
        )

    def seed_builtin_roles(self) -> None:
        """Create the built-in roles, or bring their permissions up to date."""
        with self._tx() as conn:
            for name, permissions in BUILTIN_ROLES.items():
                conn.execute(
                    "INSERT INTO roles (name, builtin, permissions) VALUES (?, 1, ?) "
                    "ON CONFLICT (name) DO UPDATE SET permissions = excluded.permissions, "
                    "builtin = 1",
                    (name, json.dumps(list(permissions))),
                )

    def get_role(self, role_id: int) -> Role | None:
        """Return a role by id, or None."""
        row = self._one("SELECT * FROM roles WHERE id = ?", (role_id,))
        return self._role(row) if row else None

    def get_role_by_name(self, name: str) -> Role | None:
        """Return a role by name, or None."""
        row = self._one("SELECT * FROM roles WHERE name = ?", (name,))
        return self._role(row) if row else None

    def add_role(self, name: str, permissions: Iterable[str]) -> Role:
        """Create a custom role.

        Raises:
            StoreError: If a permission is unknown or the name is taken
        """
        wanted = list(dict.fromkeys(permissions))
        unknown = [p for p in wanted if p not in PERMISSIONS]
        if unknown:
            raise StoreError(f"unknown permission(s): {', '.join(unknown)}")
        try:
            with self._tx() as conn:
                cursor = conn.execute(
                    "INSERT INTO roles (name, builtin, permissions) VALUES (?, 0, ?)",
                    (name, json.dumps(wanted)),
                )
                new_id = int(cursor.lastrowid or 0)
        except sqlite3.IntegrityError as exc:
            raise StoreError(f"A role named '{name}' already exists") from exc
        role = self.get_role(new_id)
        assert role is not None
        return role

    # ------------------------------------------------------------------- grants

    @staticmethod
    def _grant(row: sqlite3.Row) -> Grant:
        return Grant(
            id=row["id"],
            connection_id=row["connection_id"],
            subject_type=row["subject_type"],
            subject_id=row["subject_id"],
            role_id=row["role_id"],
            per_user_u2_user=row["per_user_u2_user"],
            has_per_user_password=row["per_user_u2_password_enc"] is not None,
        )

    def add_grant(
        self,
        *,
        connection_id: int,
        subject_type: str,
        role_id: int,
        subject_id: int | None = None,
        per_user_u2_user: str | None = None,
        per_user_u2_password: str | None = None,
    ) -> Grant:
        """Give a user, a group or everyone a role on a connection.

        Raises:
            StoreError: If that subject already has a grant on the connection, or the
                combination breaks a schema rule (a U2 login on a non-user grant)
        """
        try:
            with self._tx() as conn:
                cursor = conn.execute(
                    "INSERT INTO grants (connection_id, subject_type, subject_id, role_id, "
                    "per_user_u2_user, per_user_u2_password_enc, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        connection_id,
                        subject_type,
                        subject_id,
                        role_id,
                        per_user_u2_user,
                        self._encrypt(per_user_u2_password),
                        self.clock(),
                    ),
                )
                new_id = int(cursor.lastrowid or 0)
        except sqlite3.IntegrityError as exc:
            if "UNIQUE" in str(exc):
                raise StoreError("That subject already has a grant on this connection") from exc
            raise StoreError(f"Invalid grant: {exc}") from exc
        row = self._one("SELECT * FROM grants WHERE id = ?", (new_id,))
        assert row is not None
        return self._grant(row)

    def grants_on_connection(self, connection_id: int) -> list[Grant]:
        """Return every grant on one connection."""
        rows = self._all(
            "SELECT * FROM grants WHERE connection_id = ? ORDER BY id", (connection_id,)
        )
        return [self._grant(row) for row in rows]

    def grants_for(
        self, user_id: int, group_ids: Iterable[int], connection_id: int | None = None
    ) -> list[Grant]:
        """Return the grants that apply to a user: theirs, their groups', and everyone's.

        Args:
            user_id: The user
            group_ids: Ids of the user's groups
            connection_id: Limit to one connection when given
        """
        groups = list(group_ids)
        placeholders = ",".join("?" for _ in groups) or "NULL"
        sql = (
            "SELECT * FROM grants WHERE ("
            "(subject_type = 'user' AND subject_id = ?) "
            f"OR (subject_type = 'group' AND subject_id IN ({placeholders})) "
            "OR subject_type = 'everyone')"
        )
        params: list[Any] = [user_id, *groups]
        if connection_id is not None:
            sql += " AND connection_id = ?"
            params.append(connection_id)
        return [self._grant(row) for row in self._all(sql + " ORDER BY id", params)]

    def grant_u2_password(self, grant_id: int) -> str | None:
        """Decrypt the per-user U2 password stored on a grant.

        Raises:
            SecretUnreadable: If it was stored under a different U2_SECRET_KEY
        """
        row = self._one("SELECT per_user_u2_password_enc FROM grants WHERE id = ?", (grant_id,))
        if row is None or row[0] is None:
            return None
        return self._box.decrypt(row[0])

    # ------------------------------------------------------------------- tokens

    @staticmethod
    def _token(row: sqlite3.Row) -> TokenRecord:
        return TokenRecord(
            id=row["id"],
            user_id=row["user_id"],
            name=row["name"],
            token_hash=row["token_hash"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            last_used_at=row["last_used_at"],
            last_used_ip=row["last_used_ip"],
            revoked_at=row["revoked_at"],
        )

    def add_token(
        self, *, user_id: int, name: str, token_hash: str, expires_at: float
    ) -> TokenRecord:
        """Store a new personal access token's hash."""
        with self._tx() as conn:
            cursor = conn.execute(
                "INSERT INTO tokens (user_id, name, token_hash, created_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (user_id, name, token_hash, self.clock(), expires_at),
            )
            new_id = int(cursor.lastrowid or 0)
        row = self._one("SELECT * FROM tokens WHERE id = ?", (new_id,))
        assert row is not None
        return self._token(row)

    def get_token_by_hash(self, token_hash: str) -> TokenRecord | None:
        """Return the token with this hash, or None."""
        row = self._one("SELECT * FROM tokens WHERE token_hash = ?", (token_hash,))
        return self._token(row) if row else None

    def touch_token(self, token_id: int, *, at: float, ip: str | None) -> None:
        """Record that a token was just used."""
        with self._tx() as conn:
            conn.execute(
                "UPDATE tokens SET last_used_at = ?, last_used_ip = ? WHERE id = ?",
                (at, ip, token_id),
            )

    def revoke_token(self, token_id: int, *, at: float) -> None:
        """Revoke a token. Revoking twice keeps the first time."""
        with self._tx() as conn:
            conn.execute(
                "UPDATE tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?",
                (at, token_id),
            )

    def list_tokens(self, user_id: int) -> list[TokenRecord]:
        """Return a user's tokens, newest first."""
        rows = self._all(
            "SELECT * FROM tokens WHERE user_id = ? ORDER BY created_at DESC, id DESC",
            (user_id,),
        )
        return [self._token(row) for row in rows]

    # -------------------------------------------------------------------- audit

    def add_audit(
        self,
        *,
        kind: str,
        action: str,
        outcome: str,
        actor_user_id: int | None = None,
        actor_label: str | None = None,
        connection_id: int | None = None,
        params: dict[str, Any] | None = None,
        duration_ms: float | None = None,
    ) -> None:
        """Append an audit row. Parameters whose names suggest a secret are redacted."""
        redacted = _redact(params)
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO audit (at, actor_user_id, actor_label, kind, connection_id, "
                "action, params, outcome, duration_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    self.clock(),
                    actor_user_id,
                    actor_label,
                    kind,
                    connection_id,
                    action,
                    None if redacted is None else json.dumps(redacted, default=str),
                    outcome,
                    duration_ms,
                ),
            )

    def recent_audit(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return the newest audit rows, newest first, with params decoded."""
        rows = self._all("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))
        result = []
        for row in rows:
            entry = dict(row)
            entry["params"] = json.loads(entry["params"]) if entry["params"] else None
            result.append(entry)
        return result

    # ----------------------------------------------------------------- settings

    def get_setting(self, key: str, default: Any = None) -> Any:
        """Return a setting's JSON value, or the default."""
        row = self._one("SELECT value FROM settings WHERE key = ?", (key,))
        return json.loads(row[0]) if row else default

    def set_setting(self, key: str, value: Any) -> None:
        """Store a setting as JSON."""
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) "
                "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                (key, json.dumps(value)),
            )
```

- [ ] **Step 6: Add the singleton**

Replace `src/u2_mcp/store/__init__.py` with:

```python
"""The settings database: connections, people, roles, grants, tokens and audit.

The store exists only in team mode (U2_SECRET_KEY set on an HTTP transport). In
stdio mode, and in HTTP mode without that key, get_store() returns None and the
server behaves exactly as it did before team mode existed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .repo import Store

_store: Store | None = None
_global_read_only = False


def install_store(store: Store | None, *, global_read_only: bool = False) -> None:
    """Install (or, with None, remove) the process-wide settings store.

    Args:
        store: The store, or None to leave team mode
        global_read_only: The U2_READ_ONLY switch, which caps every connection
    """
    global _store, _global_read_only
    _store = store
    _global_read_only = global_read_only


def get_store() -> Store | None:
    """Return the settings store, or None outside team mode."""
    return _store


def is_global_read_only() -> bool:
    """Return the U2_READ_ONLY switch recorded when the store was installed."""
    return _global_read_only
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/test_store -q`
Expected: 33 passed (11 from Task 1, 22 here).

- [ ] **Step 8: Full suite, checks, commit**

Run: `.venv/Scripts/python -m pytest -q && .venv/Scripts/ruff check . && .venv/Scripts/ruff format --check . && .venv/Scripts/mypy src/`
Expected: all pass.

```bash
git add src/u2_mcp/store tests/test_store/test_repo.py tests/conftest.py
git commit -m "feat: settings store for connections, users, groups, roles, grants, tokens and audit" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: The access decision

**Files:**
- Create: `src/u2_mcp/access.py`
- Test: `tests/test_access.py`

**Interfaces:**
- Consumes: `Store` and its methods, plus `Connection` and `Grant` (Task 3); `ANY_GRANT`, `is_write`, `WRITE_PERMISSIONS` (Task 2).
- Produces:
  - `Decision` (frozen dataclass): `allowed: bool`, `reason: str`, `connection: Connection | None`, `user_grant: Grant | None`, `permissions: frozenset[str]`
  - `decide(store, user_id: int, connection_name: str, permission: str, *, global_read_only: bool) -> Decision`
  - `VisibleConnection` (frozen dataclass): `connection: Connection`, `roles: tuple[str, ...]`, `permissions: frozenset[str]` (after the read-only caps)
  - `visible_connections(store, user_id: int, *, global_read_only: bool) -> list[VisibleConnection]`
  - `EffectiveAccess` (frozen dataclass): `connection: Connection`, `sources: dict[str, tuple[str, ...]]` (permission → where it came from), `blocked_by_read_only: tuple[str, ...]`
  - `effective_access(store, user_id: int, *, global_read_only: bool) -> list[EffectiveAccess]`

- [ ] **Step 1: Write the failing tests**

`tests/test_access.py`:

```python
"""Who may do what on which connection.

This is the code that decides who sees what, so it is tested as a table: every
row is one person, one connection, one permission, and the exact answer.
"""

from dataclasses import dataclass

import pytest

from u2_mcp.access import decide, effective_access, visible_connections
from u2_mcp.store.repo import Store


@dataclass
class World:
    store: Store
    alice: int
    bob: int


@pytest.fixture
def world(store: Store) -> World:
    """Six connections and two people, wired to exercise every rule.

    - Prod:     alice=Viewer (user), g-dev=Analyst (group)
    - Test:     g-dev=Developer
    - Archive:  g-dev=Developer, connection read-only
    - Training: everyone=Viewer
    - Hidden:   bob=Viewer only
    - Off:      everyone=Owner, connection disabled
    """

    def role(name: str) -> int:
        found = store.get_role_by_name(name)
        assert found is not None
        return found.id

    def conn(name: str, read_only: bool = False, enabled: bool = True) -> int:
        return store.add_connection(
            name=name,
            host="h",
            port=1,
            service="uvcs",
            account="A",
            shared_user="svc",
            shared_password="pw",
            read_only=read_only,
            enabled=enabled,
        ).id

    alice = store.get_or_create_sso_user("alice").id
    bob = store.get_or_create_sso_user("bob").id
    store.record_sso_login(alice, ["g-dev"])
    store.record_sso_login(bob, [])
    dev_group = store.group_ids_for_user(alice)[0]

    prod, test, archive = conn("Prod"), conn("Test"), conn("Archive", read_only=True)
    training, hidden, off = conn("Training"), conn("Hidden"), conn("Off", enabled=False)

    store.add_grant(connection_id=prod, subject_type="user", subject_id=alice,
                    role_id=role("Viewer"))
    store.add_grant(connection_id=prod, subject_type="group", subject_id=dev_group,
                    role_id=role("Analyst"))
    store.add_grant(connection_id=test, subject_type="group", subject_id=dev_group,
                    role_id=role("Developer"))
    store.add_grant(connection_id=archive, subject_type="group", subject_id=dev_group,
                    role_id=role("Developer"))
    store.add_grant(connection_id=training, subject_type="everyone", role_id=role("Viewer"))
    store.add_grant(connection_id=hidden, subject_type="user", subject_id=bob,
                    role_id=role("Viewer"))
    store.add_grant(connection_id=off, subject_type="everyone", role_id=role("Owner"))
    return World(store=store, alice=alice, bob=bob)


ALLOW = ""

CASES = [
    # who,    connection, permission,        global_ro, expected reason ("" = allowed)
    ("alice", "Prod", "records.read", False, ALLOW),
    ("alice", "Prod", "connection.use", False, ALLOW),
    ("alice", "Prod", "records.write", False, "you need records.write on Prod; ask an admin"),
    ("alice", "Test", "records.write", False, ALLOW),
    ("alice", "Test", "records.write", True, "Test is read-only"),
    ("alice", "Test", "records.read", True, ALLOW),
    ("alice", "Archive", "records.write", False, "Archive is read-only"),
    ("alice", "Archive", "records.read", False, ALLOW),
    ("alice", "Training", "records.read", False, ALLOW),
    ("alice", "Training", "records.write", False,
     "you need records.write on Training; ask an admin"),
    ("alice", "Hidden", "records.read", False, "unknown connection 'Hidden'"),
    ("alice", "Off", "records.read", False, "unknown connection 'Off'"),
    ("alice", "Nope", "records.read", False, "unknown connection 'Nope'"),
    ("bob", "Hidden", "records.read", False, ALLOW),
    ("bob", "Test", "records.read", False, "unknown connection 'Test'"),
    ("alice", "Prod", "connection.use", False, ALLOW),
    ("bob", "Prod", "connection.use", False, "unknown connection 'Prod'"),
    ("alice", "Test", "connection.use", True, ALLOW),  # housekeeping is not a write
]


@pytest.mark.parametrize(("who", "connection", "permission", "global_ro", "expected"), CASES)
def test_decision_table(
    world: World, who: str, connection: str, permission: str, global_ro: bool, expected: str
) -> None:
    user_id = world.alice if who == "alice" else world.bob
    decision = decide(world.store, user_id, connection, permission, global_read_only=global_ro)
    assert decision.allowed == (expected == ALLOW)
    assert decision.reason == expected


def test_hidden_and_missing_connections_are_indistinguishable(world: World) -> None:
    hidden = decide(world.store, world.alice, "Hidden", "records.read", global_read_only=False)
    world.store.set_connection_flags(
        world.store.get_connection_by_name("Hidden").id,  # type: ignore[union-attr]
        enabled=False,
    )
    disabled = decide(world.store, world.alice, "Hidden", "records.read", global_read_only=False)
    assert hidden == disabled
    assert hidden.connection is None


def test_a_disabled_account_is_refused_everywhere(world: World) -> None:
    world.store.set_user_disabled(world.alice, True)
    decision = decide(world.store, world.alice, "Training", "records.read", global_read_only=False)
    assert not decision.allowed
    assert decision.reason == "account disabled"


def test_the_callers_own_grant_is_reported_for_login_lookup(world: World) -> None:
    on_prod = decide(world.store, world.alice, "Prod", "records.read", global_read_only=False)
    on_test = decide(world.store, world.alice, "Test", "records.read", global_read_only=False)
    assert on_prod.user_grant is not None and on_prod.user_grant.subject_type == "user"
    assert on_test.user_grant is None


def test_grant_changes_apply_to_the_next_decision(world: World) -> None:
    assert not decide(world.store, world.bob, "Test", "records.read",
                      global_read_only=False).allowed
    test_id = world.store.get_connection_by_name("Test").id  # type: ignore[union-attr]
    viewer = world.store.get_role_by_name("Viewer")
    assert viewer is not None
    world.store.add_grant(connection_id=test_id, subject_type="user", subject_id=world.bob,
                          role_id=viewer.id)
    assert decide(world.store, world.bob, "Test", "records.read", global_read_only=False).allowed


def test_losing_groups_at_sign_in_removes_group_access(world: World) -> None:
    world.store.record_sso_login(world.alice, None)  # e.g. Entra group overage
    decision = decide(world.store, world.alice, "Test", "records.read", global_read_only=False)
    assert decision.reason == "unknown connection 'Test'"


def test_visible_connections_lists_only_granted_enabled_ones(world: World) -> None:
    visible = visible_connections(world.store, world.alice, global_read_only=False)
    assert [v.connection.name for v in visible] == ["Archive", "Prod", "Test", "Training"]
    archive = visible[0]
    assert "records.read" in archive.permissions
    assert "records.write" not in archive.permissions  # capped by read-only
    prod = visible[1]
    assert prod.roles == ("Analyst", "Viewer")


def test_visible_connections_honour_the_global_switch(world: World) -> None:
    visible = visible_connections(world.store, world.alice, global_read_only=True)
    test = next(v for v in visible if v.connection.name == "Test")
    assert "records.write" not in test.permissions


def test_effective_access_explains_where_each_permission_came_from(world: World) -> None:
    report = effective_access(world.store, world.alice, global_read_only=False)
    prod = next(r for r in report if r.connection.name == "Prod")
    assert prod.sources["records.read"] == ("group g-dev (Analyst)", "user grant (Viewer)")
    archive = next(r for r in report if r.connection.name == "Archive")
    assert "records.write" in archive.blocked_by_read_only
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/test_access.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'u2_mcp.access'`.

- [ ] **Step 3: Write the implementation**

`src/u2_mcp/access.py`:

```python
"""Who may do what, on which connection.

There is exactly one place that answers that question, and both the MCP tools
and the admin UI ask it. Two implementations of a permission rule eventually
disagree, and the disagreement is always found by the person it lets through.

Decisions are made from the settings database on every call. Nothing about a
person's rights is cached in their token or session, so revoking a grant takes
effect on the very next request.

A connection the caller has no grant on is reported exactly as a connection that
does not exist. Telling the two apart would let anyone enumerate the names of
systems they are not allowed to know about.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .permissions import ANY_GRANT, WRITE_PERMISSIONS, is_write
from .store.models import Connection, Grant, Role
from .store.repo import Store


@dataclass(frozen=True)
class Decision:
    """The answer to "may this person do this here?".

    Attributes:
        allowed: Whether the action may proceed
        reason: Empty when allowed; otherwise the message to show the caller
        connection: The connection, once it is known the caller may see it
        user_grant: The caller's own (not group or everyone) grant, which is where a
            per-user U2 login lives
        permissions: Every permission the caller's grants give on the connection
    """

    allowed: bool
    reason: str = ""
    connection: Connection | None = None
    user_grant: Grant | None = None
    permissions: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class VisibleConnection:
    """A connection a caller can use, with what they can do there right now."""

    connection: Connection
    roles: tuple[str, ...]
    permissions: frozenset[str]


@dataclass(frozen=True)
class EffectiveAccess:
    """For one connection: each permission a person holds and which grants supply it."""

    connection: Connection
    sources: dict[str, tuple[str, ...]]
    blocked_by_read_only: tuple[str, ...]


def _roles_for(store: Store, grants: list[Grant]) -> dict[int, Role]:
    roles: dict[int, Role] = {}
    for grant in grants:
        if grant.role_id not in roles:
            role = store.get_role(grant.role_id)
            if role is not None:
                roles[grant.role_id] = role
    return roles


def _grants_on(store: Store, user_id: int, connection_id: int | None) -> list[Grant]:
    group_ids = store.group_ids_for_user(user_id)
    return store.grants_for(user_id, group_ids, connection_id)


def _capped(permissions: frozenset[str], read_only: bool) -> frozenset[str]:
    return permissions - WRITE_PERMISSIONS if read_only else permissions


def decide(
    store: Store,
    user_id: int,
    connection_name: str,
    permission: str,
    *,
    global_read_only: bool,
) -> Decision:
    """Decide whether a user may exercise a permission on a named connection.

    Args:
        store: The settings database
        user_id: The caller's user id
        connection_name: The connection the caller asked for, as they typed it
        permission: A permission from permissions.py, or ANY_GRANT for housekeeping
        global_read_only: The U2_READ_ONLY switch

    Returns:
        The decision, with the exact message to show when refused
    """
    user = store.get_user(user_id)
    if user is None or user.disabled:
        return Decision(allowed=False, reason="account disabled")

    unknown = Decision(allowed=False, reason=f"unknown connection '{connection_name}'")
    connection = store.get_connection_by_name(connection_name)
    if connection is None or not connection.enabled:
        return unknown

    grants = _grants_on(store, user_id, connection.id)
    if not grants:
        return unknown

    roles = _roles_for(store, grants)
    permissions: frozenset[str] = frozenset().union(*(r.permissions for r in roles.values()))
    user_grant = next((g for g in grants if g.subject_type == "user"), None)

    if permission != ANY_GRANT and permission not in permissions:
        return Decision(
            allowed=False,
            reason=f"you need {permission} on {connection.name}; ask an admin",
            connection=connection,
            permissions=permissions,
        )

    if is_write(permission) and (connection.read_only or global_read_only):
        return Decision(
            allowed=False,
            reason=f"{connection.name} is read-only",
            connection=connection,
            permissions=permissions,
        )

    return Decision(
        allowed=True,
        connection=connection,
        user_grant=user_grant,
        permissions=permissions,
    )


def visible_connections(
    store: Store, user_id: int, *, global_read_only: bool
) -> list[VisibleConnection]:
    """List the connections a user can use, with their effective permissions on each.

    Args:
        store: The settings database
        user_id: The user
        global_read_only: The U2_READ_ONLY switch

    Returns:
        Enabled connections the user has any grant on, ordered by name. Disabled
        users see nothing.
    """
    user = store.get_user(user_id)
    if user is None or user.disabled:
        return []

    grants = _grants_on(store, user_id, None)
    roles = _roles_for(store, grants)
    by_connection: dict[int, list[Grant]] = {}
    for grant in grants:
        by_connection.setdefault(grant.connection_id, []).append(grant)

    visible = []
    for connection in store.list_connections():
        mine = by_connection.get(connection.id)
        if not connection.enabled or not mine:
            continue
        held = [roles[g.role_id] for g in mine if g.role_id in roles]
        permissions: frozenset[str] = frozenset().union(*(role.permissions for role in held))
        visible.append(
            VisibleConnection(
                connection=connection,
                roles=tuple(sorted({role.name for role in held})),
                permissions=_capped(permissions, connection.read_only or global_read_only),
            )
        )
    return visible


def effective_access(
    store: Store, user_id: int, *, global_read_only: bool
) -> list[EffectiveAccess]:
    """Explain, per connection, each permission a user holds and which grant gives it.

    This answers "why can't Bob...?" in the admin UI without anyone reading code.

    Args:
        store: The settings database
        user_id: The user
        global_read_only: The U2_READ_ONLY switch

    Returns:
        One entry per connection the user can see, ordered by connection name
    """
    group_labels = {g.id: g.label or g.external_id for g in store.list_groups()}
    grants = _grants_on(store, user_id, None)
    roles = _roles_for(store, grants)
    report = []

    for visible in visible_connections(store, user_id, global_read_only=global_read_only):
        connection = visible.connection
        sources: dict[str, list[str]] = {}
        for grant in grants:
            if grant.connection_id != connection.id or grant.role_id not in roles:
                continue
            role = roles[grant.role_id]
            if grant.subject_type == "user":
                origin = f"user grant ({role.name})"
            elif grant.subject_type == "group":
                label = group_labels.get(grant.subject_id or 0, str(grant.subject_id))
                origin = f"group {label} ({role.name})"
            else:
                origin = f"everyone ({role.name})"
            for permission in role.permissions:
                sources.setdefault(permission, []).append(origin)

        read_only = connection.read_only or global_read_only
        blocked = tuple(sorted(p for p in sources if read_only and p in WRITE_PERMISSIONS))
        report.append(
            EffectiveAccess(
                connection=connection,
                sources={p: tuple(sorted(o)) for p, o in sorted(sources.items())},
                blocked_by_read_only=blocked,
            )
        )
    return report
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/test_access.py -q`
Expected: 26 passed (18 table rows + 8 named tests).

- [ ] **Step 5: Full suite, checks, commit**

Run: `.venv/Scripts/python -m pytest -q && .venv/Scripts/ruff check . && .venv/Scripts/ruff format . && .venv/Scripts/mypy src/`
Expected: all pass. `ruff format` rewraps the long `add_grant(...)` calls in the test, which is expected.

```bash
git add src/u2_mcp/access.py tests/test_access.py
git commit -m "feat: single access decision for every tool and admin page" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Personal access tokens

**Files:**
- Create: `src/u2_mcp/tokens.py`
- Test: `tests/test_tokens.py`

**Interfaces:**
- Consumes: `Store` (`add_token`, `get_token_by_hash`, `touch_token`, `revoke_token`, `get_user`, `clock`), `User`, `TokenRecord` (Task 3).
- Produces:
  - `TOKEN_PREFIX = "u2pat_"`, `DEFAULT_LIFETIME_DAYS = 90`, `DEFAULT_FRESHNESS_DAYS = 30`
  - `TokenRejected(Exception)`, whose `str()` is the message to show
  - `generate_token() -> str`, `hash_token(token: str) -> str`, `looks_like_token(value: str) -> bool`
  - `create_token(store, user_id: int, name: str, *, lifetime_days: int = 90, max_lifetime_days: int | None = None) -> tuple[str, TokenRecord]`
  - `verify_token(store, token: str, *, freshness_days: int = 30, ip: str | None = None) -> tuple[User, TokenRecord]`
  - `revoke(store, token_id: int) -> None`

- [ ] **Step 1: Write the failing tests**

`tests/test_tokens.py`:

```python
"""Personal access tokens: how Copilot outside VS Code proves who is calling."""

import pytest

from u2_mcp.store.repo import Store
from u2_mcp.tokens import (
    TOKEN_PREFIX,
    TokenRejected,
    create_token,
    generate_token,
    hash_token,
    looks_like_token,
    revoke,
    verify_token,
)

DAY = 86400.0


class Clock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock(store: Store) -> Clock:
    fake = Clock()
    store.clock = fake
    return fake


@pytest.fixture
def sso_user(store: Store, clock: Clock) -> int:
    user = store.get_or_create_sso_user("sub-1")
    store.record_sso_login(user.id, [])
    return user.id


def test_tokens_have_the_prefix_and_enough_randomness() -> None:
    first, second = generate_token(), generate_token()
    assert first.startswith(TOKEN_PREFIX) and len(first) == len(TOKEN_PREFIX) + 43
    assert first != second
    assert looks_like_token(first) and not looks_like_token("eyJhbGciOi...")


def test_only_the_hash_is_stored(store: Store, sso_user: int) -> None:
    token, record = create_token(store, sso_user, "laptop")
    assert record.token_hash == hash_token(token)
    assert token not in record.token_hash
    dump = "\n".join(store._conn.iterdump())
    assert token not in dump


def test_a_valid_token_names_its_owner_and_records_use(
    store: Store, sso_user: int, clock: Clock
) -> None:
    token, _ = create_token(store, sso_user, "laptop")
    user, record = verify_token(store, token, ip="10.1.2.3")
    assert user.id == sso_user
    stored = store.get_token_by_hash(hash_token(token))
    assert stored is not None
    assert stored.last_used_at == clock.now and stored.last_used_ip == "10.1.2.3"


def test_use_is_recorded_at_most_once_a_minute(
    store: Store, sso_user: int, clock: Clock
) -> None:
    token, _ = create_token(store, sso_user, "laptop")

    def last_used() -> float | None:
        record = store.get_token_by_hash(hash_token(token))
        assert record is not None
        return record.last_used_at

    verify_token(store, token)
    first_use = clock.now
    clock.now += 30
    verify_token(store, token)
    assert last_used() == first_use
    clock.now += 31
    verify_token(store, token)
    assert last_used() == clock.now


@pytest.mark.parametrize(
    ("setup", "message"),
    [
        ("unknown", "unknown token"),
        ("revoked", "token revoked"),
        ("expired", "token expired"),
        ("disabled", "account disabled"),
        ("not_a_pat", "not a personal access token"),
    ],
)
def test_refusals(
    store: Store, sso_user: int, clock: Clock, setup: str, message: str
) -> None:
    token, record = create_token(store, sso_user, "laptop", lifetime_days=10)
    if setup == "unknown":
        token = generate_token()
    elif setup == "revoked":
        revoke(store, record.id)
    elif setup == "expired":
        clock.now += 10 * DAY
        store.record_sso_login(sso_user, [])  # stay fresh so expiry is what refuses
    elif setup == "disabled":
        store.set_user_disabled(sso_user, True)
    elif setup == "not_a_pat":
        token = "some-oauth-token"
    with pytest.raises(TokenRejected, match=message):
        verify_token(store, token)


def test_sso_users_must_have_signed_in_recently(
    store: Store, sso_user: int, clock: Clock
) -> None:
    token, _ = create_token(store, sso_user, "laptop")
    clock.now += 29 * DAY
    verify_token(store, token)
    clock.now += 2 * DAY
    with pytest.raises(TokenRejected, match="sign in to the admin site to reactivate"):
        verify_token(store, token)
    store.record_sso_login(sso_user, [])
    verify_token(store, token)


def test_sso_users_who_never_signed_in_cannot_use_tokens(store: Store, clock: Clock) -> None:
    user = store.get_or_create_sso_user("imported")
    token, _ = create_token(store, user.id, "laptop")
    with pytest.raises(TokenRejected, match="reactivate"):
        verify_token(store, token)


def test_local_users_are_exempt_from_the_sign_in_rule(store: Store, clock: Clock) -> None:
    user = store.add_local_user("breakglass")
    token, _ = create_token(store, user.id, "script")
    clock.now += 60 * DAY
    assert verify_token(store, token)[0].id == user.id


def test_lifetime_must_be_positive_and_within_the_cap(store: Store, sso_user: int) -> None:
    with pytest.raises(ValueError, match="at least 1 day"):
        create_token(store, sso_user, "x", lifetime_days=0)
    with pytest.raises(ValueError, match="at most 30 days"):
        create_token(store, sso_user, "x", lifetime_days=90, max_lifetime_days=30)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/test_tokens.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'u2_mcp.tokens'`.

- [ ] **Step 3: Write the implementation**

`src/u2_mcp/tokens.py`:

```python
"""Personal access tokens, for MCP clients that cannot do a browser sign-in.

A token proves who is calling and nothing more. What that person may do is
decided afresh on every call (access.py), so changing someone's role never
requires reissuing their token.

Only a SHA-256 hash is stored. The tokens are 256 bits of randomness, so a fast
hash is the right tool: there is nothing to brute-force, and verifying must be
cheap because it happens on every request.

An SSO user's token stops working when that user has not signed in through SSO
for a while. Without that rule, someone IT disabled -- or removed from a group --
would keep their access through a token until it expired, because tokens never
pass through the identity provider. Signing in again refreshes both their
standing and their group membership.
"""

from __future__ import annotations

import hashlib
import secrets

from .store.models import TokenRecord, User
from .store.repo import Store

TOKEN_PREFIX = "u2pat_"
DEFAULT_LIFETIME_DAYS = 90
DEFAULT_FRESHNESS_DAYS = 30
_TOUCH_INTERVAL_SECONDS = 60.0
_DAY_SECONDS = 86400.0


class TokenRejected(Exception):
    """Raised when a presented token cannot be used. The message is safe to show."""

    pass


def generate_token() -> str:
    """Return a new random token: the prefix plus 43 url-safe characters."""
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Return the hex SHA-256 of a token, the only form that is stored."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def looks_like_token(value: str) -> bool:
    """Return whether a bearer value is a personal access token rather than OAuth."""
    return value.startswith(TOKEN_PREFIX)


def create_token(
    store: Store,
    user_id: int,
    name: str,
    *,
    lifetime_days: int = DEFAULT_LIFETIME_DAYS,
    max_lifetime_days: int | None = None,
) -> tuple[str, TokenRecord]:
    """Create a token for a user.

    Args:
        store: The settings database
        user_id: Owner of the token
        name: A label the owner chose, such as "work laptop"
        lifetime_days: How long the token lasts
        max_lifetime_days: The admin's cap, if any

    Returns:
        The token (show it once, never store it) and its stored record

    Raises:
        ValueError: If the lifetime is not positive or exceeds the cap
    """
    if lifetime_days < 1:
        raise ValueError("A token must last at least 1 day")
    if max_lifetime_days is not None and lifetime_days > max_lifetime_days:
        raise ValueError(f"Tokens may last at most {max_lifetime_days} days")
    token = generate_token()
    record = store.add_token(
        user_id=user_id,
        name=name,
        token_hash=hash_token(token),
        expires_at=store.clock() + lifetime_days * _DAY_SECONDS,
    )
    return token, record


def verify_token(
    store: Store,
    token: str,
    *,
    freshness_days: int = DEFAULT_FRESHNESS_DAYS,
    ip: str | None = None,
) -> tuple[User, TokenRecord]:
    """Check a presented token and return its owner.

    Args:
        store: The settings database
        token: The bearer value presented
        freshness_days: How recently an SSO owner must have signed in
        ip: The caller's address, recorded as last-used

    Returns:
        The token's owner and the token record

    Raises:
        TokenRejected: With a message safe to show the caller
    """
    if not looks_like_token(token):
        raise TokenRejected("not a personal access token")

    record = store.get_token_by_hash(hash_token(token))
    if record is None:
        raise TokenRejected("unknown token")

    now = store.clock()
    if record.revoked_at is not None:
        raise TokenRejected("token revoked")
    if now >= record.expires_at:
        raise TokenRejected("token expired")

    user = store.get_user(record.user_id)
    if user is None or user.disabled:
        raise TokenRejected("account disabled")

    if user.kind == "sso":
        last = user.last_sso_login_at
        if last is None or now - last > freshness_days * _DAY_SECONDS:
            raise TokenRejected("sign in to the admin site to reactivate your tokens")

    if record.last_used_at is None or now - record.last_used_at >= _TOUCH_INTERVAL_SECONDS:
        store.touch_token(record.id, at=now, ip=ip)

    return user, record


def revoke(store: Store, token_id: int) -> None:
    """Revoke a token immediately."""
    store.revoke_token(token_id, at=store.clock())
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/test_tokens.py -q`
Expected: 13 passed.

- [ ] **Step 5: Full suite, checks, commit**

Run: `.venv/Scripts/python -m pytest -q && .venv/Scripts/ruff check . && .venv/Scripts/ruff format . && .venv/Scripts/mypy src/`
Expected: all pass.

```bash
git add src/u2_mcp/tokens.py tests/test_tokens.py
git commit -m "feat: personal access tokens with hashing, expiry and SSO freshness" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Routes: which connection and which U2 login a call uses

**Files:**
- Create: `src/u2_mcp/routing.py`
- Modify: `src/u2_mcp/identity.py` (two fields, `LOCAL_CALLER`, new `caller_for_user`), `src/u2_mcp/registry.py` (`for_route`, `current`), `src/u2_mcp/connection.py` (`connect` passes port and SSL)
- Test: `tests/test_routing.py`

**Interfaces:**
- Consumes: `Decision` (Task 4); `Store.shared_password`, `Store.grant_u2_password`, `Connection`, `User`, `SecretUnreadable` (Tasks 1 and 3); `U2Credentials` (existing `credentials.py`); `U2Config` (existing).
- Produces:
  - `CallerIdentity.user_id: int | None` (default None) and `CallerIdentity.auth_method: str` (default `"oauth"`; `LOCAL_CALLER` uses `"stdio"`)
  - `caller_for_user(user: User, *, auth_method: str, client_id: str | None = None) -> CallerIdentity`
  - `Route` (frozen dataclass): `connection: Connection`, `credentials: U2Credentials`, property `key -> str`
  - `RouteError(Exception)`, with a message safe to show
  - `resolve_route(store, decision: Decision) -> Route`
  - `use_route(route: Route) -> ContextManager[Route]` and `current_route() -> Route | None`
  - `config_for(base: U2Config, connection: Connection) -> U2Config`
  - `ConnectionRegistry.for_route(route: Route) -> ConnectionManager`. `ConnectionRegistry.current()` now prefers the installed route.

- [ ] **Step 1: Write the failing tests**

`tests/test_routing.py`:

```python
"""A tool call reaches the right U2 server, as the right U2 user."""

import pytest

from tests.mocks.mock_uopy import MockSession
from u2_mcp.access import decide
from u2_mcp.config import U2Config
from u2_mcp.connection import ConnectionManager
from u2_mcp.credentials import U2Credentials
from u2_mcp.identity import LOCAL_CALLER, caller_for_user, use_caller
from u2_mcp.registry import ConnectionRegistry
from u2_mcp.routing import (
    Route,
    RouteError,
    config_for,
    current_route,
    resolve_route,
    use_route,
)
from u2_mcp.store.crypto import SecretBox
from u2_mcp.store.repo import Store


def _role(store: Store, name: str) -> int:
    role = store.get_role_by_name(name)
    assert role is not None
    return role.id


@pytest.fixture
def setup(store: Store) -> dict[str, int]:
    prod = store.add_connection(
        name="Prod", host="prod.example", port=31438, service="uvcs", account="LIVE",
        shared_user="svc", shared_password="prod-pw", read_only=False,
    ).id
    test = store.add_connection(
        name="Test", host="test.example", port=31439, service="udcs", account="TRAIN",
        login_mode="per_user", read_only=True,
    ).id
    alice = store.get_or_create_sso_user("alice").id
    bob = store.get_or_create_sso_user("bob").id
    store.record_sso_login(alice, ["g-dev"])
    group = store.group_ids_for_user(alice)[0]
    viewer = _role(store, "Viewer")
    store.add_grant(connection_id=prod, subject_type="everyone", role_id=viewer)
    store.add_grant(connection_id=test, subject_type="user", subject_id=bob, role_id=viewer,
                    per_user_u2_user="bob_u2", per_user_u2_password="bob-pw")
    store.add_grant(connection_id=test, subject_type="group", subject_id=group, role_id=viewer)
    return {"prod": prod, "test": test, "alice": alice, "bob": bob}


def _route(store: Store, user_id: int, connection: str) -> Route:
    decision = decide(store, user_id, connection, "records.read", global_read_only=False)
    assert decision.allowed, decision.reason
    return resolve_route(store, decision)


def test_shared_connections_use_the_connection_login(store: Store, setup: dict[str, int]) -> None:
    route = _route(store, setup["alice"], "Prod")
    assert route.credentials.user == "svc"
    assert route.credentials.password == "prod-pw"
    assert route.credentials.account == "LIVE"
    assert route.credentials.is_shared


def test_per_user_connections_use_the_callers_own_login(
    store: Store, setup: dict[str, int]
) -> None:
    route = _route(store, setup["bob"], "Test")
    assert route.credentials.user == "bob_u2" and route.credentials.password == "bob-pw"
    assert not route.credentials.is_shared


def test_group_access_to_a_per_user_connection_needs_a_personal_login(
    store: Store, setup: dict[str, int]
) -> None:
    with pytest.raises(RouteError) as caught:
        _route(store, setup["alice"], "Test")
    assert str(caught.value) == "no U2 login set for you on Test; ask an admin"


def test_a_shared_connection_without_a_password_is_refused(store: Store) -> None:
    store.add_connection(name="Bare", host="h", port=1, service="uvcs", account="A")
    user = store.get_or_create_sso_user("u").id
    store.add_grant(
        connection_id=store.get_connection_by_name("Bare").id,  # type: ignore[union-attr]
        subject_type="everyone",
        role_id=_role(store, "Viewer"),
    )
    with pytest.raises(RouteError, match="has no U2 login configured"):
        _route(store, user, "Bare")


def test_an_unreadable_password_is_reported_not_crashed(
    store: Store, setup: dict[str, int]
) -> None:
    store._box = SecretBox("w" * 40)  # as if U2_SECRET_KEY changed
    with pytest.raises(RouteError, match="cannot be read"):
        _route(store, setup["alice"], "Prod")


def test_config_for_points_at_the_connection(store: Store, mock_config: U2Config) -> None:
    connection = store.add_connection(
        name="X", host="x.example", port=4000, service="udcs", account="ACC", ssl=True,
        read_only=True,
    )
    config = config_for(mock_config, connection)
    assert (config.host, config.port, config.service, config.ssl, config.account) == (
        "x.example", 4000, "udcs", True, "ACC",
    )
    assert config.read_only
    assert mock_config.host == "test-host.example.com"  # the base is untouched


def test_the_route_is_scoped_to_a_block(store: Store, setup: dict[str, int]) -> None:
    route = _route(store, setup["alice"], "Prod")
    assert current_route() is None
    with use_route(route):
        assert current_route() is route
    assert current_route() is None


class TestRegistry:
    def test_each_connection_and_login_gets_its_own_session(
        self, store: Store, setup: dict[str, int], mock_config: U2Config
    ) -> None:
        registry = ConnectionRegistry(mock_config)
        prod_alice = registry.for_route(_route(store, setup["alice"], "Prod"))
        prod_bob = registry.for_route(_route(store, setup["bob"], "Prod"))
        test_bob = registry.for_route(_route(store, setup["bob"], "Test"))

        assert prod_alice is prod_bob  # same connection, same shared login
        assert test_bob is not prod_bob
        assert prod_bob.config.host == "prod.example"
        assert test_bob.config.host == "test.example"
        assert test_bob.credentials.user == "bob_u2"

    def test_current_prefers_the_installed_route(
        self, store: Store, setup: dict[str, int], mock_config: U2Config
    ) -> None:
        registry = ConnectionRegistry(mock_config)
        route = _route(store, setup["bob"], "Test")
        with use_route(route):
            assert registry.current().config.host == "test.example"
        with use_caller(LOCAL_CALLER):
            assert registry.current().config.host == "test-host.example.com"


def test_each_connection_dials_its_own_port_and_ssl(
    store: Store, mock_config: U2Config, mock_uopy: MockSession
) -> None:
    """A connection marked SSL must not quietly connect in the clear."""
    connection = store.add_connection(
        name="Secure", host="s.example", port=40001, service="udcs", account="ACC", ssl=True,
        shared_user="u", shared_password="p",
    )
    credentials = U2Credentials(user="u", password="p", account="ACC", is_shared=True)
    ConnectionManager(config_for(mock_config, connection), credentials).connect()
    kwargs = mock_uopy.connect_kwargs
    assert (kwargs["host"], kwargs["port"], kwargs["ssl"], kwargs["service"]) == (
        "s.example", 40001, True, "udcs",
    )


def test_callers_built_from_users_carry_their_id(store: Store) -> None:
    sso = store.get_or_create_sso_user("sub-9", email="e@x.com", display_name="Eve")
    local = store.add_local_user("ops")
    sso_caller = caller_for_user(sso, auth_method="token")
    local_caller = caller_for_user(local, auth_method="local")
    assert (sso_caller.user_id, sso_caller.subject, sso_caller.auth_method) == (
        sso.id, "sub-9", "token",
    )
    assert local_caller.subject == "local:ops"
    assert LOCAL_CALLER.auth_method == "stdio" and LOCAL_CALLER.user_id is None
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/test_routing.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'u2_mcp.routing'`.

- [ ] **Step 3: Extend the caller identity**

In `src/u2_mcp/identity.py`:

1. Below the existing imports, add:

```python
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .store.models import User
```

If `typing` is already imported for `Any`, extend that import instead: `from typing import TYPE_CHECKING, Any`.

2. In the `CallerIdentity` docstring's `Attributes:` list, add these two lines after `is_authenticated`:

```
        user_id: The settings-database user, in team mode; None otherwise
        auth_method: How the caller proved who they are: "oauth", "token",
            "local" or "stdio"
```

3. Add two fields after `is_authenticated: bool = True` and before `claims`:

```python
    user_id: int | None = None
    auth_method: str = "oauth"
```

4. Replace `LOCAL_CALLER` with:

```python
# Stdio mode has no OAuth: the caller is whoever started the process.
LOCAL_CALLER = CallerIdentity(
    subject="local",
    name="local operator",
    is_authenticated=False,
    auth_method="stdio",
)
```

5. Append at the end of the module:

```python
def caller_for_user(
    user: User, *, auth_method: str, client_id: str | None = None
) -> CallerIdentity:
    """Build the caller for a settings-database user.

    Args:
        user: The user the request was authenticated as
        auth_method: "oauth", "token" or "local"
        client_id: The OAuth client, when there is one

    Returns:
        The caller, carrying the user's id for access decisions
    """
    subject = user.sso_subject or f"local:{user.username}"
    return CallerIdentity(
        subject=subject,
        email=user.email,
        name=user.display_name,
        client_id=client_id,
        is_authenticated=True,
        user_id=user.id,
        auth_method=auth_method,
    )
```

- [ ] **Step 4: Write the routing module**

`src/u2_mcp/routing.py`:

```python
"""Which U2 server, and which U2 login, the current tool call uses.

Once access.py has said yes, this module turns that decision into a route: the
connection's address plus the database login to present there. The route is held
in a context variable for the duration of the call, and the connection registry
reads it to hand out the matching session. A tool never chooses its own server.

FastMCP runs synchronous tools inline on the request's task, so a context variable
set by the guard around the call is visible to everything the tool calls.
"""

from __future__ import annotations

import contextlib
import contextvars
from collections.abc import Iterator
from dataclasses import dataclass

from .access import Decision
from .config import U2Config
from .credentials import U2Credentials
from .store.crypto import SecretUnreadable
from .store.models import Connection
from .store.repo import Store


class RouteError(Exception):
    """Raised when an allowed call has no usable U2 login. The message is safe to show."""

    pass


@dataclass(frozen=True)
class Route:
    """The connection a call targets and the login it presents there."""

    connection: Connection
    credentials: U2Credentials

    @property
    def key(self) -> str:
        """Return the key that keeps one route's session apart from every other."""
        return f"{self.connection.id}:{self.credentials.pool_key}"


_route_var: contextvars.ContextVar[Route | None] = contextvars.ContextVar(
    "u2_route", default=None
)


def current_route() -> Route | None:
    """Return the route of the call in progress, or None outside team mode."""
    return _route_var.get()


@contextlib.contextmanager
def use_route(route: Route) -> Iterator[Route]:
    """Install a route for the duration of the block."""
    token = _route_var.set(route)
    try:
        yield route
    finally:
        _route_var.reset(token)


def resolve_route(store: Store, decision: Decision) -> Route:
    """Turn an allowed decision into a route.

    Args:
        store: The settings database
        decision: An allowed Decision from access.decide()

    Returns:
        The route for the call

    Raises:
        RouteError: If the connection has no usable login for this caller
    """
    connection = decision.connection
    if connection is None or not decision.allowed:
        raise ValueError("resolve_route needs an allowed decision")

    try:
        if connection.login_mode == "shared":
            password = store.shared_password(connection.id)
            if connection.shared_user is None or password is None:
                raise RouteError(f"{connection.name} has no U2 login configured; ask an admin")
            credentials = U2Credentials(
                user=connection.shared_user,
                password=password,
                account=connection.account,
                is_shared=True,
            )
        else:
            grant = decision.user_grant
            password = None if grant is None else store.grant_u2_password(grant.id)
            if grant is None or grant.per_user_u2_user is None or password is None:
                raise RouteError(f"no U2 login set for you on {connection.name}; ask an admin")
            credentials = U2Credentials(
                user=grant.per_user_u2_user,
                password=password,
                account=connection.account,
                is_shared=False,
            )
    except SecretUnreadable as exc:
        raise RouteError(
            f"the stored U2 password for {connection.name} cannot be read; "
            "ask an admin to re-enter it"
        ) from exc

    return Route(connection=connection, credentials=credentials)


def config_for(base: U2Config, connection: Connection) -> U2Config:
    """Return a copy of the server configuration pointed at one connection.

    Safety settings (timeouts, blocked commands, row limits) carry over from the
    base. Read-only is the stricter of the server switch and the connection's.
    """
    return base.model_copy(
        update={
            "host": connection.host,
            "port": connection.port,
            "service": connection.service,
            "ssl": connection.ssl,
            "account": connection.account,
            "read_only": base.read_only or connection.read_only,
        }
    )
```

- [ ] **Step 5: Teach the registry about routes**

In `src/u2_mcp/registry.py`:

1. Add `from .routing import Route, config_for, current_route` to the imports.

2. Replace the body of `for_caller` from `credentials = self._resolver.resolve(caller)` to the end of the method with:

```python
        credentials = self._resolver.resolve(caller)
        return self._manager_for(
            credentials.pool_key,
            lambda: ConnectionManager(self._config, credentials),
            caller.display_name,
        )

    def for_route(self, route: Route) -> ConnectionManager:
        """Return the connection manager for a team-mode route.

        Args:
            route: The connection and login chosen for this call

        Returns:
            The manager holding that route's session, pointed at its server
        """
        return self._manager_for(
            route.key,
            lambda: ConnectionManager(config_for(self._config, route.connection), route.credentials),
            route.connection.name,
        )

    def _manager_for(
        self, key: str, create: Callable[[], ConnectionManager], label: str
    ) -> ConnectionManager:
        """Return the manager for a key, creating it (and evicting) if needed."""
        with self._lock:
            manager = self._managers.get(key)
            if manager is not None:
                self._managers.move_to_end(key)
                return manager

            evicted = self._take_evictable_managers()
            manager = create()
            self._managers[key] = manager
            logger.info(
                f"Opened connection slot '{key}' for {label} "
                f"({len(self._managers)}/{self._max_connections} in use)"
            )

        # Closing happens outside the lock. The connection being evicted may be
        # the one that stopped responding, and closing a wedged socket can block
        # for as long as the network timeout -- which would freeze every caller.
        self._close_evicted(evicted)
        return manager
```

3. Add `from collections.abc import Callable` to the imports.

4. Replace `current` with:

```python
    def current(self) -> ConnectionManager:
        """Return the connection manager for the current request.

        In team mode the guard has installed a route naming the connection and
        login; otherwise the caller's login is resolved as before.
        """
        route = current_route()
        if route is not None:
            return self.for_route(route)
        return self.for_caller(current_caller())
```

The `lambda` line in `for_route` is longer than 100 characters. Run `ruff format src/u2_mcp/registry.py` after editing and it will wrap it.

- [ ] **Step 5b: Pass each connection's port and SSL setting to the driver**

`ConnectionManager.connect()` passes only host, user, password, account and service to `uopy.connect`. `uopy.connect` also accepts `port` and `ssl`. Without them every connection silently uses uopy's default port, and a connection marked SSL connects unencrypted. This affects `U2_PORT` and `U2_SSL` today as well.

In `src/u2_mcp/connection.py`, in `connect()`, change the `_uopy().connect(` call to:

```python
            self._session = _uopy().connect(
                host=self._config.host,
                port=self._config.port,
                user=self._credentials.user,
                password=self._credentials.password,
                account=self._credentials.account,
                service=self._config.service,
                ssl=self._config.ssl,
            )
```

Some existing tests may assert the exact keywords passed to `uopy.connect`. Find them with `grep -rn "connect_kwargs\|assert_called_with(" tests`. Update their expected values to include `port` and `ssl`, taken from the `mock_env` values (`31438` and `False`).

- [ ] **Step 6: Run the tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/test_routing.py tests/test_registry.py tests/test_identity.py -q`
Expected: all pass. That is 11 new tests here, and the existing registry and identity tests are unchanged.

- [ ] **Step 7: Full suite, checks, commit**

Run: `.venv/Scripts/python -m pytest -q && .venv/Scripts/ruff check . && .venv/Scripts/ruff format . && .venv/Scripts/mypy src/`
Expected: all pass. If mypy reports an import cycle, it is `routing → access → store`, which is a one-way chain. Confirm that `identity.py` imports `store.models` only under `TYPE_CHECKING`.

```bash
git add src/u2_mcp/routing.py src/u2_mcp/identity.py src/u2_mcp/registry.py tests/test_routing.py
git commit -m "feat: route each call to its connection and U2 login" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Guard every tool

**Files:**
- Create: `src/u2_mcp/guard.py`
- Modify: `src/u2_mcp/server.py` (four tools, a new `list_connections`, the startup check in `main`), `src/u2_mcp/tools/dictionary.py`, `files.py`, `knowledge.py`, `query.py`, `subroutine.py`, `transaction.py`, `update.py`
- Modify tests that call the old `list_connections` tool (see Step 6)
- Test: `tests/test_guard.py`

**Interfaces:**
- Consumes: `decide`, `visible_connections` (Task 4); `resolve_route`, `use_route`, `RouteError` (Task 6); `get_store`, `is_global_read_only` (Task 3); `current_caller`, `IdentityError` (existing); `TOOL_PERMISSIONS`, `UNSCOPED_TOOLS`, `unmapped_tools` (Task 2).
- Produces:
  - `guarded() -> Callable[[F], F]`, a decorator placed directly under `@mcp.tool()`
  - `check_tool_coverage(mcp_instance) -> None`, which raises `GuardError`
  - `GuardError(Exception)`
  - `LOCAL_CONNECTION_NAME = "default"`
  - An MCP tool `list_sessions`, which is the old `list_connections`
  - An MCP tool `list_connections`, which lists the caller's connections

- [ ] **Step 1: Write the failing tests**

`tests/test_guard.py`:

```python
"""No tool runs without an access check, and each call reaches the right server."""

from collections.abc import Iterator
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

import u2_mcp.server as server
from tests.mocks.mock_uopy import MockSession
from u2_mcp.guard import GuardError, check_tool_coverage, guarded
from u2_mcp.identity import LOCAL_CALLER, caller_for_user, use_caller
from u2_mcp.server import get_connection_manager
from u2_mcp.store import install_store
from u2_mcp.store.repo import Store


# Probe tools: real guarded functions whose bodies report where they ran.
@guarded()
def read_record(file_name: str, connection: str | None = None) -> dict[str, Any]:
    manager = get_connection_manager()
    return {"host": manager.config.host, "user": manager.credentials.user}


CALLS: list[str] = []


@guarded()
def write_record(file_name: str, connection: str | None = None) -> dict[str, Any]:
    CALLS.append(file_name)
    return {"written": file_name}


class TestCoverage:
    def test_every_registered_tool_is_guarded_or_unscoped(self) -> None:
        check_tool_coverage(server.mcp)

    def test_every_scoped_tool_accepts_a_connection_argument(self) -> None:
        for name, tool in server.mcp._tool_manager._tools.items():
            properties = tool.parameters.get("properties", {})
            if name == "list_connections":
                assert "connection" not in properties
            else:
                assert "connection" in properties, name

    def test_an_unguarded_tool_stops_startup(self) -> None:
        probe = FastMCP("probe")

        @probe.tool()
        def read_record(connection: str | None = None) -> dict[str, Any]:
            return {}

        with pytest.raises(GuardError, match="read_record is not guarded"):
            check_tool_coverage(probe)

    def test_an_unmapped_tool_stops_startup(self) -> None:
        probe = FastMCP("probe")

        @probe.tool()
        def brand_new_tool() -> dict[str, Any]:
            return {}

        with pytest.raises(GuardError, match="brand_new_tool has no permission"):
            check_tool_coverage(probe)

    def test_a_guarded_tool_must_take_a_connection(self) -> None:
        with pytest.raises(ValueError, match="'connection'"):

            @guarded()
            def read_record() -> dict[str, Any]:
                return {}

    def test_a_guarded_tool_must_have_a_permission(self) -> None:
        with pytest.raises(ValueError, match="TOOL_PERMISSIONS"):

            @guarded()
            def mystery(connection: str | None = None) -> dict[str, Any]:
                return {}


class TestLocalMode:
    """Stdio, and HTTP without U2_SECRET_KEY: one connection called 'default'."""

    def test_omitted_or_default_connection_runs(self, connection_manager: Any) -> None:
        assert read_record("X")["host"] == "test-host.example.com"
        assert read_record("X", connection="default")["host"] == "test-host.example.com"

    def test_any_other_name_is_unknown(self, connection_manager: Any) -> None:
        assert read_record("X", connection="Prod") == {"error": "unknown connection 'Prod'"}


@pytest.fixture
def team(store: Store, mock_env: dict[str, str], mock_uopy: MockSession) -> Iterator[dict[str, Any]]:
    """Team mode with Prod (alice=Viewer, bob=Viewer) and Test (alice=Developer)."""

    def role(name: str) -> int:
        found = store.get_role_by_name(name)
        assert found is not None
        return found.id

    prod = store.add_connection(name="Prod", host="prod.example", port=1, service="uvcs",
                                account="LIVE", shared_user="psvc", shared_password="p",
                                read_only=False).id
    test = store.add_connection(name="Test", host="test.example", port=40000, service="uvcs",
                                account="TRAIN", shared_user="tsvc", shared_password="t",
                                ssl=True, read_only=False).id
    alice = store.get_or_create_sso_user("alice")
    bob = store.get_or_create_sso_user("bob")
    store.add_grant(connection_id=prod, subject_type="user", subject_id=alice.id,
                    role_id=role("Viewer"))
    store.add_grant(connection_id=test, subject_type="user", subject_id=alice.id,
                    role_id=role("Developer"))
    store.add_grant(connection_id=prod, subject_type="user", subject_id=bob.id,
                    role_id=role("Viewer"))
    mock_uopy.add_file("CUSTOMERS", {"1": "SMITH"})
    install_store(store)
    CALLS.clear()
    try:
        yield {
            "alice": caller_for_user(alice, auth_method="token"),
            "bob": caller_for_user(bob, auth_method="token"),
            "session": mock_uopy,
        }
    finally:
        install_store(None)
        server.reset_connection_manager()


class TestTeamMode:
    def test_the_named_connection_is_the_one_reached(self, team: dict[str, Any]) -> None:
        with use_caller(team["alice"]):
            assert read_record("X", connection="Test") == {"host": "test.example", "user": "tsvc"}
            assert read_record("X", connection="Prod") == {"host": "prod.example", "user": "psvc"}

    def test_several_connections_require_a_choice(self, team: dict[str, Any]) -> None:
        with use_caller(team["alice"]):
            assert read_record("X") == {"error": "say which connection to use: Prod, Test"}

    def test_a_single_connection_needs_no_name(self, team: dict[str, Any]) -> None:
        with use_caller(team["bob"]):
            assert read_record("X")["host"] == "prod.example"

    def test_refusals_never_run_the_tool(self, team: dict[str, Any]) -> None:
        with use_caller(team["alice"]):
            refused = write_record("X", connection="Prod")
        assert refused == {"error": "you need records.write on Prod; ask an admin"}
        assert CALLS == []

    def test_hidden_connections_are_unknown(self, team: dict[str, Any]) -> None:
        with use_caller(team["bob"]):
            assert read_record("X", connection="Test") == {"error": "unknown connection 'Test'"}

    def test_an_unsigned_request_is_refused(self, team: dict[str, Any]) -> None:
        with use_caller(LOCAL_CALLER):
            assert read_record("X") == {"error": "this request is not signed in"}

    def test_list_connections_shows_only_mine(self, team: dict[str, Any]) -> None:
        with use_caller(team["bob"]):
            listed = server.list_connections()
        assert [c["name"] for c in listed["connections"]] == ["Prod"]
        assert listed["connections"][0]["roles"] == ["Viewer"]


@pytest.mark.asyncio
async def test_routing_holds_through_fastmcps_own_call_path(team: dict[str, Any]) -> None:
    """The guard's context must survive however FastMCP actually runs a tool."""
    session: MockSession = team["session"]
    arguments = {"file_name": "CUSTOMERS", "record_id": "1"}

    with use_caller(team["alice"]):
        await server.mcp.call_tool("read_record", {**arguments, "connection": "Test"})
        assert session.connect_kwargs["host"] == "test.example"
        assert session.connect_kwargs["user"] == "tsvc"
        assert session.connect_kwargs["port"] == 40000
        assert session.connect_kwargs["ssl"] is True

        await server.mcp.call_tool("read_record", {**arguments, "connection": "Prod"})
        assert session.connect_kwargs["host"] == "prod.example"
        assert session.connect_kwargs["ssl"] is False

    with use_caller(team["bob"]):
        result = await server.mcp.call_tool("read_record", {**arguments, "connection": "Test"})
    assert "unknown connection 'Test'" in str(result)
    assert session.connect_kwargs["host"] == "prod.example"  # bob never reached Test
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/test_guard.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'u2_mcp.guard'`.

- [ ] **Step 3: Write the guard**

`src/u2_mcp/guard.py`:

```python
"""The access check every tool passes through before it runs.

The guard sits between FastMCP and the tool body. It works out who is calling and
which connection they mean, asks access.decide() whether the tool's permission is
held there, and -- only on a yes -- installs the route the connection registry
will use. A refusal is returned as the tool's result, and the tool body never runs.

Outside team mode there is no settings store, the caller is the local operator,
and the only connection is "default", built from environment variables, exactly
as before team mode existed.

check_tool_coverage() is called at startup. A tool registered without the guard,
or without a permission, stops the server rather than shipping unprotected.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from typing import Any, TypeVar, cast

from .access import decide, visible_connections
from .identity import IdentityError, current_caller
from .permissions import TOOL_PERMISSIONS, unmapped_tools
from .routing import Route, RouteError, resolve_route, use_route
from .store import get_store, is_global_read_only

F = TypeVar("F", bound=Callable[..., dict[str, Any]])

LOCAL_CONNECTION_NAME = "default"
_GUARD_MARK = "__u2_guarded__"


class GuardError(Exception):
    """Raised at startup when a tool would be served without an access check."""

    pass


class _Refused(Exception):
    """A refusal whose message is returned to the caller as the tool's error."""

    pass


def _route_for(permission: str, requested: str | None) -> Route | None:
    """Decide a call and return its route; None means run as the local operator.

    Raises:
        _Refused: With the message to show the caller
    """
    store = get_store()
    if store is None:
        if requested not in (None, LOCAL_CONNECTION_NAME):
            raise _Refused(f"unknown connection '{requested}'")
        return None

    try:
        caller = current_caller()
    except IdentityError as exc:
        raise _Refused(str(exc)) from exc
    if caller.user_id is None:
        raise _Refused("this request is not signed in")

    global_read_only = is_global_read_only()
    name = requested
    if name is None:
        names = [
            visible.connection.name
            for visible in visible_connections(
                store, caller.user_id, global_read_only=global_read_only
            )
        ]
        if not names:
            raise _Refused("you have no connections; ask an admin")
        if len(names) > 1:
            raise _Refused(f"say which connection to use: {', '.join(names)}")
        name = names[0]

    decision = decide(store, caller.user_id, name, permission, global_read_only=global_read_only)
    if not decision.allowed:
        raise _Refused(decision.reason)
    try:
        return resolve_route(store, decision)
    except RouteError as exc:
        raise _Refused(str(exc)) from exc


def guarded() -> Callable[[F], F]:
    """Put a tool behind the access check for its permission in TOOL_PERMISSIONS.

    Place directly under @mcp.tool(). The tool must accept `connection: str | None
    = None`; the guard reads it, and the tool body may ignore it.

    Raises:
        ValueError: At import, if the tool has no permission or no connection argument
    """

    def decorate(fn: F) -> F:
        name = fn.__name__
        permission = TOOL_PERMISSIONS.get(name)
        if permission is None:
            raise ValueError(f"{name} has no entry in permissions.TOOL_PERMISSIONS")
        signature = inspect.signature(fn)
        if "connection" not in signature.parameters:
            raise ValueError(f"{name} must accept a 'connection' argument to be guarded")

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> dict[str, Any]:
            requested = signature.bind_partial(*args, **kwargs).arguments.get("connection")
            try:
                route = _route_for(permission, requested)
            except _Refused as refusal:
                return {"error": str(refusal)}
            if route is None:
                return fn(*args, **kwargs)
            with use_route(route):
                return fn(*args, **kwargs)

        setattr(wrapper, _GUARD_MARK, True)
        return cast(F, wrapper)

    return decorate


def check_tool_coverage(mcp_instance: Any) -> None:
    """Refuse to serve any tool that lacks a permission or the guard.

    Args:
        mcp_instance: A FastMCP instance with its tools registered

    Raises:
        GuardError: Naming every offending tool
    """
    tools = mcp_instance._tool_manager._tools
    problems = [f"{name} has no permission" for name in unmapped_tools(tools)]
    problems += [
        f"{name} is not guarded"
        for name, tool in sorted(tools.items())
        if name in TOOL_PERMISSIONS and not getattr(tool.fn, _GUARD_MARK, False)
    ]
    if problems:
        raise GuardError("Refusing to serve tools without an access check: " + "; ".join(problems))
```

`UNSCOPED_TOOLS` (only `list_connections`) is deliberately unguarded. `unmapped_tools` already accepts it, and the second check only looks at tools in `TOOL_PERMISSIONS`.

- [ ] **Step 4: Guard every tool**

Make the same three edits to every function in the table below:

1. Add `from ..guard import guarded` to the module's imports. In `server.py` the import is `from .guard import check_tool_coverage, guarded`.
2. Put `@guarded()` on the line directly below `@mcp.tool()`.
3. Add `connection: str | None = None` as the **last** parameter. In the docstring's `Args:` section, add this line last. If the function has no `Args:` section, create one.

```
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.
```

The function bodies do not change.

| File | Signature after the change |
|---|---|
| `server.py` | `def connect(connection: str \| None = None) -> dict[str, Any]:` |
| `server.py` | `def disconnect(connection: str \| None = None) -> dict[str, Any]:` |
| `server.py` | `def list_sessions(connection: str \| None = None) -> dict[str, Any]:` (renamed from `list_connections`; first docstring line becomes `"""List the database sessions this server holds open for you.`) |
| `server.py` | `def watchdog_status(connection: str \| None = None) -> dict[str, Any]:` |
| `tools/dictionary.py` | `def list_dictionary(file_name: str, include_system: bool = False, connection: str \| None = None) -> dict[str, Any]:` |
| `tools/dictionary.py` | `def get_field_definition(file_name: str, field_name: str, connection: str \| None = None) -> dict[str, Any]:` |
| `tools/dictionary.py` | `def describe_file(file_name: str, connection: str \| None = None) -> dict[str, Any]:` |
| `tools/dictionary.py` | `def analyze_file_structure(file_name: str, sample_size: int = 100, connection: str \| None = None) -> dict[str, Any]:` |
| `tools/dictionary.py` | `def get_account_info(connection: str \| None = None) -> dict[str, Any]:` |
| `tools/files.py` | `def list_files(pattern: str = "*", connection: str \| None = None) -> dict[str, Any]:` |
| `tools/files.py` | `def read_record(file_name: str, record_id: str, connection: str \| None = None) -> dict[str, Any]:` |
| `tools/files.py` | `def read_records(file_name: str, record_ids: list[str], connection: str \| None = None) -> dict[str, Any]:` |
| `tools/files.py` | `def write_record(file_name: str, record_id: str, fields: dict[str, Any], confirm: bool = False, connection: str \| None = None) -> dict[str, Any]:` |
| `tools/files.py` | `def delete_record(file_name: str, record_id: str, confirm: bool = False, connection: str \| None = None) -> dict[str, Any]:` |
| `tools/files.py` | `def get_file_info(file_name: str, connection: str \| None = None) -> dict[str, Any]:` |
| `tools/files.py` | `def export_to_json(file_name: str, record_ids: list[str], expand_mv: bool = False, connection: str \| None = None) -> dict[str, Any]:` |
| `tools/files.py` | `def export_to_csv(file_name: str, record_ids: list[str], expand_mv: bool = False, mv_delimiter: str = "\|", connection: str \| None = None) -> dict[str, Any]:` |
| `tools/knowledge.py` | `def save_knowledge(topic: str, content: str, append: bool = False, connection: str \| None = None) -> dict[str, Any]:` |
| `tools/knowledge.py` | `def list_knowledge(connection: str \| None = None) -> dict[str, Any]:` |
| `tools/knowledge.py` | `def get_all_knowledge(connection: str \| None = None) -> dict[str, Any]:` |
| `tools/knowledge.py` | `def get_knowledge_topic(topic: str, connection: str \| None = None) -> dict[str, Any]:` |
| `tools/knowledge.py` | `def search_knowledge(query: str, connection: str \| None = None) -> dict[str, Any]:` |
| `tools/knowledge.py` | `def delete_knowledge(topic: str, confirm: bool = False, connection: str \| None = None) -> dict[str, Any]:` |
| `tools/query.py` | `def execute_query(query: str, max_rows: int \| None = None, connection: str \| None = None) -> dict[str, Any]:` |
| `tools/query.py` | `def execute_tcl(command: str, connection: str \| None = None) -> dict[str, Any]:` |
| `tools/query.py` | `def get_select_list(query: str, max_ids: int \| None = None, connection: str \| None = None) -> dict[str, Any]:` |
| `tools/query.py` | `def validate_query(query: str, connection: str \| None = None) -> dict[str, Any]:` |
| `tools/subroutine.py` | `def call_subroutine(name: str, args: list[str] \| None = None, num_args: int \| None = None, connection: str \| None = None) -> dict[str, Any]:` |
| `tools/subroutine.py` | `def list_catalog(pattern: str = "*", connection: str \| None = None) -> dict[str, Any]:` |
| `tools/transaction.py` | `def begin_transaction(connection: str \| None = None) -> dict[str, Any]:` |
| `tools/transaction.py` | `def commit_transaction(connection: str \| None = None) -> dict[str, Any]:` |
| `tools/transaction.py` | `def rollback_transaction(connection: str \| None = None) -> dict[str, Any]:` |
| `tools/transaction.py` | `def get_transaction_status(connection: str \| None = None) -> dict[str, Any]:` |
| `tools/update.py` | `def update_value(file_name: str, record_id: str, position: int, index: int, value: str, confirm: bool = False, connection: str \| None = None) -> dict[str, Any]:` |

(`\|` in the table is a literal `|`. Run `ruff format` afterwards to wrap long signatures.)

Here is one tool in full, so the shape is unambiguous (`tools/files.py`):

```python
@mcp.tool()
@guarded()
def read_record(file_name: str, record_id: str, connection: str | None = None) -> dict[str, Any]:
    """Read a single record from a Universe file.

    The record is returned with fields parsed into structured JSON,
    preserving multivalue and subvalue structure.

    Args:
        file_name: Name of the Universe file
        record_id: Record ID (key) to read
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        Dictionary containing record id, fields (by number), and optionally
        the raw record data. Returns error if record not found.
    """
    manager = get_connection_manager()
    ...  # body unchanged
```

- [ ] **Step 4b: Stop `list_catalog` from passing caller text to `CATALOG`**

`list_catalog` builds `CATALOG "<pattern>"` from the caller's `pattern` and runs it directly, which bypasses the blocked-command check. `CATALOG` is the verb that makes BASIC code live, so a pattern such as `BP" MYPROG` must never reach it. Task 2 moved the tool to `subroutine.call`. Here, restrict the pattern.

Add this test to `tests/test_guard.py`:

```python
def test_list_catalog_refuses_patterns_that_could_change_the_command(
    connection_manager: Any,
) -> None:
    from u2_mcp.tools.subroutine import list_catalog

    refused = list_catalog('BP" MYPROG')
    assert refused == {
        "error": "pattern may contain only letters, digits, '.', '_', '-' and '*'"
    }
    assert list_catalog("ORD*") != refused  # an ordinary pattern gets past the check
```

In `src/u2_mcp/tools/subroutine.py`, add `import re` to the imports if it is not there. Below the imports, add:

```python
# CATALOG is the verb that makes BASIC code live, so the pattern spliced into it
# may not carry quotes or spaces that would turn a listing into a cataloguing.
_CATALOG_PATTERN = re.compile(r"[A-Za-z0-9._*-]{1,64}")
```

Make these the first lines of `list_catalog`'s body, before `manager = get_connection_manager()`:

```python
    if not _CATALOG_PATTERN.fullmatch(pattern):
        return {"error": "pattern may contain only letters, digits, '.', '_', '-' and '*'"}
```

Run: `.venv/Scripts/python -m pytest tests/test_guard.py -k list_catalog -q`
Expected: PASS once Step 4 is done. Before this step the first assertion fails.

- [ ] **Step 5: Add the new `list_connections` tool and the startup check**

In `src/u2_mcp/server.py`:

1. Add these imports beside the existing ones:

```python
from .access import visible_connections
from .guard import check_tool_coverage, guarded
from .identity import IdentityError
from .store import get_store, is_global_read_only
```

`current_caller` is already imported in `server.py`. If it is not, add it to the existing `from .identity import (...)` block.

2. Directly after the renamed `list_sessions` tool, add:

```python
@mcp.tool()
def list_connections() -> dict[str, Any]:
    """List the U2 connections you can use, with your roles and permissions on each.

    Pass one of these names as the `connection` argument of any other tool. When
    only one connection is listed, `connection` can be left out.

    Returns:
        Dictionary with a `connections` list
    """
    store = get_store()
    if store is None:
        config = get_connection_manager().config
        return {
            "connections": [
                {
                    "name": "default",
                    "account": config.account,
                    "read_only": config.read_only,
                    "roles": [],
                    "permissions": "all",
                }
            ]
        }

    try:
        caller = current_caller()
    except IdentityError as exc:
        return {"error": str(exc)}
    if caller.user_id is None:
        return {"error": "this request is not signed in"}

    global_read_only = is_global_read_only()
    return {
        "connections": [
            {
                "name": visible.connection.name,
                "account": visible.connection.account,
                "read_only": visible.connection.read_only or global_read_only,
                "roles": list(visible.roles),
                "permissions": sorted(visible.permissions),
            }
            for visible in visible_connections(
                store, caller.user_id, global_read_only=global_read_only
            )
        ]
    }
```

3. In `main()`, make this the first statement inside the function body:

```python
    # A tool without an access check must stop the server, not ship open.
    check_tool_coverage(mcp)
```

The tool modules register their tools when `server.py` imports them at the bottom, so by the time `main()` runs, every tool is registered.

- [ ] **Step 6: Update tests that used the old tool name**

Run: `.venv/Scripts/python -m pytest -q -x`

If any test fails because it calls the server tool `list_connections` and expects open sessions, change that call to `list_sessions`. Find such calls with:

```bash
grep -rn "server.list_connections\|import list_connections\|list_connections()" tests
```

Leave calls to `ConnectionManager.list_connections()` (the manager method) unchanged. Only the MCP tool was renamed.

- [ ] **Step 7: Run the tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/test_guard.py -q`
Expected: 17 passed.

Run: `.venv/Scripts/python -m pytest -q`
Expected: all pass.

- [ ] **Step 8: Checks and commit**

Run: `.venv/Scripts/ruff check . && .venv/Scripts/ruff format . && .venv/Scripts/mypy src/`
Expected: no errors.

```bash
git add src/u2_mcp tests
git commit -m "feat: guard every tool with a per-connection access check" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Knowledge kept per connection

**Files:**
- Modify: `src/u2_mcp/utils/knowledge.py` (`get_knowledge_store`, plus a reset helper), `src/u2_mcp/resources/knowledge.py`
- Test: `tests/test_tools/test_knowledge_per_connection.py`

**Interfaces:**
- Consumes: `current_route()` (Task 6); `get_store()` and `store.data_dir` (Task 3).
- Produces:
  - `get_knowledge_store()` returns the store for the current route's connection in team mode, and the existing global store otherwise.
  - `reset_connection_knowledge_stores() -> None`, for tests.
  - In team mode the `u2://knowledge` resource returns a pointer to the tools instead of any connection's notes.

- [ ] **Step 1: Write the failing tests**

`tests/test_tools/test_knowledge_per_connection.py`:

```python
"""What was learned about Prod stays with Prod."""

from collections.abc import Iterator
from typing import Any

import pytest

import u2_mcp.server as server
from tests.mocks.mock_uopy import MockSession
from u2_mcp.identity import caller_for_user, use_caller
from u2_mcp.resources.knowledge import get_database_knowledge
from u2_mcp.store import install_store
from u2_mcp.store.repo import Store
from u2_mcp.tools.knowledge import get_all_knowledge, save_knowledge
from u2_mcp.utils.knowledge import reset_connection_knowledge_stores


@pytest.fixture
def alice(store: Store, mock_env: dict[str, str], mock_uopy: MockSession) -> Iterator[Any]:
    analyst = store.get_role_by_name("Analyst")
    assert analyst is not None
    user = store.get_or_create_sso_user("alice")
    for name in ("Prod", "Test"):
        connection = store.add_connection(
            name=name, host=f"{name}.example", port=1, service="uvcs", account="A",
            shared_user="svc", shared_password="pw", read_only=False,
        )
        store.add_grant(connection_id=connection.id, subject_type="user",
                        subject_id=user.id, role_id=analyst.id)
    install_store(store)
    reset_connection_knowledge_stores()
    try:
        with use_caller(caller_for_user(user, auth_method="token")):
            yield store
    finally:
        install_store(None)
        reset_connection_knowledge_stores()
        server.reset_connection_manager()


def test_notes_saved_on_one_connection_are_not_seen_on_another(alice: Store) -> None:
    saved = save_knowledge("CUSTOMERS", "Holds customer master records", connection="Prod")
    assert "error" not in saved
    assert "Holds customer master records" in str(get_all_knowledge(connection="Prod"))
    assert "Holds customer master records" not in str(get_all_knowledge(connection="Test"))


def test_notes_live_under_the_data_directory(alice: Store) -> None:
    save_knowledge("CUSTOMERS", "x", connection="Prod")
    prod_id = alice.get_connection_by_name("Prod").id  # type: ignore[union-attr]
    assert (alice.data_dir / "knowledge" / f"connection-{prod_id}.md").exists()


def test_the_resource_does_not_leak_notes_in_team_mode(alice: Store) -> None:
    save_knowledge("CUSTOMERS", "secret-ish note", connection="Prod")
    text = get_database_knowledge()
    assert "secret-ish note" not in text
    assert "list_knowledge" in text
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/test_tools/test_knowledge_per_connection.py -q`
Expected: FAIL with `ImportError: cannot import name 'reset_connection_knowledge_stores'`.

- [ ] **Step 3: Implement per-connection stores**

In `src/u2_mcp/utils/knowledge.py`:

1. Add `import threading` to the imports, along with:

```python
from ..routing import current_route
from ..store import get_store
```

2. Replace the section from `# Global instance` to the end of `get_knowledge_store` with:

```python
# Global instance, used outside team mode
_knowledge_store: KnowledgeStore | None = None

# Team mode: one store per connection, so notes about one system never surface
# while working on another.
_connection_stores: dict[int, KnowledgeStore] = {}
_connection_stores_lock = threading.Lock()


def get_knowledge_store() -> KnowledgeStore:
    """Get the knowledge store for the current call.

    In team mode the guard has chosen a connection, and its notes live in
    <U2_DATA_DIR>/knowledge/connection-<id>.md. Otherwise there is one store, at
    U2_KNOWLEDGE_PATH or ~/.u2-mcp/knowledge.md, as before.
    """
    global _knowledge_store
    route = current_route()
    settings = get_store()
    if route is not None and settings is not None:
        connection_id = route.connection.id
        with _connection_stores_lock:
            store = _connection_stores.get(connection_id)
            if store is None:
                path = settings.data_dir / "knowledge" / f"connection-{connection_id}.md"
                store = KnowledgeStore(path)
                _connection_stores[connection_id] = store
            return store

    if _knowledge_store is None:
        # Check for custom path in environment
        custom_path = os.environ.get("U2_KNOWLEDGE_PATH")
        _knowledge_store = KnowledgeStore(custom_path)
    return _knowledge_store


def reset_connection_knowledge_stores() -> None:
    """Forget the per-connection stores (for tests and after connection changes)."""
    with _connection_stores_lock:
        _connection_stores.clear()
```

3. In `src/u2_mcp/resources/knowledge.py`, add `from ..store import get_store` and replace the function body with:

```python
    if get_store() is not None:
        # Resources are read outside any tool call, so there is no connection to
        # scope them to -- and no access check. Point at the guarded tools instead.
        return (
            "Knowledge is kept per connection on this server. Use list_connections, "
            "then list_knowledge or get_all_knowledge with a connection name."
        )
    store = get_knowledge_store()
    return store.get_all()
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/test_tools/test_knowledge_per_connection.py tests/test_tools/test_knowledge.py -q`
Expected: all pass (3 new, plus the existing knowledge tests).

- [ ] **Step 5: Full suite, checks, commit**

Run: `.venv/Scripts/python -m pytest -q && .venv/Scripts/ruff check . && .venv/Scripts/ruff format . && .venv/Scripts/mypy src/`
Expected: all pass.

```bash
git add src/u2_mcp/utils/knowledge.py src/u2_mcp/resources/knowledge.py tests/test_tools/test_knowledge_per_connection.py
git commit -m "feat: keep learned knowledge per connection in team mode" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: Team-mode startup and import of today's configuration

**Files:**
- Modify: `src/u2_mcp/config.py` (five settings), `src/u2_mcp/store/repo.py` (`link_pending_sso_user`)
- Create: `src/u2_mcp/store/bootstrap.py`
- Test: `tests/test_store/test_bootstrap.py`

**Interfaces:**
- Consumes: `SecretBox`, `open_database`, `DATABASE_FILENAME`, `Store` (Tasks 1 and 3); `MappedCredentialResolver._load` and `_password_for`, `CredentialError` (existing `credentials.py`); `decide` (Task 4, in tests).
- Produces:
  - New `U2Config` fields:
    - `secret_key: SecretStr | None` (`U2_SECRET_KEY`)
    - `data_dir: str` (`U2_DATA_DIR`, default `/data`)
    - `public_url: str | None` (`U2_PUBLIC_URL`)
    - `sso_groups_claim: str` (`U2_SSO_GROUPS_CLAIM`, default `groups`)
    - `token_freshness_days: int` (`U2_TOKEN_FRESHNESS_DAYS`, default 30)
  - `Store.link_pending_sso_user(email: str, subject: str) -> User | None`
  - `TeamModeError(Exception)`
  - `open_team_store(config: U2Config) -> Store | None`
  - `import_environment(store, config) -> None`
  - `IMPORT_CONNECTION_NAME = "default"`, `IMPORT_ROLE = "Imported access"`, `IMPORT_PERMISSIONS` (Developer's permissions minus every `basic.*`)
  - The import creates `Imported access` as a custom, editable role. It holds exactly the permissions today's tools need, so when the BASIC tools arrive, grants made by the import do not quietly gain compile rights.
  - Users imported by email get the SSO subject `pending:<lowercased email>` until their first sign-in links them.

- [ ] **Step 1: Add the settings**

In `src/u2_mcp/config.py`, add `SecretStr` to the existing `from pydantic import ...` line. Then add this block directly after the `credential_map_path` field:

```python
    # Team mode: settings database, access control and personal access tokens
    secret_key: SecretStr | None = Field(
        default=None,
        alias="U2_SECRET_KEY",
        description=(
            "Turns on team mode for the HTTP transports and encrypts the secrets in "
            "the settings database. At least 32 characters. Keep it in your vault: "
            "without it, stored U2 passwords cannot be read."
        ),
    )
    data_dir: str = Field(
        default="/data",
        alias="U2_DATA_DIR",
        description="Directory for the settings database and per-connection knowledge",
    )
    public_url: str | None = Field(
        default=None,
        alias="U2_PUBLIC_URL",
        description="The URL people use to reach this server, e.g. https://u2-mcp.corp.example",
    )
    sso_groups_claim: str = Field(
        default="groups",
        alias="U2_SSO_GROUPS_CLAIM",
        description="Identity-provider claim that lists a person's groups",
    )
    token_freshness_days: int = Field(
        default=30,
        alias="U2_TOKEN_FRESHNESS_DAYS",
        description=(
            "An SSO user's personal access tokens stop working when they have not "
            "signed in through SSO for this many days"
        ),
    )
```

- [ ] **Step 2: Add `link_pending_sso_user` to the store**

In `src/u2_mcp/store/repo.py`, directly after `get_user_by_subject`, add:

```python
    def link_pending_sso_user(self, email: str, subject: str) -> User | None:
        """Give a user imported by email address their real SSO subject.

        Credential maps may be keyed by email. Those users are imported with the
        placeholder subject "pending:<email>" and linked here on first sign-in.

        Returns:
            The linked user, or None when no pending user has that email
        """
        with self._tx() as conn:
            row = conn.execute(
                "SELECT id FROM users WHERE sso_subject = ?", (f"pending:{email.lower()}",)
            ).fetchone()
            if row is None:
                return None
            user_id = int(row["id"])
            conn.execute("UPDATE users SET sso_subject = ? WHERE id = ?", (subject, user_id))
        return self.get_user(user_id)
```

- [ ] **Step 3: Write the failing tests**

`tests/test_store/test_bootstrap.py`:

```python
"""Team mode starts safely and keeps today's deployments working."""

import json
import os
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest

from u2_mcp.access import decide
from u2_mcp.config import U2Config
from u2_mcp.store.bootstrap import TeamModeError, open_team_store
from u2_mcp.store.repo import Store

KEY = "s" * 40


@pytest.fixture
def team_env(mock_env: dict[str, str], tmp_path: Path) -> Iterator[Path]:
    with patch.dict(os.environ, {"U2_SECRET_KEY": KEY, "U2_DATA_DIR": str(tmp_path)}):
        yield tmp_path


def _open() -> Store:
    store = open_team_store(U2Config())
    assert store is not None
    return store


def test_without_a_key_there_is_no_team_mode(mock_env: dict[str, str], tmp_path: Path) -> None:
    with patch.dict(os.environ, {"U2_DATA_DIR": str(tmp_path)}):
        assert open_team_store(U2Config()) is None


def test_an_existing_database_without_its_key_refuses_to_start(team_env: Path) -> None:
    _open()._conn.close()
    with patch.dict(os.environ, {"U2_SECRET_KEY": ""}), pytest.raises(
        TeamModeError, match="U2_SECRET_KEY is not set"
    ):
        open_team_store(U2Config())


def test_a_short_key_is_refused(mock_env: dict[str, str], tmp_path: Path) -> None:
    with patch.dict(os.environ, {"U2_SECRET_KEY": "short", "U2_DATA_DIR": str(tmp_path)}):
        with pytest.raises(TeamModeError, match="at least 32"):
            open_team_store(U2Config())


def test_shared_mode_import_keeps_todays_behaviour(team_env: Path) -> None:
    store = _open()
    connection = store.get_connection_by_name("default")
    assert connection is not None
    assert (connection.host, connection.account, connection.login_mode) == (
        "test-host.example.com",
        "TEST",
        "shared",
    )
    assert connection.shared_user == "test-user"
    assert store.shared_password(connection.id) == "test-password"
    assert not connection.read_only  # mock_env sets U2_READ_ONLY=false

    grants = store.grants_on_connection(connection.id)
    imported = store.get_role_by_name("Imported access")
    assert imported is not None and not imported.builtin
    assert [(g.subject_type, g.role_id) for g in grants] == [("everyone", imported.id)]
    assert "records.write" in imported.permissions
    assert not any(p.startswith("basic.") for p in imported.permissions)

    newcomer = store.get_or_create_sso_user("someone-new")
    assert decide(store, newcomer.id, "default", "records.write", global_read_only=False).allowed
    assert store.recent_audit(1)[0]["action"] == "import_environment"


def test_the_import_happens_once(team_env: Path) -> None:
    _open()._conn.close()
    store = _open()
    assert len(store.list_connections()) == 1
    assert len(store.grants_on_connection(store.list_connections()[0].id)) == 1


def test_read_only_carries_over(team_env: Path) -> None:
    with patch.dict(os.environ, {"U2_READ_ONLY": "true"}):
        store = _open()
    connection = store.get_connection_by_name("default")
    assert connection is not None and connection.read_only


def test_mapped_mode_imports_each_person_and_nobody_else(team_env: Path) -> None:
    credential_map = team_env / "credentials.json"
    credential_map.write_text(
        json.dumps(
            {
                "sub-alice": {"user": "alice_u2", "password": "a"},
                "Bob@Corp.com": {"user": "bob_u2", "password_env": "BOB_PW"},
                "carol": {"user": "c", "account": "OTHER", "password": "x"},
                "dave": {"user": "d"},
            }
        ),
        encoding="utf-8",
    )
    env = {
        "U2_IDENTITY_MODE": "mapped",
        "U2_CREDENTIAL_MAP_PATH": str(credential_map),
        "BOB_PW": "b",
    }
    with patch.dict(os.environ, env):
        store = _open()

    connection = store.get_connection_by_name("default")
    assert connection is not None and connection.login_mode == "per_user"
    grants = store.grants_on_connection(connection.id)
    assert sorted(g.per_user_u2_user or "" for g in grants) == ["alice_u2", "bob_u2"]
    assert all(g.subject_type == "user" for g in grants)

    alice = store.get_user_by_subject("sub-alice")
    assert alice is not None
    alice_grant = next(g for g in grants if g.subject_id == alice.id)
    assert store.grant_u2_password(alice_grant.id) == "a"

    linked = store.link_pending_sso_user("bob@corp.com", "real-bob-subject")
    assert linked is not None and linked.sso_subject == "real-bob-subject"
    assert linked.email == "Bob@Corp.com"

    stranger = store.get_or_create_sso_user("stranger")
    assert not decide(store, stranger.id, "default", "records.read",
                      global_read_only=False).allowed


def test_mapped_mode_without_a_map_refuses_to_start(team_env: Path) -> None:
    env = {"U2_IDENTITY_MODE": "mapped", "U2_CREDENTIAL_MAP_PATH": str(team_env / "none.json")}
    with patch.dict(os.environ, env), pytest.raises(TeamModeError, match="credential map"):
        open_team_store(U2Config())
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/test_store/test_bootstrap.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'u2_mcp.store.bootstrap'`.

- [ ] **Step 5: Write the bootstrap**

`src/u2_mcp/store/bootstrap.py`:

```python
"""Team mode startup: open the settings database and carry today's setup into it.

Team mode is switched on by U2_SECRET_KEY and nothing else. Without it the HTTP
transports run exactly as they did before team mode existed. Once a settings
database exists, though, leaving the key out is refused rather than silently
falling back -- otherwise deleting one environment variable would switch every
access rule off.

The first start imports U2_HOST and friends as a connection named "default",
granting what the server allowed before, and no more:

- shared mode: every authenticated caller could use the shared login, so
  "everyone" gets the Imported access role (read-only still follows U2_READ_ONLY);
- mapped mode: only people in the credential map could connect, so exactly they
  get Imported access with their own U2 login, and nobody else gets anything.

Imported access is a custom role holding exactly what today's tools can do. It is
deliberately not Developer: Developer will grow as new tools arrive (BASIC
compile, for one), and a grant nobody chose should not grow with it.
"""

from __future__ import annotations

import logging
from pathlib import Path

from ..config import U2Config
from ..credentials import CredentialError, MappedCredentialResolver
from ..permissions import BUILTIN_ROLES
from .crypto import SecretBox
from .db import DATABASE_FILENAME, open_database
from .repo import Store

logger = logging.getLogger(__name__)

IMPORT_CONNECTION_NAME = "default"
IMPORT_ROLE = "Imported access"
IMPORT_PERMISSIONS: tuple[str, ...] = tuple(
    p for p in BUILTIN_ROLES["Developer"] if not p.startswith("basic.")
)


class TeamModeError(Exception):
    """Raised when team mode cannot start safely."""

    pass


def open_team_store(config: U2Config) -> Store | None:
    """Open the settings database if team mode is on.

    Args:
        config: Server configuration

    Returns:
        The store, or None when U2_SECRET_KEY is not set and no database exists

    Raises:
        TeamModeError: If a database exists without its key, the key is too short,
            or today's configuration cannot be imported
    """
    db_path = Path(config.data_dir).expanduser() / DATABASE_FILENAME
    secret = config.secret_key.get_secret_value() if config.secret_key else ""

    if not secret:
        if db_path.exists():
            raise TeamModeError(
                f"A settings database exists at {db_path} but U2_SECRET_KEY is not set. "
                "Set it to the key this database was created with. Team mode cannot be "
                "switched off by leaving the key out."
            )
        return None

    try:
        box = SecretBox(secret)
    except ValueError as exc:
        raise TeamModeError(str(exc)) from exc

    store = Store(open_database(db_path), box, db_path.parent)
    store.seed_builtin_roles()
    if not store.has_connections():
        import_environment(store, config)
    return store


def import_environment(store: Store, config: U2Config) -> None:
    """Create the "default" connection and grants from today's environment settings.

    Args:
        store: An empty settings store
        config: Server configuration

    Raises:
        TeamModeError: If mapped mode is configured but its credential map cannot be read
    """
    role = store.get_role_by_name(IMPORT_ROLE) or store.add_role(IMPORT_ROLE, IMPORT_PERMISSIONS)

    if config.identity_mode == "mapped":
        connection = store.add_connection(
            name=IMPORT_CONNECTION_NAME,
            host=config.host,
            port=config.port,
            service=config.service,
            account=config.account,
            ssl=config.ssl,
            login_mode="per_user",
            read_only=config.read_only,
            actor="import",
        )
        imported, skipped = _import_credential_map(store, config, connection.id, role.id)
        logger.info(
            f"Team mode imported {imported} person(s) from the credential map as "
            f"{IMPORT_ROLE} on '{IMPORT_CONNECTION_NAME}'"
        )
        params: dict[str, object] = {
            "identity_mode": "mapped",
            "imported": imported,
            "skipped": skipped,
        }
    else:
        connection = store.add_connection(
            name=IMPORT_CONNECTION_NAME,
            host=config.host,
            port=config.port,
            service=config.service,
            account=config.account,
            ssl=config.ssl,
            login_mode="shared",
            shared_user=config.user,
            shared_password=config.password,
            read_only=config.read_only,
            actor="import",
        )
        store.add_grant(connection_id=connection.id, subject_type="everyone", role_id=role.id)
        logger.warning(
            f"Team mode imported U2_HOST as connection '{IMPORT_CONNECTION_NAME}' and gave "
            f"every signed-in user the {IMPORT_ROLE} role on it, matching how this server "
            "behaved before team mode. Narrow this in the admin UI."
        )
        params = {"identity_mode": "shared", "everyone_role": IMPORT_ROLE}

    store.add_audit(
        kind="admin",
        action="import_environment",
        outcome="ok",
        actor_label="startup",
        connection_id=connection.id,
        params=params,
    )


def _import_credential_map(
    store: Store, config: U2Config, connection_id: int, role_id: int
) -> tuple[int, list[str]]:
    """Give each credential-map entry a user and a per-user grant.

    Returns:
        How many entries were imported, and why each skipped one was skipped
    """
    try:
        entries = MappedCredentialResolver._load(Path(config.credential_map_path).expanduser())
    except CredentialError as exc:
        raise TeamModeError(
            f"U2_IDENTITY_MODE=mapped, but the credential map could not be imported: {exc}"
        ) from exc

    imported = 0
    skipped: list[str] = []
    for key, entry in sorted(entries.items()):
        if not isinstance(entry, dict) or not entry.get("user"):
            skipped.append(f"{key}: no user")
            continue
        if entry.get("account") and entry["account"] != config.account:
            skipped.append(
                f"{key}: account {entry['account']} differs from U2_ACCOUNT; "
                "add it as its own connection in the admin UI"
            )
            continue
        try:
            password = MappedCredentialResolver._password_for(key, entry)
        except CredentialError as exc:
            skipped.append(f"{key}: {exc}")
            continue

        if "@" in key:
            user = store.get_or_create_sso_user(f"pending:{key.lower()}", email=key)
        else:
            user = store.get_or_create_sso_user(key)
        store.add_grant(
            connection_id=connection_id,
            subject_type="user",
            subject_id=user.id,
            role_id=role_id,
            per_user_u2_user=entry["user"],
            per_user_u2_password=password,
        )
        imported += 1

    for reason in skipped:
        logger.warning(f"Credential map entry skipped: {reason}")
    return imported, skipped
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/test_store/test_bootstrap.py tests/test_config.py -q`
Expected: all pass (8 new).

- [ ] **Step 7: Full suite, checks, commit**

Run: `.venv/Scripts/python -m pytest -q && .venv/Scripts/ruff check . && .venv/Scripts/ruff format . && .venv/Scripts/mypy src/`
Expected: all pass.

```bash
git add src/u2_mcp/config.py src/u2_mcp/store tests/test_store/test_bootstrap.py
git commit -m "feat: team-mode startup that imports today's configuration without widening access" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 10: Team-mode sign-in, tokens on the wire, audit, and end-to-end proof

**Files:**
- Create: `src/u2_mcp/team_auth.py`
- Modify: `src/u2_mcp/auth/provider.py` (`__init__`, `load_access_token`, `handle_idp_callback`), `src/u2_mcp/exposure.py` (`check_network_exposure`, `_check_unauthenticated_reach`), `src/u2_mcp/server.py` (audit wrapper, `run_sse_server`, `run_streamable_http_server` split into `build_streamable_http_app` + run)
- Test: `tests/test_team_auth.py`, `tests/test_team_mode_e2e.py`

**Interfaces:**
- Consumes: everything above. `open_team_store`, `TeamModeError` (Task 9); `create_token`, `verify_token`, `TokenRejected`, `looks_like_token`, `hash_token` (Task 5); `caller_for_user` (Task 6); `install_store`, `get_store` (Task 3); `check_tool_coverage` (Task 7); `TokenInfo` (existing `auth/idp/base.py`); `AccessToken`, `TokenVerifier` (MCP SDK).
- Produces:
  - `team_auth.PAT_SCOPES = ["u2:read", "u2:write"]`
  - `team_auth.PatVerifier(store, *, freshness_days: int, resource: str | None)` with `async verify_token(token) -> AccessToken | None`
  - `team_auth.ClientAddressMiddleware` (ASGI)
  - `team_auth.groups_from_claims(claims: dict, claim_name: str) -> list[str] | None`
  - `team_auth.make_sign_in_handler(store, groups_claim: str) -> Callable[[TokenInfo], None]`
  - `team_auth.make_identity_resolver(store, oauth_storage) -> Callable[[], CallerIdentity | None]`
  - `U2OAuthProvider(..., on_sign_in=None, pat_verifier=None)`
  - `check_network_exposure(config, transport, *, authenticated: bool = False)`
  - `server.build_streamable_http_app(config: U2Config) -> Starlette`

- [ ] **Step 1: Write the failing unit tests**

`tests/test_team_auth.py`:

```python
"""Turning a request into a person: tokens, OAuth callers and SSO sign-ins."""

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp.server.auth.provider import AccessToken

from u2_mcp.auth.idp.base import TokenInfo
from u2_mcp.auth.provider import U2OAuthProvider
from u2_mcp.auth.storage import PendingAuthorization, StoredToken
from u2_mcp.store.repo import Store
from u2_mcp.team_auth import (
    PatVerifier,
    _client_ip,
    groups_from_claims,
    make_identity_resolver,
    make_sign_in_handler,
)
from u2_mcp.tokens import create_token


@pytest.mark.parametrize(
    ("claims", "name", "expected"),
    [
        ({"groups": ["a", "b"]}, "groups", ["a", "b"]),
        ({"groups": "solo"}, "groups", ["solo"]),
        ({}, "groups", []),  # provider sends no groups at all
        ({"_claim_names": {"groups": "src1"}}, "groups", None),  # Entra overage
        ({"hasgroups": True}, "groups", None),  # Entra overage, implicit flow
        ({"roles": ["x"]}, "roles", ["x"]),
        ({"groups": 42}, "groups", []),
    ],
)
def test_groups_from_claims(claims: dict[str, Any], name: str, expected: list[str] | None) -> None:
    assert groups_from_claims(claims, name) == expected


class TestSignIn:
    def test_a_first_sign_in_creates_the_user_with_groups(self, store: Store) -> None:
        handler = make_sign_in_handler(store, "groups")
        handler(TokenInfo(subject="s1", email="a@x.com", name="Alice",
                          raw_claims={"groups": ["g-dev"]}))
        user = store.get_user_by_subject("s1")
        assert user is not None and user.display_name == "Alice"
        assert user.last_sso_login_at is not None
        assert len(store.group_ids_for_user(user.id)) == 1
        assert store.recent_audit(1)[0]["action"] == "sso_sign_in"

    def test_an_email_imported_user_is_linked_not_duplicated(self, store: Store) -> None:
        pending = store.get_or_create_sso_user("pending:bob@corp.com", email="bob@corp.com")
        make_sign_in_handler(store, "groups")(TokenInfo(subject="real-bob", email="Bob@Corp.com"))
        user = store.get_user_by_subject("real-bob")
        assert user is not None and user.id == pending.id

    def test_groups_from_the_adapter_are_used_when_claims_lack_them(self, store: Store) -> None:
        make_sign_in_handler(store, "groups")(TokenInfo(subject="s2", groups=["g-ops"]))
        user = store.get_user_by_subject("s2")
        assert user is not None and len(store.group_ids_for_user(user.id)) == 1


class TestPatVerifier:
    @pytest.mark.asyncio
    async def test_a_valid_token_is_accepted_with_read_scope(self, store: Store) -> None:
        user = store.add_local_user("ops")
        token, record = create_token(store, user.id, "script")
        verifier = PatVerifier(store, freshness_days=30, resource="https://u2.example")
        ip_token = _client_ip.set("10.9.8.7")
        try:
            access = await verifier.verify_token(token)
        finally:
            _client_ip.reset(ip_token)
        assert access is not None
        assert "u2:read" in access.scopes
        assert access.client_id == f"pat-{record.id}"
        stored = store.get_token_by_hash(record.token_hash)
        assert stored is not None and stored.last_used_ip == "10.9.8.7"

    @pytest.mark.asyncio
    async def test_bad_or_foreign_tokens_are_refused(self, store: Store) -> None:
        verifier = PatVerifier(store, freshness_days=30, resource=None)
        assert await verifier.verify_token("u2pat_" + "x" * 43) is None
        assert await verifier.verify_token("an-oauth-token") is None


class TestIdentityResolver:
    def test_a_token_names_its_owner(self, store: Store) -> None:
        user = store.add_local_user("ops")
        token, record = create_token(store, user.id, "script")
        access = AccessToken(token=token, client_id=f"pat-{record.id}", scopes=["u2:read"])
        resolve = make_identity_resolver(store, None)
        with patch("mcp.server.auth.middleware.auth_context.get_access_token",
                   return_value=access):
            caller = resolve()
        assert caller is not None
        assert (caller.user_id, caller.auth_method) == (user.id, "token")

    def test_an_oauth_token_names_the_signed_in_person(self, store: Store) -> None:
        sso = store.get_or_create_sso_user("s1", display_name="Alice")
        oauth_storage = MagicMock()
        oauth_storage.get_access_token.return_value = StoredToken(
            token="at", token_type="access", client_id="vscode", user_subject="s1", scope="u2:read"
        )
        access = AccessToken(token="at", client_id="vscode", scopes=["u2:read"])
        resolve = make_identity_resolver(store, oauth_storage)
        with patch("mcp.server.auth.middleware.auth_context.get_access_token",
                   return_value=access):
            caller = resolve()
        assert caller is not None
        assert (caller.user_id, caller.auth_method, caller.client_id) == (sso.id, "oauth", "vscode")

    def test_an_older_oauth_session_links_an_email_imported_user(self, store: Store) -> None:
        pending = store.get_or_create_sso_user("pending:bob@corp.com", email="bob@corp.com")
        oauth_storage = MagicMock()
        oauth_storage.get_access_token.return_value = StoredToken(
            token="at", token_type="access", client_id="vscode", user_subject="real-bob",
            scope="u2:read", user_claims={"email": "Bob@Corp.com"},
        )
        access = AccessToken(token="at", client_id="vscode", scopes=["u2:read"])
        with patch("mcp.server.auth.middleware.auth_context.get_access_token",
                   return_value=access):
            caller = make_identity_resolver(store, oauth_storage)()
        assert caller is not None and caller.user_id == pending.id

    def test_no_token_means_no_caller(self, store: Store) -> None:
        with patch("mcp.server.auth.middleware.auth_context.get_access_token",
                   return_value=None):
            assert make_identity_resolver(store, None)() is None


class TestProviderHooks:
    @pytest.mark.asyncio
    async def test_personal_tokens_bypass_the_oauth_store(self) -> None:
        expected = AccessToken(token="u2pat_x", client_id="pat-1", scopes=["u2:read"])
        pat_verifier = AsyncMock(return_value=expected)
        provider = U2OAuthProvider(idp_adapter=MagicMock(), issuer_url="https://u2.example",
                                   pat_verifier=pat_verifier)
        assert await provider.load_access_token("u2pat_x") is expected
        assert await provider.load_access_token("not-a-pat") is None
        pat_verifier.assert_awaited_once_with("u2pat_x")

    @pytest.mark.asyncio
    async def test_a_completed_idp_sign_in_is_reported_once(self) -> None:
        info = TokenInfo(subject="s1", email="a@x.com", raw_claims={"groups": []})
        adapter = MagicMock()
        adapter.exchange_code = AsyncMock(return_value=MagicMock(access_token="idp-at"))
        adapter.validate_token = AsyncMock(return_value=info)
        seen: list[TokenInfo] = []
        provider = U2OAuthProvider(idp_adapter=adapter, issuer_url="https://u2.example",
                                   on_sign_in=seen.append)
        provider.storage.store_pending_auth(PendingAuthorization(
            state="st", client_id="c", redirect_uri="https://client/cb", scope="u2:read",
            code_challenge=None, code_challenge_method=None,
            claude_redirect_uri="https://client/cb", claude_state="cs",
        ))
        await provider.handle_idp_callback("code", "st")
        assert seen == [info]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/test_team_auth.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'u2_mcp.team_auth'`.

- [ ] **Step 3: Write `team_auth.py`**

`src/u2_mcp/team_auth.py`:

```python
"""Authentication in team mode: personal access tokens, OAuth callers and sign-ins.

Three jobs, all about turning a request into a settings-database user:

- PatVerifier lets the MCP SDK's bearer-auth middleware accept personal access
  tokens, with or without an OAuth provider alongside.
- The identity resolver tells the rest of the server which user is calling, so
  access.decide() can answer for them.
- The sign-in handler runs once per completed SSO sign-in: it creates the user on
  first sight, replaces their groups, and restarts their token freshness window.
"""

from __future__ import annotations

import contextvars
import logging
from collections.abc import Callable
from typing import Any

from mcp.server.auth.provider import AccessToken

from .auth.idp.base import TokenInfo
from .identity import CallerIdentity, caller_for_user
from .store.repo import Store
from .tokens import TokenRejected, hash_token, looks_like_token, verify_token

logger = logging.getLogger(__name__)

# Scopes a personal access token carries. Permissions are decided per call by
# access.py; these only satisfy the transport's required_scopes check.
PAT_SCOPES = ["u2:read", "u2:write"]

_client_ip: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "u2_client_ip", default=None
)


class ClientAddressMiddleware:
    """Record the caller's address for the request, so token use can be attributed.

    Pure ASGI rather than BaseHTTPMiddleware, so the context variable is set in the
    same task the authentication middleware runs in.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        token = _client_ip.set(client[0] if client else None)
        try:
            await self.app(scope, receive, send)
        finally:
            _client_ip.reset(token)


class PatVerifier:
    """Accept personal access tokens as MCP bearer tokens.

    Args:
        store: The settings database
        freshness_days: How recently an SSO owner must have signed in
        resource: This server's URL, reported as the token's resource
    """

    def __init__(self, store: Store, *, freshness_days: int, resource: str | None) -> None:
        self._store = store
        self._freshness_days = freshness_days
        self._resource = resource

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return an AccessToken for a valid personal token, otherwise None."""
        if not looks_like_token(token):
            return None
        try:
            _user, record = verify_token(
                self._store, token, freshness_days=self._freshness_days, ip=_client_ip.get()
            )
        except TokenRejected as exc:
            logger.info(f"Personal access token refused: {exc}")
            return None
        return AccessToken(
            token=token,
            client_id=f"pat-{record.id}",
            scopes=list(PAT_SCOPES),
            expires_at=int(record.expires_at),
            resource=self._resource,
        )


def groups_from_claims(claims: dict[str, Any], claim_name: str) -> list[str] | None:
    """Read group membership from identity-provider claims.

    Returns:
        The groups; [] when the provider sends none; None when the provider says
        there are groups but left them out (Microsoft Entra's "group overage")
    """
    value = claims.get(claim_name)
    if value is None:
        claim_sources = claims.get("_claim_names") or {}
        overage = claim_name in claim_sources or bool(claims.get("hasgroups"))
        return None if overage else []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return []


def make_sign_in_handler(store: Store, groups_claim: str) -> Callable[[TokenInfo], None]:
    """Build the provider's on_sign_in hook for team mode.

    Args:
        store: The settings database
        groups_claim: Name of the claim that lists groups (U2_SSO_GROUPS_CLAIM)
    """

    def on_sign_in(info: TokenInfo) -> None:
        claims = dict(info.raw_claims or {})
        if groups_claim not in claims and groups_claim == "groups" and info.groups is not None:
            claims["groups"] = info.groups

        if store.get_user_by_subject(info.subject) is None and info.email:
            store.link_pending_sso_user(info.email, info.subject)
        user = store.get_or_create_sso_user(
            info.subject, email=info.email, display_name=info.name
        )
        groups = groups_from_claims(claims, groups_claim)
        store.record_sso_login(user.id, groups)
        store.add_audit(
            kind="auth",
            action="sso_sign_in",
            outcome="ok",
            actor_user_id=user.id,
            actor_label=user.label,
            params={"groups": None if groups is None else len(groups)},
        )

    return on_sign_in


def make_identity_resolver(
    store: Store, oauth_storage: Any | None
) -> Callable[[], CallerIdentity | None]:
    """Build the resolver that names the settings-database user behind a request.

    Args:
        store: The settings database
        oauth_storage: The OAuth provider's token store, or None in token-only mode
    """
    from mcp.server.auth.middleware import auth_context

    def resolve() -> CallerIdentity | None:
        access = auth_context.get_access_token()
        if access is None:
            return None

        if looks_like_token(access.token):
            record = store.get_token_by_hash(hash_token(access.token))
            user = store.get_user(record.user_id) if record else None
            if user is None:
                return None
            return caller_for_user(user, auth_method="token", client_id=access.client_id)

        if oauth_storage is None:
            return None
        stored = oauth_storage.get_access_token(access.token)
        if stored is None:
            return None
        user = store.get_user_by_subject(stored.user_subject)
        if user is None:
            # A token issued before team mode existed skips on_sign_in, so link a
            # user imported by email here too -- otherwise they are locked out
            # until their next full sign-in.
            claims = getattr(stored, "user_claims", None) or {}
            email = claims.get("email")
            if email:
                user = store.link_pending_sso_user(email, stored.user_subject)
            if user is None:
                user = store.get_or_create_sso_user(
                    stored.user_subject, email=email, display_name=claims.get("name")
                )
        return caller_for_user(user, auth_method="oauth", client_id=stored.client_id)

    return resolve
```

The tests patch `mcp.server.auth.middleware.auth_context.get_access_token`. The resolver looks the function up on the module at call time (`auth_context.get_access_token()`), so the patch takes effect.

- [ ] **Step 4: Add the provider hooks**

In `src/u2_mcp/auth/provider.py`:

1. Add to the imports:

```python
from collections.abc import Awaitable, Callable

from ..tokens import looks_like_token
from .idp.base import TokenInfo
```

If `TokenInfo` is only imported under `TYPE_CHECKING` today, import it normally. It is a plain dataclass, so this creates no cycle.

2. Extend `__init__`. Add two keyword parameters after `storage`:

```python
        on_sign_in: Callable[[TokenInfo], None] | None = None,
        pat_verifier: Callable[[str], Awaitable[AccessToken | None]] | None = None,
```

Document them in the docstring's `Args:`:

```
            on_sign_in: Called once for each completed IdP sign-in (not refresh),
                with the IdP's user info. Team mode records the user and groups.
            pat_verifier: Verifies personal access tokens; when set, bearer values
                starting "u2pat_" are checked by it instead of the OAuth store.
```

Then store them, after `self.storage = ...`:

```python
        self.on_sign_in = on_sign_in
        self.pat_verifier = pat_verifier
```

3. At the top of `load_access_token`'s body, before `stored = self.storage.get_access_token(token)`, add:

```python
        if self.pat_verifier is not None and looks_like_token(token):
            return await self.pat_verifier(token)
```

4. In `handle_idp_callback`, find the comment `# Generate authorization code for Claude`. Insert this immediately before it:

```python
        # Team mode records each completed sign-in: it creates the user, refreshes
        # their groups and restarts their token freshness window. If that fails the
        # sign-in is refused, rather than issuing a token nobody can attribute.
        if self.on_sign_in is not None:
            try:
                self.on_sign_in(user_info)
            except Exception as e:
                logger.error(f"Recording the sign-in failed: {e}")
                raise AuthorizeError(
                    error="server_error",
                    error_description="Could not record the sign-in",
                ) from e
```

- [ ] **Step 5: Let the exposure check count token authentication**

In `src/u2_mcp/exposure.py`:

1. Change the signature and body of `check_network_exposure`:

```python
def check_network_exposure(
    config: U2Config, transport: str, *, authenticated: bool = False
) -> None:
    """Refuse to start a server whose configuration exposes the database unsafely.

    Args:
        config: The configuration the server is about to run with
        transport: 'stdio', 'sse' or 'streamable-http'
        authenticated: True when requests are authenticated by something other
            than U2_AUTH_ENABLED -- team mode's personal access tokens

    Raises:
        ExposureError: If the configuration would expose the database unsafely
    """
    if transport not in _NETWORK_TRANSPORTS:
        return

    _check_unauthenticated_reach(config, transport, authenticated)
    _check_credentialed_wildcard_cors(config)
```

2. Change `_check_unauthenticated_reach`'s signature to `(config: U2Config, transport: str, authenticated: bool = False) -> None`. Change its first condition to:

```python
    if config.auth_enabled or authenticated or is_loopback(config.http_host):
        return
```

- [ ] **Step 6: Make the audit wrapper idempotent and add the database sink**

In `src/u2_mcp/server.py`, add these imports:

```python
from .routing import current_route
from .store import get_store, install_store
from .store.bootstrap import open_team_store
from .team_auth import (
    ClientAddressMiddleware,
    PatVerifier,
    make_identity_resolver,
    make_sign_in_handler,
)
```

Then replace `_wrap_tools_with_audit` in full with:

```python
_AUDIT_MARK = "__u2_audited__"


def _record_tool_audit(
    tool_name: str,
    parameters: dict[str, Any],
    result: Any,
    error: str | None,
    duration_ms: float,
) -> None:
    """Write one tool call to the settings database's audit table, in team mode."""
    store = get_store()
    if store is None:
        return
    try:
        try:
            caller: CallerIdentity | None = current_caller()
        except IdentityError:
            caller = None
        requested = parameters.get("connection")
        connection = store.get_connection_by_name(requested) if requested else None
        refused = isinstance(result, dict) and "error" in result
        store.add_audit(
            kind="tool",
            action=tool_name,
            outcome="error" if error or refused else "ok",
            actor_user_id=caller.user_id if caller else None,
            actor_label=caller.display_name if caller else None,
            connection_id=connection.id if connection else None,
            params=dict(parameters),
            duration_ms=duration_ms,
        )
    except Exception as exc:  # noqa: BLE001 - auditing must not break the call it records
        logger.warning(f"Could not write the audit row for {tool_name}: {exc}")


def _wrap_tools_with_audit(mcp_instance: FastMCP) -> None:
    """Wrap every registered tool with audit logging, exactly once.

    Two sinks are checked at call time: the JSONL audit log (U2_AUDIT_ENABLED)
    and, in team mode, the settings database. Wrapping is idempotent because the
    Streamable HTTP instance shares Tool objects with the module-level one, and a
    second wrap would log every call twice.

    Args:
        mcp_instance: The FastMCP instance with registered tools
    """
    audit_logger = get_audit_logger()
    if audit_logger:
        audit_logger.start_session()

    for tool_name, tool in mcp_instance._tool_manager._tools.items():
        if getattr(tool.fn, _AUDIT_MARK, False):
            continue
        original_fn = tool.fn

        @functools.wraps(original_fn)
        def wrapped_fn(
            *args: Any,
            _original_fn: Callable[..., Any] = original_fn,
            _tool_name: str = tool_name,
            **kwargs: Any,
        ) -> Any:
            start_time = time.time()
            error_msg = None
            result = None

            try:
                result = _original_fn(*args, **kwargs)
                return result
            except Exception as e:
                error_msg = str(e)
                raise
            finally:
                duration_ms = (time.time() - start_time) * 1000
                if get_audit_logger():
                    audit_tool_call(
                        tool_name=_tool_name,
                        parameters=kwargs,
                        result=result,
                        error=error_msg,
                        duration_ms=duration_ms,
                        credentials=_current_login(),
                    )
                _record_tool_audit(_tool_name, kwargs, result, error_msg, duration_ms)

        setattr(wrapped_fn, _AUDIT_MARK, True)
        tool.fn = wrapped_fn
```

Also add `IdentityError` to the `from .identity import (...)` block, if Task 7 did not already add it.

In `_current_login`, use the route when one is installed. Replace its `try:` body with:

```python
        route = current_route()
        if route is not None:
            return route.credentials
        if _connection_manager is not None:
            return _connection_manager.credentials
        return get_connection_registry().resolver.resolve(current_caller())
```

- [ ] **Step 7: Refuse team mode on the unauthenticated legacy transport**

In `run_sse_server`, directly after `config = U2Config()`, add:

```python
    # The legacy SSE transport authenticates nobody, so it cannot enforce team
    # mode's per-person access. Refuse rather than silently ignore the key.
    if config.secret_key is not None:
        raise SystemExit(
            "U2_SECRET_KEY is set, which turns on team mode, but --http (SSE) cannot "
            "authenticate callers. Use --streamable-http."
        )
```

- [ ] **Step 8: Split the Streamable HTTP startup and wire team mode in**

In `src/u2_mcp/server.py`, replace `run_streamable_http_server` in full with the two functions below. The OAuth, CORS, logging and watchdog behaviour is unchanged. The new parts are the team-mode store, the PAT verifier, the identity resolver, the sign-in hook and the client-address middleware.

```python
def build_streamable_http_app(config: U2Config) -> Any:
    """Build the Streamable HTTP application, including team mode when configured.

    Split from run_streamable_http_server so tests can serve the real application.

    Args:
        config: Server configuration

    Returns:
        The Starlette application to serve
    """
    from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
    from mcp.server.fastmcp import FastMCP as FastMCPAuth
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.middleware.cors import CORSMiddleware
    from starlette.requests import Request
    from starlette.responses import Response
    from starlette.routing import Route

    from .auth.callback import handle_oauth_callback
    from .auth.idp import create_idp_adapter
    from .auth.provider import U2OAuthProvider
    from .auth.storage import create_auth_storage

    check_tool_coverage(mcp)

    # Team mode: U2_SECRET_KEY set. Opens (and on first start, populates) the
    # settings database; every tool call is then decided per person.
    store = open_team_store(config)
    if store is not None:
        install_store(store, global_read_only=config.read_only)
        logger.info(f"Team mode on: settings database in {store.data_dir}")

    # Refuse an unsafe exposure before the port is opened, not on first request.
    check_network_exposure(config, transport="streamable-http", authenticated=store is not None)

    # Initialize audit logging if enabled
    _init_audit_logging(config)

    public_url = (
        config.public_url
        or config.auth_issuer_url
        or f"http://{config.http_host}:{config.http_port}"
    )
    pat_verifier = (
        PatVerifier(store, freshness_days=config.token_freshness_days, resource=public_url)
        if store is not None
        else None
    )

    auth_provider = None
    auth_settings = None
    token_verifier = None

    if config.auth_enabled:
        if not config.auth_issuer_url:
            raise ValueError("U2_AUTH_ISSUER_URL is required when auth is enabled")
        if not config.idp_discovery_url and not config.duo_api_host:
            raise ValueError(
                "U2_IDP_DISCOVERY_URL (or U2_DUO_API_HOST for Duo) is required when auth is enabled"
            )

        # Create external IdP adapter
        idp_adapter = create_idp_adapter(config)

        # Create OAuth provider. In team mode it also accepts personal access
        # tokens and reports each completed sign-in to the settings database.
        auth_provider = U2OAuthProvider(
            idp_adapter=idp_adapter,
            issuer_url=config.auth_issuer_url,
            token_expiry=config.token_expiry_seconds,
            refresh_token_expiry=config.refresh_token_expiry_seconds,
            storage=create_auth_storage(config.auth_storage, config.auth_storage_path),
            on_sign_in=(
                make_sign_in_handler(store, config.sso_groups_claim) if store is not None else None
            ),
            pat_verifier=pat_verifier.verify_token if pat_verifier is not None else None,
        )

        # Validating the issuer URL here means a malformed one fails at startup
        # rather than at the first sign-in attempt.
        issuer_url = AnyHttpUrl(config.auth_issuer_url)

        # Configure auth settings for FastMCP
        auth_settings = AuthSettings(
            issuer_url=issuer_url,
            resource_server_url=issuer_url,
            client_registration_options=ClientRegistrationOptions(
                enabled=True,  # Required for Claude.ai DCR
                valid_scopes=["u2:read", "u2:write"],
                default_scopes=["u2:read"],
            ),
            revocation_options=RevocationOptions(enabled=True),
            required_scopes=["u2:read"],
        )

        # Close the loop between authentication and attribution: the bearer token
        # on the request is looked up to recover the person it was issued to.
        if store is not None:
            set_identity_resolver(make_identity_resolver(store, auth_provider.storage))
        else:
            _install_identity_resolver(auth_provider)

        logger.info(f"OAuth enabled with {config.idp_provider} IdP")
        logger.info(f"Caller identity mode: {config.identity_mode}")
    elif store is not None:
        # Team mode without SSO: personal access tokens are the only way in.
        token_verifier = pat_verifier
        auth_settings = AuthSettings(
            issuer_url=AnyHttpUrl(public_url),
            resource_server_url=None,
            required_scopes=["u2:read"],
        )
        set_identity_resolver(make_identity_resolver(store, None))
        logger.info("Team mode without SSO: personal access tokens required")

    # Create new FastMCP instance with auth configured
    # Note: We need a new instance because the original 'mcp' was created without auth
    mcp_streamable = FastMCPAuth(
        name="U2 MCP Server",
        auth_server_provider=auth_provider,
        token_verifier=token_verifier,
        auth=auth_settings,
        host=config.http_host,
        port=config.http_port,
        streamable_http_path="/",  # Root path for Claude.ai compatibility
    )

    # Copy tools, resources and prompts from the module-level instance, where the
    # tool modules registered them. Copy the dicts directly: add_tool expects
    # functions, not Tool objects.
    mcp_streamable._tool_manager._tools.update(mcp._tool_manager._tools)
    mcp_streamable._resource_manager._resources.update(mcp._resource_manager._resources)
    mcp_streamable._prompt_manager._prompts.update(mcp._prompt_manager._prompts)

    # Wrap tools with audit logging (JSONL when enabled; the database in team mode)
    _wrap_tools_with_audit(mcp_streamable)

    app = mcp_streamable.streamable_http_app()

    # Request logging: method, path and outcome. Never a body, never a header --
    # OAuth responses carry access and refresh tokens, and the first characters
    # of a bearer token are still part of a bearer token.
    class RequestLoggingMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next: Any) -> Response:
            has_authorization = "authorization" in request.headers

            logger.info(
                "REQUEST: %s %s auth=%s origin=%s",
                request.method,
                request.url.path,
                "present" if has_authorization else "none",
                request.headers.get("origin", "none"),
            )

            response: Response = await call_next(request)

            logger.info(
                "RESPONSE: %s %s -> %s",
                request.method,
                request.url.path,
                response.status_code,
            )

            return response

    app.add_middleware(RequestLoggingMiddleware)

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.http_cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Outermost, so the caller's address is known when tokens are verified.
    app.add_middleware(ClientAddressMiddleware)

    # Add custom OAuth callback route for external IdP
    if auth_provider:
        provider = auth_provider

        async def oauth_callback_handler(request: Request) -> Response:
            return await handle_oauth_callback(request, provider)

        app.routes.append(Route("/oauth/callback", oauth_callback_handler, methods=["GET"]))

    return app


def run_streamable_http_server() -> None:
    """Run the MCP server in Streamable HTTP mode for Claude.ai Integrations.

    This mode supports:
    - Streamable HTTP transport (MCP 2025-06-18 spec)
    - OAuth authentication with external IdP (Duo, Auth0, OIDC)
    - Dynamic Client Registration (DCR) for Claude.ai
    - Team mode (U2_SECRET_KEY): per-person access and personal access tokens
    """
    import threading

    import uvicorn

    config = U2Config()
    app = build_streamable_http_app(config)

    # Initialize the connection watchdog
    watchdog = _init_watchdog(config)

    logger.info(
        f"Starting U2 MCP Server (Streamable HTTP) on {config.http_host}:{config.http_port}"
    )
    logger.info(f"MCP endpoint: http://{config.http_host}:{config.http_port}/")
    if config.auth_enabled:
        logger.info("OAuth endpoints: /authorize, /token, /register, /.well-known/*")
        logger.info("OAuth callback: /oauth/callback")
    logger.info(f"CORS origins: {config.http_cors_origins}")

    def run_watchdog_sync() -> None:
        """Run the watchdog in a separate thread with its own event loop."""
        import asyncio

        async def watchdog_main() -> None:
            if watchdog:
                await watchdog.start()
                # Keep running until stopped
                while watchdog.is_running:
                    await asyncio.sleep(1)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(watchdog_main())
        finally:
            loop.close()

    if watchdog:
        watchdog_thread = threading.Thread(target=run_watchdog_sync, daemon=True)
        watchdog_thread.start()
        logger.info("Watchdog thread started")

    uvicorn.run(
        app,
        host=config.http_host,
        port=config.http_port,
        log_level="info",
    )
```

- [ ] **Step 9: Write the end-to-end test**

`tests/test_team_mode_e2e.py`:

```python
"""The real server, over real HTTP, with real tokens: who reaches what."""

import json
import os
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import httpx
import pytest
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

import u2_mcp.server as server
from tests.mocks.mock_uopy import MockSession
from u2_mcp.config import U2Config
from u2_mcp.identity import set_identity_resolver
from u2_mcp.store import get_store, install_store
from u2_mcp.tokens import create_token


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.fixture
def running(mock_env: dict[str, str], mock_uopy: MockSession, tmp_path: Path) -> Iterator[Any]:
    """Serve build_streamable_http_app on a real port, in team mode without SSO.

    World: "default" is imported from the environment (everyone = Imported access).
    "Test" is added, with only alice granted (Viewer).
    """
    port = _free_port()
    env = {
        "U2_SECRET_KEY": "e" * 40,
        "U2_DATA_DIR": str(tmp_path),
        "U2_HTTP_HOST": "127.0.0.1",
        "U2_HTTP_PORT": str(port),
        "U2_WATCHDOG_ENABLED": "false",
        "U2_AUDIT_ENABLED": "false",
    }
    with patch.dict(os.environ, env):
        app = server.build_streamable_http_app(U2Config())
        store = get_store()
        assert store is not None

        viewer = store.get_role_by_name("Viewer")
        assert viewer is not None
        alice = store.get_or_create_sso_user("alice")
        bob = store.get_or_create_sso_user("bob")
        store.record_sso_login(alice.id, [])
        store.record_sso_login(bob.id, [])
        test = store.add_connection(name="Test", host="test.example", port=1, service="uvcs",
                                    account="TRAIN", shared_user="tsvc", shared_password="t",
                                    read_only=False)
        store.add_grant(connection_id=test.id, subject_type="user", subject_id=alice.id,
                        role_id=viewer.id)
        mock_uopy.add_file("CUSTOMERS", {"1": "SMITH"})

        uv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
        thread = threading.Thread(target=uv.run, daemon=True)
        thread.start()
        deadline = time.time() + 10
        while not uv.started:
            if time.time() > deadline:
                raise RuntimeError("test server did not start")
            time.sleep(0.05)

        try:
            yield {
                "url": f"http://127.0.0.1:{port}/",
                "store": store,
                "session": mock_uopy,
                "alice": create_token(store, alice.id, "laptop")[0],
                "bob": create_token(store, bob.id, "laptop")[0],
                "alice_id": alice.id,
                "test_id": test.id,
            }
        finally:
            uv.should_exit = True
            thread.join(10)
            install_store(None)
            set_identity_resolver(None)
            server.reset_connection_manager()


async def _call(url: str, token: str, tool: str, arguments: dict[str, Any]) -> str:
    headers = {"Authorization": f"Bearer {token}"}
    async with streamablehttp_client(url, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool, arguments)
    return "\n".join(getattr(block, "text", "") for block in result.content)


@pytest.mark.asyncio
async def test_each_token_sees_only_its_owners_connections(running: dict[str, Any]) -> None:
    alice = json.loads(await _call(running["url"], running["alice"], "list_connections", {}))
    bob = json.loads(await _call(running["url"], running["bob"], "list_connections", {}))
    assert [c["name"] for c in alice["connections"]] == ["Test", "default"]
    assert [c["name"] for c in bob["connections"]] == ["default"]


@pytest.mark.asyncio
async def test_a_call_reaches_the_named_server_and_no_other(running: dict[str, Any]) -> None:
    args = {"file_name": "CUSTOMERS", "record_id": "1"}
    session: MockSession = running["session"]

    await _call(running["url"], running["alice"], "read_record", {**args, "connection": "Test"})
    assert session.connect_kwargs["host"] == "test.example"

    await _call(running["url"], running["alice"], "read_record", {**args, "connection": "default"})
    assert session.connect_kwargs["host"] == "test-host.example.com"

    refused = await _call(
        running["url"], running["bob"], "read_record", {**args, "connection": "Test"}
    )
    assert "unknown connection 'Test'" in refused
    assert session.connect_kwargs["host"] == "test-host.example.com"


@pytest.mark.asyncio
async def test_requests_without_a_valid_token_are_turned_away(running: dict[str, Any]) -> None:
    body = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    accept = {"Accept": "application/json, text/event-stream"}
    async with httpx.AsyncClient() as client:
        missing = await client.post(running["url"], json=body, headers=accept)
        forged = await client.post(
            running["url"],
            json=body,
            headers={**accept, "Authorization": "Bearer u2pat_" + "x" * 43},
        )
    assert missing.status_code == 401
    assert forged.status_code == 401


@pytest.mark.asyncio
async def test_tool_calls_are_audited_with_the_person(running: dict[str, Any]) -> None:
    await _call(
        running["url"],
        running["alice"],
        "read_record",
        {"file_name": "CUSTOMERS", "record_id": "1", "connection": "Test"},
    )
    rows = [r for r in running["store"].recent_audit(20) if r["action"] == "read_record"]
    assert rows
    assert rows[0]["actor_user_id"] == running["alice_id"]
    assert rows[0]["connection_id"] == running["test_id"]
    assert rows[0]["outcome"] == "ok"
```

- [ ] **Step 10: Run the new tests**

Run: `.venv/Scripts/python -m pytest tests/test_team_auth.py tests/test_team_mode_e2e.py -q`
Expected: 22 passed (18 unit, 4 end-to-end).

If the end-to-end tests hang on shutdown, check that `uv.should_exit = True` is reached. The fixture's `finally` must run even when a test fails.

- [ ] **Step 11: Full suite, checks, commit**

Run: `.venv/Scripts/python -m pytest -q && .venv/Scripts/ruff check . && .venv/Scripts/ruff format . && .venv/Scripts/mypy src/`
Expected: all pass, including the original 503.

```bash
git add src/u2_mcp tests/test_team_auth.py tests/test_team_mode_e2e.py
git commit -m "feat: team-mode sign-in, personal tokens over HTTP, audit, and end-to-end proof" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 11: Document team mode for operators

**Files:**
- Modify: `docs/configuration.md` (new section), `CHANGELOG.md` (new entry at the top)

**Interfaces:**
- Consumes: the settings names from Task 9 and the behaviour from Tasks 7–10.
- Produces: documentation only.

- [ ] **Step 1: Add the configuration section**

Append to `docs/configuration.md`:

````markdown
## Team mode

Team mode gives each person their own access, per connection, and lets one server
reach several U2 systems. It is switched on by setting `U2_SECRET_KEY` and running
with `--streamable-http`. Without that key the server behaves exactly as before.

| Variable | Default | Purpose |
|---|---|---|
| `U2_SECRET_KEY` | (unset) | Turns team mode on and encrypts stored secrets. At least 32 characters. Keep a copy in your vault. Without it, stored U2 passwords cannot be read. |
| `U2_DATA_DIR` | `/data` | Holds `u2-mcp.db` (settings) and per-connection knowledge. |
| `U2_PUBLIC_URL` | (unset) | The URL people use to reach the server. |
| `U2_SSO_GROUPS_CLAIM` | `groups` | The identity-provider claim that lists groups. |
| `U2_TOKEN_FRESHNESS_DAYS` | `30` | An SSO user's tokens pause after this many days without an SSO sign-in. |

### First start

On first start the existing `U2_HOST` settings become a connection named `default`:

- With `U2_IDENTITY_MODE=shared`, every signed-in person gets the `Imported access`
  role on `default`, which is what the server allowed before. The connection's
  read-only switch follows `U2_READ_ONLY`. Narrow this once the admin UI is available.
- With `U2_IDENTITY_MODE=mapped`, each person in the credential map gets
  `Imported access` with their own U2 login, and nobody else gets access. Entries
  keyed by email are linked to the person at their first sign-in.
- `Imported access` is an ordinary, editable role. It holds exactly what today's
  tools can do, and it does not grow when new tools (such as BASIC compile) arrive.

### Choosing a connection

Every tool takes an optional `connection` argument. `list_connections` shows the
connections you can use and your permissions on each. If you can use only one,
`connection` can be left out.

### Personal access tokens

In team mode, clients that cannot do a browser sign-in authenticate with a
personal access token: `Authorization: Bearer u2pat_...`. Tokens are created in
the admin UI (phase 2). Until then they can be created from Python:

```python
from u2_mcp.config import U2Config
from u2_mcp.store.bootstrap import open_team_store
from u2_mcp.tokens import create_token

store = open_team_store(U2Config())
user = store.add_local_user("ops")
print(create_token(store, user.id, "script")[0])
```
````

- [ ] **Step 2: Add the changelog entry**

At the top of `CHANGELOG.md`, below its title, add:

```markdown
## Unreleased

### Added
- Team mode (`U2_SECRET_KEY`): a settings database with connections, users, SSO
  groups, roles, grants, personal access tokens and an audit table.
- Several U2 connections from one server; every tool takes `connection`.
- `list_connections` lists the caller's connections, roles and permissions.

### Changed
- The tool that listed open database sessions is now `list_sessions`.
- The server refuses to start if any tool lacks an access check.
```

- [ ] **Step 3: Commit**

```bash
git add docs/configuration.md CHANGELOG.md
git commit -m "docs: team mode configuration and first-start behaviour" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Done when

- Every task's tests pass, along with the original 503 tests (4 skipped on Windows).
- `ruff check .`, `ruff format --check .` and `mypy src/` are clean.
- Without `U2_SECRET_KEY`, stdio and HTTP behave exactly as before. The only visible change is the `connection` argument and the `list_sessions` rename.
- With `U2_SECRET_KEY`, `tests/test_team_mode_e2e.py` proves that tokens authenticate, each person reaches only their own connections, the right U2 server is used, and calls are audited.

Phase 2 (the admin site) is planned next, against this code.
