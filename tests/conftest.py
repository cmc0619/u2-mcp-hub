"""Pytest configuration and fixtures for u2-mcp tests."""

import os
from collections.abc import Generator, Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import pytest
from argon2 import PasswordHasher  # noqa: E402

# Production argon2 costs about 50 ms a hash, and the admin tests hash passwords
# in nearly every fixture. Tests check the logic, not the cost: hash cheaply.
# Browser tests run the real server in its own process, with the real cost.
import u2_mcp.passwords as _passwords  # noqa: E402
from tests.mocks.mock_uopy import (
    MockCommand,
    MockFile,
    MockList,
    MockSession,
    MockSubroutine,
    UOError,
)
from u2_mcp.config import U2Config
from u2_mcp.connection import ConnectionManager

_passwords._hasher = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)

# Importing uopy makes ./logs, and parallel workers race to make it: make it first.
os.makedirs("logs", exist_ok=True)
_passwords._dummy_hash.cache_clear()


@pytest.fixture
def mock_env() -> Generator[dict[str, str], None, None]:
    """Provide mock environment variables for testing."""
    env_vars = {
        "U2_HOST": "test-host.example.com",
        "U2_USER": "test-user",
        "U2_PASSWORD": "test-password",
        "U2_ACCOUNT": "TEST",
        "U2_SERVICE": "uvcs",
        "U2_PORT": "31438",
        "U2_SSL": "false",
        "U2_READ_ONLY": "false",
        "U2_MAX_RECORDS": "1000",
        "U2_BLOCKED_COMMANDS": "DELETE.FILE,CLEAR.FILE",
    }
    with patch.dict(os.environ, env_vars, clear=False):
        yield env_vars


@pytest.fixture
def mock_config(mock_env: dict[str, str]) -> U2Config:
    """Provide a test configuration instance."""
    return U2Config()


@pytest.fixture
def mock_config_read_only(mock_env: dict[str, str]) -> U2Config:
    """Provide a read-only test configuration."""
    with patch.dict(os.environ, {"U2_READ_ONLY": "true"}):
        return U2Config()


@pytest.fixture
def mock_session() -> "MockSession":
    """Provide a mock uopy session that speaks the current uopy 1.4 API."""
    return MockSession()


@pytest.fixture
def mock_uopy(mock_session: "MockSession") -> Generator["MockSession", None, None]:
    """Replace every uopy entry point the server uses with a mock.

    Patching the whole surface -- not just `connect` -- is what lets a test
    exercise the real production code path instead of a rewritten one.
    """

    def fake_connect(**kwargs: Any) -> MockSession:
        """Hand back a live session, mirroring a real reconnect to the same server."""
        mock_session.is_active = True
        mock_session.connect_kwargs = kwargs
        return mock_session

    with (
        patch("uopy.connect", side_effect=fake_connect),
        patch("uopy.UOError", UOError),
        patch("uopy.File", MockFile),
        patch("uopy.Command", MockCommand),
        patch("uopy.List", MockList),
        patch("uopy.Subroutine", MockSubroutine),
    ):
        yield mock_session


@pytest.fixture
def connection_manager(
    mock_config: U2Config, mock_uopy: "MockSession"
) -> Generator["ConnectionManager", None, None]:
    """Provide a ConnectionManager wired to the mock session, plus a clean global.

    Tool functions reach for the module-level connection manager, so this
    fixture installs one and tears it down to keep tests isolated.
    """
    import u2_mcp.server as server_module

    manager = ConnectionManager(mock_config)
    server_module._connection_manager = manager
    try:
        yield manager
    finally:
        server_module._connection_manager = None


@pytest.fixture
def sample_record_data() -> dict[str, Any]:
    """Provide sample record data for testing."""
    # AM = chr(254), VM = chr(253), SM = chr(252)
    AM = chr(254)
    VM = chr(253)

    return {
        "simple": "John Doe" + AM + "123 Main St" + AM + "CA",
        "multivalue": "John Doe" + AM + "555-1234" + VM + "555-5678" + AM + "CA",
        "complex": (
            "ACME Corp" + AM + "John Smith" + VM + "Jane Doe" + AM + "555-1111" + VM + "555-2222"
        ),
    }


@pytest.fixture
def sample_parsed_fields() -> dict[str, Any]:
    """Provide sample parsed field structures."""
    return {
        "simple": {"1": "John Doe", "2": "123 Main St", "3": "CA"},
        "multivalue": {"1": "John Doe", "2": ["555-1234", "555-5678"], "3": "CA"},
    }


if TYPE_CHECKING:
    from u2_mcp.store.repo import Store


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


@pytest.fixture(autouse=True)
def stdio_knowledge_database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Keep stdio's knowledge database in tmp_path, never in the real home directory."""
    import u2_mcp.utils.knowledge as knowledge

    path = tmp_path / "stdio" / "u2-mcp.db"
    monkeypatch.setattr(knowledge, "STDIO_DATABASE", path)
    knowledge.close_stdio_database()
    try:
        yield path
    finally:
        knowledge.close_stdio_database()


@pytest.fixture
def oauth_storage(store: "Store") -> Any:
    """OAuth state in the test settings database."""
    from u2_mcp.auth.storage import AuthStorage

    return AuthStorage(store.locked)
