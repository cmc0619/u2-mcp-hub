"""Fixtures for tool tests that need a manager built from particular settings."""

import os
from collections.abc import Callable, Iterator
from unittest.mock import patch

import pytest

import u2_mcp.server as server_module
from tests.mocks.mock_uopy import MockSession
from u2_mcp.config import U2Config
from u2_mcp.connection import ConnectionManager


@pytest.fixture
def make_manager(
    mock_env: dict[str, str], mock_uopy: MockSession
) -> Iterator[Callable[..., ConnectionManager]]:
    """Build and install a ConnectionManager whose config adds the given U2_* variables."""

    def build(**env: str) -> ConnectionManager:
        with patch.dict(os.environ, env):
            manager = ConnectionManager(U2Config())
        server_module._connection_manager = manager
        return manager

    try:
        yield build
    finally:
        server_module._connection_manager = None
