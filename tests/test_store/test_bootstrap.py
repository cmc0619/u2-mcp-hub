"""Team mode opens its settings database safely."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from u2_mcp.config import U2Config
from u2_mcp.store.bootstrap import TeamModeError, open_store_for_cli, open_team_store


def test_a_short_key_is_refused(mock_env: dict[str, str], tmp_path: Path) -> None:
    env = {"U2_SECRET_KEY": "short", "U2_DATA_DIR": str(tmp_path)}
    with patch.dict(os.environ, env), pytest.raises(TeamModeError, match="at least 32"):
        open_team_store(U2Config())


def test_a_first_start_has_roles_and_no_connections(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The environment's U2_HOST is never imported; the setup wizard adds connections."""
    monkeypatch.setenv("U2_SECRET_KEY", "k" * 40)
    monkeypatch.setenv("U2_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("U2_HOST", "env-host.example")

    store = open_team_store(U2Config())

    assert store.list_connections() == []
    assert store.get_role_by_name("Viewer") is not None


def test_the_cli_never_creates_a_database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("U2_SECRET_KEY", "k" * 40)
    monkeypatch.setenv("U2_DATA_DIR", str(tmp_path))

    with pytest.raises(TeamModeError, match="No settings database"):
        open_store_for_cli(U2Config())
    assert list(tmp_path.iterdir()) == []
