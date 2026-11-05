"""Tests for u2_mcp.config module."""

import os
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from u2_mcp.config import U2Config


class TestU2Config:
    """Tests for U2Config settings class."""

    def test_config_loads_required_vars(self, mock_env):
        """Test that required environment variables are loaded."""
        config = U2Config()

        assert config.host == "test-host.example.com"
        assert config.user == "test-user"
        assert config.password == "test-password"
        assert config.account == "TEST"

    def test_config_loads_optional_vars(self, mock_env):
        """Test that optional environment variables are loaded."""
        config = U2Config()

        assert config.service == "uvcs"
        assert config.port == 31438
        assert config.ssl is False
        assert config.read_only is False
        assert config.max_records == 1000

    def test_config_default_values(self):
        """Test default values when optional vars not set."""
        env_vars = {
            "U2_HOST": "host",
            "U2_USER": "user",
            "U2_PASSWORD": "pass",
            "U2_ACCOUNT": "ACC",
        }
        with patch.dict(os.environ, env_vars, clear=True):
            config = U2Config()

            assert config.service == "uvcs"
            assert config.port == 31438
            assert config.ssl is False
            assert config.timeout == 30
            # Deliberate: writes are opt-in,
            # because the person who forgets to set this is the person who
            # needed it set. tests/test_read_only_default.py carries the reason.
            assert config.read_only is True
            assert config.max_records == 10000

    def test_config_blocked_commands_parsing(self, mock_env):
        """Test parsing of blocked commands from comma-separated string."""
        config = U2Config()

        assert "DELETE.FILE" in config.blocked_commands
        assert "CLEAR.FILE" in config.blocked_commands

    def test_config_blocked_commands_uppercase(self):
        """Test that blocked commands are uppercased."""
        env_vars = {
            "U2_HOST": "host",
            "U2_USER": "user",
            "U2_PASSWORD": "pass",
            "U2_ACCOUNT": "ACC",
            "U2_BLOCKED_COMMANDS": "delete.file,clear.file",
        }
        with patch.dict(os.environ, env_vars, clear=True):
            config = U2Config()

            assert "DELETE.FILE" in config.blocked_commands
            assert "CLEAR.FILE" in config.blocked_commands

    def test_config_service_validation_uvcs(self):
        """Test that uvcs service type is valid."""
        env_vars = {
            "U2_HOST": "host",
            "U2_USER": "user",
            "U2_PASSWORD": "pass",
            "U2_ACCOUNT": "ACC",
            "U2_SERVICE": "uvcs",
        }
        with patch.dict(os.environ, env_vars, clear=True):
            config = U2Config()
            assert config.service == "uvcs"

    def test_config_service_validation_udcs(self):
        """Test that udcs service type is valid."""
        env_vars = {
            "U2_HOST": "host",
            "U2_USER": "user",
            "U2_PASSWORD": "pass",
            "U2_ACCOUNT": "ACC",
            "U2_SERVICE": "udcs",
        }
        with patch.dict(os.environ, env_vars, clear=True):
            config = U2Config()
            assert config.service == "udcs"

    def test_config_service_validation_invalid(self):
        """Test that invalid service type raises error."""
        env_vars = {
            "U2_HOST": "host",
            "U2_USER": "user",
            "U2_PASSWORD": "pass",
            "U2_ACCOUNT": "ACC",
            "U2_SERVICE": "invalid",
        }
        with (
            patch.dict(os.environ, env_vars, clear=True),
            pytest.raises(ValueError, match="uvcs.*udcs"),
        ):
            U2Config()


def test_stdio_refuses_to_start_without_its_login(monkeypatch: pytest.MonkeyPatch) -> None:
    from u2_mcp import server

    for name in ("U2_HOST", "U2_USER", "U2_PASSWORD", "U2_ACCOUNT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("sys.argv", ["u2-mcp"])

    with pytest.raises(SystemExit, match="U2_HOST, U2_USER, U2_PASSWORD, U2_ACCOUNT"):
        server.main()


class TestTeamModeWithoutEnvironmentConnection:
    """Team mode can start on an empty /data, before any connection exists."""

    def test_connection_settings_are_optional_in_team_mode(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for name in ("U2_HOST", "U2_USER", "U2_PASSWORD", "U2_ACCOUNT"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("U2_SECRET_KEY", "k" * 40)

        config = U2Config()

        assert config.host == ""

    def test_environment_is_read_by_u2_alias_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Shell variables like USER must never fill a field by its bare name."""
        for name in ("U2_HOST", "U2_USER", "U2_PASSWORD", "U2_ACCOUNT"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("U2_SECRET_KEY", "k" * 40)
        monkeypatch.setenv("USER", "runner")
        monkeypatch.setenv("HOST", "some-shell-host")
        monkeypatch.setenv("PASSWORD", "shell-password")
        monkeypatch.setenv("ACCOUNT", "SHELLACCT")

        config = U2Config()

        assert config.user == ""
        assert config.host == ""
        assert config.password == ""
        assert config.account == ""

    def test_admin_allowlist_parses_addresses_and_networks(
        self, mock_env: dict[str, str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("U2_ADMIN_ALLOWED_IPS", "10.0.0.0/8, 192.168.1.5")

        networks = U2Config().admin_allowed_networks

        assert [str(n) for n in networks] == ["10.0.0.0/8", "192.168.1.5/32"]

    def test_admin_allowlist_rejects_garbage(
        self, mock_env: dict[str, str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("U2_ADMIN_ALLOWED_IPS", "10.0.0.0/8,not-an-address")

        with pytest.raises(ValidationError, match="not-an-address"):
            U2Config()

    def test_admin_allowlist_defaults_to_everyone(self, mock_env: dict[str, str]) -> None:
        assert U2Config().admin_allowed_networks == []

    def test_a_blank_secret_key_reads_as_unset(self, mock_env: dict[str, str]) -> None:
        """With the connection set, an empty key simply means no team mode."""
        with patch.dict(os.environ, {"U2_SECRET_KEY": ""}):
            assert U2Config().secret_key is None

    def test_admin_allowlist_ignores_empty_entries(
        self, mock_env: dict[str, str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A trailing comma, as in "10.0.0.1,", is not an entry."""
        monkeypatch.setenv("U2_ADMIN_ALLOWED_IPS", "10.0.0.1,")

        assert [str(n) for n in U2Config().admin_allowed_networks] == ["10.0.0.1/32"]

    def test_admin_allowlist_takes_ipv6_networks(
        self, mock_env: dict[str, str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """IPv6 addresses and networks are entries too."""
        monkeypatch.setenv("U2_ADMIN_ALLOWED_IPS", "2001:db8::/32, ::1")

        assert [str(n) for n in U2Config().admin_allowed_networks] == ["2001:db8::/32", "::1/128"]


def test_trusted_proxies_parse_and_reject_garbage(
    monkeypatch: pytest.MonkeyPatch, mock_env: dict[str, str]
) -> None:
    monkeypatch.setenv("U2_TRUSTED_PROXIES", "10.0.0.1, 172.16.0.0/12,")
    networks = [str(n) for n in U2Config().trusted_proxy_networks]
    assert networks == ["10.0.0.1/32", "172.16.0.0/12"]
    monkeypatch.setenv("U2_TRUSTED_PROXIES", "proxy.local")
    with pytest.raises(ValueError, match="U2_TRUSTED_PROXIES entry 'proxy.local'"):
        U2Config()


def test_no_trusted_proxies_by_default(mock_env: dict[str, str]) -> None:
    assert U2Config().trusted_proxy_networks == []


def test_basic_files_default_and_override(mock_env: dict[str, str]) -> None:
    from u2_mcp.config import U2Config

    assert U2Config().basic_files == ["*BP", "BP.*"]
    with patch.dict(os.environ, {"U2_BASIC_FILES": " SRC , *BP ,"}):
        assert U2Config().basic_files == ["SRC", "*BP"]
