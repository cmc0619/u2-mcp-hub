"""Tests for transaction management.

A transaction left open holds locks on a live production file, so the tools that
open one have to be exact about state: what is open, what closed it, and what
happens when a caller asks for something that makes no sense.
"""

from collections.abc import Iterator

import pytest

from tests.mocks.mock_uopy import MockSession
from u2_mcp.config import U2Config
from u2_mcp.connection import ConnectionManager
from u2_mcp.identity import caller_for_user, use_caller
from u2_mcp.store import install_store
from u2_mcp.store.repo import Store
from u2_mcp.tools.transaction import (
    begin_transaction,
    commit_transaction,
    get_transaction_status,
    rollback_transaction,
)


class TestTransactionLifecycle:
    """Opening and closing a unit of work."""

    def test_beginning_a_transaction_opens_one(self, connection_manager: ConnectionManager) -> None:
        """Starting a transaction reports it as open."""
        result = begin_transaction()

        assert result["status"] == "success"
        assert result["in_transaction"] is True

    def test_committing_closes_it(self, connection_manager: ConnectionManager) -> None:
        """Committing leaves no transaction open."""
        begin_transaction()

        result = commit_transaction()

        assert result["in_transaction"] is False

    def test_committing_reaches_the_database(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """The commit is issued to the server, not merely tracked locally."""
        begin_transaction()
        commit_transaction()

        assert mock_uopy.transaction_log == ["start", "commit"]

    def test_rolling_back_closes_it(self, connection_manager: ConnectionManager) -> None:
        """Rolling back leaves no transaction open."""
        begin_transaction()

        result = rollback_transaction()

        assert result["in_transaction"] is False

    def test_rolling_back_reaches_the_database(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """The rollback is issued to the server."""
        begin_transaction()
        rollback_transaction()

        assert mock_uopy.transaction_log == ["start", "rollback"]


class TestInvalidRequests:
    """Asking for something that makes no sense must not corrupt the state."""

    def test_a_second_begin_is_refused(self, connection_manager: ConnectionManager) -> None:
        """Nested transactions are refused rather than silently ignored."""
        begin_transaction()

        result = begin_transaction()

        assert "error" in result

    def test_the_first_transaction_survives_a_refused_second(
        self, connection_manager: ConnectionManager
    ) -> None:
        """A refused nested begin leaves the open transaction intact."""
        begin_transaction()
        begin_transaction()

        assert get_transaction_status()["in_transaction"] is True

    def test_committing_nothing_is_refused(self, connection_manager: ConnectionManager) -> None:
        """A commit with no transaction open reports an error."""
        result = commit_transaction()

        assert "error" in result

    def test_rolling_back_nothing_is_refused(self, connection_manager: ConnectionManager) -> None:
        """A rollback with no transaction open reports an error."""
        result = rollback_transaction()

        assert "error" in result


class TestStatus:
    """Reporting what is currently open."""

    def test_status_reports_no_transaction_initially(
        self, connection_manager: ConnectionManager
    ) -> None:
        """A fresh connection has nothing open."""
        assert get_transaction_status()["in_transaction"] is False

    def test_status_reports_an_open_transaction(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """An open transaction is visible in the status."""
        begin_transaction()

        assert get_transaction_status()["in_transaction"] is True
        assert mock_uopy.transaction_log == ["start"]

    @pytest.mark.parametrize(
        ("role_name", "read_only", "global_read_only"),
        [
            ("Viewer", False, False),
            ("Viewer", True, False),
            ("Owner", True, False),
            ("Owner", False, True),
            ("Connection only", True, True),
        ],
    )
    def test_baseline_status_access_does_not_grant_transaction_mutation(
        self,
        store: Store,
        mock_env: dict[str, str],
        mock_uopy: MockSession,
        role_name: str,
        read_only: bool,
        global_read_only: bool,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import u2_mcp.server as server

        monkeypatch.setenv("U2_READ_ONLY", str(global_read_only).lower())
        server.reset_connection_manager()
        role = (
            store.add_role(role_name, [])
            if role_name == "Connection only"
            else store.get_role_by_name(role_name)
        )
        assert role is not None
        user = store.get_or_create_sso_user("inspector")
        connection = store.add_connection(
            name="Inspect",
            host="h",
            port=1,
            service="uvcs",
            account="A",
            shared_user="svc",
            shared_password="pw",
            read_only=read_only,
        )
        store.add_grant(
            connection_id=connection.id, subject_type="user", subject_id=user.id, role_id=role.id
        )
        install_store(store, global_read_only=global_read_only)
        try:
            with use_caller(caller_for_user(user, auth_method="token")):
                assert get_transaction_status(connection="Inspect") == {
                    "in_transaction": False,
                    "started_at": None,
                    "read_only_mode": read_only or global_read_only,
                }
                for tool in (begin_transaction, commit_transaction, rollback_transaction):
                    assert "error" in tool(connection="Inspect")
            stranger = store.get_or_create_sso_user("stranger")
            with use_caller(caller_for_user(stranger, auth_method="token")):
                for tool in (
                    get_transaction_status,
                    begin_transaction,
                    commit_transaction,
                    rollback_transaction,
                ):
                    assert tool(connection="Inspect") == {"error": "unknown connection 'Inspect'"}
            assert mock_uopy.transaction_log == []
            assert mock_uopy.executed_commands == []
        finally:
            install_store(None)
            server.reset_connection_manager()

    def test_status_reports_read_only_mode(self, connection_manager: ConnectionManager) -> None:
        """The status says whether the server can write at all."""
        assert get_transaction_status()["read_only_mode"] is False


class TestReadOnlyMode:
    """No transaction should open on a server that cannot write."""

    @pytest.fixture
    def read_only_manager(
        self, mock_config_read_only: U2Config, mock_uopy: MockSession
    ) -> Iterator[ConnectionManager]:
        """Install a read-only connection manager as the server's global."""
        import u2_mcp.server as server_module

        manager = ConnectionManager(mock_config_read_only)
        server_module._connection_manager = manager
        try:
            yield manager
        finally:
            server_module._connection_manager = None

    def test_beginning_a_transaction_is_refused(self, read_only_manager: ConnectionManager) -> None:
        """Read-only mode refuses to open a transaction."""
        result = begin_transaction()

        assert "error" in result

    def test_nothing_reaches_the_database(
        self, read_only_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """The refusal happens before the server is asked to do anything."""
        begin_transaction()

        assert mock_uopy.transaction_log == []


class TestSharedLogins:
    """A transaction belongs to the session, so it must not span several people."""

    def test_refused_over_a_network_transport_on_a_shared_login(
        self,
        connection_manager: ConnectionManager,
        mock_uopy: MockSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """In team mode another person's writes would land inside it, so it is never opened."""
        monkeypatch.setattr("u2_mcp.tools.transaction.get_store", lambda: object())

        result = begin_transaction()

        assert result["in_transaction"] is False
        assert "shared" in result["error"]
        assert mock_uopy.transaction_log == []

    def test_allowed_for_the_one_stdio_operator(
        self, connection_manager: ConnectionManager
    ) -> None:
        """On a stdio pipe there is only one person, so a shared login is safe."""
        assert connection_manager.credentials.is_shared

        assert begin_transaction()["status"] == "success"

    def test_allowed_on_a_personal_login(
        self,
        mock_config: U2Config,
        mock_uopy: MockSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """With their own U2 login, a network caller can use transactions."""
        import u2_mcp.server as server_module
        from u2_mcp.credentials import U2Credentials

        monkeypatch.setattr("u2_mcp.tools.transaction.get_store", lambda: object())
        personal = U2Credentials(user="alice", password="pw", account="TEST", is_shared=False)
        server_module._connection_manager = ConnectionManager(mock_config, personal)
        try:
            assert begin_transaction()["status"] == "success"
        finally:
            server_module.reset_connection_manager()
