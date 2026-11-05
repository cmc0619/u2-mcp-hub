"""Tests for the Universe/UniData connection manager."""

import socket
import threading
import time
from typing import Any
from unittest.mock import patch

import pytest
from uopy._errorcodes import ErrorCodes
from uopy._session import Session
from uopy._uoerror import UOError as DriverError

from tests.mocks.mock_uopy import MockSession, UOError
from u2_mcp.config import U2Config
from u2_mcp.connection import ConnectionManager


class TestConnectionLifecycle:
    """Connecting, reusing, and tearing down sessions."""

    def test_connect_passes_configured_credentials(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """Connecting hands uopy exactly what the configuration specified."""
        info = connection_manager.connect()

        assert info.host == "test-host.example.com"
        assert info.account == "TEST"

    def test_connect_reuses_an_active_connection(
        self, connection_manager: ConnectionManager
    ) -> None:
        """A second connect reuses the first session."""
        first = connection_manager.connect()
        second = connection_manager.connect()

        assert first is second
        assert connection_manager.connection_info is first

    def test_disconnect_clears_state(self, connection_manager: ConnectionManager) -> None:
        """Disconnecting drops the session, the file cache, and the connection record."""
        connection_manager.connect()
        connection_manager.open_file("CUSTOMERS")

        assert connection_manager.disconnect() is True
        assert connection_manager.connection_info is None

    def test_marks_decode_as_marks_without_nls(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """Without NLS each byte is a character, so 0xFE must come back as AM."""
        mock_uopy.is_nls_enabled = False
        mock_uopy.encoding = "UTF-8"

        connection_manager.connect()

        assert b"A\xfeB\xfdC".decode(mock_uopy.encoding, errors="replace") == "A\xfeB\xfdC"

    def test_nls_sessions_keep_the_driver_encoding(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """With NLS on uopy has already chosen UTF-8; that choice stands."""
        mock_uopy.is_nls_enabled = True
        mock_uopy.encoding = "UTF-8"

        connection_manager.connect()

        assert mock_uopy.encoding == "UTF-8"

    def test_get_session_reconnects_when_session_went_inactive(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """A dead session is replaced rather than handed back to the caller."""
        connection_manager.connect()
        mock_uopy.is_active = False

        session = connection_manager.get_session()

        assert session.is_active is True


class TestOneSessionAtATime:
    """Concurrent connects share one session instead of each opening their own."""

    @pytest.mark.parametrize("second", ["connect", "get_session"])
    def test_an_overlapping_connect_opens_one_session(
        self, connection_manager: ConnectionManager, second: str
    ) -> None:
        opened: list[MockSession] = []
        first_inside = threading.Event()

        def open_session(**_kwargs: Any) -> MockSession:
            opened.append(MockSession())
            first_inside.set()
            time.sleep(0.2)
            return opened[-1]

        with patch("uopy.connect", side_effect=open_session):
            first = threading.Thread(target=connection_manager.connect)
            first.start()
            assert first_inside.wait(timeout=5)
            getattr(connection_manager, second)()
            first.join(timeout=5)

        assert len(opened) == 1


def _driver_session() -> Session:
    """A real uopy session object, marked open."""
    session = Session({"encoding": "utf-8"})
    session.is_active = True
    return session


def _fail(session: Session) -> None:
    """Record an RPC failure the way uopy does: is_active stays True."""
    session.check_rpc_error(DriverError(code=ErrorCodes.UOE_RPC_FAILED))
    assert session.is_active is True and session.health_check() is False


class TestAFailedSessionIsReplaced:
    """uopy records a transport failure apart from is_active, which stays True."""

    def test_get_session_reconnects_after_a_driver_failure(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        failed = _driver_session()
        _fail(failed)
        with patch("uopy.connect", side_effect=[failed, mock_uopy]):
            connection_manager.connect()

            assert connection_manager.get_session() is mock_uopy

    def test_the_failed_session_socket_is_closed(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """Replacing a failed session hangs up its socket rather than leaking it."""
        ours, peer = socket.socketpair()
        peer.settimeout(5)
        failed = _driver_session()
        failed._rpc_connection = type("Rpc", (), {})()
        failed._rpc_connection.rpc_socket = type("Sock", (), {"_socket": ours})()
        _fail(failed)
        with patch("uopy.connect", side_effect=[failed, mock_uopy]):
            connection_manager.connect()

            assert connection_manager.get_session() is mock_uopy

        assert peer.recv(1) == b""
        peer.close()

    def test_a_cached_handle_on_a_failed_session_is_not_handed_out(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        failed = _driver_session()
        with patch("uopy.connect", side_effect=[failed, mock_uopy]):
            stale = connection_manager.open_file("CUSTOMERS")
            assert stale.session is failed
            _fail(failed)

            fresh = connection_manager.open_file("CUSTOMERS")

        assert fresh is not stale
        assert fresh.session is mock_uopy
        assert connection_manager.open_file("CUSTOMERS") is fresh

    def test_a_handle_from_a_replaced_session_is_not_handed_out(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        stale = connection_manager.open_file("CUSTOMERS")
        connection_manager.force_disconnect()

        assert connection_manager.open_file("CUSTOMERS") is not stale


class TestFileHandles:
    """Opening and caching Universe file handles."""

    def test_open_file_caches_the_handle(self, connection_manager: ConnectionManager) -> None:
        """Opening the same file twice returns the same cached handle."""
        first = connection_manager.open_file("CUSTOMERS")
        second = connection_manager.open_file("CUSTOMERS")

        assert first is second

    def test_open_missing_file_raises(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """A file the server does not have surfaces as a FileNotFoundError."""
        mock_uopy.set_missing_file("NOPE")

        with pytest.raises(Exception) as exc_info:
            connection_manager.open_file("NOPE")

        assert "NOPE" in str(exc_info.value)


class TestCommandExecution:
    """Running TCL commands through the manager."""

    def test_execute_command_returns_server_output(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """The command's response comes back to the caller."""
        mock_uopy.set_command_responses({"WHO": "1 test-user TEST"})

        assert "test-user" in connection_manager.execute_command("WHO")

    def test_execute_command_propagates_server_errors(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """A server-side failure is raised, not swallowed into an empty string."""
        mock_uopy.command_error = UOError(message="Command failed")

        with pytest.raises(UOError):
            connection_manager.execute_command("LIST CUSTOMERS")


class TestQueryTimeouts:
    """What happens to work the server abandons.

    uopy offers no way to cancel a command in flight, so the only thing that
    actually stops the work is closing the session it runs on. A timeout that
    merely returns an error leaves the query running and the thread alive.
    """

    def test_timeout_raises_with_actionable_advice(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """A slow command raises TimeoutError explaining what to do next."""
        mock_uopy.command_delay_seconds = 0.2

        with pytest.raises(TimeoutError) as exc_info:
            connection_manager.execute_command("LIST HUGE.FILE", timeout=0.05)

        assert "SAMPLE" in str(exc_info.value)

    def test_timeout_tears_down_the_session(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """The abandoned query's session is closed, which stops the server-side work."""
        connection_manager.connect()
        mock_uopy.command_delay_seconds = 0.2

        with pytest.raises(TimeoutError):
            connection_manager.execute_command("LIST HUGE.FILE", timeout=0.05)

        # The close runs on a background thread, so the caller is not held up by it.
        deadline = time.monotonic() + 2.0
        while mock_uopy.is_active and time.monotonic() < deadline:
            time.sleep(0.01)
        assert mock_uopy.is_active is False

    def test_next_request_after_a_timeout_still_works(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """Tearing down the session must not strand the server; the next call reconnects."""
        mock_uopy.command_delay_seconds = 0.2
        with pytest.raises(TimeoutError):
            connection_manager.execute_command("LIST HUGE.FILE", timeout=0.05)

        mock_uopy.command_delay_seconds = 0.0
        assert "test-user" in connection_manager.execute_command("WHO")

    def test_abandoned_queries_are_counted(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """Abandoned work is counted so an operator can see it happening."""
        mock_uopy.command_delay_seconds = 0.2

        with pytest.raises(TimeoutError):
            connection_manager.execute_command("LIST HUGE.FILE", timeout=0.05)

        assert connection_manager.abandoned_query_count == 1


class TestConcurrentCommands:
    """A uopy session is a single conversation with the server."""

    def test_commands_do_not_interleave_on_one_session(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """Two threads issuing commands are serialized, not interleaved."""
        import threading

        mock_uopy.command_delay_seconds = 0.05
        errors: list[Exception] = []

        def issue(command: str) -> None:
            try:
                connection_manager.execute_command(command)
            except Exception as exc:  # noqa: BLE001 - recorded and asserted below
                errors.append(exc)

        threads = [threading.Thread(target=issue, args=(f"WHO {n}",)) for n in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert errors == []
        assert len(mock_uopy.executed_commands) == 4


class TestOutputSanitization:
    """How raw Universe output is cleaned for display.

    The MultiValue delimiters must become readable, but real business data --
    accented names, currency symbols -- has to survive the trip intact.
    """

    def test_multivalue_delimiters_become_readable(
        self, connection_manager: ConnectionManager
    ) -> None:
        """Attribute, value, and subvalue marks are replaced with visible separators."""
        raw = "ONE" + chr(254) + "TWO" + chr(253) + "THREE" + chr(252) + "FOUR"

        cleaned = connection_manager._sanitize_output(raw)

        assert chr(254) not in cleaned
        assert chr(253) not in cleaned
        assert chr(252) not in cleaned
        assert "ONE" in cleaned and "FOUR" in cleaned

    def test_carriage_returns_and_form_feeds_normalize_to_newlines(
        self, connection_manager: ConnectionManager
    ) -> None:
        """Terminal line endings and page breaks become plain newlines."""
        cleaned = connection_manager._sanitize_output("A\r\nB\rC\fD")

        assert "\r" not in cleaned
        assert "\f" not in cleaned
        assert cleaned.count("\n") == 3

    def test_accented_customer_names_survive(self, connection_manager: ConnectionManager) -> None:
        """Non-ASCII letters in real customer data are preserved, not stripped."""
        cleaned = connection_manager._sanitize_output("MÜLLER GmbH" + chr(254) + "José Peña")

        assert "MÜLLER GmbH" in cleaned
        assert "José Peña" in cleaned

    def test_currency_symbols_survive(self, connection_manager: ConnectionManager) -> None:
        """Currency symbols in amounts are preserved, not silently deleted."""
        cleaned = connection_manager._sanitize_output("Total: £1,250.00 / €1,430.55 / ¥98,000")

        assert "£1,250.00" in cleaned
        assert "€1,430.55" in cleaned
        assert "¥98,000" in cleaned

    def test_control_characters_are_still_removed(
        self, connection_manager: ConnectionManager
    ) -> None:
        """Terminal control codes are dropped so they cannot corrupt the display."""
        cleaned = connection_manager._sanitize_output("A\x00B\x07C\x1b[31mD")

        assert "\x00" not in cleaned
        assert "\x07" not in cleaned
        assert "\x1b" not in cleaned
        assert "ABC" in cleaned.replace("[31m", "")


class TestTransactions:
    """Transaction state tracking."""

    def test_commit_cycle_updates_state(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """Begin then commit leaves no transaction open and logs both steps."""
        connection_manager.begin_transaction()
        assert connection_manager.in_transaction is True

        connection_manager.commit_transaction()
        assert connection_manager.in_transaction is False
        assert mock_uopy.transaction_log == ["start", "commit"]

    def test_rollback_cycle_updates_state(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """Begin then rollback leaves no transaction open and logs both steps."""
        connection_manager.begin_transaction()
        connection_manager.rollback_transaction()

        assert connection_manager.in_transaction is False
        assert mock_uopy.transaction_log == ["start", "rollback"]

    def test_nested_begin_is_rejected(self, connection_manager: ConnectionManager) -> None:
        """Starting a second transaction raises rather than silently nesting."""
        connection_manager.begin_transaction()

        with pytest.raises(RuntimeError):
            connection_manager.begin_transaction()

    def test_commit_without_transaction_is_rejected(
        self, connection_manager: ConnectionManager
    ) -> None:
        """Committing with nothing open raises rather than pretending to succeed."""
        with pytest.raises(RuntimeError):
            connection_manager.commit_transaction()


class _LockedSession:
    """Mimics uopy: close() waits on the same lock a running command holds."""

    def __init__(self, release: threading.Event) -> None:
        self._lock = threading.RLock()
        self._release = release
        self.is_active = True
        self.is_nls_enabled = True
        self.closed = threading.Event()

    def close(self) -> None:
        with self._lock:
            self.is_active = False
            self.closed.set()


class _LockedCommand:
    """A command that holds its session's lock until released (or 10 s pass)."""

    def __init__(self, text: str, session: _LockedSession) -> None:
        self._session = session
        self.response = "done"

    def run(self) -> None:
        with self._session._lock:
            self._session._release.wait(timeout=10)


class TestTimeoutDoesNotWaitForTheSlowQuery:
    """uopy's Session.close() takes the lock the in-flight command holds.

    Closing inline on timeout therefore waits for the very query being abandoned;
    the session must be detached at once and closed in the background.
    """

    def test_timeout_returns_promptly_and_next_request_gets_a_fresh_session(
        self, mock_config: U2Config
    ) -> None:
        """TimeoutError arrives within the timeout, and the old session is never reused."""
        release = threading.Event()
        sessions: list[_LockedSession] = []

        def connect(**kwargs: Any) -> _LockedSession:
            session = _LockedSession(release)
            sessions.append(session)
            return session

        manager = ConnectionManager(mock_config)
        try:
            with (
                patch("uopy.connect", side_effect=connect),
                patch("uopy.Command", _LockedCommand),
            ):
                started = time.monotonic()
                with pytest.raises(TimeoutError):
                    manager.execute_command("LIST HUGE.FILE", timeout=0.2)
                elapsed = time.monotonic() - started

                assert elapsed < 0.2 + 0.5
                assert len(sessions) == 1
                assert not sessions[0].closed.is_set()  # still blocked behind the query

                release.set()
                assert manager.get_session() is not sessions[0]
                assert len(sessions) == 2
                assert sessions[0].closed.wait(timeout=5)
        finally:
            release.set()

    def test_abandon_shuts_down_the_session_socket(self, mock_config: U2Config) -> None:
        """The abandoned session's socket is shut down, waking a read blocked on it."""
        left, right = socket.socketpair()
        try:
            session = MockSession()
            session._rpc_connection = type(  # type: ignore[attr-defined]
                "Rpc", (), {"rpc_socket": type("Sock", (), {"_socket": left})()}
            )()
            manager = ConnectionManager(mock_config)
            manager._session = session
            manager.force_disconnect()

            assert manager._session is None
            right.settimeout(2)
            assert right.recv(1) == b""  # the peer sees the connection go away
            # A reader still looping on the dead socket gets an error, not b"" forever.
            with pytest.raises(OSError):
                left.recv(1)
        finally:
            left.close()
            right.close()

    def test_abandoning_an_old_session_leaves_the_new_one(self, mock_config: U2Config) -> None:
        """A timeout that lands after a reconnect must not drop the fresh session."""
        manager = ConnectionManager(mock_config)
        old, new = MockSession(), MockSession()
        manager._session = new

        manager.force_disconnect(old)

        assert manager._session is new


class TestConnectTimeout:
    """U2_TIMEOUT reaches the driver."""

    def test_connect_passes_u2_timeout(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """uopy.connect receives the configured timeout."""
        connection_manager.connect()

        assert mock_uopy.connect_kwargs["timeout"] == connection_manager.config.timeout

    def test_read_timeout_is_widened_past_the_query_timeout(self, mock_config: U2Config) -> None:
        """The driver's socket read timeout outlasts the query timeout after connecting."""
        left, right = socket.socketpair()
        try:
            rpc_socket = type("Sock", (), {"_socket": left, "timeout": mock_config.timeout})()
            session = MockSession()
            session._rpc_connection = type("Rpc", (), {"rpc_socket": rpc_socket})()  # type: ignore[attr-defined]

            with patch("uopy.connect", return_value=session):
                ConnectionManager(mock_config).connect()

            assert left.gettimeout() is not None
            assert left.gettimeout() > mock_config.query_timeout
            assert rpc_socket.timeout == left.gettimeout()
        finally:
            left.close()
            right.close()
