"""Connection management for Universe/UniData databases."""

import contextlib
import logging
import socket
import threading
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from types import ModuleType
from typing import Any

# Workaround for uopy bug on macOS - TCP_KEEPIDLE doesn't exist on macOS
if not hasattr(socket, "TCP_KEEPIDLE"):
    socket.TCP_KEEPIDLE = socket.TCP_KEEPALIVE  # type: ignore[attr-defined]

from .config import U2Config
from .credentials import U2Credentials
from .driver import get_driver

logger = logging.getLogger(__name__)


def _uopy() -> ModuleType:
    """Return the configured driver.

    Resolved per call rather than captured at import time, so configuration can
    change between tests without the module needing to be reloaded.
    """
    return get_driver()


# MultiValue delimiters, named so the sanitizer reads as intent rather than magic numbers.
AM = chr(254)  # Attribute mark - separates fields
VM = chr(253)  # Value mark - separates values within a field
SM = chr(252)  # Subvalue mark - separates subvalues within a value

# Unicode categories that must never reach a user's screen: control codes,
# formatting marks, surrogates, private-use and unassigned code points.
_NON_DISPLAYABLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})


@dataclass
class ConnectionInfo:
    """Information about the open database session."""

    host: str
    account: str
    service: str
    connected_at: datetime


@dataclass
class TransactionState:
    """Tracks the current transaction state."""

    in_transaction: bool = False
    started_at: datetime | None = None


# Seconds a session's socket read may outlast the query timeout before the driver
# gives up on its own; execute_command's timeout is the one meant to fire first.
_READ_TIMEOUT_SLACK = 30


def _shutdown_socket(session: Any) -> None:
    """Shut down a uopy session's socket without taking the session's lock.

    A read blocked on the socket returns at once, so the thread running the
    abandoned command finishes and releases the session lock. Best effort: it
    reaches into driver internals and does nothing when they are absent.

    Args:
        session: The session being abandoned
    """
    rpc_socket = getattr(getattr(session, "_rpc_connection", None), "rpc_socket", None)
    raw = getattr(rpc_socket, "_socket", None)
    if raw is None:
        return
    with contextlib.suppress(Exception):
        raw.shutdown(socket.SHUT_RDWR)
    # After a shutdown, recv returns b"" rather than raising, and uopy's loop that
    # reads a reply body would spin on that forever. A closed socket raises.
    with contextlib.suppress(Exception):
        raw.close()


def _abandon(session: Any) -> None:
    """Hang up a dropped session now and close it on a daemon thread.

    uopy's close waits for the session lock an RPC in flight holds, so nobody
    waits for it.

    Args:
        session: A session the manager no longer holds
    """
    _shutdown_socket(session)
    threading.Thread(
        target=_close_quietly, args=(session,), name="u2-session-close", daemon=True
    ).start()


def _close_quietly(session: Any) -> None:
    """Close an abandoned session, logging rather than raising on failure.

    Args:
        session: The session to close
    """
    try:
        session.close()
    except Exception as exc:  # noqa: BLE001 - the session is already abandoned
        logger.warning(f"Error closing an abandoned session: {exc}")


class ConnectionError(Exception):
    """Raised when a database connection fails."""

    pass


class FileNotFoundError(Exception):
    """Raised when a Universe file cannot be opened."""

    pass


# uopy's Command.status after run(): the command stopped to ask for input. While it
# waits, the session refuses every other call ("[30114] An Execute is currently
# active on the server"), so it must be cancelled before anything else runs.
_EXEC_REPLY = 1


class TransactionLostError(RuntimeError):
    """Raised when dropping a session to recover from a fault rolled back a transaction.

    Never swallowed: an answer that looks successful must not hide lost writes.
    """


class ConnectionManager:
    """One session to a Universe/UniData server, under one login.

    Reconnects on the next request when the session is gone, caches file
    handles and tracks the transaction state.

    Args:
        config: U2Config instance with connection parameters
    """

    def __init__(self, config: U2Config, credentials: "U2Credentials | None" = None) -> None:
        self._config = config
        # Credentials may belong to one person rather than the whole server, so the
        # database can enforce its own security against the real caller.
        self._credentials = credentials or U2Credentials(
            user=config.user,
            password=config.password,
            account=config.account,
            is_shared=True,
        )
        self._session: Any | None = None  # uopy.Session
        self._info: ConnectionInfo | None = None
        self._transaction = TransactionState()
        # Open file handles by name, each with the session it was opened on.
        self._open_files: dict[str, tuple[Any, Any]] = {}
        # Opening a file is serialized per file name, so a burst of callers opening
        # the same file share one handle, while opens of other files are not held up.
        self._file_open_locks: dict[str, threading.Lock] = {}
        self._file_open_locks_guard = threading.Lock()
        # One conversation per session: commands must not interleave on the wire.
        self._command_lock = threading.RLock()
        # Establishing a session is serialized separately, so a burst of callers
        # arriving to find no session opens one connection rather than one each.
        self._session_lock = threading.RLock()
        self._abandoned_queries = 0

    @property
    def config(self) -> U2Config:
        """Return the configuration object."""
        return self._config

    @property
    def credentials(self) -> U2Credentials:
        """Return the database login this manager connects with."""
        return self._credentials

    @property
    def connection_info(self) -> ConnectionInfo | None:
        """Return the open session's details, or None when not connected."""
        return self._info

    @property
    def in_transaction(self) -> bool:
        """Return whether a transaction is currently active."""
        return self._transaction.in_transaction

    def connect(self) -> ConnectionInfo:
        """Open the session, or return the one already open.

        Returns:
            ConnectionInfo with connection details

        Raises:
            ConnectionError: If connection fails
        """
        with self._session_lock:
            return self._connect()

    def _connect(self) -> ConnectionInfo:
        """Open the session unless one is open; the caller holds _session_lock."""
        if self._info is not None and self._session is not None:
            return self._info

        try:
            logger.info(
                f"Connecting to {self._config.host}/{self._credentials.account} "
                f"as {self._credentials.user}"
            )

            self._session = _uopy().connect(
                host=self._config.host,
                port=self._config.port,
                user=self._credentials.user,
                password=self._credentials.password,
                account=self._credentials.account,
                service=self._config.service,
                ssl=self._config.ssl,
                timeout=self._config.timeout,
            )
            self._widen_read_timeout(self._session)
            # Without NLS the server sends a byte per character, marks included
            # (0xFB-0xFF). uopy decodes with the host's preferred encoding, UTF-8 in
            # the container, which turned every mark into U+FFFD. Latin-1 maps each
            # byte to the character of the same number, which is what AM, VM and SM are.
            if not self._session.is_nls_enabled:
                self._session.encoding = "latin-1"

            info = ConnectionInfo(
                host=self._config.host,
                account=self._credentials.account,
                service=self._config.service,
                connected_at=datetime.now(),
            )
            self._info = info

            logger.info(f"Connected successfully to {self._credentials.account}")
            return info

        except _uopy().UOError as e:
            logger.error(f"Connection failed: {e}")
            raise ConnectionError(f"Failed to connect to {self._config.host}: {e}") from e

    def _widen_read_timeout(self, session: Any) -> None:
        """Keep the driver's socket timeout from cutting a query short.

        uopy applies its one `timeout` to the TCP connect, the login, and every
        later read on the socket. U2_TIMEOUT is meant as the connect timeout, so
        once the session is up the read timeout is raised to outlast the query
        timeout; execute_command is what bounds a query. Best effort: a driver
        without these internals keeps the timeout it connected with.

        Args:
            session: The session just opened
        """
        read_timeout = max(self._config.timeout, self._config.query_timeout + _READ_TIMEOUT_SLACK)
        if read_timeout <= self._config.timeout:
            return
        rpc_socket = getattr(getattr(session, "_rpc_connection", None), "rpc_socket", None)
        raw = getattr(rpc_socket, "_socket", None)
        if rpc_socket is None or raw is None:
            return
        try:
            raw.settimeout(read_timeout)
            # uopy restores this value after its own health check.
            rpc_socket.timeout = read_timeout
        except Exception as exc:  # noqa: BLE001 - the connect timeout still applies
            logger.debug(f"Could not raise the session read timeout: {exc}")

    def disconnect(self) -> bool:
        """Close the session, waiting for a login in progress to finish first.

        Returns:
            True if a session was closed, False if none was open
        """
        with self._session_lock:
            if self._info is None:
                return False
            session = self._session
            self._discard()
        if session is not None:
            try:
                session.close()
            except _uopy().UOError as e:
                logger.warning(f"Error during disconnect: {e}")
                return False
        logger.info("Disconnected")
        return True

    def _discard(self) -> None:
        """Forget the session so the next connect() genuinely opens a new one."""
        self._session = None
        self._info = None
        self._open_files.clear()
        self._transaction = TransactionState()

    def get_session(self) -> Any:
        """Get the active uopy session, auto-reconnecting if necessary.

        Establishing a session is serialized: when a burst of requests arrives to
        find no session, every one of them would otherwise open its own. Those
        duplicates leak a database connection each and stay invisible until the
        server runs out of them.

        Returns:
            Active uopy.Session object

        Raises:
            ConnectionError: If reconnection fails
        """
        with self._session_lock:
            return self._establish_session()

    def _establish_session(self) -> Any:
        """Return a live session for this login, reconnecting if needed.

        Returns:
            Active uopy.Session object

        Raises:
            ConnectionError: If a session cannot be established
        """
        if self._session is None:
            self._discard()
            self._connect()

        # Verify the connection is still alive before handing it to a caller.
        # uopy leaves is_active True after a transport failure and records the
        # failure in _is_rpc_failed. That flag is read rather than calling
        # health_check(), which waits for the session lock any RPC in flight holds.
        session = self._session
        try:
            is_alive = (
                session is not None
                and bool(session.is_active)
                and not getattr(session, "_is_rpc_failed", False)
            )
        except (_uopy().UOError, AttributeError):
            is_alive = False

        if not is_alive:
            logger.warning("Connection lost, attempting reconnect")
            self._discard()
            if session is not None:
                _abandon(session)
            self._connect()

        if self._session is None:
            raise ConnectionError(f"Failed to establish a session to {self._config.host}")

        return self._session

    def open_file(self, file_name: str) -> Any:
        """Open a Universe file.

        File handles are cached for efficiency. A handle only works on the session
        that opened it, so one cached on a failed or replaced session is reopened.

        Args:
            file_name: Name of the file to open

        Returns:
            _uopy().File object

        Raises:
            FileNotFoundError: If file cannot be opened
        """
        session = self.get_session()
        cached = self._open_files.get(file_name)
        if cached is not None and cached[0] is session:
            return cached[1]

        with self._file_open_locks_guard:
            file_lock = self._file_open_locks.setdefault(file_name, threading.Lock())
        with file_lock:
            # Another caller may have opened it while this one waited.
            session = self.get_session()
            cached = self._open_files.get(file_name)
            if cached is not None and cached[0] is session:
                return cached[1]
            try:
                file_handle = _uopy().File(file_name, session=session)
            except _uopy().UOError as e:
                raise FileNotFoundError(f"Cannot open file '{file_name}': {e}") from e
            self._open_files[file_name] = (session, file_handle)
            return file_handle

    def close_file(self, file_name: str) -> bool:
        """Close a cached file handle.

        Args:
            file_name: Name of the file to close

        Returns:
            True if file was closed, False if not found
        """
        if file_name in self._open_files:
            del self._open_files[file_name]
            return True
        return False

    @property
    def abandoned_query_count(self) -> int:
        """Return how many queries have been abandoned to a timeout.

        Abandoned work is worth surfacing: a rising count means queries are
        routinely outrunning the timeout and the limit or the queries need review.
        """
        return self._abandoned_queries

    def execute_command(self, command_text: str, timeout: float | None = None) -> str:
        """Execute a TCL command and return the response (see run_command)."""
        return self.run_command(command_text, timeout)[0]

    def run_command(self, command_text: str, timeout: float | None = None) -> tuple[str, int]:
        """Execute a TCL command; return its response and @SYSTEM.RETURN.CODE.

        A uopy session is a single conversation with the server, so commands are
        serialized: two at once on one session would interleave and corrupt each
        other's replies.

        Args:
            command_text: TCL command to execute
            timeout: Optional timeout in seconds (defaults to config.query_timeout)

        Returns:
            The response (sanitized for display), and the server's return code,
            which is negative when the server rejected the command

        Raises:
            TimeoutError: If command exceeds timeout
        """
        effective_timeout = timeout if timeout is not None else self._config.query_timeout

        with self._command_lock:
            session = self.get_session()
            result, completed = self._start_command(command_text, session)

            if completed.wait(timeout=effective_timeout):
                if result["error"]:
                    raise result["error"]
                return self._sanitize_output(result["response"] or ""), result["return_code"]

            had_transaction = self._transaction.in_transaction
            self._abandon_command(command_text, effective_timeout, session)
            raise TimeoutError(
                f"Query exceeded {effective_timeout} second timeout and was abandoned. "
                "The database session was closed to stop the work; the next request will "
                "reconnect. Consider adding a SAMPLE clause or narrowing the selection "
                "criteria."
                + (
                    " The open transaction was rolled back by the server when the session closed."
                    if had_transaction
                    else ""
                )
            )

    def run_select_command(
        self, command_text: str, timeout: float | None = None
    ) -> tuple[str, int]:
        """Run a command that makes a select list, then clear the list it left."""
        with self._command_lock:
            try:
                result = self.run_command(command_text, timeout)
            except Exception:
                self._clear_select_list_quietly(self._session)
                raise

            try:
                self._clear_select_list(self._session)
            except TransactionLostError:
                raise
            except Exception:
                if result[1] >= 0:
                    raise
            return result

    def _clear_select_list(self, session: Any | None) -> None:
        """Clear a session's active select list, dropping the session if cleanup fails.

        Raises:
            TransactionLostError: When dropping the session rolled back an open
                transaction
        """
        if session is None or session is not self._session:
            return

        had_transaction = self._transaction.in_transaction
        try:
            output, return_code = self.run_command("CLEARSELECT")
            if return_code < 0:
                raise RuntimeError(output or "The server rejected CLEARSELECT")
        except Exception as exc:
            self.force_disconnect(session)
            logger.warning(f"Could not clear the select list; disconnected the session: {exc}")
            if had_transaction:
                raise TransactionLostError(
                    f"Could not clear the select list ({exc}), so the database session was "
                    "closed. The open transaction was rolled back by the server and its "
                    "uncommitted changes are lost."
                ) from exc
            raise

    def _clear_select_list_quietly(self, session: Any | None) -> None:
        """Clear the list when the answer is already settled; only lost writes surface."""
        try:
            self._clear_select_list(session)
        except TransactionLostError:
            raise
        except Exception:  # noqa: BLE001 - the session was dropped; the next call reconnects
            pass

    def _start_command(self, command_text: str, session: Any) -> tuple[dict[str, Any], Any]:
        """Run a command on a worker thread so the caller can time it out.

        Args:
            command_text: TCL command to execute
            session: The uopy session to run it on

        Returns:
            Tuple of (result holder, completion event)
        """
        import threading

        result: dict[str, Any] = {"response": None, "error": None, "return_code": 0}
        completed = threading.Event()

        def run_command() -> None:
            try:
                cmd = _uopy().Command(command_text, session=session)
                cmd.run()
                result["response"] = str(cmd.response) if cmd.response else ""
                result["return_code"] = cmd.at_system_return_code
                if getattr(cmd, "status", 0) == _EXEC_REPLY:
                    # Nothing here answers prompts. Keep what the server said (often
                    # the real diagnostic), cancel the prompt so the session is
                    # usable, and report the command as rejected.
                    cmd.cancel()
                    result["return_code"] = -1
                    result["response"] = (
                        result["response"].rstrip()
                        + "\n(The command stopped to ask for input and was cancelled.)"
                    ).lstrip()
            except Exception as e:
                result["error"] = e
            finally:
                completed.set()

        threading.Thread(target=run_command, daemon=True).start()
        return result, completed

    def _abandon_command(self, command_text: str, effective_timeout: float, session: Any) -> None:
        """Stop a query that outran its timeout.

        uopy gives no way to cancel a command in flight, so returning an error
        would leave the query running on the server and the thread alive against a
        session another request would reuse. Closing the session is what actually
        stops the work: the socket drops and the server abandons the command.

        Args:
            command_text: The command being abandoned, for the log
            effective_timeout: The timeout it exceeded, for the log
            session: The session the command is running on
        """
        self._abandoned_queries += 1
        logger.error(
            f"Query timed out after {effective_timeout}s and was abandoned "
            f"(total abandoned: {self._abandoned_queries}): {command_text[:100]}"
        )
        self.force_disconnect(session)

    def _sanitize_output(self, text: str) -> str:
        """Clean up Universe output for display.

        Replaces MultiValue delimiters with readable separators and strips
        terminal control codes. Real business data -- accented customer names,
        currency symbols -- is preserved: filtering by Unicode category rather
        than by "is it plain ASCII" is what keeps MULLER from losing its umlaut.

        Args:
            text: Raw output from Universe

        Returns:
            Cleaned text suitable for JSON/display
        """
        # Normalize terminal line endings and page breaks to plain newlines.
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        text = text.replace("\f", "\n")

        # Convert MultiValue delimiters to readable text
        # AM (chr 254) = field/attribute separator -> newline
        # VM (chr 253) = multivalue separator -> pipe
        # SM (chr 252) = subvalue separator -> semicolon
        text = text.replace(AM, "\n")
        text = text.replace(VM, " | ")
        text = text.replace(SM, " ; ")

        return "".join(char for char in text if self._is_displayable(char))

    @staticmethod
    def _is_displayable(char: str) -> bool:
        """Return whether a character is safe to show to a user.

        Keeps newlines and tabs, drops the control, format, surrogate and
        private-use categories, and keeps every ordinary printable character
        regardless of alphabet.

        Args:
            char: A single character

        Returns:
            True if the character should survive sanitization
        """
        if char in ("\n", "\t"):
            return True
        return unicodedata.category(char) not in _NON_DISPLAYABLE_CATEGORIES

    def create_select_list(self) -> Any:
        """Create a new select list object.

        Returns:
            _uopy().List object for select operations
        """
        session = self.get_session()
        return _uopy().List(session=session)

    def select_ids(self, command_text: str, limit: int | None = None) -> tuple[list[str], bool]:
        """Run a SELECT and read its select list, as one turn on the session.

        The active select list belongs to the session, not the caller, so the
        command lock is held from the SELECT until the list is read to its end or
        cleared: any other command in between could replace it.

        Args:
            command_text: The SELECT or SSELECT to run
            limit: Most ids to read; the rest of the list is cleared

        Returns:
            The ids, and whether that is all of them

        Raises:
            TimeoutError: If the SELECT exceeds the query timeout
        """
        with self._command_lock:
            ids: list[str] = []
            session: Any | None = None
            try:
                output, return_code = self.run_command(command_text)
                session = self._session
                if return_code < 0:
                    raise RuntimeError(output)

                select = self.create_select_list()
                if self._session is not session:
                    raise ConnectionError("The session was replaced during the selection")
                while True:
                    value = select.next()
                    if value is None or str(value) == "":
                        return ids, True
                    if limit is not None and len(ids) >= limit:
                        return ids, False
                    ids.append(str(value))
            finally:
                # The select list belongs to the session, even after it is exhausted.
                # A session dropped on timeout took its list with it.
                if session is None:
                    session = self._session
                self._clear_select_list_quietly(session)

    def force_disconnect(self, session: Any | None = None) -> None:
        """Drop the current session at once, closing it in the background.

        Used by execute_command to abandon a query that outran its timeout, which
        cannot wait for the close:
        uopy's Session.close() takes the session's own lock, which an in-flight
        command holds until the server answers, so closing inline would make the
        caller wait for exactly the slow work it is trying to give up on.

        The manager forgets the session first, so the next request opens a fresh
        one and never reuses this one. The socket is then shut down, which wakes a
        read blocked on it and tells the server the client has gone, and the
        session is closed on a daemon thread with no manager lock held.

        Args:
            session: The session to drop. When given and the manager has already
                moved on to another, only the given one is shut down.
        """
        logger.warning("Force disconnecting database connection")
        with self._session_lock:
            if session is None:
                session = self._session
            if session is not None and session is self._session:
                self._discard()
        if session is not None:
            _abandon(session)

    def begin_transaction(self) -> bool:
        """Begin a database transaction.

        Returns:
            True if transaction started successfully

        Raises:
            RuntimeError: If already in a transaction
        """
        if self._transaction.in_transaction:
            raise RuntimeError("Transaction already in progress")

        session = self.get_session()
        try:
            session.tx_start()
            self._transaction.in_transaction = True
            self._transaction.started_at = datetime.now()
            logger.info("Transaction started")
            return True
        except _uopy().UOError as e:
            logger.error(f"Failed to start transaction: {e}")
            raise

    def commit_transaction(self) -> bool:
        """Commit the current transaction.

        Returns:
            True if committed successfully

        Raises:
            RuntimeError: If not in a transaction
        """
        if not self._transaction.in_transaction:
            raise RuntimeError("No transaction in progress")

        session = self.get_session()
        try:
            session.tx_commit()
            self._transaction = TransactionState()
            logger.info("Transaction committed")
            return True
        except _uopy().UOError as e:
            logger.error(f"Failed to commit transaction: {e}")
            raise

    def rollback_transaction(self) -> bool:
        """Rollback the current transaction.

        Returns:
            True if rolled back successfully

        Raises:
            RuntimeError: If not in a transaction
        """
        if not self._transaction.in_transaction:
            raise RuntimeError("No transaction in progress")

        session = self.get_session()
        try:
            session.tx_rollback()
            self._transaction = TransactionState()
            logger.info("Transaction rolled back")
            return True
        except _uopy().UOError as e:
            logger.error(f"Failed to rollback transaction: {e}")
            raise
