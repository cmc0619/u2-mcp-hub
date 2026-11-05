"""Mock implementations of uopy objects for testing.

These mocks simulate Rocket's `uopy` package without requiring a live
Universe/UniData server. They deliberately mirror the *current* uopy 1.4 API
that `u2_mcp` calls -- constructor-style objects (`uopy.File(name, session=...)`,
`uopy.Command(text, session=...)`) rather than the older session-factory style --
so a test that passes here means the production code path really works.

Install them with the `mock_uopy` fixture in conftest.py.
"""

import re
from collections.abc import Callable
from typing import Any

RECORD_NOT_FOUND = 30001  # uopy's UOE_RNF
RECORD_LOCKED = 30002  # uopy's UOE_LCK


class UOError(Exception):
    """Stand-in for `uopy.UOError`, carrying the server's status code when one is given."""

    def __init__(self, code: int | None = None, message: str = ""):
        """Record the error code and message, in uopy's argument order."""
        super().__init__(message)
        self.code = code


class MockFile:
    """Mock Universe file handle, created as `uopy.File(name, session=...)`."""

    def __init__(self, name: str = "", session: Any = None, records: dict[str, str] | None = None):
        """Open a mock file, raising UOError if the session says it does not exist."""
        self.name = name
        self.session = session
        # A session may pre-seed records, and may declare a file missing.
        if session is not None and hasattr(session, "_files"):
            if name in getattr(session, "_missing_files", set()):
                raise UOError(message=f"File '{name}' not found")
            self._records: dict[str, str] = session._files.setdefault(name, {})
        else:
            self._records = records if records is not None else {}
        self.is_open = True

    def _locks(self) -> dict[tuple[str, str], object] | None:
        """Return the session's record-lock table, or None for a sessionless file."""
        return getattr(self.session, "_record_locks", None)

    def read(self, record_id: str, lock_flag: int = 0) -> str:
        """Read a record's raw data, raising UOError when the key is absent.

        Any lock_flag takes an exclusive record lock first, as READU does: it is
        refused when another session holds the lock, and it is kept even when the
        record is not there, as on a real server.
        """
        locks = self._locks()
        if lock_flag and locks is not None:
            key = (self.name, record_id)
            owner = locks.get(key)
            if owner is not None and owner is not self.session:
                raise UOError(RECORD_LOCKED, "This file or record is locked by another user")
            locks[key] = self.session
            hook = self.session.locked_read_hook
            if hook is not None:
                self.session.locked_read_hook = None
                hook()
        if record_id not in self._records:
            raise UOError(RECORD_NOT_FOUND, f"Record '{record_id}' not found in '{self.name}'")
        return self._records[record_id]

    def write(self, record_id: str, data: Any) -> None:
        """Write raw record data under the given key, releasing this session's lock on it."""
        self._records[record_id] = str(data)
        self.unlock(record_id)

    def unlock(self, record_id: str) -> None:
        """Release this session's lock on a record; releasing an unheld lock is harmless."""
        locks = self._locks()
        if locks is not None and locks.get((self.name, record_id)) is self.session:
            del locks[(self.name, record_id)]

    def delete(self, record_id: str) -> None:
        """Delete a record, raising UOError when the key is absent."""
        if record_id not in self._records:
            raise UOError(message=f"Record '{record_id}' not found in '{self.name}'")
        del self._records[record_id]

    def close(self) -> None:
        """Close the file handle."""
        self.is_open = False


class MockCommand:
    """Mock TCL command, created as `uopy.Command(text, session=...)`."""

    def __init__(self, command_text: str = "", session: Any = None):
        """Prepare a command; the session supplies canned responses."""
        self.command_text = command_text
        self.session = session
        self.response: str = ""
        self.status: int = 0
        self.at_system_return_code: int = 0

    def cancel(self) -> None:
        """Cancel a command waiting for input, as uopy does."""
        if self.status == 1 and self.session is not None:
            self.session.cancelled_commands.append(self.command_text)
            self.session.waiting_command = None
        self.status = 0

    def run(self) -> None:
        """Execute the command, recording it on the session and setting a response."""
        session = self.session
        if session is not None:
            session.waiting_command = None  # a new Command replaces the bound one
            session.executed_commands.append(self.command_text)
            if any(p.upper() in self.command_text.upper() for p in session.prompting_commands):
                self.status = 1
                session.waiting_command = self
            self.at_system_return_code = session.return_code
            if session.command_error is not None:
                raise session.command_error
            if session.command_delay_seconds:
                import time

                time.sleep(session.command_delay_seconds)
            if session.select_from_files:
                selected = _select_from_file(session, self.command_text)
                if selected is not None:
                    self.response = selected
                    return
            for pattern, canned in session.command_responses.items():
                if pattern.upper() in self.command_text.upper():
                    self.response = canned
                    return
        self.response = _default_response(self.command_text)


def _default_response(command_text: str) -> str:
    """Return a plausible Universe response for common commands."""
    upper = command_text.upper()
    if upper.startswith("WHO"):
        return "1 test-user TEST"
    if upper.startswith("LISTFILES") or upper.startswith("LIST.FILE"):
        return "CUSTOMERS\nORDERS\nPRODUCTS\n3 files listed."
    if upper.startswith("FILE.STAT"):
        return "File name = CUSTOMERS\nNumber of records = 500"
    if upper.startswith("COUNT"):
        return "5 records counted."
    if upper.startswith("LIST") or upper.startswith("SORT"):
        return "ID001 Value1\nID002 Value2\n2 records listed."
    if upper.startswith("SELECT") or upper.startswith("SSELECT"):
        return "3 records selected to list 0."
    return f"Command executed: {command_text}"


_BARE_SELECT = re.compile(r"^\s*S?SELECT\s+((?:DICT\s+)?\S+)\s*$", re.IGNORECASE)


def _select_from_file(session: Any, command_text: str) -> str | None:
    """Answer a bare SELECT/SSELECT or CLEARSELECT from seeded files, else None."""
    if command_text.strip().upper() == "CLEARSELECT":
        session.select_list = []
        return ""
    match = _BARE_SELECT.match(command_text)
    if not match:
        return None
    name = " ".join(match.group(1).split())
    if name in session._missing_files:
        session.select_list = []
        return f"Cannot open file {name}"
    if name not in session._files:
        return None
    session.select_list = sorted(session._files[name])
    return f"{len(session.select_list)} records selected to list 0."


class MockList:
    """Mock select list, created as `uopy.List(session=...)`."""

    def __init__(self, session: Any = None, list_no: int = 0):
        """Create a select list backed by the session's pending record ids."""
        self.session = session
        self.list_no = list_no
        pending = list(getattr(session, "select_list", [])) if session is not None else []
        self._pending: list[str] = pending
        self._index = 0

    def next(self) -> str | None:
        """Return the next record id, or None when the list is exhausted."""
        if self.session is not None and getattr(self.session, "waiting_command", None):
            raise UOError(code=30114, message="An Execute is currently active on the server")
        if self._index >= len(self._pending):
            return None
        value = self._pending[self._index]
        self._index += 1
        return value


class MockSubroutine:
    """Mock BASIC subroutine, created as `uopy.Subroutine(name, n, session=...)`."""

    def __init__(self, name: str = "", num_args: int = 0, session: Any = None):
        """Prepare a subroutine call with `num_args` argument slots."""
        self.name = name
        self.num_args = num_args
        self.session = session
        self.args: list[str] = [""] * num_args

    def set_arg(self, index: int, value: Any) -> None:
        """Set an input argument by position."""
        if index >= len(self.args):
            raise UOError(message=f"Argument index {index} is out of range for '{self.name}'")
        self.args[index] = str(value)

    def get_arg(self, index: int) -> str:
        """Read an argument back after the call."""
        if index >= len(self.args):
            raise UOError(message=f"Argument index {index} is out of range for '{self.name}'")
        return self.args[index]

    def call(self) -> None:
        """Execute the subroutine, prefixing each non-empty argument with RESULT:."""
        if self.session is not None:
            self.session.called_subroutines.append((self.name, list(self.args)))
            if self.session.subroutine_error is not None:
                raise self.session.subroutine_error
        for i, value in enumerate(self.args):
            if value:
                self.args[i] = f"RESULT:{value}"


class MockSession:
    """Mock uopy session returned by `uopy.connect(...)`.

    Test helpers let a test declare exactly what the fake server should do:
    seeded records, canned command output, a select list, or a raised error.
    """

    def __init__(self, **connect_kwargs: Any):
        """Create an active session, remembering the connect arguments."""
        self.connect_kwargs = connect_kwargs
        self.is_active: bool = True
        self.is_nls_enabled: bool = False
        # @SYSTEM.RETURN.CODE after each command: negative when the server rejects it.
        self.return_code: int = 0
        self.encoding: str = "UTF-8"
        self.executed_commands: list[str] = []
        self.command_responses: dict[str, str] = {}
        # Commands (substring match) that stop at a prompt, as uopy's EXEC_REPLY.
        self.prompting_commands: set[str] = set()
        self.waiting_command: Any = None
        self.cancelled_commands: list[str] = []
        self.command_error: Exception | None = None
        self.command_delay_seconds: float = 0.0
        self.subroutine_error: Exception | None = None
        self.called_subroutines: list[tuple[str, list[str]]] = []
        self.select_list: list[str] = []
        self.in_transaction: bool = False
        self.transaction_log: list[str] = []
        self._files: dict[str, dict[str, str]] = {}
        self._missing_files: set[str] = set()
        # Opt-in: a bare SELECT/SSELECT of a seeded file selects that file's keys.
        self.select_from_files: bool = False
        # Record locks: (file, record id) -> the owning session. Sessions that share
        # this table (and _files) model two users of one server.
        self._record_locks: dict[tuple[str, str], object] = {}
        # Called once, from inside the next locking read, while the lock is held.
        self.locked_read_hook: Callable[[], None] | None = None

    # -- production API -----------------------------------------------------

    def close(self) -> None:
        """Close the session."""
        self.is_active = False

    def tx_start(self) -> None:
        """Begin a transaction."""
        self.in_transaction = True
        self.transaction_log.append("start")

    def tx_commit(self) -> None:
        """Commit the current transaction."""
        self.in_transaction = False
        self.transaction_log.append("commit")

    def tx_rollback(self) -> None:
        """Roll back the current transaction."""
        self.in_transaction = False
        self.transaction_log.append("rollback")

    # -- test helpers -------------------------------------------------------

    def add_file(self, file_name: str, records: dict[str, str] | None = None) -> None:
        """Seed a file with records so `uopy.File` can read them."""
        self._files[file_name] = dict(records or {})

    def add_program_file(self, file_name: str, programs: dict[str, str]) -> None:
        """Seed a BASIC program file and let SELECT/SSELECT list its keys."""
        self.add_file(file_name, programs)
        self.select_from_files = True

    def hold_lock_elsewhere(self, file_name: str, record_id: str) -> None:
        """Make another user hold the lock on a record."""
        self._record_locks[(file_name, record_id)] = object()

    def set_missing_file(self, file_name: str) -> None:
        """Declare a file that should fail to open."""
        self._missing_files.add(file_name)

    def set_command_responses(self, responses: dict[str, str]) -> None:
        """Set substring-matched canned responses for TCL commands."""
        self.command_responses = responses

    def set_select_list(self, record_ids: list[str]) -> None:
        """Set the record ids a `uopy.List` will hand back."""
        self.select_list = list(record_ids)
