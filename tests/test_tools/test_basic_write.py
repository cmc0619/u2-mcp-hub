"""Saving BASIC source: only over what the caller read, and never in read-only mode."""

import threading
from collections.abc import Iterator
from typing import Any
from unittest.mock import patch

import pytest

import u2_mcp.server as server_module
from tests.mocks.mock_uopy import MockSession
from u2_mcp.config import U2Config
from u2_mcp.connection import ConnectionManager
from u2_mcp.tools.basic import read_program, write_program
from u2_mcp.utils.basic_source import AM, record_hash

HELLO = AM.join(["CRT 'HELLO'", "END"])


@pytest.fixture
def bp(connection_manager: ConnectionManager, mock_uopy: MockSession) -> MockSession:
    mock_uopy.add_program_file("BP", {"HELLO": HELLO})
    return mock_uopy


def stored(session: MockSession, name: str) -> str | None:
    return session._files["BP"].get(name)


class TestSaving:
    def test_read_then_write_back_unchanged_stores_the_identical_record(
        self, bp: MockSession
    ) -> None:
        read = read_program("BP", "HELLO", numbered=False)

        saved = write_program(
            "BP", "HELLO", read["source"], expected_hash=read["hash"], confirm=True
        )

        assert stored(bp, "HELLO") == HELLO
        assert saved["hash"] == read["hash"]

    def test_an_edit_over_the_current_hash_is_saved(self, bp: MockSession) -> None:
        read = read_program("BP", "HELLO", numbered=False)

        saved = write_program(
            "BP", "HELLO", "CRT 'BYE'\r\nEND", expected_hash=read["hash"], confirm=True
        )

        assert stored(bp, "HELLO") == "CRT 'BYE'" + AM + "END"
        assert saved == {
            "status": "saved",
            "created": False,
            "file_name": "BP",
            "program": "HELLO",
            "hash": record_hash("CRT 'BYE'" + AM + "END"),
            "line_count": 2,
        }

    def test_without_a_hash_a_new_program_is_created(self, bp: MockSession) -> None:
        saved = write_program("BP", "NEW.ONE", "END", confirm=True)

        assert (saved["status"], saved["created"]) == ("saved", True)
        assert stored(bp, "NEW.ONE") == "END"

    def test_without_confirm_nothing_is_written(self, bp: MockSession) -> None:
        result = write_program("BP", "NEW.ONE", "END")

        assert result["status"] == "confirmation_required"
        assert result["creates"] is True
        assert stored(bp, "NEW.ONE") is None


class TestRefusals:
    def test_an_existing_program_needs_the_hash(self, bp: MockSession) -> None:
        result = write_program("BP", "HELLO", "END", confirm=True)

        assert result["error"] == (
            "HELLO already exists in BP; read it with read_program and pass its hash "
            "as expected_hash"
        )
        assert stored(bp, "HELLO") == HELLO

    def test_a_stale_hash_is_refused_and_the_current_hash_is_not_given(
        self, bp: MockSession
    ) -> None:
        old = read_program("BP", "HELLO")["hash"]
        bp._files["BP"]["HELLO"] = "CRT 'SOMEONE ELSE'"

        result = write_program("BP", "HELLO", "END", expected_hash=old, confirm=True)

        assert result["error"] == "HELLO changed since you read it; read it again with read_program"
        assert record_hash("CRT 'SOMEONE ELSE'") not in str(result)
        assert stored(bp, "HELLO") == "CRT 'SOMEONE ELSE'"

    def test_a_hash_for_a_program_that_is_gone_is_refused(self, bp: MockSession) -> None:
        result = write_program("BP", "GONE", "END", expected_hash="0" * 64, confirm=True)

        assert result["error"] == (
            "GONE no longer exists in BP; leave expected_hash out to create it"
        )

    def test_mark_characters_are_refused(self, bp: MockSession) -> None:
        result = write_program("BP", "NEW", "A" + chr(253) + "B", confirm=True)

        assert result["error"].startswith("source line 1 contains a U2 mark character")
        assert stored(bp, "NEW") is None

    @pytest.mark.parametrize(
        ("file_name", "program"), [("CUSTOMERS", "X"), ("BP.O", "HELLO"), ("BP", "_HELLO")]
    )
    def test_files_and_names_outside_the_rules_are_refused(
        self, bp: MockSession, file_name: str, program: str
    ) -> None:
        assert "error" in write_program(file_name, program, "END", confirm=True)


class TestRecordLock:
    """The read, the hash check and the write happen under the U2 record lock."""

    def test_a_program_another_user_has_locked_is_refused_untouched(self, bp: MockSession) -> None:
        current = read_program("BP", "HELLO")["hash"]
        bp.hold_lock_elsewhere("BP", "HELLO")

        result = write_program("BP", "HELLO", "END", expected_hash=current, confirm=True)

        assert result["error"] == "HELLO is locked by another user; try again later"
        assert stored(bp, "HELLO") == HELLO
        assert ("BP", "HELLO") in bp._record_locks  # the other user's lock is still theirs

    @pytest.mark.parametrize(
        ("program", "use_hash"),
        [("HELLO", True), ("NEW.ONE", False), ("HELLO", False), ("GONE", True)],
        ids=["saved", "created", "exists", "gone"],
    )
    def test_the_lock_is_released_on_every_path(
        self, bp: MockSession, program: str, use_hash: bool
    ) -> None:
        current = read_program("BP", "HELLO")["hash"] if use_hash else None

        write_program("BP", program, "END", expected_hash=current, confirm=True)

        assert bp._record_locks == {}

    def test_the_lock_is_released_when_the_write_fails(self, bp: MockSession) -> None:
        current = read_program("BP", "HELLO")["hash"]

        with patch("tests.mocks.mock_uopy.MockFile.write", side_effect=OSError("disk full")):
            result = write_program("BP", "HELLO", "END", expected_hash=current, confirm=True)

        assert result["error"] == "disk full"
        assert bp._record_locks == {}

    def test_a_second_user_saving_over_the_same_hash_is_refused(
        self, bp: MockSession, mock_config: U2Config
    ) -> None:
        current = read_program("BP", "HELLO")["hash"]
        other = MockSession()
        other._files = bp._files
        other._record_locks = bp._record_locks
        second: dict[str, Any] = {}

        def second_user_saves() -> None:
            first_manager = server_module._connection_manager
            with patch("uopy.connect", return_value=other):
                server_module._connection_manager = ConnectionManager(mock_config)
                try:
                    second.update(
                        write_program(
                            "BP", "HELLO", "CRT 'TWO'", expected_hash=current, confirm=True
                        )
                    )
                finally:
                    server_module._connection_manager = first_manager

        bp.locked_read_hook = second_user_saves

        first = write_program("BP", "HELLO", "CRT 'ONE'", expected_hash=current, confirm=True)

        assert first["status"] == "saved"
        assert second["error"] == "HELLO is locked by another user; try again later"
        assert stored(bp, "HELLO") == "CRT 'ONE'"
        assert bp._record_locks == {}

    def test_two_saves_on_one_connection_over_the_same_hash_save_once(
        self, bp: MockSession
    ) -> None:
        """One session owns its U2 locks, so calls sharing it are serialized in-process."""
        current = read_program("BP", "HELLO")["hash"]
        second: dict[str, Any] = {}

        def save_two() -> None:
            second.update(
                write_program("BP", "HELLO", "CRT 'TWO'", expected_hash=current, confirm=True)
            )

        worker = threading.Thread(target=save_two)

        def start_the_second_save() -> None:
            worker.start()
            worker.join(timeout=0.1)  # it must wait for this save, not finish beside it

        bp.locked_read_hook = start_the_second_save

        first = write_program("BP", "HELLO", "CRT 'ONE'", expected_hash=current, confirm=True)
        worker.join()

        assert first["status"] == "saved"
        assert second["error"] == (
            "HELLO changed since you read it; read it again with read_program"
        )
        assert stored(bp, "HELLO") == "CRT 'ONE'"


@pytest.fixture
def read_only_manager(
    mock_config_read_only: U2Config, mock_uopy: MockSession
) -> Iterator[ConnectionManager]:
    manager = ConnectionManager(mock_config_read_only)
    server_module._connection_manager = manager
    try:
        yield manager
    finally:
        server_module._connection_manager = None


def test_read_only_mode_refuses_before_anything_else(
    read_only_manager: ConnectionManager, mock_uopy: MockSession
) -> None:
    mock_uopy.add_program_file("BP", {"HELLO": HELLO})

    result = write_program("BP", "HELLO", "END", confirm=True)

    assert result["error"] == "BASIC changes are disabled in read-only mode"
    assert mock_uopy._files["BP"]["HELLO"] == HELLO
    assert "hash" in read_program("BP", "HELLO")  # reading still works
