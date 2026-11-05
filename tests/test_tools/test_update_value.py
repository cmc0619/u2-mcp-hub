"""Changing one value without moving the ones beside it.

The tool exists because `write_record` cannot make this guarantee. Handing the
server a whole rebuilt record puts responsibility for the record's shape on
whoever assembled it, and in a MultiValue file the shape is load-bearing:
position n of a set of parallel fields describes one branch, so a field that
comes back a different length has moved a quantity onto a different branch.

Nothing catches that. The record stays well formed, no constraint is broken, and
no later read can tell. So these tests are mostly about what the tool refuses.
"""

from __future__ import annotations

from typing import Any

import pytest

from u2_mcp.tools.update import update_value
from u2_mcp.utils.record_lock import LOCK_EXCLUSIVE, write_guard

AM = chr(254)
VM = chr(253)


class _UOError(Exception):
    """Stands in for uopy.UOError, which carries a status code."""

    def __init__(self, code: int) -> None:
        super().__init__(f"status {code}")
        self.code = code


class _Handle:
    """A file shaped like uopy's: read with a lock flag, write, unlock."""

    def __init__(self, record: str, read_error: int | None = None) -> None:
        self.record = record
        self.read_error = read_error
        self.read_flags: list[int] = []
        self.writes: list[str] = []
        self.unlocks = 0
        self.manager: Any = None
        self.guard_held_during_write: bool | None = None

    def read(self, record_id: str, lock_flag: int = 0) -> str:
        self.read_flags.append(lock_flag)
        if self.read_error is not None:
            raise _UOError(self.read_error)
        return self.record

    def write(self, record_id: str, record: str, lock_flag: int = 0) -> None:
        self.guard_held_during_write = write_guard(self.manager).locked()
        self.writes.append(record)
        self.record = record

    def unlock(self, record_id: str, clear_flag: bool = False) -> None:
        self.unlocks += 1


class _Manager:
    """Answers the one open the tool makes."""

    def __init__(self, handle: Any, read_only: bool = False) -> None:
        self._handle = handle
        handle.manager = self
        self.config = type("Config", (), {"read_only": read_only})()

    def open_file(self, file_name: str) -> Any:
        return self._handle


def _use(monkeypatch: pytest.MonkeyPatch, handle: _Handle, read_only: bool = False) -> None:
    manager = _Manager(handle, read_only=read_only)
    monkeypatch.setattr("u2_mcp.tools.update.get_connection_manager", lambda: manager)


@pytest.fixture
def inventory(monkeypatch: pytest.MonkeyPatch) -> _Handle:
    """Four branches, with bins recorded for only the first two."""
    record = AM.join(
        [
            VM.join(["AUR", "LKW", "BOU", "DEN"]),
            VM.join(["10", "20", "30", "40"]),
            VM.join(["1", "2", "3", "4"]),
            VM.join(["A-1", "B-2"]),
        ]
    )
    handle = _Handle(record)
    _use(monkeypatch, handle)
    return handle


class TestItRefusesBeforeItActs:
    def test_a_write_needs_confirmation(self, inventory: _Handle) -> None:
        result = update_value("INVENTORY", "P-1", 2, 0, "99")

        assert result["status"] == "confirmation_required"
        assert inventory.writes == []

    def test_read_only_mode_refuses_even_with_confirmation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        handle = _Handle("a")
        _use(monkeypatch, handle, read_only=True)

        result = update_value("INVENTORY", "P-1", 2, 0, "99", confirm=True)

        assert "read-only" in result["error"]
        assert handle.writes == []

    def test_an_index_past_the_end_is_refused_not_padded(self, inventory: _Handle) -> None:
        # Bins exist for two branches. Writing a third would invent a position,
        # which is a claim about a branch nobody made.
        result = update_value("INVENTORY", "P-1", 4, 2, "C-3", confirm=True)

        assert "does not exist" in result["error"]
        assert inventory.writes == []

    def test_a_field_past_the_end_is_refused(self, inventory: _Handle) -> None:
        result = update_value("INVENTORY", "P-1", 5, 0, "x", confirm=True)

        assert "Field 5 does not exist" in result["error"]
        assert inventory.writes == []

    def test_a_missing_record_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        handle = _Handle("", read_error=30001)
        _use(monkeypatch, handle)

        result = update_value("INVENTORY", "P-9", 1, 0, "x", confirm=True)

        assert "does not exist" in result["error"]
        assert handle.writes == []

    def test_a_record_locked_by_someone_else_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        handle = _Handle("a", read_error=30002)
        _use(monkeypatch, handle)

        result = update_value("INVENTORY", "P-1", 1, 0, "x", confirm=True)

        assert "locked by another user" in result["error"]
        assert handle.writes == []


class TestItChangesUnderTheRecordLock:
    def test_the_read_takes_the_lock_without_waiting(self, inventory: _Handle) -> None:
        update_value("INVENTORY", "P-1", 2, 0, "99", confirm=True)

        assert inventory.read_flags == [LOCK_EXCLUSIVE]

    def test_the_lock_is_released_after_a_change(self, inventory: _Handle) -> None:
        update_value("INVENTORY", "P-1", 2, 0, "99", confirm=True)

        assert inventory.unlocks == 1

    def test_the_lock_is_released_after_a_refusal(self, inventory: _Handle) -> None:
        update_value("INVENTORY", "P-1", 4, 9, "x", confirm=True)

        assert inventory.unlocks == 1

    def test_calls_on_one_session_take_turns(self, inventory: _Handle) -> None:
        # The record lock belongs to the session, so it cannot keep apart two
        # calls on the same connection; the per-manager guard does.
        update_value("INVENTORY", "P-1", 2, 0, "99", confirm=True)

        assert inventory.guard_held_during_write is True


class TestItRefusesMarksInTheValue:
    @pytest.mark.parametrize("mark", [chr(code) for code in range(251, 256)])
    def test_a_value_carrying_a_mark_is_refused_before_anything_is_read(
        self, inventory: _Handle, mark: str
    ) -> None:
        # A mark in the value would add a field, value or subvalue: a new position.
        result = update_value("INVENTORY", "P-1", 2, 0, "99" + mark + "100", confirm=True)

        assert "mark" in result["error"]
        assert inventory.writes == []
        assert inventory.read_flags == []


class TestItChangesOnlyThatValue:
    def test_the_change_is_written(self, inventory: _Handle) -> None:
        result = update_value("INVENTORY", "P-1", 2, 0, "555", confirm=True)

        assert inventory.writes == [result["after"]]
        assert result["after"].split(AM)[1].split(VM)[0] == "555"
        assert result["before"] != result["after"]

    def test_a_short_field_stays_short(self, inventory: _Handle) -> None:
        # Bins are recorded for two of four branches, and that is legitimate.
        result = update_value("INVENTORY", "P-1", 4, 1, "B-9", confirm=True)

        assert result["after"].split(AM)[3].split(VM) == ["A-1", "B-9"]
        assert [field.split(VM) for field in result["after"].split(AM)[:3]] == [
            field.split(VM) for field in result["before"].split(AM)[:3]
        ]
