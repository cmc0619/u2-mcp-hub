"""Exports account for every record asked for.

An export that quietly drops a record reads exactly like a complete one, so each
requested id is exported, reported missing, or reported as failed with a reason.
"""

import json

from tests.mocks.mock_uopy import MockSession
from u2_mcp.connection import ConnectionManager
from u2_mcp.tools.files import export_to_csv, export_to_json

AM = chr(254)


def _seed(session: MockSession) -> None:
    session._files["CUSTOMERS"] = {"C1": f"Alice{AM}0", "C2": f"Bob{AM}5", "EMPTY": ""}


class TestCompleteExports:
    def test_every_record_found_is_complete(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        _seed(mock_uopy)

        result = export_to_json("CUSTOMERS", ["C1", "C2"])

        assert result["status"] == "success"
        assert result["is_complete"] is True
        assert result["record_count"] == 2

    def test_an_empty_record_is_exported_not_dropped(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """An empty record exists; it is not the same as a missing one."""
        _seed(mock_uopy)

        result = export_to_json("CUSTOMERS", ["EMPTY"])

        assert result["is_complete"] is True
        assert [row["id"] for row in json.loads(result["data"])] == ["EMPTY"]


class TestPartialExports:
    def test_a_missing_record_is_named(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        _seed(mock_uopy)

        result = export_to_csv("CUSTOMERS", ["C1", "NOPE"])

        assert result["status"] == "partial"
        assert result["is_complete"] is False
        assert result["missing_ids"] == ["NOPE"]
        assert result["record_count"] == 1

    def test_an_unreadable_record_is_named_with_the_reason(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        _seed(mock_uopy)
        handle = connection_manager.open_file("CUSTOMERS")
        real_read = handle.read

        def read(record_id: str, lock_flag: int = 0) -> str:
            if record_id == "C2":
                raise RuntimeError("network dropped")
            return real_read(record_id, lock_flag)

        handle.read = read

        result = export_to_json("CUSTOMERS", ["C1", "C2"])

        assert result["status"] == "partial"
        assert result["failed_ids"] == {"C2": "network dropped"}
        assert result["record_count"] == 1
