"""Tests for the record access tools.

These are the tools that touch business data, so they carry the heaviest safety
obligations: read-only mode must hold, writes must be confirmed deliberately,
and MultiValue structure must survive both directions of the trip.
"""

from collections.abc import Iterator

import pytest

from tests.mocks.mock_uopy import MockSession
from u2_mcp.config import U2Config
from u2_mcp.connection import ConnectionManager
from u2_mcp.tools.files import (
    delete_record,
    get_file_info,
    list_files,
    read_record,
    read_records,
    write_record,
)

AM = chr(254)
VM = chr(253)

# A customer with three phone numbers in one field -- the shape that makes
# MultiValue MultiValue.
CUSTOMER_RECORD = "SMITH JOHN" + AM + "555-1234" + VM + "555-9876" + AM + "CA"


@pytest.fixture
def customers(connection_manager: ConnectionManager, mock_uopy: MockSession) -> MockSession:
    """Seed a CUSTOMERS file with one structured record."""
    mock_uopy.add_file("CUSTOMERS", {"AR1042": CUSTOMER_RECORD})
    return mock_uopy


class TestReadingRecords:
    """Reading data out without flattening it."""

    def test_a_record_is_returned_by_id(self, customers: MockSession) -> None:
        """Reading a known key returns that record."""
        result = read_record("CUSTOMERS", "AR1042")

        assert result["id"] == "AR1042"
        assert "error" not in result

    def test_multivalues_come_back_as_a_list(self, customers: MockSession) -> None:
        """Three phone numbers in one field arrive as three list items, not one string."""
        result = read_record("CUSTOMERS", "AR1042")

        assert result["fields"]["2"] == ["555-1234", "555-9876"]

    def test_single_values_stay_scalar(self, customers: MockSession) -> None:
        """A field with one value is a string, not a one-item list."""
        result = read_record("CUSTOMERS", "AR1042")

        assert result["fields"]["1"] == "SMITH JOHN"

    def test_a_missing_record_reports_an_error(self, customers: MockSession) -> None:
        """An unknown key returns an error rather than an empty record."""
        result = read_record("CUSTOMERS", "NOSUCH")

        assert "error" in result

    def test_a_missing_file_reports_an_error(self, customers: MockSession) -> None:
        """A file that will not open reports why."""
        customers.set_missing_file("GHOST")

        result = read_record("GHOST", "AR1042")

        assert "error" in result
        assert result["file"] == "GHOST"


class TestReadingManyRecords:
    """Batch reads report both what was found and what was not."""

    def test_found_records_are_returned(self, customers: MockSession) -> None:
        """Known keys come back as records."""
        result = read_records("CUSTOMERS", ["AR1042"])

        assert result["count"] == 1

    def test_missing_keys_are_reported_individually(self, customers: MockSession) -> None:
        """A key that does not exist is named, rather than silently dropped."""
        result = read_records("CUSTOMERS", ["AR1042", "NOSUCH"])

        assert result["count"] == 1
        assert result["errors"][0]["id"] == "NOSUCH"

    def test_a_batch_over_the_limit_is_refused(
        self, customers: MockSession, connection_manager: ConnectionManager
    ) -> None:
        """Asking for more records than the configured cap is refused up front."""
        too_many = [f"ID{n}" for n in range(connection_manager.config.max_records + 1)]

        result = read_records("CUSTOMERS", too_many)

        assert "error" in result


class TestWriteSafety:
    """Writes must be deliberate, and must not happen at all in read-only mode."""

    def test_a_write_without_confirmation_does_nothing(self, customers: MockSession) -> None:
        """An unconfirmed write asks for confirmation instead of writing."""
        result = write_record("CUSTOMERS", "NEW01", {"1": "TEST"})

        assert result["status"] == "confirmation_required"

    def test_an_unconfirmed_write_leaves_the_data_untouched(self, customers: MockSession) -> None:
        """Nothing reaches the file until confirm is set."""
        write_record("CUSTOMERS", "NEW01", {"1": "TEST"})

        assert "NEW01" not in customers._files["CUSTOMERS"]

    @pytest.mark.parametrize(
        "fields",
        [{"0": "NEW"}, {"-1": "NEW"}, {"01": "NEW"}, {"1": "NEW", "02": "X"}, {"A": "NEW"}],
    )
    def test_a_bad_field_number_is_refused_before_writing(
        self, customers: MockSession, fields: dict[str, str]
    ) -> None:
        """Field numbers start at 1 and are written plainly; anything else would drop data."""
        result = write_record("CUSTOMERS", "AR1042", fields, confirm=True)

        assert "error" in result
        assert customers._files["CUSTOMERS"]["AR1042"] == CUSTOMER_RECORD

    def test_a_confirmed_write_stores_the_record(self, customers: MockSession) -> None:
        """With confirmation, the record is written."""
        result = write_record("CUSTOMERS", "NEW01", {"1": "TEST"}, confirm=True)

        assert result["status"] == "success"
        assert "NEW01" in customers._files["CUSTOMERS"]

    def test_multivalues_survive_the_round_trip(self, customers: MockSession) -> None:
        """A list written as multivalues reads back as the same list."""
        write_record("CUSTOMERS", "NEW02", {"1": "ACME", "2": ["a@x.com", "b@x.com"]}, confirm=True)

        assert read_record("CUSTOMERS", "NEW02")["fields"]["2"] == ["a@x.com", "b@x.com"]

    def test_an_unconfirmed_delete_does_nothing(self, customers: MockSession) -> None:
        """A delete also requires explicit confirmation."""
        result = delete_record("CUSTOMERS", "AR1042")

        assert result["status"] == "confirmation_required"
        assert "AR1042" in customers._files["CUSTOMERS"]

    def test_a_confirmed_delete_removes_the_record(self, customers: MockSession) -> None:
        """With confirmation, the record is deleted."""
        result = delete_record("CUSTOMERS", "AR1042", confirm=True)

        assert result["status"] == "deleted"
        assert "AR1042" not in customers._files["CUSTOMERS"]


class TestReadOnlyMode:
    """Read-only mode is the safe setting for a pilot, so it must genuinely hold."""

    @pytest.fixture
    def read_only_manager(
        self, mock_config_read_only: U2Config, mock_uopy: MockSession
    ) -> Iterator[ConnectionManager]:
        """Install a read-only connection manager as the server's global."""
        import u2_mcp.server as server_module

        manager = ConnectionManager(mock_config_read_only)
        server_module._connection_manager = manager
        mock_uopy.add_file("CUSTOMERS", {"AR1042": CUSTOMER_RECORD})
        try:
            yield manager
        finally:
            server_module._connection_manager = None

    def test_writes_are_refused(self, read_only_manager: ConnectionManager) -> None:
        """A confirmed write is still refused when the server is read-only."""
        result = write_record("CUSTOMERS", "NEW01", {"1": "TEST"}, confirm=True)

        assert "error" in result

    def test_a_refused_write_changes_nothing(
        self, read_only_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """Read-only means the data is untouched, not merely that an error is returned."""
        write_record("CUSTOMERS", "NEW01", {"1": "TEST"}, confirm=True)

        assert "NEW01" not in mock_uopy._files["CUSTOMERS"]

    def test_deletes_are_refused(self, read_only_manager: ConnectionManager) -> None:
        """A confirmed delete is refused when the server is read-only."""
        result = delete_record("CUSTOMERS", "AR1042", confirm=True)

        assert "error" in result

    def test_a_refused_delete_leaves_the_record(
        self, read_only_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """The record survives a delete attempt in read-only mode."""
        delete_record("CUSTOMERS", "AR1042", confirm=True)

        assert "AR1042" in mock_uopy._files["CUSTOMERS"]

    def test_reads_still_work(self, read_only_manager: ConnectionManager) -> None:
        """Read-only blocks writing, not reading."""
        assert read_record("CUSTOMERS", "AR1042")["id"] == "AR1042"


class TestFileDiscovery:
    """Finding out what is on the server."""

    def test_files_are_listed(self, customers: MockSession) -> None:
        """The names come from a select list of VOC's file entries, not a printout."""
        customers.set_select_list(["CUSTOMERS", "ORDERS"])

        result = list_files()

        assert result["files"] == ["CUSTOMERS", "ORDERS"]
        assert result["count"] == 2
        assert customers.executed_commands[0].startswith("SSELECT VOC")

    def test_a_pattern_returns_the_selected_file_names(self, customers: MockSession) -> None:
        """SELECT prints only a count; the names are in the select list."""
        customers.set_command_responses({"SELECT VOC": "2 records selected to list 0."})
        customers.set_select_list(["CUSTOMERS", "CUSTOMER.HISTORY"])

        result = list_files("CUST*")

        assert result["files"] == ["CUSTOMERS", "CUSTOMER.HISTORY"]
        assert result["count"] == 2

    def test_file_statistics_are_returned(self, customers: MockSession) -> None:
        """File information comes back without error."""
        result = get_file_info("CUSTOMERS")

        assert "error" not in result
        assert result["record_count"] == 500


# What UniVerse prints for FILE.STAT: labels and values separated by "=".
UNIVERSE_FILE_STAT = """File name                               = CUSTOMERS
File type                               = 18
Number of groups in file (modulo)       = 101
Separation                              = 4
Number of records                       = 2412
Number of physical bytes                = 413696
Average number of records per group     = 23.8812
"""


class TestFileStatistics:
    @pytest.mark.parametrize(
        ("output", "return_code"),
        [
            ('Illegal option found on command line: "MCP.MISSING".', 0),
            ("Cannot open file MCP.MISSING.", 0),
            ("Cannot open file MCP.MISSING.", -1),
            (UNIVERSE_FILE_STAT, -1),
            ("", 0),
        ],
    )
    def test_failed_file_stat_returns_error_not_empty_metadata(
        self,
        customers: MockSession,
        output: str,
        return_code: int,
    ) -> None:
        customers.set_command_responses({"FILE.STAT": output})
        customers.return_code = return_code

        result = get_file_info("MCP.MISSING")

        assert result == {
            "error": output.strip() or "FILE.STAT returned no recognized statistics",
            "file": "MCP.MISSING",
        }

    @pytest.mark.parametrize(
        "output",
        [
            "File type: 18\nRecord count: 0",
            "File type = 18\nNumber of records = 0\nSeparation = 4",
            "Number of records = 0",
        ],
    )
    def test_optional_missing_statistics_are_not_command_failures(
        self,
        customers: MockSession,
        output: str,
    ) -> None:
        customers.set_command_responses({"FILE.STAT": output})

        result = get_file_info("CUSTOMERS")

        assert "error" not in result
        assert result["record_count"] == 0
        assert result["modulo"] is None
        assert result["raw_output"] == output

    def test_universe_file_stat_is_parsed(self, customers: MockSession) -> None:
        """Type, modulo, separation and record count come back as numbers."""
        customers.set_command_responses({"FILE.STAT": UNIVERSE_FILE_STAT})

        result = get_file_info("CUSTOMERS")

        assert (result["type"], result["modulo"], result["separation"]) == (18, 101, 4)
        assert result["record_count"] == 2412
