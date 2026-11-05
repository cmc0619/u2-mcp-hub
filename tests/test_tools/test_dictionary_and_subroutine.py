"""Tests for schema discovery and BASIC subroutine calls.

Discovery is how the AI learns a file's field names before it guesses at them,
and subroutines are how it reuses business logic that already exists. Both need
to behave predictably when the server answers with something unexpected.
"""

from collections.abc import Iterator

import pytest

from tests.mocks.mock_uopy import MockSession, UOError
from u2_mcp.config import U2Config
from u2_mcp.connection import ConnectionManager
from u2_mcp.tools.dictionary import (
    describe_file,
    get_account_info,
    get_field_definition,
    list_dictionary,
)
from u2_mcp.tools.subroutine import call_subroutine, list_catalog

AM = chr(254)

# A D-type dictionary item, in Universe's field order:
# 1 type, 2 field number, 3 conversion, 4 heading, 5 format, 6 single/multi.
NAME_FIELD = "D" + AM + "1" + AM + "" + AM + "Customer Name" + AM + "30L" + AM + "S"
STATE_FIELD = "D" + AM + "4" + AM + "" + AM + "State" + AM + "2L" + AM + "S"


def seed_dictionary(session: MockSession) -> None:
    """Give CUSTOMERS a dictionary with two data fields."""
    session.add_file("DICT CUSTOMERS", {"NAME": NAME_FIELD, "STATE": STATE_FIELD})
    session.select_from_files = True


class TestDictionaryListing:
    """Reading a file's field definitions."""

    def test_dictionary_items_are_listed(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """The file's dictionary items come back by name."""
        seed_dictionary(mock_uopy)

        result = list_dictionary("CUSTOMERS")

        names = [item["name"] for item in result["dictionary_items"]]
        assert "NAME" in names
        assert "STATE" in names

    def test_field_numbers_are_reported(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """A data field reports which attribute of the record it reads."""
        seed_dictionary(mock_uopy)

        result = list_dictionary("CUSTOMERS")
        name_item = next(item for item in result["dictionary_items"] if item["name"] == "NAME")

        assert name_item["field_number"] == "1"
        assert name_item["heading"] == "Customer Name"

    def test_a_single_field_definition_is_returned(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """One named field can be looked up on its own."""
        seed_dictionary(mock_uopy)

        result = get_field_definition("CUSTOMERS", "NAME")

        assert "error" not in result
        assert result["name"] == "NAME"
        assert result["type"] == "D"
        assert result["field_number"] == "1"

    @pytest.mark.parametrize(
        ("record", "expected"),
        [
            # An I-type item's field 2 is its expression, not a field number.
            ("I" + AM + "QTY*PRICE" + AM + "MD2", {"expression": "QTY*PRICE", "conversion": "MD2"}),
            ("X", {"description": "Reserved field position"}),
        ],
    )
    def test_other_item_types_report_their_own_fields(
        self,
        connection_manager: ConnectionManager,
        mock_uopy: MockSession,
        record: str,
        expected: dict[str, str],
    ) -> None:
        mock_uopy.add_file("DICT CUSTOMERS", {"ITEM": record})

        result = get_field_definition("CUSTOMERS", "ITEM")

        assert result["type"] == record.split(AM)[0]
        assert {key: result[key] for key in expected} == expected

    def test_an_unknown_field_reports_an_error(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """Asking for a field that is not in the dictionary reports an error."""
        seed_dictionary(mock_uopy)

        assert "error" in get_field_definition("CUSTOMERS", "NOSUCH")

    def test_describe_file_summarises_the_structure(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """A high-level description names the file and its fields."""
        seed_dictionary(mock_uopy)

        result = describe_file("CUSTOMERS")

        assert result["file"] == "CUSTOMERS"
        assert "error" not in result
        assert result["data_field_count"] == 2

    def test_a_type_with_a_description_is_still_its_type(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """Field 1 may carry a description after the type code: "D Customer name"."""
        mock_uopy.add_file("DICT CUSTOMERS", {"NAME": "D Customer name" + AM + "1"})

        result = get_field_definition("CUSTOMERS", "NAME")

        assert result["type"] == "D"
        assert result["description"] == "Customer name"
        assert result["field_number"] == "1"


class TestAccountInfo:
    def test_files_come_from_the_select_list(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """The file names are VOC keys, not words cut from a LISTFILES printout."""
        mock_uopy.set_select_list(["CUSTOMERS", "ORDERS"])

        result = get_account_info()

        assert result["files"] == ["CUSTOMERS", "ORDERS"]
        assert not any(c.startswith("LISTFILES") for c in mock_uopy.executed_commands)


class TestSubroutineCalls:
    """Running cataloged BASIC programs."""

    def test_arguments_are_returned_after_the_call(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """Output arguments come back to the caller."""
        result = call_subroutine("GET.CUSTOMER", ["AR1042"])

        assert result["status"] == "success"
        assert result["args_out"] == ["RESULT:AR1042"]

    def test_the_subroutine_receives_its_arguments(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """What was passed in is what the program was called with."""
        call_subroutine("GET.CUSTOMER", ["AR1042"])

        assert mock_uopy.called_subroutines == [("GET.CUSTOMER", ["AR1042"])]

    def test_output_only_arguments_are_padded(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """A program with output slots is called with all of them present."""
        result = call_subroutine("GET.CUSTOMER", ["AR1042"], num_args=3)

        assert result["num_args"] == 3
        assert len(result["args_out"]) == 3

    def test_too_few_slots_for_the_arguments_is_refused(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """Declaring fewer arguments than are supplied is refused before the call."""
        result = call_subroutine("GET.CUSTOMER", ["a", "b", "c"], num_args=2)

        assert "error" in result
        assert mock_uopy.called_subroutines == []

    def test_a_failing_subroutine_reports_the_error(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """A program that fails on the server surfaces as an error, not a crash."""
        mock_uopy.subroutine_error = UOError(message="Program not cataloged")

        result = call_subroutine("MISSING.PROGRAM", ["x"])

        assert "error" in result

    def test_the_catalog_can_be_listed(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """Available cataloged programs are discoverable."""
        mock_uopy.set_command_responses({"MAP": MAP_OUTPUT})

        result = list_catalog()

        assert result["programs"] == [
            "*GET.CUSTOMER",
            "*CALC.ORDER.TOTAL",
            "*CUST.REPORT",
            "-LEGACY.CUST",  # global names may also begin with -, $ or !
        ]


MAP_OUTPUT = """Catalog Name                 Type  Who     Date
---------------------------- ----  ------  ---------
*GET.CUSTOMER                B     dev     01 NOV 26
*CALC.ORDER.TOTAL            B     dev     01 NOV 26
*CUST.REPORT                 B     dev     02 NOV 26
-LEGACY.CUST                 B     dev     03 NOV 26

3 entries in the catalog.
"""


class TestListCatalogIsReadOnly:
    """Issue #16: listing the catalog inspects it; it never runs CATALOG or a program."""

    def test_only_map_runs(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        mock_uopy.set_command_responses({"MAP": MAP_OUTPUT})

        list_catalog("*CUST*")

        assert mock_uopy.executed_commands == ["MAP"]
        assert not any("CATALOG" in c.upper() for c in mock_uopy.executed_commands)
        assert mock_uopy.called_subroutines == []

    def test_the_pattern_is_matched_here(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        mock_uopy.set_command_responses({"MAP": MAP_OUTPUT})

        result = list_catalog("*CUST*")

        assert result["programs"] == ["*GET.CUSTOMER", "*CUST.REPORT", "-LEGACY.CUST"]
        assert result["count"] == 3

    def test_unidata_is_refused_without_running_anything(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        connection_manager.config.service = "udcs"

        result = list_catalog()

        assert "UniData" in result["error"]
        assert mock_uopy.executed_commands == []

    def test_a_rejected_map_reports_the_servers_message(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        mock_uopy.set_command_responses({"MAP": "MAP: not allowed"})
        mock_uopy.return_code = -1

        result = list_catalog()

        assert result["error"] == "MAP: not allowed"

    def test_listing_is_inspection_and_calling_is_not(self) -> None:
        from u2_mcp.permissions import TOOL_PERMISSIONS, is_write

        assert TOOL_PERMISSIONS["list_catalog"] == "schema.read"
        assert not is_write(TOOL_PERMISSIONS["list_catalog"])
        assert TOOL_PERMISSIONS["call_subroutine"] == "subroutine.call"
        assert TOOL_PERMISSIONS["catalog_program"] == "basic.catalog"


class TestSubroutinesAreRefusedInReadOnlyMode:
    """Read-only has to cover the tool that can do anything.

    A cataloged subroutine is arbitrary BASIC. It can WRITE, DELETE, CLEARFILE or
    shell out, and the server sees only its name -- there is no way to tell a
    reporting routine from a destructive one before calling it.

    Every other write path checked `read_only` and this one did not, so read-only
    mode disabled the tools that announce themselves as writes while leaving open
    the one that could do anything without saying so. The documentation said
    read-only "prevents all write operations" throughout.
    """

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

    def test_a_subroutine_call_is_refused(self, read_only_manager: ConnectionManager) -> None:
        result = call_subroutine("ANY.SUBROUTINE", ["x"])

        assert "error" in result

    def test_the_refusal_says_why(self, read_only_manager: ConnectionManager) -> None:
        # Whoever hits this needs to know it is a policy and not a fault, or they
        # will go looking for a subroutine that does not exist.
        result = call_subroutine("ANY.SUBROUTINE", ["x"])

        assert "read-only" in result["error"].lower()

    def test_the_subroutine_is_never_reached(
        self, read_only_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """Refused before the call, not after it.

        A subroutine that ran and then had its result discarded would have
        already done whatever it does.
        """
        call_subroutine("ANY.SUBROUTINE", ["x"])

        assert mock_uopy.called_subroutines == []
