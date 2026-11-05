"""Listing, reading and searching BASIC source, on both products."""

from collections.abc import Callable
from typing import Any

import pytest

from tests.mocks.mock_uopy import MockFile, MockSession, UOError
from u2_mcp.connection import ConnectionManager
from u2_mcp.tools import basic
from u2_mcp.tools.basic import list_programs, read_program, search_programs
from u2_mcp.utils.basic_source import AM, record_hash

HELLO = AM.join(["* says hello", "CRT 'HELLO'", "END"])
ORDERS = AM.join(["SUBROUTINE ORD.POST(ID)", "OPEN 'ORDERS' TO F ELSE STOP", "RETURN"])


def seed(session: MockSession) -> None:
    session.add_program_file("BP", {"HELLO": HELLO, "ORD.POST": ORDERS, "ORD.VOID": "RETURN"})


class TestListPrograms:
    def test_universe_lists_programs_and_marks_compiled_from_bp_o(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        seed(mock_uopy)
        mock_uopy.add_file("BP.O", {"HELLO": "object code"})

        result = list_programs("BP")

        assert result["programs"] == [
            {"name": "HELLO", "compiled": True},
            {"name": "ORD.POST", "compiled": False},
            {"name": "ORD.VOID", "compiled": False},
        ]
        assert (result["count"], result["total_matching"], result["truncated"]) == (3, 3, False)
        assert "SSELECT BP" in mock_uopy.executed_commands

    def test_universe_without_an_object_file_reports_compiled_unknown(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        seed(mock_uopy)
        mock_uopy.set_missing_file("BP.O")

        result = list_programs("BP")

        assert {p["compiled"] for p in result["programs"]} == {None}

    def test_unidata_hides_object_records_and_uses_them(
        self, make_manager: Callable[..., ConnectionManager], mock_uopy: MockSession
    ) -> None:
        make_manager(U2_SERVICE="udcs")
        mock_uopy.add_program_file("BP", {"HELLO": HELLO, "_HELLO": "obj", "OTHER": "END"})

        result = list_programs("BP")

        assert result["programs"] == [
            {"name": "HELLO", "compiled": True},
            {"name": "OTHER", "compiled": False},
        ]

    def test_the_pattern_is_applied_here_and_never_sent_to_the_server(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        seed(mock_uopy)

        result = list_programs("BP", pattern="ORD.*")

        assert [p["name"] for p in result["programs"]] == ["ORD.POST", "ORD.VOID"]
        assert not any("ORD" in command for command in mock_uopy.executed_commands)

    def test_a_cut_list_says_so(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        seed(mock_uopy)

        result = list_programs("BP", max_results=1)

        assert (result["count"], result["total_matching"], result["truncated"]) == (1, 3, True)
        assert "partial list" in result["warning"]

    @pytest.mark.parametrize(
        ("file_name", "pattern", "message"),
        [
            ("CUSTOMERS", "*", "CUSTOMERS is not a BASIC program file on this server."),
            ("BP.O", "*", "BP.O holds object code, not source"),
            ("BP", 'X" Y', "pattern may contain only letters"),
        ],
    )
    def test_refusals_come_before_any_command(
        self,
        connection_manager: ConnectionManager,
        mock_uopy: MockSession,
        file_name: str,
        pattern: str,
        message: str,
    ) -> None:
        result = list_programs(file_name, pattern=pattern)

        assert result["error"].startswith(message)
        assert mock_uopy.executed_commands == []

    def test_a_custom_setting_admits_another_file(
        self, make_manager: Callable[..., ConnectionManager], mock_uopy: MockSession
    ) -> None:
        make_manager(U2_BASIC_FILES="SRC")
        mock_uopy.add_program_file("SRC", {"A": "END"})

        assert [p["name"] for p in list_programs("SRC")["programs"]] == ["A"]
        assert "error" in list_programs("BP")


class TestReadProgram:
    def test_returns_numbered_lines_and_the_hash_of_the_record(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        seed(mock_uopy)

        result = read_program("BP", "HELLO")

        assert result["numbered_source"] == "    1  * says hello\n    2  CRT 'HELLO'\n    3  END"
        assert result["hash"] == record_hash(HELLO)
        assert (result["line_count"], result["start_line"], result["end_line"]) == (3, 1, 3)
        assert result["truncated"] is False
        assert "source" not in result

    def test_unnumbered_returns_the_exact_text(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        seed(mock_uopy)

        result = read_program("BP", "HELLO", numbered=False)

        assert result["source"] == "* says hello\nCRT 'HELLO'\nEND"
        assert "numbered_source" not in result

    def test_a_page_is_marked_and_the_hash_still_covers_the_whole_record(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        seed(mock_uopy)

        result = read_program("BP", "HELLO", start_line=2, max_lines=1)

        assert result["numbered_source"] == "    2  CRT 'HELLO'"
        assert (result["end_line"], result["truncated"], result["next_start_line"]) == (2, True, 3)
        assert result["hash"] == record_hash(HELLO)

    def test_a_missing_program_is_reported(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        seed(mock_uopy)

        assert read_program("BP", "NOPE")["error"] == "NOPE not found in BP"

    def test_unidata_object_records_cannot_be_read(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        assert read_program("BP", "_HELLO")["error"].startswith("program must be 1-64")

    def test_a_data_file_cannot_be_read_through_basic_read(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        mock_uopy.add_file("CUSTOMERS", {"1": "SMITH"})

        assert "not a BASIC program file" in read_program("CUSTOMERS", "1")["error"]


class TestSearchPrograms:
    def test_finds_lines_case_insensitively_by_default(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        seed(mock_uopy)

        result = search_programs("BP", "open 'orders'")

        assert result["matches"] == [
            {"program": "ORD.POST", "line": 2, "text": "OPEN 'ORDERS' TO F ELSE STOP"}
        ]
        assert (result["programs_scanned"], result["stopped_because"]) == (3, None)
        assert result["truncated"] is False

    def test_case_sensitive_search(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        seed(mock_uopy)

        assert search_programs("BP", "return", case_sensitive=True)["match_count"] == 0
        assert search_programs("BP", "RETURN", case_sensitive=True)["match_count"] == 2

    def test_text_is_literal_not_a_regex(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        mock_uopy.add_program_file("BP", {"A": "X = Y.*Z", "B": "X = YabcZ"})

        assert [m["program"] for m in search_programs("BP", "Y.*Z")["matches"]] == ["A"]

    def test_stops_at_max_matches_and_says_why(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        seed(mock_uopy)

        result = search_programs("BP", "R", max_matches=2)

        assert (result["match_count"], result["stopped_because"]) == (2, "max_matches")
        assert result["truncated"] is True

    def test_stops_at_max_programs_and_says_why(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        seed(mock_uopy)

        result = search_programs("BP", "NOTHING", max_programs=2)

        assert (result["programs_scanned"], result["stopped_because"]) == (2, "max_programs")

    def test_long_lines_are_trimmed_in_matches(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        mock_uopy.add_program_file("BP", {"A": "CRT '" + "X" * 1000 + "'"})

        assert len(search_programs("BP", "CRT")["matches"][0]["text"]) == 300

    @pytest.mark.parametrize("text", ["", "X" * 201])
    def test_text_length_is_bounded(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession, text: str
    ) -> None:
        assert search_programs("BP", text)["error"] == "text must be 1-200 characters"


class TestBounds:
    def test_a_search_that_outruns_its_time_budget_stops_and_says_so(
        self,
        connection_manager: ConnectionManager,
        mock_uopy: MockSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        seed(mock_uopy)
        monkeypatch.setattr(basic, "MAX_SEARCH_SECONDS", 0)

        result = search_programs("BP", "CRT")

        assert (result["stopped_because"], result["truncated"]) == ("time", True)
        assert result["programs_scanned"] == 0

    def test_the_query_timeout_lowers_the_search_budget(
        self, make_manager: Callable[..., ConnectionManager], mock_uopy: MockSession
    ) -> None:
        manager = make_manager(U2_QUERY_TIMEOUT="7")

        assert basic._search_seconds(manager) == 7

    def test_exactly_the_cap_of_ids_is_complete_and_clears_the_select_list(
        self,
        connection_manager: ConnectionManager,
        mock_uopy: MockSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        seed(mock_uopy)
        monkeypatch.setattr(basic, "SELECT_READ_LIMIT", 3)

        result = list_programs("BP")

        assert (result["total_matching"], result["truncated"]) == (3, False)
        assert mock_uopy.executed_commands.count("CLEARSELECT") == 2
        assert mock_uopy.executed_commands[-1] == "CLEARSELECT"

    def test_one_id_over_the_cap_is_partial_and_clears_the_select_list(
        self,
        connection_manager: ConnectionManager,
        mock_uopy: MockSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_uopy.add_program_file("BP", {"A": "END", "B": "END", "C": "END", "D": "END"})
        monkeypatch.setattr(basic, "SELECT_READ_LIMIT", 3)

        result = list_programs("BP")

        assert (result["total_matching"], result["truncated"]) == (3, True)
        assert "partial list" in result["warning"]
        assert "CLEARSELECT" in mock_uopy.executed_commands

    def test_a_search_over_a_capped_list_says_it_is_partial(
        self,
        connection_manager: ConnectionManager,
        mock_uopy: MockSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Programs past the cap were never searched, so no match is not 'not there'."""
        mock_uopy.add_program_file("BP", {"A": "END", "B": "END", "C": "END", "D": "END"})
        monkeypatch.setattr(basic, "SELECT_READ_LIMIT", 3)

        result = search_programs("BP", "NOWHERE")

        assert result["truncated"] is True
        assert result["stopped_because"] == "max_programs_listed"

    def test_compiled_is_unknown_past_a_capped_object_list(
        self,
        connection_manager: ConnectionManager,
        mock_uopy: MockSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A program missing from a partial BP.O list may still be compiled."""
        mock_uopy.add_program_file("BP", {"A": "END", "B": "END"})
        mock_uopy.add_file("BP.O", {"A": "obj", "X1": "obj", "X2": "obj", "X3": "obj"})
        monkeypatch.setattr(basic, "SELECT_READ_LIMIT", 3)

        compiled = {p["name"]: p["compiled"] for p in list_programs("BP")["programs"]}

        assert compiled == {"A": True, "B": None}

    def test_reading_past_the_end_keeps_end_line_within_line_count(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        seed(mock_uopy)

        result = read_program("BP", "HELLO", start_line=50)

        assert (result["line_count"], result["end_line"], result["truncated"]) == (3, 3, False)

    def test_a_start_past_the_end_is_an_empty_range_with_a_note(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        seed(mock_uopy)

        result = read_program("BP", "HELLO", start_line=50, numbered=False)

        assert result["source"] == ""
        assert result["note"] == "start_line 50 is past the end: the program has 3 lines"
        assert "note" not in read_program("BP", "HELLO")


class TestUnexpectedErrors:
    @pytest.fixture
    def broken_reads(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def read(self: Any, record_id: str, lock_flag: int = 0) -> str:
            raise UOError(99, "device not found")

        monkeypatch.setattr(MockFile, "read", read)

    def test_a_read_failure_that_only_mentions_not_found_is_not_a_missing_program(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession, broken_reads: None
    ) -> None:
        seed(mock_uopy)

        assert read_program("BP", "HELLO")["error"] == "device not found"

    def test_search_reports_a_failing_read_instead_of_counting_it_unreadable(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession, broken_reads: None
    ) -> None:
        seed(mock_uopy)

        result = search_programs("BP", "CRT")

        assert result["error"] == "device not found"
        assert "matches" not in result

    def test_a_program_deleted_during_a_search_is_counted_unreadable(
        self,
        connection_manager: ConnectionManager,
        mock_uopy: MockSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        seed(mock_uopy)
        listed = (["HELLO", "GONE"], None, True, True)
        monkeypatch.setattr(basic, "_programs", lambda *a, **k: listed)

        result = search_programs("BP", "CRT")

        assert (result["unreadable"], result["match_count"]) == (1, 1)
