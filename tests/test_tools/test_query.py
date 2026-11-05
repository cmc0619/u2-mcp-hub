"""Tests for the query execution tools.

These exercise the tool functions the AI client actually calls, through the real
connection manager and against the mock uopy layer.
"""

import threading
from collections.abc import Callable
from typing import Any
from unittest.mock import patch

import pytest

from tests.mocks.mock_uopy import MockSession
from u2_mcp.connection import ConnectionManager
from u2_mcp.tools.basic import _select_ids
from u2_mcp.tools.query import execute_query, execute_tcl, get_select_list, validate_query


class TestQuerySafety:
    """Only read-only query verbs may reach the database."""

    def test_allowed_verb_runs(self, connection_manager: ConnectionManager) -> None:
        """A COUNT query is permitted and reaches the server."""
        result = execute_query('COUNT CUSTOMERS WITH STATE = "CA"')

        assert result["status"] == "success"
        assert "error" not in result

    def test_a_query_the_server_rejects_is_not_a_success(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """RetrieVe reports a failed statement with a negative @SYSTEM.RETURN.CODE."""
        mock_uopy.set_command_responses({"LIST": "Syntax error in RetrieVe statement"})
        mock_uopy.return_code = -1

        result = execute_query("LIST CUSTOMERS WITH WITH")

        assert result["status"] == "error"
        assert "Syntax error" in result["output"]

    def test_a_count_reports_no_row_limit(self, connection_manager: ConnectionManager) -> None:
        """COUNT is not capped, so no max_rows is claimed for it."""
        result = execute_query("COUNT CUSTOMERS", max_rows=3)

        assert result["max_rows"] is None
        assert result["executed_query"] == "COUNT CUSTOMERS"

    def test_write_verb_is_refused(self, connection_manager: ConnectionManager) -> None:
        """A DELETE statement is refused before it reaches the database."""
        result = execute_query("DELETE CUSTOMERS AR1042")

        assert "error" in result

    def test_refused_query_never_reaches_the_server(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """A refused query executes nothing at all."""
        execute_query("DELETE CUSTOMERS AR1042")

        assert mock_uopy.executed_commands == []

    def test_blocked_tcl_command_is_refused(self, connection_manager: ConnectionManager) -> None:
        """A destructive TCL command is blocked by the validator."""
        result = execute_tcl("DELETE.FILE CUSTOMERS")

        assert "error" in result

    def test_blocked_tcl_command_never_reaches_the_server(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """A blocked TCL command executes nothing at all."""
        execute_tcl("CLEAR.FILE CUSTOMERS")

        assert mock_uopy.executed_commands == []


class TestPositiveLimits:
    @pytest.mark.parametrize(
        ("tool", "argument", "query"),
        [
            (execute_query, "max_rows", "LIST CUSTOMERS"),
            (execute_query, "max_rows", "COUNT CUSTOMERS"),
            (get_select_list, "max_ids", "SELECT CUSTOMERS"),
        ],
    )
    @pytest.mark.parametrize("limit", [0, -1])
    def test_nonpositive_limit_never_executes_a_query(
        self,
        connection_manager: ConnectionManager,
        mock_uopy: MockSession,
        tool: Callable[..., dict[str, Any]],
        argument: str,
        query: str,
        limit: int,
    ) -> None:
        result = tool(query, **{argument: limit})

        assert result == {"error": f"{argument} must be a positive integer", "query": query}
        assert mock_uopy.executed_commands == []

    @pytest.mark.parametrize(
        ("tool", "argument", "query"),
        [
            (execute_query, "max_rows", "LIST CUSTOMERS"),
            (get_select_list, "max_ids", "SELECT CUSTOMERS"),
        ],
    )
    @pytest.mark.parametrize(("provided", "limit"), [(False, None), (True, None), (True, 1)])
    def test_omitted_null_and_one_have_explicit_limit_semantics(
        self,
        connection_manager: ConnectionManager,
        mock_uopy: MockSession,
        tool: Callable[..., dict[str, Any]],
        argument: str,
        query: str,
        provided: bool,
        limit: int | None,
    ) -> None:
        mock_uopy.set_select_list(["ID001"])
        result = tool(query, **({argument: limit} if provided else {}))

        assert "error" not in result
        assert result[argument] == (connection_manager.config.max_records if limit is None else 1)

    @pytest.mark.parametrize("count", [0, 1, 2])
    def test_select_list_one_exact_and_over_limit(
        self,
        connection_manager: ConnectionManager,
        mock_uopy: MockSession,
        count: int,
    ) -> None:
        ids = [f"ID{n}" for n in range(count)]
        mock_uopy.set_select_list(ids)

        result = get_select_list("SELECT CUSTOMERS", max_ids=1)

        assert result["record_ids"] == ids[:1]
        assert result["count"] == min(count, 1)
        assert result["truncated"] == (count > 1)
        assert result["is_complete"] == (count <= 1)
        assert ("warning" in result) == (count > 1)


class TestResultCompleteness:
    """A partial answer must never be presented as a complete one."""

    @pytest.mark.parametrize(
        "query",
        [
            "COUNT CUSTOMERS",
            "SUM CUSTOMERS BALANCE",
            "SELECT CUSTOMERS",
            "SSELECT CUSTOMERS",
        ],
    )
    def test_unchanged_commands_report_the_actual_query(
        self,
        connection_manager: ConnectionManager,
        mock_uopy: MockSession,
        query: str,
    ) -> None:
        result = execute_query(query, max_rows=1)

        assert result["executed_query"] == query == mock_uopy.executed_commands[0]
        assert result["max_rows"] is None
        assert result["status"] == "success"
        assert result["is_complete"] is True

    @pytest.mark.parametrize(
        "query",
        [
            "COUNT CUSTOMERS",
            "SUM CUSTOMERS BALANCE",
            "SELECT CUSTOMERS",
            "LIST CUSTOMERS",
            "SORT CUSTOMERS",
            "LIST CUSTOMERS SAMPLE 1",
        ],
    )
    def test_server_rejection_does_not_claim_completeness_or_sampling(
        self,
        connection_manager: ConnectionManager,
        mock_uopy: MockSession,
        query: str,
    ) -> None:
        mock_uopy.set_command_responses({query: "Syntax error in RetrieVe statement"})
        mock_uopy.return_code = -1

        result = execute_query(query, max_rows=1)

        assert result["status"] == "error"
        assert result["output"] == "Syntax error in RetrieVe statement"
        assert result["executed_query"] == mock_uopy.executed_commands[0]
        assert result["is_complete"] is False
        assert result["max_rows"] is None
        assert "warning" not in result

    def test_successful_zero_match_count_is_complete(
        self,
        connection_manager: ConnectionManager,
        mock_uopy: MockSession,
    ) -> None:
        mock_uopy.set_command_responses({"COUNT": "0 records counted."})

        result = execute_query("COUNT CUSTOMERS", max_rows=1)

        assert result["status"] == "success"
        assert result["executed_query"] == "COUNT CUSTOMERS"
        assert result["output"] == "0 records counted."
        assert result["is_complete"] is True
        assert result["max_rows"] is None
        assert "warning" not in result

    @pytest.mark.parametrize("record_count", [1, 3, 4])
    def test_server_sample_does_not_claim_that_rows_were_omitted(
        self,
        connection_manager: ConnectionManager,
        mock_uopy: MockSession,
        record_count: int,
    ) -> None:
        """A server-imposed SAMPLE reports unknown completeness at all result sizes."""
        mock_uopy.set_command_responses({"LIST CUSTOMERS": f"{record_count} records listed."})

        result = execute_query("LIST CUSTOMERS", max_rows=3)

        assert result["executed_query"] == "LIST CUSTOMERS SAMPLE 3"
        assert result["is_complete"] is None
        assert result["max_rows"] == 3
        assert "completeness is unknown" in result["warning"]
        assert "Results were limited" not in result["warning"]

    def test_count_query_is_not_marked_incomplete(
        self, connection_manager: ConnectionManager
    ) -> None:
        """A COUNT returns a single figure, so nothing was truncated."""
        result = execute_query('COUNT CUSTOMERS WITH STATE = "CA"')

        assert result["is_complete"] is True

    def test_caller_sample_within_the_limit_is_respected(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """A SAMPLE within the limit runs as written and is not reported as a cap."""
        result = execute_query("LIST CUSTOMERS SAMPLE 3", max_rows=5)

        assert mock_uopy.executed_commands[0] == "LIST CUSTOMERS SAMPLE 3"
        assert result["is_complete"] is False
        assert result["max_rows"] is None
        assert "its own SAMPLE" in result["warning"]

    def test_a_caller_sample_above_the_limit_is_lowered(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """Writing a large SAMPLE is not a way around U2_MAX_RECORDS."""
        result = execute_query("LIST CUSTOMERS SAMPLE 1000000", max_rows=10)

        assert mock_uopy.executed_commands[0] == "LIST CUSTOMERS SAMPLE 10"
        assert result["max_rows"] == 10
        assert result["is_complete"] is None
        assert "completeness is unknown" in result["warning"]

    def test_sort_is_capped_like_list(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """SORT gets the same server cap and unknown-completeness warning as LIST."""
        result = execute_query("SORT CUSTOMERS BY NAME", max_rows=10)

        assert mock_uopy.executed_commands[0] == "SORT CUSTOMERS BY NAME SAMPLE 10"
        assert result["is_complete"] is None

    def test_quoted_sample_is_data_not_a_clause(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """A value that reads "SAMPLE 5" leaves the row cap in place."""
        result = execute_query('LIST NOTES WITH TEXT = "SAMPLE 5"', max_rows=10)

        assert mock_uopy.executed_commands[0] == 'LIST NOTES WITH TEXT = "SAMPLE 5" SAMPLE 10'
        assert result["is_complete"] is None

    def test_explicit_sample_with_a_quoted_value_is_preserved_verbatim(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """A quoted value beside an explicit SAMPLE is not rewritten."""
        execute_query('LIST CUST WITH CITY = "Straße" SAMPLE 5000', max_rows=100)

        assert mock_uopy.executed_commands[0] == 'LIST CUST WITH CITY = "Straße" SAMPLE 100'

    def test_a_field_ending_in_sample_is_not_a_clause(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """LOT.SAMPLE 5 is a field and a value, so the cap is still added."""
        result = execute_query("LIST LOTS WITH LOT.SAMPLE 5", max_rows=10)

        assert mock_uopy.executed_commands[0] == "LIST LOTS WITH LOT.SAMPLE 5 SAMPLE 10"
        assert result["is_complete"] is None

    def test_quoted_sample_beside_an_explicit_sample_is_preserved(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """Only the real clause is lowered; the quoted value is left as it was."""
        execute_query("LIST NOTES WITH TEXT = 'SAMPLE 99' SAMPLE 50", max_rows=10)

        assert mock_uopy.executed_commands[0] == "LIST NOTES WITH TEXT = 'SAMPLE 99' SAMPLE 10"

    def test_list_dict_is_capped(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """Dictionary listings retain the ordinary row cap."""
        result = execute_query("LIST DICT CUSTOMERS", max_rows=3)

        assert mock_uopy.executed_commands[0] == "LIST DICT CUSTOMERS SAMPLE 3"
        assert result["is_complete"] is None

    def test_a_totals_report_with_its_detail_lines_is_capped(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """TOTAL still prints a line per record, so it is capped, and says what that does."""
        query = "LIST CUSTOMERS BY STATE BREAK.ON STATE TOTAL BALANCE"

        result = execute_query(query, max_rows=3)

        assert mock_uopy.executed_commands[0] == query + " SAMPLE 3"
        assert result["max_rows"] == 3
        assert result["is_complete"] is None
        assert "DET.SUP" in result["warning"]

    @pytest.mark.parametrize("query", ["LIST ORDERS TOTAL", "LIST ORDERS TOTAL AMOUNT"])
    def test_a_field_named_total_does_not_lift_the_cap(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession, query: str
    ) -> None:
        execute_query(query, max_rows=3)

        assert mock_uopy.executed_commands[0] == query + " SAMPLE 3"

    def test_a_totals_only_report_runs_over_every_record(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """DET.SUP prints only the totals, so a sample would only make them wrong."""
        query = "LIST CUSTOMERS BY STATE BREAK.ON STATE TOTAL BALANCE DET.SUP"

        result = execute_query(query, max_rows=3)

        assert mock_uopy.executed_commands[0] == query
        assert result["max_rows"] is None
        assert result["is_complete"] is True
        assert "warning" not in result

    def test_det_sup_does_not_keep_a_large_caller_sample(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """A totals-only report runs as written, SAMPLE included: it prints no rows."""
        query = "LIST CUSTOMERS TOTAL BALANCE DET.SUP SAMPLE 50"

        result = execute_query(query, max_rows=3)

        assert mock_uopy.executed_commands[0] == query
        # The totals cover only the caller's sample, so they are not complete.
        assert result["is_complete"] is False
        assert "its own SAMPLE" in result["warning"]

    @pytest.mark.parametrize("query", ["LIST DET.SUP", "LIST DICT DET.SUP", "SORT DET.SUP BY X"])
    def test_a_file_named_det_sup_is_still_capped(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession, query: str
    ) -> None:
        """Only an option after the file name suppresses the detail lines."""
        execute_query(query, max_rows=3)

        assert mock_uopy.executed_commands[0] == query + " SAMPLE 3"

    @pytest.mark.parametrize("query", ["QSELECT CUSTOMERS 1", "GET.LIST SAVED", "SEARCH CUSTOMERS"])
    def test_other_select_verbs_clear_their_list(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession, query: str
    ) -> None:
        """A list left active would restrict the next query on this session."""
        execute_query(query)

        assert mock_uopy.executed_commands == [query, "CLEARSELECT"]

    def test_select_list_reports_truncation(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """A select list cut short at the cap says so, and says it in words."""
        mock_uopy.set_select_list([f"ID{n:03d}" for n in range(50)])

        result = get_select_list("SELECT CUSTOMERS", max_ids=10)

        assert result["truncated"] is True
        assert result["is_complete"] is False
        assert len(result["record_ids"]) == 10

    def test_complete_select_list_is_marked_complete(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """A select list that fit under the cap is reported as complete."""
        mock_uopy.set_select_list(["ID001", "ID002"])

        result = get_select_list("SELECT CUSTOMERS", max_ids=10)

        assert result["truncated"] is False
        assert result["is_complete"] is True
        assert mock_uopy.executed_commands[-1] == "CLEARSELECT"

    @pytest.mark.parametrize("verb", ["SELECT", "SSELECT"])
    def test_execute_query_clears_selection_before_next_query(
        self,
        connection_manager: ConnectionManager,
        mock_uopy: MockSession,
        verb: str,
    ) -> None:
        """An execute_query selection cannot change a later independent query."""
        mock_uopy.select_list = ["ID001", "ID002"]

        selected = execute_query(f"{verb} CUSTOMERS")
        counted = execute_query("COUNT CUSTOMERS")

        assert selected["status"] == "success"
        assert selected["output"] == "3 records selected to list 0."
        assert counted["output"] == "5 records counted."
        assert mock_uopy.executed_commands[:3] == [
            f"{verb} CUSTOMERS",
            "CLEARSELECT",
            "COUNT CUSTOMERS",
        ]

    def test_failed_select_list_read_is_cleared_and_keeps_its_error(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """A list-read failure is reported while leaving the session reusable."""

        class FailedSelectList:
            def next(self) -> None:
                raise RuntimeError("select list read failed")

        connection_manager.create_select_list = lambda: FailedSelectList()  # type: ignore[method-assign]

        result = get_select_list("SELECT CUSTOMERS")
        counted = execute_query("COUNT CUSTOMERS")

        assert result["error"] == "select list read failed"
        assert mock_uopy.executed_commands[-2:] == ["CLEARSELECT", "COUNT CUSTOMERS"]
        assert counted["status"] == "success"

    def test_rejected_select_preserves_diagnostic_and_clears_state(
        self,
        connection_manager: ConnectionManager,
        mock_uopy: MockSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A rejected SELECT's original diagnostic survives successful cleanup."""
        connection_manager.connect()
        original_run_command = connection_manager.run_command

        def reject_select(command_text: str, timeout: float | None = None) -> tuple[str, int]:
            if command_text == "SELECT MISSING.FILE":
                return "File MISSING.FILE not found", -1
            return original_run_command(command_text, timeout)

        monkeypatch.setattr(connection_manager, "run_command", reject_select)

        result = get_select_list("SELECT MISSING.FILE")
        counted = execute_query("COUNT CUSTOMERS")

        assert result["error"] == "File MISSING.FILE not found"
        assert mock_uopy.executed_commands[-2:] == ["CLEARSELECT", "COUNT CUSTOMERS"]
        assert counted["status"] == "success"

    def test_uncleanable_selection_disconnects_before_next_query(
        self,
        connection_manager: ConnectionManager,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A session is not reused when CLEARSELECT itself fails."""
        original_run_command = connection_manager.run_command

        def fail_clear(command_text: str, timeout: float | None = None) -> tuple[str, int]:
            if command_text == "CLEARSELECT":
                raise RuntimeError("clear failed")
            return original_run_command(command_text, timeout)

        monkeypatch.setattr(connection_manager, "run_command", fail_clear)

        result = execute_query("SELECT CUSTOMERS")
        assert connection_manager._session is None

        counted = execute_query("COUNT CUSTOMERS")

        assert result["error"] == "clear failed"
        assert connection_manager._session is not None
        assert counted["status"] == "success"

    @pytest.mark.parametrize("tool", ["get_select_list", "execute_query"])
    def test_a_failed_clear_that_loses_a_transaction_is_an_error(
        self,
        connection_manager: ConnectionManager,
        mock_uopy: MockSession,
        monkeypatch: pytest.MonkeyPatch,
        tool: str,
    ) -> None:
        """Dropping the session rolls back pending writes; a read must not report success."""
        mock_uopy.set_select_list(["A", "B"])
        connection_manager.begin_transaction()
        original_run_command = connection_manager.run_command

        def fail_clear(command_text: str, timeout: float | None = None) -> tuple[str, int]:
            if command_text == "CLEARSELECT":
                raise RuntimeError("clear failed")
            return original_run_command(command_text, timeout)

        monkeypatch.setattr(connection_manager, "run_command", fail_clear)

        if tool == "get_select_list":
            result = get_select_list("SELECT CUSTOMERS")
        else:
            result = execute_query("QSELECT CUSTOMERS 1")

        assert "rolled back" in result["error"]
        assert not connection_manager.in_transaction


def _hold_the_gap_open(
    manager: ConnectionManager, first: Callable[[], Any], second: Callable[[], Any]
) -> tuple[Any, Any, bool]:
    """Pause the first call between its SELECT and its select list; run the second.

    Returns:
        Both results, and whether the second call had to wait for the first
    """
    in_gap, release = threading.Event(), threading.Event()
    original = manager.create_select_list
    paused: list[bool] = []

    def create_select_list() -> Any:
        if not paused:
            paused.append(True)
            in_gap.set()
            release.wait(timeout=5)
        return original()

    manager.create_select_list = create_select_list  # type: ignore[method-assign]
    results: dict[str, Any] = {}
    a = threading.Thread(target=lambda: results.update(first=first()))
    b = threading.Thread(target=lambda: results.update(second=second()))
    a.start()
    assert in_gap.wait(timeout=5), "the first call never reached its select list"
    b.start()
    b.join(timeout=0.3)
    second_waited = b.is_alive()
    release.set()
    a.join(timeout=5)
    b.join(timeout=5)
    return results.get("first"), results.get("second"), second_waited


class TestASelectOwnsTheSessionUntilItsListIsRead:
    """The active select list belongs to the session, so another SELECT replaces it."""

    @pytest.fixture
    def two_files(self, mock_uopy: MockSession) -> None:
        mock_uopy.select_from_files = True
        mock_uopy.add_file("A", {"A1": "x"})
        mock_uopy.add_file("B", {"B1": "y"})

    def test_get_select_list_returns_only_its_own_ids(
        self, connection_manager: ConnectionManager, two_files: None
    ) -> None:
        first, second, second_waited = _hold_the_gap_open(
            connection_manager,
            lambda: get_select_list("SELECT A"),
            lambda: get_select_list("SELECT B"),
        )

        assert first["record_ids"] == ["A1"]
        assert second["record_ids"] == ["B1"]
        assert second_waited

    def test_basic_selection_returns_only_its_own_ids(
        self, connection_manager: ConnectionManager, two_files: None
    ) -> None:
        first, second, second_waited = _hold_the_gap_open(
            connection_manager,
            lambda: _select_ids(connection_manager, "A"),
            lambda: _select_ids(connection_manager, "B"),
        )

        assert first == (["A1"], True)
        assert second == (["B1"], True)
        assert second_waited

    def test_a_session_replaced_in_the_gap_is_an_error_not_an_empty_list(
        self, connection_manager: ConnectionManager, two_files: None
    ) -> None:
        original = connection_manager.create_select_list

        def disconnect_first() -> Any:
            connection_manager.disconnect()  # as an admin eviction does, off the lock
            return original()

        connection_manager.create_select_list = disconnect_first  # type: ignore[method-assign]
        connection_manager.connect()

        with patch("uopy.connect", return_value=MockSession()):
            result = get_select_list("SELECT A")

        assert "replaced" in result["error"]

    def test_a_list_cut_short_is_cleared(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        mock_uopy.select_from_files = True
        mock_uopy.add_file("C", {f"C{n}": "x" for n in range(5)})

        result = get_select_list("SELECT C", max_ids=2)

        assert result["truncated"] is True
        assert mock_uopy.executed_commands[-1] == "CLEARSELECT"

    def test_a_select_that_times_out_clears_nothing_on_a_new_session(
        self,
        connection_manager: ConnectionManager,
        mock_uopy: MockSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_uopy.command_delay_seconds = 0.5
        monkeypatch.setattr(connection_manager.config, "query_timeout", 0.1)

        result = get_select_list("SELECT C")

        assert "timeout" in result["error"]
        assert "CLEARSELECT" not in mock_uopy.executed_commands


class TestQueryValidation:
    """Dry-running a query before it executes."""

    def test_valid_query_passes(self, connection_manager: ConnectionManager) -> None:
        """A well-formed LIST validates cleanly."""
        result = validate_query('LIST CUSTOMERS NAME WITH STATE = "CA"')

        assert result["valid"] is True

    def test_validation_executes_nothing(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        """Validating a query does not run it."""
        validate_query('LIST CUSTOMERS WITH STATE = "CA"')

        assert mock_uopy.executed_commands == []

    def test_explicit_output_field_does_not_trigger_output_field_hint(
        self, connection_manager: ConnectionManager
    ) -> None:
        """Local validation does not guess whether a LIST output field was supplied."""
        result = validate_query('LIST CUSTOMER WITH ENTITY.TYPE.1 = "1" ENTITY.TYPE')

        assert result["valid"] is True
        assert all("specifying output fields" not in hint for hint in result["suggestions"])

    def test_disallowed_verb_fails_validation(self, connection_manager: ConnectionManager) -> None:
        """A write verb is rejected by validation with an explanation."""
        result = validate_query("DELETE CUSTOMERS")

        assert result["valid"] is False
        assert result["error"]


class TestACommandThatStopsAtAPrompt:
    """Issue #26: a SELECT that stops to ask for input must not bury its own message.

    uopy leaves such a command waiting (EXEC_REPLY), and the session then refuses
    every other call with "[30114] An Execute is currently active on the server".
    """

    def test_get_select_list_returns_the_servers_message(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        mock_uopy.prompting_commands = {"SELECT MISSING.FILE"}
        mock_uopy.set_command_responses({"SELECT MISSING.FILE": "MISSING.FILE is not a file name."})

        result = get_select_list("SELECT MISSING.FILE", max_ids=2)

        assert "MISSING.FILE is not a file name." in result["error"]
        assert "30114" not in result["error"]
        assert mock_uopy.cancelled_commands == ["SELECT MISSING.FILE"]

    def test_the_next_query_runs_without_a_reconnect(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        mock_uopy.prompting_commands = {"SELECT MISSING.FILE"}
        get_select_list("SELECT MISSING.FILE", max_ids=2)
        session = connection_manager._session

        counted = execute_query("COUNT VOC")

        assert counted["status"] == "success"
        assert connection_manager._session is session

    def test_execute_query_reports_a_prompt_as_an_error(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        mock_uopy.prompting_commands = {"LIST NOFILE"}
        mock_uopy.set_command_responses({"LIST NOFILE": "Enter file name:"})

        result = execute_query("LIST NOFILE")

        assert result["status"] == "error"
        assert "Enter file name:" in result["output"]
        assert "asked for input" in result["output"] or "ask for input" in result["output"]
