"""Query execution tools for u2-mcp."""

import logging
import re
from typing import Any

from ..guard import guarded
from ..server import get_connection_manager, mcp
from ..utils.safety import ALLOWED_QUERY_COMMANDS, CommandValidator

logger = logging.getLogger(__name__)

# A real SAMPLE clause is the word followed by a count, not the word in a name.
_SAMPLE_CLAUSE = re.compile(r"(?<![\w.])SAMPLE\s+(\d+)", re.IGNORECASE)
_AGGREGATE_CLAUSE = re.compile(
    r"(?<![\w.])(?:BREAK\.ON|GRAND\.TOTAL|TOTAL)(?![\w.])", re.IGNORECASE
)
# DET.SUP suppresses the detail lines, so the report prints only its totals.
_DETAIL_SUPPRESSED = re.compile(r"(?<![\w.])DET\.SUP(?![\w.])", re.IGNORECASE)
# The verb, an optional DICT, and the file name.
_VERB_AND_FILE = re.compile(r"\s*\S+\s+(?:DICT\s+)?\S+", re.IGNORECASE)

# RetrieVe string literals: "...", '...' and \...\. Text inside them is data.
_LITERAL = re.compile(r"\"[^\"]*\"|'[^']*'|\\[^\\]*\\")

# Verbs whose ordinary output is one row per record.
_ROW_VERBS = ("LIST", "SORT")

# Verbs that leave an active select list on the session.
_SELECT_VERBS = ("SELECT", "SSELECT", "QSELECT", "GET.LIST", "SEARCH")


def _cap_rows(query: str, limit: int) -> tuple[str, bool, bool, bool]:
    """Keep a LIST or SORT within limit rows.

    Returns:
        The query to run; whether this server capped it (a SAMPLE added, or the
        caller's own lowered to the limit); whether the caller wrote a SAMPLE; and
        whether the report has totals, which a cap then computes over the sample.

    A report with DET.SUP prints only its totals, so it runs whole. TOTAL and
    BREAK.ON alone still print a line per record and are capped like any LIST.
    Text inside string literals is ignored, so a value such as "SAMPLE 5" in a
    WITH clause cannot pass for a clause.
    """
    words = query.split(maxsplit=1)
    if not words or not words[0].upper().startswith(_ROW_VERBS):
        return query, False, False, False

    # Blank out literals, keeping every offset, then look for clauses outside them.
    # Not upper-cased first: "ß" becomes "SS", which would shift every offset.
    masked = _LITERAL.sub(lambda match: " " * len(match.group()), query)
    # Options follow the verb and the file name: a file called DET.SUP is not one.
    head = _VERB_AND_FILE.match(masked)
    options = masked[head.end() :] if head else ""
    aggregate = bool(_AGGREGATE_CLAUSE.search(options))
    clauses = list(_SAMPLE_CLAUSE.finditer(masked))
    if _DETAIL_SUPPRESSED.search(options):
        # Totals only: no rows to cap, but the caller's own SAMPLE still limits them.
        return query, False, bool(clauses), aggregate

    if not clauses:
        return f"{query} SAMPLE {limit}", True, False, aggregate

    capped = False
    for clause in reversed(clauses):
        if int(clause.group(1)) > limit:
            start, end = clause.span(1)
            query = query[:start] + str(limit) + query[end:]
            capped = True
    return query, capped, True, aggregate


@mcp.tool()
@guarded()
def execute_query(
    query: str, max_rows: int | None = None, connection: str | None = None
) -> dict[str, Any]:
    """Execute a RetrieVe/UniQuery statement and return results.

    Supports read-only query commands: LIST, SORT, SELECT, SSELECT, COUNT, SUM,
    SEARCH, QSELECT and GET.LIST. LIST and SORT are limited to max_rows rows (or
    U2_MAX_RECORDS): a SAMPLE is added, or a larger SAMPLE lowered. A report with
    DET.SUP prints only its totals and runs over every record; TOTAL or BREAK.ON
    without DET.SUP is capped, and its totals then cover only the sample.
    SELECT, SSELECT, QSELECT, GET.LIST and SEARCH return only their messages and
    their select list is cleared; use get_select_list for record IDs. A SELECT
    here never restricts a later call, so a SELECT-then-LIST pair must be one
    statement (LIST FILE WITH ...). A SELECT run through execute_tcl is not
    cleared.

    Example: execute_query('SELECT CUSTOMERS WITH STATE = "CA"') returns
    output such as "42 record(s) selected to SELECT list #0.".

    Args:
        query: RetrieVe/UniQuery statement
               Examples:
               - 'LIST CUSTOMERS WITH STATE = "CA"'
               - 'SELECT ORDERS WITH ORDER.DATE >= "01/01/2024" BY ORDER.DATE'
               - 'COUNT INVOICES WITH STATUS = "OPEN"'
        max_rows: Positive row limit for LIST/SORT, at most U2_MAX_RECORDS.
            Omitted or None uses U2_MAX_RECORDS; zero/negative values are rejected.
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        Dictionary containing query, executed_query (the actual command), output,
        status ("error" when the server rejected the statement; output then holds
        its message), and max_rows (the limit, when this server capped the query;
        otherwise None). `is_complete` is None when a cap makes completeness
        unknown, and False when the caller's own SAMPLE ran or the server
        rejected the statement. A capped or sampled answer carries a `warning`.
    """
    if max_rows is not None and max_rows <= 0:
        return {"error": "max_rows must be a positive integer", "query": query}

    manager = get_connection_manager()
    config = manager.config

    # Validate query safety
    validator = CommandValidator(config.blocked_commands, config.read_only)
    is_safe, error_msg = validator.is_query_safe(query)

    if not is_safe:
        return {"error": error_msg, "query": query}

    # Apply row limit
    effective_max = min(config.max_records if max_rows is None else max_rows, config.max_records)

    try:
        # U2_MAX_RECORDS holds for every LIST and SORT, whatever SAMPLE the caller wrote.
        modified_query, capped, has_explicit_sample, has_totals = _cap_rows(query, effective_max)
        first_word = query.split(maxsplit=1)[0].upper() if query.split() else ""
        # A select list left active would quietly restrict the next query on the session.
        if first_word in _SELECT_VERBS:
            output, return_code = manager.run_select_command(modified_query)
        else:
            output, return_code = manager.run_command(modified_query)

        succeeded = return_code >= 0
        result: dict[str, Any] = {
            "query": query,
            "executed_query": modified_query,
            "output": output,
            # The output holds the server's own message when it rejected the query.
            "status": "success" if succeeded else "error",
            "max_rows": effective_max if succeeded and capped else None,
            "is_complete": (
                False
                if not succeeded or (has_explicit_sample and not capped)
                else None
                if capped
                else True
            ),
        }

        if succeeded and capped:
            result["warning"] = (
                f"A server-imposed SAMPLE {effective_max} was applied; the response may "
                "omit matching rows, but completeness is unknown. Narrow the selection "
                "criteria, or raise max_rows up to U2_MAX_RECORDS."
            )
            if has_totals:
                result["warning"] += (
                    " The totals cover only the sampled records; add DET.SUP to get "
                    "totals over every record without the detail lines."
                )
        elif succeeded and has_explicit_sample:
            result["warning"] = (
                "The query includes its own SAMPLE clause, so matching rows may be "
                "omitted by design."
            )

        return result

    except Exception as e:
        logger.error(f"Error executing query: {e}")
        return {"error": str(e), "query": query}


@mcp.tool()
@guarded()
def execute_tcl(command: str, connection: str | None = None) -> dict[str, Any]:
    """Execute a TCL/ECL command and return the output.

    TCL (Terminal Control Language) commands provide system-level operations.
    Dangerous commands are blocked by the safety validator. Some commands
    are disabled in read-only mode.

    Args:
        command: TCL/ECL command to execute
                 Examples:
                 - 'WHO' - Show current user info
                 - 'DATE' - Show current date
                 - 'LISTFILES' - List available files
                 - 'FILE.STAT CUSTOMERS' - Show file statistics
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        Dictionary containing command, output, and status.
        Returns error if command is blocked.
    """
    manager = get_connection_manager()
    config = manager.config

    # Validate command safety
    validator = CommandValidator(config.blocked_commands, config.read_only)
    is_valid, error_msg = validator.validate(command)

    if not is_valid:
        return {"error": error_msg, "command": command}

    try:
        output = manager.execute_command(command)

        return {
            "command": command,
            "output": output,
            "status": "success",
        }

    except Exception as e:
        logger.error(f"Error executing TCL command: {e}")
        return {"error": str(e), "command": command}


@mcp.tool()
@guarded()
def get_select_list(
    query: str, max_ids: int | None = None, connection: str | None = None
) -> dict[str, Any]:
    """Execute a SELECT statement and return the list of record IDs.

    This is useful for getting a list of matching records for further processing,
    without retrieving the full record data.

    Args:
        query: SELECT or SSELECT statement
               Example: 'SELECT CUSTOMERS WITH STATE = "CA"'
        max_ids: Positive maximum IDs to return. Omitted or None uses U2_MAX_RECORDS;
            zero/negative values are rejected before execution.
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        Dictionary containing query, list of record IDs, count, whether results
        were truncated, and is_complete. The selection is cleared before the
        tool returns, so it never carries over to a later call.

    Example: get_select_list('SELECT CUSTOMERS WITH STATE = "CA"', max_ids=100)
    returns up to 100 IDs; truncated is true when more matched.
    """
    if max_ids is not None and max_ids <= 0:
        return {"error": "max_ids must be a positive integer", "query": query}

    manager = get_connection_manager()
    config = manager.config

    # Validate query starts with SELECT or SSELECT
    query_upper = query.upper().strip()
    first_word = query_upper.split()[0] if query_upper else ""

    if first_word not in ("SELECT", "SSELECT"):
        return {"error": "Query must start with SELECT or SSELECT", "query": query}

    effective_max = min(config.max_records if max_ids is None else max_ids, config.max_records)

    try:
        record_ids, complete = manager.select_ids(query, effective_max)
        truncated = not complete

        result: dict[str, Any] = {
            "query": query,
            "record_ids": record_ids,
            "count": len(record_ids),
            "truncated": truncated,
            "is_complete": not truncated,
            "max_ids": effective_max,
        }

        if truncated:
            result["warning"] = (
                f"More records matched than the {effective_max} returned here. This is a "
                "partial list; narrow the selection criteria for a complete answer."
            )

        return result

    except Exception as e:
        logger.error(f"Error executing select: {e}")
        return {"error": str(e), "query": query}


# =============================================================================
# Phase 3: AI-Optimized Query Validation
# =============================================================================


@mcp.tool()
@guarded()
def validate_query(query: str, connection: str | None = None) -> dict[str, Any]:
    """Validate a RetrieVe/UniQuery statement before execution.

    Checks locally whether the statement is allowed to be attempted by
    execute_query. It does not validate server syntax or schema, so an accepted
    statement can still be rejected by the server.

    Args:
        query: Query statement to validate
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        Dictionary containing validation results:
        - valid: Whether the statement is allowed to be attempted
        - command: The query command detected (LIST, SELECT, etc.)
        - warnings: List of potential issues
        - suggestions: Helpful hints for common patterns
    """
    manager = get_connection_manager()
    config = manager.config

    result: dict[str, Any] = {
        "query": query,
        "valid": False,
        "command": None,
        "warnings": [],
        "suggestions": [],
        "error": None,
    }

    if not query or not query.strip():
        result["error"] = "Query cannot be empty"
        return result

    query_upper = query.upper().strip()
    parts = query_upper.split()
    first_word = parts[0] if parts else ""

    result["command"] = first_word

    # Check if command is allowed
    if first_word not in ALLOWED_QUERY_COMMANDS:
        result["error"] = (
            f"Command '{first_word}' not allowed. Use: LIST, SELECT, SORT, COUNT, etc."
        )
        return result

    # Validate with safety checks
    validator = CommandValidator(config.blocked_commands, config.read_only)
    is_safe, error_msg = validator.is_query_safe(query)

    if not is_safe:
        result["error"] = error_msg
        return result

    # Basic syntax validation
    warnings = []
    suggestions = []

    # Check for file name after command
    if len(parts) < 2:
        result["error"] = f"{first_word} requires a file name"
        return result

    file_name = parts[1]
    result["file"] = file_name

    # Check for common issues - proper quoting of string values
    if "WITH" in query_upper and "= " in query and '"' not in query and "'" not in query:
        warnings.append("String values should be quoted with double quotes")
        suggestions.append('Example: WITH STATE = "CA" (not WITH STATE = CA)')

    # Check for BY clause
    if first_word in ("LIST", "SELECT") and "BY" not in query_upper:
        suggestions.append("Consider adding BY clause for sorted results: ... BY field_name")

    # Check for potential multivalue explosion
    if "BY.EXP" not in query_upper and "BY-EXP" not in query_upper and first_word == "LIST":
        suggestions.append("Use BY.EXP to explode multivalues: ... BY.EXP mv_field")

    result["valid"] = True
    result["warnings"] = warnings
    result["suggestions"] = suggestions

    return result
