"""BASIC program tools: list, read, search, write, compile and catalog source.

Each tool works only on files matching U2_BASIC_FILES, so basic.read and basic.write
never become a second way to read or write ordinary data. Names are checked before
any I/O, and only checked names reach TCL; patterns are applied here, in Python.

Running a program is deliberately not here: call_subroutine and execute_tcl do that
under their own permissions.
"""

from __future__ import annotations

import fnmatch
import logging
import time
from typing import Any

from ..connection import FileNotFoundError
from ..guard import guarded
from ..server import get_connection_manager, mcp
from ..utils.basic_source import (
    PATTERN_PROBLEM,
    PATTERN_RE,
    cap_output,
    catalog_command,
    compile_command,
    name_problem,
    numbered_lines,
    object_file_name,
    parse_compile_output,
    program_file_problem,
    record_hash,
    record_to_lines,
    source_problem,
    source_to_record,
    split_object_ids,
)
from ..utils.record_lock import (
    LOCK_EXCLUSIVE,
    is_locked,
    is_missing,
    record_lock_released,
    write_guard,
)

logger = logging.getLogger(__name__)

MAX_LIST_RESULTS = 5000
SELECT_READ_LIMIT = 50_000
MAX_READ_LINES = 5000
MAX_SEARCH_PROGRAMS = 1000
MAX_SEARCH_MATCHES = 1000
MAX_SEARCH_CHARS = 20_000_000
MAX_SEARCH_SECONDS = 20
MATCH_TEXT_CHARS = 300
READ_ONLY_MESSAGE = "BASIC changes are disabled in read-only mode"


def _clamp(value: int, ceiling: int) -> int:
    """Keep a caller's limit between 1 and the ceiling."""
    return max(1, min(value, ceiling))


def _error(
    message: str, file_name: str, program: str | None = None, **extra: Any
) -> dict[str, Any]:
    """Build a refusal that names what it was about."""
    result: dict[str, Any] = {"error": message, "file_name": file_name}
    if program is not None:
        result["program"] = program
    result.update(extra)
    return result


def _read_problem(manager: Any, file_name: str, program: str | None = None) -> str | None:
    """Return why a read of this file (and program) is refused, or None."""
    problem = program_file_problem(file_name, manager.config.basic_files)
    if problem is None and program is not None:
        problem = name_problem("program", program)
    return problem


def _change_problem(manager: Any, file_name: str, program: str, verb: str | None) -> str | None:
    """Return why a change is refused, or None. Read-only is checked first.

    Args:
        verb: The TCL verb the change runs, refused when the operator listed it in
            U2_BLOCKED_COMMANDS; None for a plain save
    """
    if manager.config.read_only:
        return READ_ONLY_MESSAGE
    problem = _read_problem(manager, file_name, program)
    if problem is None and verb is not None and verb in manager.config.blocked_commands:
        problem = f"{verb} is in U2_BLOCKED_COMMANDS on this server, so this tool is turned off"
    return problem


def _read_raw(handle: Any, program: str, *, lock: bool = False) -> str | None:
    """Return a program's stored record, or None when there is no such record.

    Args:
        lock: Take the exclusive record lock first, without waiting (READU); the
            caller releases it, even when the record is not there
    """
    try:
        raw = handle.read(program, lock_flag=LOCK_EXCLUSIVE) if lock else handle.read(program)
    except Exception as error:
        if not is_locked(error) and is_missing(error):
            return None
        raise
    return None if raw is None else str(raw)


def _select_ids(manager: Any, file_name: str) -> tuple[list[str], bool]:
    """Return a file's record ids (at most SELECT_READ_LIMIT), and whether that is all."""
    ids, complete = manager.select_ids(f"SSELECT {file_name}", SELECT_READ_LIMIT)
    return ids, complete


def _search_seconds(manager: Any) -> float:
    """Return how long one search may run: MAX_SEARCH_SECONDS, or the query timeout if lower."""
    return float(min(MAX_SEARCH_SECONDS, manager.config.query_timeout))


def _universe_objects(manager: Any, file_name: str) -> tuple[set[str] | None, bool]:
    """Return the programs with object code in <file>.O (None when it will not open).

    The flag says whether that is all of them: past the selection limit, a program
    absent from the set may still be compiled.
    """
    object_file = object_file_name(file_name)
    try:
        manager.open_file(object_file)
    except FileNotFoundError:
        return None, True
    ids, complete = _select_ids(manager, object_file)
    return set(ids), complete


def _programs(
    manager: Any, file_name: str, pattern: str, *, with_objects: bool
) -> tuple[list[str], set[str] | None, bool, bool]:
    """Return matching program names, the compiled ones (None = unknown), and whether
    each of those two lists is complete."""
    manager.open_file(file_name)
    ids, complete = _select_ids(manager, file_name)
    names, objects = split_object_ids(manager.config.service, ids)
    objects_complete = complete
    if objects is None and with_objects:
        objects, objects_complete = _universe_objects(manager, file_name)
    chosen = sorted(name for name in names if fnmatch.fnmatchcase(name, pattern))
    return chosen, objects, complete, objects_complete


def _compiled(name: str, objects: set[str] | None, objects_complete: bool) -> bool | None:
    """Return whether a program has object code; None when that cannot be told."""
    if objects is None:
        return None
    if name in objects:
        return True
    return False if objects_complete else None


@mcp.tool()
@guarded()
def list_programs(
    file_name: str = "BP",
    pattern: str = "*",
    max_results: int = 500,
    connection: str | None = None,
) -> dict[str, Any]:
    """List the BASIC programs in a program file, and which have object code.

    Args:
        file_name: A BASIC program file (one matching U2_BASIC_FILES), such as BP
        pattern: Program name pattern; * is the only wildcard
        max_results: How many names to return (at most 5000)
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        programs ({name, compiled}; compiled is null when it cannot be told), count,
        total_matching and truncated.
    """
    manager = get_connection_manager()
    problem = _read_problem(manager, file_name)
    if problem is None and not PATTERN_RE.fullmatch(pattern):
        problem = PATTERN_PROBLEM
    if problem:
        return _error(problem, file_name)
    limit = _clamp(max_results, MAX_LIST_RESULTS)
    try:
        chosen, objects, complete, objects_complete = _programs(
            manager, file_name, pattern, with_objects=True
        )
    except Exception as error:
        logger.error(f"Error listing programs in {file_name}: {error}")
        return _error(str(error), file_name)
    shown = chosen[:limit]
    truncated = len(chosen) > limit or not complete
    result: dict[str, Any] = {
        "file_name": file_name,
        "programs": [
            {"name": name, "compiled": _compiled(name, objects, objects_complete)} for name in shown
        ],
        "count": len(shown),
        "total_matching": len(chosen),
        "truncated": truncated,
    }
    if truncated:
        result["warning"] = (
            "This is a partial list. Narrow the pattern, or raise max_results (at most 5000)."
        )
    return result


@mcp.tool()
@guarded()
def read_program(
    file_name: str,
    program: str,
    start_line: int = 1,
    max_lines: int = 2000,
    numbered: bool = True,
    connection: str | None = None,
) -> dict[str, Any]:
    """Read a BASIC program's source, with line numbers, and its hash.

    Pass the hash to write_program as expected_hash to save a change. It covers the
    whole program even when only some lines are returned.

    Args:
        file_name: A BASIC program file (one matching U2_BASIC_FILES), such as BP
        program: The program's name (its record id)
        start_line: First line to return, counting from one
        max_lines: How many lines to return (at most 5000)
        numbered: True returns numbered_source ("    1  text" per line); False returns
            source, the exact text, for editing and saving back
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        hash, line_count, start_line, end_line, truncated (more lines follow),
        next_start_line when truncated, and numbered_source or source.
    """
    manager = get_connection_manager()
    problem = _read_problem(manager, file_name, program)
    if problem:
        return _error(problem, file_name, program)
    try:
        raw = _read_raw(manager.open_file(file_name), program)
    except Exception as error:
        logger.error(f"Error reading {file_name} {program}: {error}")
        return _error(str(error), file_name, program)
    if raw is None:
        return _error(f"{program} not found in {file_name}", file_name, program)
    lines = record_to_lines(raw)
    start = max(1, start_line)
    chosen = lines[start - 1 : start - 1 + _clamp(max_lines, MAX_READ_LINES)]
    end = min(start - 1 + len(chosen), len(lines))
    result: dict[str, Any] = {
        "file_name": file_name,
        "program": program,
        "hash": record_hash(raw),
        "line_count": len(lines),
        "start_line": start,
        "end_line": end,
        "truncated": end < len(lines),
    }
    if result["truncated"]:
        result["next_start_line"] = end + 1
    if start > len(lines):
        result["note"] = f"start_line {start} is past the end: the program has {len(lines)} lines"
    if numbered:
        result["numbered_source"] = numbered_lines(chosen, start)
    else:
        result["source"] = "\n".join(chosen)
    return result


@mcp.tool()
@guarded()
def search_programs(
    file_name: str,
    text: str,
    pattern: str = "*",
    case_sensitive: bool = False,
    max_programs: int = 200,
    max_matches: int = 100,
    connection: str | None = None,
) -> dict[str, Any]:
    """Find the lines of BASIC source that contain some text (literal, not a regex).

    Args:
        file_name: A BASIC program file (one matching U2_BASIC_FILES), such as BP
        text: The text to find, 1-200 characters
        pattern: Which programs to search; * is the only wildcard
        case_sensitive: Match case exactly (default: ignore case)
        max_programs: How many programs to read at most (at most 1000)
        max_matches: How many matching lines to return at most (at most 1000)
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        matches ({program, line, text}), match_count, programs_scanned,
        programs_matching_pattern, unreadable, truncated, and stopped_because
        (null, "max_matches", "max_programs", "max_bytes" or "time").
    """
    manager = get_connection_manager()
    problem = _read_problem(manager, file_name)
    if problem is None and not PATTERN_RE.fullmatch(pattern):
        problem = PATTERN_PROBLEM
    if problem is None and not 1 <= len(text) <= 200:
        problem = "text must be 1-200 characters"
    if problem:
        return _error(problem, file_name)
    program_limit = _clamp(max_programs, MAX_SEARCH_PROGRAMS)
    match_limit = _clamp(max_matches, MAX_SEARCH_MATCHES)
    needle = text if case_sensitive else text.lower()
    matches: list[dict[str, Any]] = []
    scanned = unreadable = chars = 0
    stopped: str | None = None
    # The time budget covers collecting the program names as well as reading them.
    deadline = time.monotonic() + _search_seconds(manager)
    try:
        names, _objects, complete, _ = _programs(manager, file_name, pattern, with_objects=False)
        handle = manager.open_file(file_name)
        for name in names:
            if time.monotonic() >= deadline:
                stopped = "time"
                break
            if scanned >= program_limit:
                stopped = "max_programs"
                break
            if chars >= MAX_SEARCH_CHARS:
                stopped = "max_bytes"
                break
            scanned += 1
            raw = _read_raw(handle, name)  # a missing record is None; any other failure ends it
            if raw is None:
                unreadable += 1
                continue
            chars += len(raw)
            for number, line in enumerate(record_to_lines(raw), start=1):
                if needle in (line if case_sensitive else line.lower()):
                    matches.append(
                        {"program": name, "line": number, "text": line[:MATCH_TEXT_CHARS]}
                    )
                    if len(matches) >= match_limit:
                        stopped = "max_matches"
                        break
            if stopped:
                break
    except Exception as error:
        logger.error(f"Error searching {file_name}: {error}")
        return _error(str(error), file_name)
    if stopped is None and not complete:
        stopped = "max_programs_listed"  # the file holds more programs than one search lists
    return {
        "file_name": file_name,
        "text": text,
        "matches": matches,
        "match_count": len(matches),
        "programs_scanned": scanned,
        "programs_matching_pattern": len(names),
        "unreadable": unreadable,
        "truncated": stopped is not None,
        "stopped_because": stopped,
    }


def _stale_problem(
    file_name: str, program: str, current: str | None, expected_hash: str | None
) -> str | None:
    """Return why a save would overwrite something the caller has not read, or None."""
    if current is None:
        if expected_hash is None:
            return None
        return f"{program} no longer exists in {file_name}; leave expected_hash out to create it"
    if expected_hash is None:
        return (
            f"{program} already exists in {file_name}; read it with read_program and pass "
            "its hash as expected_hash"
        )
    if expected_hash.lower() != record_hash(current):
        return f"{program} changed since you read it; read it again with read_program"
    return None


@mcp.tool()
@guarded()
def write_program(
    file_name: str,
    program: str,
    source: str,
    expected_hash: str | None = None,
    confirm: bool = False,
    connection: str | None = None,
) -> dict[str, Any]:
    """Save BASIC source, only over the version you read.

    Leave expected_hash out to create a new program; it is refused if the program
    exists. To change a program, pass the hash read_program gave you; the save is
    refused if the program changed since. The check and the save happen under the
    program's record lock, so a program another user has locked is refused. Lines
    are split on any line end and a trailing newline becomes an empty last line.
    Disabled in read-only mode.

    Args:
        file_name: A BASIC program file (one matching U2_BASIC_FILES), such as BP
        program: The program's name (its record id)
        source: The whole program, lines separated by newlines
        expected_hash: The hash read_program returned; leave out to create
        confirm: Must be True to save. This is a safety measure.
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        status "saved", created, the new hash and line_count; or
        status "confirmation_required".
    """
    manager = get_connection_manager()
    problem = _change_problem(manager, file_name, program, None) or source_problem(source)
    if problem:
        return _error(problem, file_name, program)
    record = source_to_record(source)
    line_count = len(record_to_lines(record))
    if not confirm:
        return {
            "status": "confirmation_required",
            "message": "Set confirm=True to save this program",
            "file_name": file_name,
            "program": program,
            "line_count": line_count,
            "creates": expected_hash is None,
        }
    try:
        with write_guard(manager):
            handle = manager.open_file(file_name)
            with record_lock_released(handle, program):
                current = _read_raw(handle, program, lock=True)
                refusal = _stale_problem(file_name, program, current, expected_hash)
                if refusal:
                    return _error(refusal, file_name, program)
                handle.write(program, record)
    except Exception as error:
        if is_locked(error):
            return _error(
                f"{program} is locked by another user; try again later", file_name, program
            )
        logger.error(f"Error saving {file_name} {program}: {error}")
        return _error(str(error), file_name, program)
    return {
        "status": "saved",
        "created": current is None,
        "file_name": file_name,
        "program": program,
        "hash": record_hash(record),
        "line_count": line_count,
    }


def _run_for_program(manager: Any, file_name: str, program: str, command: str) -> str | None:
    """Run a command about one program; None when the program is not there."""
    if _read_raw(manager.open_file(file_name), program) is None:
        return None
    return str(manager.execute_command(command))


@mcp.tool()
@guarded()
def compile_program(
    file_name: str,
    program: str,
    confirm: bool = False,
    connection: str | None = None,
) -> dict[str, Any]:
    """Compile a BASIC program and report its errors by line.

    Compiling replaces the program's object code, which is what callers of a
    cataloged program run. A compile that outruns U2_QUERY_TIMEOUT is abandoned and
    the database session is closed; the next call reconnects. Disabled in read-only
    mode, and when the operator blocked BASIC in U2_BLOCKED_COMMANDS.

    Args:
        file_name: A BASIC program file (one matching U2_BASIC_FILES), such as BP
        program: The program's name (its record id)
        confirm: Must be True to compile. This is a safety measure.
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        status ("compiled", "failed" or "unknown"; never a guessed success),
        errors ({line, message}), warnings, the command, and the compiler's output
        (at most 20000 characters; output_truncated says if it was cut).
    """
    manager = get_connection_manager()
    problem = _change_problem(manager, file_name, program, "BASIC")
    if problem:
        return _error(problem, file_name, program)
    service = manager.config.service
    command = compile_command(service, file_name, program)
    if not confirm:
        return {
            "status": "confirmation_required",
            "message": "Set confirm=True to compile; this replaces the program's object code",
            "file_name": file_name,
            "program": program,
            "command": command,
        }
    try:
        output = _run_for_program(manager, file_name, program, command)
    except Exception as error:
        logger.error(f"Error compiling {file_name} {program}: {error}")
        return _error(str(error), file_name, program, command=command)
    if output is None:
        return _error(f"{program} not found in {file_name}", file_name, program)
    parsed = parse_compile_output(service, output)
    text, cut = cap_output(output)
    return {
        "file_name": file_name,
        "program": program,
        "command": command,
        "status": parsed["status"],
        "errors": parsed["errors"],
        "warnings": parsed["warnings"],
        "output": text,
        "output_truncated": cut,
    }


@mcp.tool()
@guarded()
def catalog_program(
    file_name: str,
    program: str,
    confirm: bool = False,
    connection: str | None = None,
) -> dict[str, Any]:
    """Catalog a compiled BASIC program locally, in this account only.

    Global cataloging is not offered: it changes the program for every account on
    the server, and is left to an administrator at TCL. Disabled in read-only mode,
    and when the operator blocked CATALOG in U2_BLOCKED_COMMANDS.

    Args:
        file_name: A BASIC program file (one matching U2_BASIC_FILES), such as BP
        program: The program's name (its record id)
        confirm: Must be True to catalog. This is a safety measure.
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        status "ran", the command, and its output (at most 20000 characters), which
        says whether the catalog succeeded: its wording differs between releases.
    """
    manager = get_connection_manager()
    problem = _change_problem(manager, file_name, program, "CATALOG")
    if problem:
        return _error(problem, file_name, program)
    command = catalog_command(manager.config.service, file_name, program)
    if not confirm:
        return {
            "status": "confirmation_required",
            "message": (
                "Set confirm=True to catalog this program locally; callers in this account "
                "then run the new code"
            ),
            "file_name": file_name,
            "program": program,
            "command": command,
        }
    try:
        output = _run_for_program(manager, file_name, program, command)
    except Exception as error:
        logger.error(f"Error cataloging {file_name} {program}: {error}")
        return _error(str(error), file_name, program, command=command)
    if output is None:
        return _error(f"{program} not found in {file_name}", file_name, program)
    text, cut = cap_output(output)
    return {
        "file_name": file_name,
        "program": program,
        "command": command,
        "status": "ran",
        "output": text,
        "output_truncated": cut,
    }
