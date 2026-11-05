# BASIC Tools Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Six MCP tools (`list_programs`, `read_program`, `search_programs`, `write_program`, `compile_program`, `catalog_program`) that let an AI assistant work with UniVerse/UniData BASIC source under the existing `basic.*` permissions.

**Architecture:** Pure helpers in `src/u2_mcp/utils/basic_source.py`: names, the program-file allowlist, source↔record conversion, the hash, the command table and the compiler-output parsers. The tools are thin, in `src/u2_mcp/tools/basic.py`, behind `@guarded()`, and they use the ConnectionManager (`open_file`, `execute_command`, `create_select_list`). The audit wrapper in `server.py` replaces the source text with a summary before either sink sees it.

**Tech Stack:** Python 3.10, FastMCP, uopy (mocked by `tests/mocks/mock_uopy.py`), pytest, pytest-asyncio.

Spec: `docs/superpowers/specs/2026-10-31-basic-tools-design.md`.

## Global Constraints

- Python 3.10. `ruff==0.16.5`, line length 100, rules `E,F,I,UP,B,SIM`. Run `ruff format`, then `mypy src/ --ignore-missing-imports`. Use Google docstrings and type hints on every function.
- Every task ends with these checks, run through `.venv/Scripts/python -m`. All must pass, with no new warnings:
  - `pytest -q`
  - `ruff check .`
  - `ruff format --check .`
  - `mypy src/ --ignore-missing-imports`
  - `bandit -r src/ --severity-level medium --confidence-level medium -q`
- Code blocks here are compacted. Run `.venv/Scripts/python -m ruff format .` after pasting.
- **No schema migration.** Do not change `PERMISSIONS`, `WRITE_PERMISSIONS` or `BUILTIN_ROLES`.
- **No new dependency.** Nothing is downloaded.
- **New environment variable:** `U2_BASIC_FILES`, comma-separated glob patterns. The default is `*BP,BP.*`.
- **Names:** `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`. Patterns: `[A-Za-z0-9._*-]{1,64}`. Only validated names reach TCL, and patterns are applied in Python.
- **Exact messages:** use those in the spec's "Error messages" list, character for character.
- **Read-only:** the change tools check `manager.config.read_only` first, then names. In team mode the guard also refuses.
- **Audit never holds the source text:** `source` is replaced by `{"chars", "lines", "sha256"}`.
- **Wording:** no GitHub Copilot-specific language anywhere. Say "your AI assistant" or "your MCP client".
- **Git:**
  - Branch `feature/basic-tools`.
  - Stage files by path only. Never `git add -A`, `git add .` or `git add -f`; `.superpowers/` is git-ignored.
  - Do not push; the controller pushes.
  - End every commit message with `Co-Authored-By: Claude <model name> <noreply@anthropic.com>`.

## File structure

| File | Responsibility |
|------|----------------|
| `src/u2_mcp/utils/basic_source.py` (new) | Pure rules: names, file allowlist, source↔record, hash, command table, compiler parsers, output cap |
| `src/u2_mcp/tools/basic.py` (new) | The six tools |
| `src/u2_mcp/tools/__init__.py` | Registers `basic` |
| `src/u2_mcp/server.py` | Imports `basic`; the audit wrapper summarizes parameters |
| `src/u2_mcp/config.py` | `U2_BASIC_FILES` → `basic_files` |
| `src/u2_mcp/permissions.py` | Six `TOOL_PERMISSIONS` entries |
| `src/u2_mcp/utils/audit.py` | `summarize_parameters` |
| `src/u2_mcp/admin/templates/roles/edit.html` | Fallback text `No tools` |
| `tests/mocks/mock_uopy.py` | Opt-in `select_from_files`, `add_program_file`, `CLEARSELECT` |
| `tests/test_utils/test_basic_source.py` (new) | Helper tests |
| `tests/test_tools/conftest.py` (new) | `make_manager` fixture |
| `tests/test_tools/test_basic_read.py` (new) | `list_programs`, `read_program`, `search_programs` |
| `tests/test_tools/test_basic_write.py` (new) | `write_program` |
| `tests/test_tools/test_basic_compile.py` (new) | `compile_program`, `catalog_program` |
| `tests/test_basic_access.py` (new) | Team-mode permissions, read-only, audit summary |
| `tests/test_team_mode_e2e.py` | One BASIC journey over HTTP |
| Docs | `docs/tools.md`, `README.md`, `CHANGELOG.md`, `docs/configuration.md`, `docs/admin.md`, `docs/hardening.md`, `docs/what-is-mcp.md` |

---

### Task 1: Pure helpers, `U2_BASIC_FILES`, and the permission map

**Files:**
- Create: `src/u2_mcp/utils/basic_source.py`
- Modify: `src/u2_mcp/config.py` (field after `blocked_commands_str`, property after `blocked_commands`, class docstring)
- Modify: `src/u2_mcp/permissions.py` (`TOOL_PERMISSIONS`)
- Test: `tests/test_utils/test_basic_source.py`, `tests/test_permissions.py`, `tests/test_config.py`

**Interfaces:**
- Produces (all in `u2_mcp.utils.basic_source`):
  - `AM: str`, `NAME_RE`, `PATTERN_RE`, `PATTERN_PROBLEM: str`, `MAX_SOURCE_CHARS = 1_000_000`, `MAX_OUTPUT_CHARS = 20_000`, `MAX_COMPILE_ERRORS = 200`
  - `name_problem(kind: str, value: str) -> str | None`
  - `program_file_problem(file_name: str, allowed: list[str]) -> str | None`
  - `record_hash(raw: str) -> str`, `record_to_lines(raw: str) -> list[str]`, `source_to_record(source: str) -> str`, `source_hash(source: str) -> str`, `source_problem(source: str) -> str | None`
  - `numbered_lines(lines: list[str], start: int) -> str`, `cap_output(text: str) -> tuple[str, bool]`
  - `compile_command(service: str, file_name: str, program: str) -> str`, `catalog_command(service: str, file_name: str, program: str) -> str`. Both raise `ValueError` on a bad name.
  - `object_file_name(file_name: str) -> str` (UniVerse `<file>.O`)
  - `split_object_ids(service: str, ids: list[str]) -> tuple[list[str], set[str] | None]`
  - `parse_compile_output(service: str, output: str) -> dict[str, Any]` returning `{"status", "errors", "warnings"}`
- Produces: `U2Config.basic_files: list[str]`, and six new `TOOL_PERMISSIONS` entries.

- [ ] **Step 1: Write the failing tests**

`tests/test_utils/test_basic_source.py`:

```python
"""The rules the BASIC tools stand on, tested without a database."""

import pytest

from u2_mcp.utils.basic_source import (
    AM, MAX_OUTPUT_CHARS, PATTERN_RE, cap_output, catalog_command, compile_command,
    name_problem, numbered_lines, object_file_name, parse_compile_output,
    program_file_problem, record_hash, record_to_lines, source_hash, source_problem,
    source_to_record, split_object_ids,
)

ALLOWED = ["*BP", "BP.*"]

UV_OK = "Compiling: Source = 'BP/HELLO', Object = 'BP.O/HELLO'\n*\nCompilation Complete."
UV_WARN = (
    "Compiling: Source = 'BP/HELLO', Object = 'BP.O/HELLO'\n*\n"
    "WARNING: Variable 'X' never assigned a value.\nCompilation Complete."
)
UV_BAD = (
    "Compiling: Source = 'BP/BAD', Object = 'BP.O/BAD'\n*\n"
    '0003   PRINT "A" "\n                  ^\n'
    "End of Line unexpected, Was expecting: Array Name, Variable, Literal Number\n\n"
    "1 Errors detected, No Object Code Produced."
)
UD_OK = "Compiling Unibasic: BP/HELLO in mode 'u'.\ncompilation finished"
UD_BAD = (
    "Compiling Unibasic: BP/BAD in mode 'u'.\nmain program: syntax error at or before\n"
    'line 3 : PRINT "A" "\n                   ^\ncompilation failed'
)


class TestNames:
    @pytest.mark.parametrize("name", ["BP", "HELLO", "ORD.POST", "A-1", "x_y", "9LIVES"])
    def test_ordinary_names_pass(self, name: str) -> None:
        assert name_problem("program", name) is None

    @pytest.mark.parametrize(
        "name",
        ["", "*GLOBAL", "-OPT", "$X", "!X", "_HELLO", "A B", 'A"B', "A;B", "A'B", "X" * 65],
    )
    def test_names_with_meaning_or_quotes_are_refused(self, name: str) -> None:
        assert name_problem("program", name) == (
            "program must be 1-64 letters, digits, '.', '_' or '-', "
            "starting with a letter or digit"
        )

    def test_patterns_allow_wildcards_only(self) -> None:
        assert PATTERN_RE.fullmatch("ORD*")
        assert not PATTERN_RE.fullmatch('BP" X')


class TestProgramFiles:
    @pytest.mark.parametrize("name", ["BP", "bp", "XBP", "SUBS.BP", "BP.UTIL"])
    def test_program_files_pass(self, name: str) -> None:
        assert program_file_problem(name, ALLOWED) is None

    def test_a_data_file_is_refused_and_the_setting_is_named(self) -> None:
        assert program_file_problem("CUSTOMERS", ALLOWED) == (
            "CUSTOMERS is not a BASIC program file on this server. Program files are "
            "those matching U2_BASIC_FILES: *BP, BP.*"
        )

    def test_object_files_are_never_source(self) -> None:
        assert program_file_problem("BP.O", ALLOWED) == "BP.O holds object code, not source"

    def test_a_bad_file_name_is_reported_as_a_name(self) -> None:
        assert program_file_problem("BP X", ALLOWED) == name_problem("file_name", "BP X")


class TestSourceAndRecord:
    @pytest.mark.parametrize(
        "raw", ["", "CRT 'HI'", "A" + AM + "B", "A" + AM + "", AM + AM + "END", "café" + AM + "€"]
    )
    def test_reading_then_writing_back_stores_the_identical_record(self, raw: str) -> None:
        source = "\n".join(record_to_lines(raw))
        assert source_to_record(source) == raw
        assert source_hash(source) == record_hash(raw)

    def test_windows_and_old_mac_line_ends_become_lines(self) -> None:
        assert source_to_record("A\r\nB\rC") == AM.join(["A", "B", "C"])

    def test_a_trailing_newline_is_an_empty_last_line(self) -> None:
        assert source_to_record("A\n") == "A" + AM

    def test_an_empty_record_has_no_lines(self) -> None:
        assert record_to_lines("") == []

    def test_the_hash_is_sha256_of_the_stored_record(self) -> None:
        assert record_hash("A") == (
            "559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd"
        )

    @pytest.mark.parametrize("code", [251, 252, 253, 254, 255])
    def test_mark_characters_are_refused_with_their_line(self, code: int) -> None:
        assert source_problem("OK\nBAD" + chr(code)) == (
            "source line 2 contains a U2 mark character (chr 251-255), "
            "which would change the record's shape"
        )

    def test_accented_letters_below_the_marks_are_not_marks(self) -> None:
        # é is chr(233) and ø chr(248). û ü ý þ ÿ ARE chr(251)-chr(255): the marks.
        assert source_problem("CRT 'café ø'") is None

    def test_oversized_source_is_refused(self) -> None:
        assert source_problem("X" * 1_000_001) == "source is longer than 1000000 characters"

    def test_numbered_lines_start_where_asked(self) -> None:
        assert numbered_lines(["A", "B"], 9) == "    9  A\n   10  B"

    def test_output_is_capped(self) -> None:
        text, cut = cap_output("X" * (MAX_OUTPUT_CHARS + 5))
        assert (len(text), cut) == (MAX_OUTPUT_CHARS, True)
        assert cap_output("short") == ("short", False)


class TestCommands:
    @pytest.mark.parametrize("service", ["uvcs", "udcs"])
    def test_the_commands_name_the_mode_explicitly(self, service: str) -> None:
        assert compile_command(service, "BP", "HELLO") == "BASIC BP HELLO"
        assert catalog_command(service, "BP", "HELLO") == "CATALOG BP HELLO LOCAL"

    @pytest.mark.parametrize("bad", ['HI" GLOBAL', "*HI", "HI X"])
    def test_builders_refuse_names_that_were_not_checked(self, bad: str) -> None:
        with pytest.raises(ValueError):
            compile_command("uvcs", "BP", bad)
        with pytest.raises(ValueError):
            catalog_command("udcs", bad, "HELLO")

    def test_universe_object_code_lives_in_a_dot_o_file(self) -> None:
        assert object_file_name("BP") == "BP.O"

    def test_unidata_object_records_are_hidden_and_mark_their_program(self) -> None:
        names, objects = split_object_ids("udcs", ["A", "_A", "B"])
        assert (names, objects) == (["A", "B"], {"A"})

    def test_universe_listing_is_left_whole(self) -> None:
        assert split_object_ids("uvcs", ["A", "_A"]) == (["A", "_A"], None)


class TestCompilerOutput:
    def test_universe_success(self) -> None:
        assert parse_compile_output("uvcs", UV_OK) == {
            "status": "compiled", "errors": [], "warnings": []
        }

    def test_universe_warning_still_compiles(self) -> None:
        parsed = parse_compile_output("uvcs", UV_WARN)
        assert parsed["status"] == "compiled"
        assert parsed["warnings"] == ["WARNING: Variable 'X' never assigned a value."]

    def test_universe_error_has_its_line_and_message(self) -> None:
        parsed = parse_compile_output("uvcs", UV_BAD)
        assert parsed["status"] == "failed"
        assert parsed["errors"] == [
            {
                "line": 3,
                "message": "End of Line unexpected, Was expecting: Array Name, Variable, "
                "Literal Number",
            }
        ]

    def test_unidata_success(self) -> None:
        assert parse_compile_output("udcs", UD_OK)["status"] == "compiled"

    def test_unidata_error_has_its_line_and_message(self) -> None:
        parsed = parse_compile_output("udcs", UD_BAD)
        assert parsed["status"] == "failed"
        assert parsed["errors"] == [
            {"line": 3, "message": "main program: syntax error at or before"}
        ]

    @pytest.mark.parametrize("service", ["uvcs", "udcs"])
    def test_output_with_no_known_marker_is_unknown_never_success(self, service: str) -> None:
        assert parse_compile_output(service, "Command executed: BASIC BP X")["status"] == (
            "unknown"
        )

    def test_errors_are_capped(self) -> None:
        many = "\n".join(f"{n:04d}   X\nbad thing" for n in range(1, 300))
        assert len(parse_compile_output("uvcs", many)["errors"]) == 200
```

Append to `tests/test_permissions.py`:

```python
def test_basic_tools_each_map_to_their_own_permission() -> None:
    basic = {tool: p for tool, p in TOOL_PERMISSIONS.items() if p.startswith("basic.")}
    assert basic == {
        "list_programs": "basic.read",
        "read_program": "basic.read",
        "search_programs": "basic.read",
        "write_program": "basic.write",
        "compile_program": "basic.compile",
        "catalog_program": "basic.catalog",
    }


def test_every_permission_has_at_least_one_tool() -> None:
    assert set(PERMISSIONS) <= set(TOOL_PERMISSIONS.values())
```

Append to `tests/test_config.py` (it already uses `mock_env`; add `import os` and `from unittest.mock import patch` at the top if missing):

```python
def test_basic_files_default_and_override(mock_env: dict[str, str]) -> None:
    from u2_mcp.config import U2Config

    assert U2Config().basic_files == ["*BP", "BP.*"]
    with patch.dict(os.environ, {"U2_BASIC_FILES": " SRC , *BP ,"}):
        assert U2Config().basic_files == ["SRC", "*BP"]
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `.venv/Scripts/python -m pytest tests/test_utils/test_basic_source.py tests/test_permissions.py tests/test_config.py -q`
Expected: FAIL. The new test module errors with `ModuleNotFoundError: No module named 'u2_mcp.utils.basic_source'`, the two permission tests fail, and the config test fails with `AttributeError: ... 'basic_files'`.

- [ ] **Step 3: Implement `src/u2_mcp/utils/basic_source.py`**

```python
"""Pure helpers for the BASIC program tools: names, source text, hashes, compiler output.

Nothing here touches the database, so every rule the tools depend on is tested on
its own. tools/basic.py is a thin layer over these.
"""

from __future__ import annotations

import fnmatch
import hashlib
import re
from typing import Any

AM = chr(254)

# Text, subvalue, value, attribute and item marks. Any one of them inside a source
# line would silently change the record's shape once it is stored.
MARK_CHARACTERS = frozenset(chr(code) for code in range(251, 256))

# Names go into BASIC and CATALOG commands unquoted, so they are held to a set with
# nothing to quote. A leading letter or digit rules out the prefixes U2 gives
# meaning to: * - $ ! for catalog scope and options, _ for UniData object code.
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
PATTERN_RE = re.compile(r"[A-Za-z0-9._*-]{1,64}")
PATTERN_PROBLEM = "pattern may contain only letters, digits, '.', '_', '-' and '*'"

MAX_SOURCE_CHARS = 1_000_000
MAX_OUTPUT_CHARS = 20_000
MAX_COMPILE_ERRORS = 200

# The verbs each product takes. They read the same today; keyed by service so that a
# difference found against a real server changes one line. The catalog mode is always
# given, because UniData catalogs globally when none is.
_COMMANDS: dict[str, dict[str, str]] = {
    "uvcs": {"compile": "BASIC {file} {program}", "catalog": "CATALOG {file} {program} LOCAL"},
    "udcs": {"compile": "BASIC {file} {program}", "catalog": "CATALOG {file} {program} LOCAL"},
}

# Markers in compiler output. A status is only ever reported from one of these.
_MARKERS: dict[str, dict[str, tuple[str, ...]]] = {
    "uvcs": {"failed": ("errors detected", "no object code"), "compiled": ("compilation complete",)},
    "udcs": {"failed": ("compilation failed", "syntax error"), "compiled": ("compilation finished",)},
}

_CARET_RE = re.compile(r"^\s*\^\s*$")
_UV_LINE_RE = re.compile(r"^(\d{4,})(\s|$)")
_UD_LINE_RE = re.compile(r"\bline\s+(\d+)\b", re.IGNORECASE)


def name_problem(kind: str, value: str) -> str | None:
    """Return why a file or program name is refused, or None.

    Args:
        kind: "file_name" or "program", used in the message
        value: The name to check
    """
    if NAME_RE.fullmatch(value):
        return None
    return f"{kind} must be 1-64 letters, digits, '.', '_' or '-', starting with a letter or digit"


def program_file_problem(file_name: str, allowed: list[str]) -> str | None:
    """Return why a file may not be used as a BASIC program file, or None.

    Args:
        file_name: The file the caller named
        allowed: Glob patterns from U2_BASIC_FILES, matched without regard to case
    """
    problem = name_problem("file_name", file_name)
    if problem:
        return problem
    upper = file_name.upper()
    if upper.endswith(".O"):
        return f"{file_name} holds object code, not source"
    if not any(fnmatch.fnmatchcase(upper, pattern.upper()) for pattern in allowed):
        return (
            f"{file_name} is not a BASIC program file on this server. Program files are "
            f"those matching U2_BASIC_FILES: {', '.join(allowed)}"
        )
    return None


def record_hash(raw: str) -> str:
    """Return the SHA-256 hex digest of a stored record, the token write_program checks."""
    return hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()


def record_to_lines(raw: str) -> list[str]:
    """Split a stored program into its lines (attributes). An empty record has none."""
    return raw.split(AM) if raw else []


def _lines_of(source: str) -> list[str]:
    """Split caller source on any line end."""
    return source.replace("\r\n", "\n").replace("\r", "\n").split("\n")


def source_to_record(source: str) -> str:
    """Turn caller source into the record to store. Nothing is stripped."""
    return AM.join(_lines_of(source))


def source_hash(source: str) -> str:
    """Return the hash the record will have once this source is stored."""
    return record_hash(source_to_record(source))


def source_problem(source: str) -> str | None:
    """Return why source text may not be stored, or None."""
    if len(source) > MAX_SOURCE_CHARS:
        return f"source is longer than {MAX_SOURCE_CHARS} characters"
    for number, line in enumerate(_lines_of(source), start=1):
        if not MARK_CHARACTERS.isdisjoint(line):
            return (
                f"source line {number} contains a U2 mark character (chr 251-255), "
                "which would change the record's shape"
            )
    return None


def numbered_lines(lines: list[str], start: int) -> str:
    """Return lines prefixed with their numbers, counting from start."""
    return "\n".join(f"{number:>5}  {text}" for number, text in enumerate(lines, start=start))


def cap_output(text: str) -> tuple[str, bool]:
    """Return command output cut to MAX_OUTPUT_CHARS, and whether it was cut."""
    if len(text) <= MAX_OUTPUT_CHARS:
        return text, False
    return text[:MAX_OUTPUT_CHARS], True


def _command(service: str, verb: str, file_name: str, program: str) -> str:
    """Build a command from checked names. Raises ValueError on a name that is not."""
    for kind, value in (("file_name", file_name), ("program", program)):
        problem = name_problem(kind, value)
        if problem:
            raise ValueError(problem)
    return _COMMANDS[service][verb].format(file=file_name, program=program)


def compile_command(service: str, file_name: str, program: str) -> str:
    """Return the compile command for this product."""
    return _command(service, "compile", file_name, program)


def catalog_command(service: str, file_name: str, program: str) -> str:
    """Return the local catalog command for this product."""
    return _command(service, "catalog", file_name, program)


def object_file_name(file_name: str) -> str:
    """Return the UniVerse file that holds a program file's object code."""
    return f"{file_name}.O"


def split_object_ids(service: str, ids: list[str]) -> tuple[list[str], set[str] | None]:
    """Separate program names from object-code records.

    Returns:
        The program names, and the names known to be compiled. None means the object
        code lives elsewhere (UniVerse: in object_file_name(file)).
    """
    if service == "udcs":
        names = [record_id for record_id in ids if not record_id.startswith("_")]
        return names, {record_id[1:] for record_id in ids if record_id.startswith("_")}
    return list(ids), None


def _universe_errors(output: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Pair each numbered source line UniVerse echoes with the message that follows it."""
    errors: list[dict[str, Any]] = []
    warnings: list[str] = []
    pending: int | None = None
    for raw in output.splitlines():
        line = raw.strip()
        if not line or _CARET_RE.match(raw):
            continue
        if line.upper().startswith("WARNING"):
            warnings.append(line)
            continue
        numbered = _UV_LINE_RE.match(line)
        if numbered:
            pending = int(numbered.group(1))
            continue
        if pending is not None:
            errors.append({"line": pending, "message": line})
            pending = None
    return errors, warnings


def _unidata_errors(output: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Take each 'line N' UniData reports, with the error text printed just above it."""
    errors: list[dict[str, Any]] = []
    warnings: list[str] = []
    previous = ""
    for raw in output.splitlines():
        line = raw.strip()
        if not line or _CARET_RE.match(raw):
            continue
        if line.lower().startswith("warning"):
            warnings.append(line)
        else:
            found = _UD_LINE_RE.search(line)
            if found:
                message = previous if "error" in previous.lower() else line
                errors.append({"line": int(found.group(1)), "message": message})
        previous = line
    return errors, warnings


def parse_compile_output(service: str, output: str) -> dict[str, Any]:
    """Read compiler output into a status, errors and warnings.

    The status is "failed" on a failure marker, "compiled" only on the success marker
    with no errors parsed, and "unknown" otherwise: never a guessed success.
    """
    errors, warnings = (_unidata_errors if service == "udcs" else _universe_errors)(output)
    markers = _MARKERS.get(service, _MARKERS["uvcs"])
    lower = output.lower()
    if any(marker in lower for marker in markers["failed"]):
        status = "failed"
    elif any(marker in lower for marker in markers["compiled"]) and not errors:
        status = "compiled"
    else:
        status = "unknown"
    return {
        "status": status,
        "errors": errors[:MAX_COMPILE_ERRORS],
        "warnings": warnings[:MAX_COMPILE_ERRORS],
    }
```

- [ ] **Step 4: Add `U2_BASIC_FILES` to `src/u2_mcp/config.py`**

In the class docstring's "Optional environment variables", add after the `U2_BLOCKED_COMMANDS` line:

```
        U2_BASIC_FILES: Comma-separated glob patterns naming BASIC program files
```

Directly after the `blocked_commands_str` field:

```python
    basic_files_str: str = Field(
        default="*BP,BP.*",
        alias="U2_BASIC_FILES",
        description="Comma-separated glob patterns naming the files that hold BASIC source",
    )
```

Directly after the `blocked_commands` computed property:

```python
    @computed_field
    @property
    def basic_files(self) -> list[str]:
        """Parse U2_BASIC_FILES into glob patterns."""
        return [p.strip() for p in self.basic_files_str.split(",") if p.strip()]
```

- [ ] **Step 5: Map the tools in `src/u2_mcp/permissions.py`**

In `TOOL_PERMISSIONS`, insert after the `"delete_knowledge": ANY_GRANT,` line:

```python
    # basic: BASIC program source. Only files matching U2_BASIC_FILES are reachable, so
    # these never become a second way to read or write ordinary data.
    "list_programs": "basic.read",
    "read_program": "basic.read",
    "search_programs": "basic.read",
    "write_program": "basic.write",
    "compile_program": "basic.compile",
    "catalog_program": "basic.catalog",
```

- [ ] **Step 6: Run the tests to see them pass**

Run: `.venv/Scripts/python -m pytest tests/test_utils/test_basic_source.py tests/test_permissions.py tests/test_config.py tests/test_guard.py -q`
Expected: PASS. `test_guard` still passes: tools without a mapping are refused, but a mapping without a tool is not.

- [ ] **Step 7: Run the full checks, then commit**

Run the Global Constraints checks. Then:

```bash
git add src/u2_mcp/utils/basic_source.py src/u2_mcp/config.py src/u2_mcp/permissions.py tests/test_utils/test_basic_source.py tests/test_permissions.py tests/test_config.py
git commit -m "feat(basic): source, name and compiler-output helpers; U2_BASIC_FILES; tool permissions

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 2: Mock extension and the three read tools

**Files:**
- Modify: `tests/mocks/mock_uopy.py` (`MockCommand.run`, `MockSession.__init__`, new helper)
- Create: `src/u2_mcp/tools/basic.py`
- Modify: `src/u2_mcp/tools/__init__.py`, and `src/u2_mcp/server.py` (tool import list)
- Create: `tests/test_tools/conftest.py`, `tests/test_tools/test_basic_read.py`

**Interfaces:**
- Consumes: everything Task 1 produces.
- Produces, in `u2_mcp.tools.basic`:
  - `list_programs(file_name="BP", pattern="*", max_results=500, connection=None)`
  - `read_program(file_name, program, start_line=1, max_lines=2000, numbered=True, connection=None)`
  - `search_programs(file_name, text, pattern="*", case_sensitive=False, max_programs=200, max_matches=100, connection=None)`
  - Private helpers, which Tasks 3 and 4 add to: `_read_problem(manager, file_name, program=None)`, `_change_problem(manager, file_name, program, verb)`, `_read_raw(handle, program) -> str | None`, `_error(message, file_name, program=None, **extra)`, and `READ_ONLY_MESSAGE`.
- Produces in the mocks:
  - `MockSession.select_from_files: bool` (default False);
  - `MockSession.add_program_file(file_name, programs)`, which seeds the file and sets the flag;
  - with the flag on, `SELECT X`/`SSELECT X` on a seeded file selects its sorted keys, a missing file selects nothing, and `CLEARSELECT` empties the list.
- Produces the fixture `make_manager(**env) -> ConnectionManager` in `tests/test_tools/conftest.py`.

- [ ] **Step 1: Extend the mock (test infrastructure; no test of its own)**

In `tests/mocks/mock_uopy.py`, add `import re` under the module docstring, next to `from typing import Any`. In `MockSession.__init__`, after `self._missing_files: set[str] = set()`, add:

```python
        # Opt-in: a bare SELECT/SSELECT of a seeded file selects that file's keys.
        self.select_from_files: bool = False
```

In `MockCommand.run`, directly after the `command_delay_seconds` block and before the `for pattern, canned` loop:

```python
            if session.select_from_files:
                selected = _select_from_file(session, self.command_text)
                if selected is not None:
                    self.response = selected
                    return
```

Add these module-level definitions after `_default_response`:

```python
_BARE_SELECT = re.compile(r"^\s*S?SELECT\s+(\S+)\s*$", re.IGNORECASE)


def _select_from_file(session: Any, command_text: str) -> str | None:
    """Answer a bare SELECT/SSELECT or CLEARSELECT from seeded files, else None."""
    if command_text.strip().upper() == "CLEARSELECT":
        session.select_list = []
        return ""
    match = _BARE_SELECT.match(command_text)
    if not match:
        return None
    name = match.group(1)
    if name in session._missing_files:
        session.select_list = []
        return f"Cannot open file {name}"
    if name not in session._files:
        return None
    session.select_list = sorted(session._files[name])
    return f"{len(session.select_list)} records selected to list 0."
```

Add this helper to the "test helpers" section of `MockSession`:

```python
    def add_program_file(self, file_name: str, programs: dict[str, str]) -> None:
        """Seed a BASIC program file and let SELECT/SSELECT list its keys."""
        self.add_file(file_name, programs)
        self.select_from_files = True
```

- [ ] **Step 2: Add the `make_manager` fixture, in `tests/test_tools/conftest.py`**

```python
"""Fixtures for tool tests that need a manager built from particular settings."""

import os
from collections.abc import Callable, Iterator
from unittest.mock import patch

import pytest

import u2_mcp.server as server_module
from tests.mocks.mock_uopy import MockSession
from u2_mcp.config import U2Config
from u2_mcp.connection import ConnectionManager


@pytest.fixture
def make_manager(
    mock_env: dict[str, str], mock_uopy: MockSession
) -> Iterator[Callable[..., ConnectionManager]]:
    """Build and install a ConnectionManager whose config adds the given U2_* variables."""

    def build(**env: str) -> ConnectionManager:
        with patch.dict(os.environ, env):
            manager = ConnectionManager(U2Config())
        server_module._connection_manager = manager
        return manager

    try:
        yield build
    finally:
        server_module._connection_manager = None
```

- [ ] **Step 3: Write the failing tests, in `tests/test_tools/test_basic_read.py`**

```python
"""Listing, reading and searching BASIC source, on both products."""

from collections.abc import Callable

import pytest

from tests.mocks.mock_uopy import MockSession
from u2_mcp.connection import ConnectionManager
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
```

- [ ] **Step 4: Run them to see them fail**

Run: `.venv/Scripts/python -m pytest tests/test_tools/test_basic_read.py -q`
Expected: FAIL at collection with `ModuleNotFoundError: No module named 'u2_mcp.tools.basic'`.

- [ ] **Step 5: Implement `src/u2_mcp/tools/basic.py` (read tools and shared helpers)**

```python
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
from typing import Any

from ..connection import FileNotFoundError
from ..guard import guarded
from ..server import get_connection_manager, mcp
from ..utils.basic_source import (
    PATTERN_PROBLEM,
    PATTERN_RE,
    name_problem,
    numbered_lines,
    object_file_name,
    program_file_problem,
    record_hash,
    record_to_lines,
    split_object_ids,
)

logger = logging.getLogger(__name__)

MAX_LIST_RESULTS = 5000
SELECT_READ_LIMIT = 50_000
MAX_READ_LINES = 5000
MAX_SEARCH_PROGRAMS = 1000
MAX_SEARCH_MATCHES = 1000
MAX_SEARCH_CHARS = 20_000_000
MATCH_TEXT_CHARS = 300
READ_ONLY_MESSAGE = "BASIC changes are disabled in read-only mode"
_RECORD_NOT_FOUND = 30001  # uopy's status for a record that is not there


def _clamp(value: int, ceiling: int) -> int:
    """Keep a caller's limit between 1 and the ceiling."""
    return max(1, min(value, ceiling))


def _error(message: str, file_name: str, program: str | None = None, **extra: Any) -> dict[str, Any]:
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


def _is_missing(error: Exception) -> bool:
    """Return whether a read failed only because the record is not there."""
    return getattr(error, "code", None) == _RECORD_NOT_FOUND or "not found" in str(error).lower()


def _read_raw(handle: Any, program: str) -> str | None:
    """Return a program's stored record, or None when there is no such record."""
    try:
        raw = handle.read(program)
    except Exception as error:
        if _is_missing(error):
            return None
        raise
    return None if raw is None else str(raw)


def _select_ids(manager: Any, file_name: str) -> tuple[list[str], bool]:
    """Return a file's record ids, and whether that is all of them.

    The whole list is read so none is left active to feed the next command on this
    session; past SELECT_READ_LIMIT the rest is cleared instead.
    """
    manager.execute_command(f"SSELECT {file_name}")
    select = manager.create_select_list()
    ids: list[str] = []
    while len(ids) < SELECT_READ_LIMIT:
        value = select.next()
        if value is None or str(value) == "":
            return ids, True
        ids.append(str(value))
    manager.execute_command("CLEARSELECT")
    return ids, False


def _universe_objects(manager: Any, file_name: str) -> set[str] | None:
    """Return the programs with object code in <file>.O, or None when it will not open."""
    object_file = object_file_name(file_name)
    try:
        manager.open_file(object_file)
    except FileNotFoundError:
        return None
    ids, _complete = _select_ids(manager, object_file)
    return set(ids)


def _programs(
    manager: Any, file_name: str, pattern: str, *, with_objects: bool
) -> tuple[list[str], set[str] | None, bool]:
    """Return matching program names, the compiled ones (None = unknown), and completeness."""
    manager.open_file(file_name)
    ids, complete = _select_ids(manager, file_name)
    names, objects = split_object_ids(manager.config.service, ids)
    if objects is None and with_objects:
        objects = _universe_objects(manager, file_name)
    chosen = sorted(name for name in names if fnmatch.fnmatchcase(name, pattern))
    return chosen, objects, complete


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
        chosen, objects, complete = _programs(manager, file_name, pattern, with_objects=True)
    except Exception as error:
        logger.error(f"Error listing programs in {file_name}: {error}")
        return _error(str(error), file_name)
    shown = chosen[:limit]
    truncated = len(chosen) > limit or not complete
    result: dict[str, Any] = {
        "file_name": file_name,
        "programs": [
            {"name": name, "compiled": None if objects is None else name in objects}
            for name in shown
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
    end = start - 1 + len(chosen)
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
        (null, "max_matches", "max_programs" or "max_bytes").
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
    try:
        names, _objects, _complete = _programs(manager, file_name, pattern, with_objects=False)
        handle = manager.open_file(file_name)
        for name in names:
            if scanned >= program_limit:
                stopped = "max_programs"
                break
            if chars >= MAX_SEARCH_CHARS:
                stopped = "max_bytes"
                break
            scanned += 1
            try:
                raw = _read_raw(handle, name)
            except Exception:
                raw = None
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
```

Register the module. In `src/u2_mcp/tools/__init__.py`, add `basic,` as the first name inside the parentheses. In `src/u2_mcp/server.py`, add `basic,` as the first name in the `from .tools import (` list.

- [ ] **Step 6: Run the tests to see them pass**

Run: `.venv/Scripts/python -m pytest tests/test_tools/test_basic_read.py tests/test_guard.py tests/test_tools/test_query.py -q`
Expected: PASS. `test_query` proves the opt-in mock left existing select tests unchanged. `test_guard` proves the new tools are guarded and take `connection`.

- [ ] **Step 7: Run the full checks, then commit**

```bash
git add tests/mocks/mock_uopy.py tests/test_tools/conftest.py tests/test_tools/test_basic_read.py src/u2_mcp/tools/basic.py src/u2_mcp/tools/__init__.py src/u2_mcp/server.py
git commit -m "feat(basic): list_programs, read_program and search_programs

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 3: `write_program` with hash-checked saves

**Files:**
- Modify: `src/u2_mcp/tools/basic.py` (append the tool; extend the `basic_source` import)
- Create: `tests/test_tools/test_basic_write.py`

**Interfaces:**
- Consumes: `_change_problem`, `_read_raw`, `_error` (Task 2); `source_problem`, `source_to_record`, `record_to_lines`, `record_hash` (Task 1).
- Produces: `write_program(file_name, program, source, expected_hash=None, confirm=False, connection=None)`.

- [ ] **Step 1: Write the failing tests, in `tests/test_tools/test_basic_write.py`**

```python
"""Saving BASIC source: only over what the caller read, and never in read-only mode."""

from collections.abc import Iterator

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
```

- [ ] **Step 2: Run them to see them fail**

Run: `.venv/Scripts/python -m pytest tests/test_tools/test_basic_write.py -q`
Expected: FAIL with `ImportError: cannot import name 'write_program' from 'u2_mcp.tools.basic'`.

- [ ] **Step 3: Implement `write_program`**

Extend the import from `..utils.basic_source` in `src/u2_mcp/tools/basic.py` to also take `source_problem` and `source_to_record`, keeping the list sorted. Append:

```python
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
    refused if the program changed since. Lines are split on any line end and a
    trailing newline becomes an empty last line. Disabled in read-only mode.

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
        handle = manager.open_file(file_name)
        current = _read_raw(handle, program)
        refusal = _stale_problem(file_name, program, current, expected_hash)
        if refusal:
            return _error(refusal, file_name, program)
        handle.write(program, record)
    except Exception as error:
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
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `.venv/Scripts/python -m pytest tests/test_tools/test_basic_write.py tests/test_tools/test_basic_read.py -q`
Expected: PASS.

- [ ] **Step 5: Run the full checks, then commit**

```bash
git add src/u2_mcp/tools/basic.py tests/test_tools/test_basic_write.py
git commit -m "feat(basic): write_program, saved only over the version the caller read

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 4: `compile_program` and `catalog_program`

**Files:**
- Modify: `src/u2_mcp/tools/basic.py` (append the tools; extend the import)
- Create: `tests/test_tools/test_basic_compile.py`

**Interfaces:**
- Consumes: `_change_problem`, `_read_raw`, `_error` (Task 2); `compile_command`, `catalog_command`, `parse_compile_output`, `cap_output` (Task 1).
- Produces: `compile_program(file_name, program, confirm=False, connection=None)` and `catalog_program(file_name, program, confirm=False, connection=None)`.

- [ ] **Step 1: Write the failing tests, in `tests/test_tools/test_basic_compile.py`**

```python
"""Compiling and locally cataloging, on both products, under the operator's rules."""

from collections.abc import Callable, Iterator

import pytest

import u2_mcp.server as server_module
from tests.mocks.mock_uopy import MockSession
from u2_mcp.config import U2Config
from u2_mcp.connection import ConnectionManager
from u2_mcp.tools.basic import catalog_program, compile_program

UV_OK = "Compiling: Source = 'BP/HELLO', Object = 'BP.O/HELLO'\n*\nCompilation Complete."
UV_BAD = (
    "Compiling: Source = 'BP/HELLO', Object = 'BP.O/HELLO'\n*\n"
    '0003   PRINT "A" "\n                  ^\nEnd of Line unexpected\n\n'
    "1 Errors detected, No Object Code Produced."
)
UD_OK = "Compiling Unibasic: BP/HELLO in mode 'u'.\ncompilation finished"
UD_BAD = (
    "Compiling Unibasic: BP/HELLO in mode 'u'.\nmain program: syntax error at or before\n"
    'line 3 : PRINT "A" "\ncompilation failed'
)


def seed(session: MockSession, compiler_says: str) -> None:
    session.add_program_file("BP", {"HELLO": "CRT 'HI'"})
    session.set_command_responses(
        {"BASIC BP HELLO": compiler_says, "CATALOG BP HELLO LOCAL": "HELLO cataloged."}
    )


class TestCompile:
    @pytest.mark.parametrize(
        ("service", "output", "status", "errors"),
        [
            ("uvcs", UV_OK, "compiled", []),
            ("uvcs", UV_BAD, "failed", [{"line": 3, "message": "End of Line unexpected"}]),
            ("udcs", UD_OK, "compiled", []),
            (
                "udcs",
                UD_BAD,
                "failed",
                [{"line": 3, "message": "main program: syntax error at or before"}],
            ),
            ("uvcs", "something new", "unknown", []),
        ],
    )
    def test_compiler_output_is_read_for_each_product(
        self,
        make_manager: Callable[..., ConnectionManager],
        mock_uopy: MockSession,
        service: str,
        output: str,
        status: str,
        errors: list[dict[str, object]],
    ) -> None:
        make_manager(U2_SERVICE=service)
        seed(mock_uopy, output)

        result = compile_program("BP", "HELLO", confirm=True)

        assert mock_uopy.executed_commands[-1] == "BASIC BP HELLO"
        assert (result["status"], result["errors"]) == (status, errors)
        assert result["output"] == output
        assert result["output_truncated"] is False
        assert result["command"] == "BASIC BP HELLO"

    def test_without_confirm_nothing_runs(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        seed(mock_uopy, UV_OK)

        result = compile_program("BP", "HELLO")

        assert result["status"] == "confirmation_required"
        assert not any(c.startswith("BASIC") for c in mock_uopy.executed_commands)

    def test_a_missing_program_is_not_sent_to_the_compiler(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        seed(mock_uopy, UV_OK)

        assert compile_program("BP", "NOPE", confirm=True)["error"] == "NOPE not found in BP"
        assert not any(c.startswith("BASIC") for c in mock_uopy.executed_commands)

    def test_long_output_is_capped(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        seed(mock_uopy, "X" * 30_000)

        result = compile_program("BP", "HELLO", confirm=True)

        assert (len(result["output"]), result["output_truncated"]) == (20_000, True)

    @pytest.mark.parametrize("program", ['HELLO" X', "*HELLO", "-I"])
    def test_names_that_would_change_the_command_never_reach_it(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession, program: str
    ) -> None:
        seed(mock_uopy, UV_OK)

        assert "error" in compile_program("BP", program, confirm=True)
        assert mock_uopy.executed_commands == []


class TestCatalog:
    @pytest.mark.parametrize("service", ["uvcs", "udcs"])
    def test_catalogs_locally_and_returns_the_output(
        self,
        make_manager: Callable[..., ConnectionManager],
        mock_uopy: MockSession,
        service: str,
    ) -> None:
        make_manager(U2_SERVICE=service)
        seed(mock_uopy, UV_OK)

        result = catalog_program("BP", "HELLO", confirm=True)

        assert mock_uopy.executed_commands[-1] == "CATALOG BP HELLO LOCAL"
        assert (result["status"], result["output"]) == ("ran", "HELLO cataloged.")

    def test_without_confirm_nothing_runs(
        self, connection_manager: ConnectionManager, mock_uopy: MockSession
    ) -> None:
        seed(mock_uopy, UV_OK)

        assert catalog_program("BP", "HELLO")["status"] == "confirmation_required"
        assert not any(c.startswith("CATALOG") for c in mock_uopy.executed_commands)


class TestOperatorRules:
    @pytest.mark.parametrize(
        ("tool", "verb"), [(compile_program, "BASIC"), (catalog_program, "CATALOG")]
    )
    def test_a_verb_the_operator_blocked_turns_its_tool_off(
        self,
        make_manager: Callable[..., ConnectionManager],
        mock_uopy: MockSession,
        tool: Callable[..., dict[str, object]],
        verb: str,
    ) -> None:
        make_manager(U2_BLOCKED_COMMANDS=f"DELETE.FILE,{verb}")
        seed(mock_uopy, UV_OK)

        assert tool("BP", "HELLO", confirm=True)["error"] == (
            f"{verb} is in U2_BLOCKED_COMMANDS on this server, so this tool is turned off"
        )
        assert mock_uopy.executed_commands == []


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


@pytest.mark.parametrize("tool", [compile_program, catalog_program])
def test_read_only_mode_refuses_compile_and_catalog(
    read_only_manager: ConnectionManager,
    mock_uopy: MockSession,
    tool: Callable[..., dict[str, object]],
) -> None:
    seed(mock_uopy, UV_OK)

    assert tool("BP", "HELLO", confirm=True)["error"] == (
        "BASIC changes are disabled in read-only mode"
    )
    assert mock_uopy.executed_commands == []
```

- [ ] **Step 2: Run them to see them fail**

Run: `.venv/Scripts/python -m pytest tests/test_tools/test_basic_compile.py -q`
Expected: FAIL with `ImportError: cannot import name 'catalog_program'`.

- [ ] **Step 3: Implement the tools**

Extend the import from `..utils.basic_source` to also take `cap_output`, `catalog_command`, `compile_command` and `parse_compile_output`, keeping the list sorted. Append to `src/u2_mcp/tools/basic.py`:

```python
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
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `.venv/Scripts/python -m pytest tests/test_tools/ -q`
Expected: PASS.

- [ ] **Step 5: Run the full checks, then commit**

```bash
git add src/u2_mcp/tools/basic.py tests/test_tools/test_basic_compile.py
git commit -m "feat(basic): compile_program and local catalog_program

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 5: Audit summary, team-mode permissions, and the end-to-end journey

**Files:**
- Modify: `src/u2_mcp/utils/audit.py` (new function `summarize_parameters`)
- Modify: `src/u2_mcp/server.py` (`_wrap_tools_with_audit`'s `wrapped_fn`, and its import of `audit`)
- Create: `tests/test_basic_access.py`
- Modify: `tests/test_team_mode_e2e.py` (append one test)

**Interfaces:**
- Consumes: the six tools; `source_hash`, `source_to_record` and `record_to_lines` (Task 1).
- Produces: `u2_mcp.utils.audit.summarize_parameters(params: dict[str, Any]) -> dict[str, Any]`.

- [ ] **Step 1: Write the failing tests, in `tests/test_basic_access.py`**

```python
"""Who may use the BASIC tools where, and what the audit keeps of the source."""

from collections.abc import Iterator
from typing import Any

import pytest

import u2_mcp.server as server
from tests.mocks.mock_uopy import MockSession
from u2_mcp.identity import caller_for_user, use_caller
from u2_mcp.store import install_store
from u2_mcp.store.repo import Store
from u2_mcp.tools.basic import (
    catalog_program, compile_program, list_programs, read_program, search_programs,
    write_program,
)
from u2_mcp.utils.audit import summarize_parameters
from u2_mcp.utils.basic_source import source_hash

BP = {"file_name": "BP", "program": "HELLO"}


@pytest.fixture
def team(store: Store, mock_env: dict[str, str], mock_uopy: MockSession) -> Iterator[dict[str, Any]]:
    """Dev (read-write) and Live (read-only); viv=Viewer, dee=Developer, oona=Owner on both."""

    def role(name: str) -> int:
        found = store.get_role_by_name(name)
        assert found is not None
        return found.id

    def connection(name: str, *, read_only: bool) -> int:
        return store.add_connection(
            name=name, host=f"{name.lower()}.example", port=1, service="uvcs", account="DEV",
            shared_user="svc", shared_password="pw", read_only=read_only,
        ).id

    connections = (connection("Dev", read_only=False), connection("Live", read_only=True))
    people = {}
    for person, role_name in (("viv", "Viewer"), ("dee", "Developer"), ("oona", "Owner")):
        user = store.get_or_create_sso_user(person)
        for connection_id in connections:
            store.add_grant(
                connection_id=connection_id, subject_type="user", subject_id=user.id,
                role_id=role(role_name),
            )
        people[person] = caller_for_user(user, auth_method="token")
    mock_uopy.add_program_file("BP", {"HELLO": "CRT 'HI'"})
    mock_uopy.set_command_responses(
        {"BASIC BP HELLO": "Compilation Complete.", "CATALOG BP HELLO LOCAL": "done"}
    )
    install_store(store)
    try:
        yield {"people": people, "store": store}
    finally:
        install_store(None)
        server.reset_connection_manager()


def test_a_viewer_is_refused_every_read_tool(team: dict[str, Any]) -> None:
    refusal = {"error": "you need basic.read on Dev; ask an admin"}
    with use_caller(team["people"]["viv"]):
        assert list_programs("BP", connection="Dev") == refusal
        assert read_program(**BP, connection="Dev") == refusal
        assert search_programs("BP", "CRT", connection="Dev") == refusal


def test_a_developer_reads_writes_and_compiles_but_does_not_catalog(team: dict[str, Any]) -> None:
    with use_caller(team["people"]["dee"]):
        assert [p["name"] for p in list_programs("BP", connection="Dev")["programs"]] == ["HELLO"]
        read = read_program(**BP, connection="Dev")
        saved = write_program(
            **BP, source="CRT 'HO'", expected_hash=read["hash"], confirm=True, connection="Dev"
        )
        assert saved["status"] == "saved"
        assert compile_program(**BP, confirm=True, connection="Dev")["status"] == "compiled"
        assert catalog_program(**BP, confirm=True, connection="Dev") == {
            "error": "you need basic.catalog on Dev; ask an admin"
        }


def test_an_owner_catalogs(team: dict[str, Any]) -> None:
    with use_caller(team["people"]["oona"]):
        assert catalog_program(**BP, confirm=True, connection="Dev")["status"] == "ran"


def test_a_read_only_connection_refuses_changes_but_still_reads(team: dict[str, Any]) -> None:
    with use_caller(team["people"]["oona"]):
        assert "hash" in read_program(**BP, connection="Live")
        for refused in (
            write_program(**BP, source="END", confirm=True, connection="Live"),
            compile_program(**BP, confirm=True, connection="Live"),
            catalog_program(**BP, confirm=True, connection="Live"),
        ):
            assert refused == {"error": "Live is read-only"}


def test_global_read_only_refuses_changes_everywhere(team: dict[str, Any]) -> None:
    install_store(team["store"], global_read_only=True)
    with use_caller(team["people"]["oona"]):
        assert write_program(**BP, source="END", confirm=True, connection="Dev") == {
            "error": "Dev is read-only"
        }
        assert compile_program(**BP, confirm=True, connection="Dev") == {
            "error": "Dev is read-only"
        }
        assert "hash" in read_program(**BP, connection="Dev")


class TestAuditSummary:
    def test_source_becomes_its_size_and_the_hash_it_will_be_stored_with(self) -> None:
        params = {"file_name": "BP", "program": "HELLO", "source": "CRT 'HI'\nEND"}

        logged = summarize_parameters(params)

        assert logged == {
            "file_name": "BP",
            "program": "HELLO",
            "source": {"chars": 12, "lines": 2, "sha256": source_hash("CRT 'HI'\nEND")},
        }
        assert params["source"] == "CRT 'HI'\nEND"  # the call's own arguments are untouched

    def test_other_parameters_pass_through(self) -> None:
        params = {"file_name": "BP", "record_id": "1"}
        assert summarize_parameters(params) == params
```

Append to `tests/test_team_mode_e2e.py`:

```python
@pytest.mark.asyncio
async def test_a_basic_journey_from_refusal_to_an_audited_save(running: dict[str, Any]) -> None:
    store = running["store"]
    session: MockSession = running["session"]
    session.add_program_file("BP", {"HELLO": "CRT 'HI'"})
    args = {"file_name": "BP", "program": "HELLO", "connection": "Test"}

    refused = await _call(running["url"], running["alice"], "read_program", args)
    assert "you need basic.read on Test; ask an admin" in refused

    developer = store.get_role_by_name("Developer")
    assert developer is not None
    grant = store.grants_for(running["alice_id"], [], running["test_id"])[0]
    store.update_grant(grant.id, role_id=developer.id)

    read = json.loads(
        await _call(running["url"], running["alice"], "read_program", {**args, "numbered": False})
    )
    assert read["source"] == "CRT 'HI'"
    saved = json.loads(
        await _call(
            running["url"],
            running["alice"],
            "write_program",
            {**args, "source": "CRT 'HELLO'", "expected_hash": read["hash"], "confirm": True},
        )
    )
    assert saved["status"] == "saved"
    assert session._files["BP"]["HELLO"] == "CRT 'HELLO'"

    row = next(r for r in store.recent_audit(20) if r["action"] == "write_program")
    assert row["params"]["source"] == {"chars": 11, "lines": 1, "sha256": saved["hash"]}
    assert "CRT 'HELLO'" not in json.dumps(row, default=str)
```

- [ ] **Step 2: Run them to see them fail**

Run: `.venv/Scripts/python -m pytest tests/test_basic_access.py tests/test_team_mode_e2e.py -q`
Expected: FAIL. `test_basic_access.py` errors at import: `cannot import name 'summarize_parameters'`. The e2e test fails on `row["params"]["source"]`, which still holds the raw text; `Store.recent_audit` decodes the params under `"params"`.

- [ ] **Step 3: Implement `summarize_parameters` in `src/u2_mcp/utils/audit.py`**

Add the import `from .basic_source import record_to_lines, source_hash, source_to_record` with the other imports, and this module-level function, placed before `init_audit_logger`:

```python
def summarize_parameters(params: dict[str, Any]) -> dict[str, Any]:
    """Return tool parameters as they may be logged: BASIC source becomes a summary.

    Program source is the business logic itself, so neither audit sink keeps it. Its
    size and the hash it will be stored with are enough to tie the entry to a
    read_program result.

    Args:
        params: The tool call's keyword arguments (not modified)

    Returns:
        A copy with a string "source" replaced by {"chars", "lines", "sha256"}
    """
    source = params.get("source")
    if not isinstance(source, str):
        return params
    summary = {
        "chars": len(source),
        "lines": len(record_to_lines(source_to_record(source))),
        "sha256": source_hash(source),
    }
    return {**params, "source": summary}
```

- [ ] **Step 4: Use it in the audit wrapper, in `src/u2_mcp/server.py`**

Change the import line to:

```python
from .utils.audit import audit_tool_call, get_audit_logger, init_audit_logger, summarize_parameters
```

In `wrapped_fn`'s `finally:` block, replace:

```python
            finally:
                duration_ms = (time.time() - start_time) * 1000
                if get_audit_logger():
```

with:

```python
            finally:
                duration_ms = (time.time() - start_time) * 1000
                logged = summarize_parameters(kwargs)
                if get_audit_logger():
```

Then, in the same block, change `parameters=kwargs,` to `parameters=logged,`. Change `_record_tool_audit(_tool_name, kwargs, result, error_msg, duration_ms, route)` to `_record_tool_audit(_tool_name, logged, result, error_msg, duration_ms, route)`.

- [ ] **Step 5: Run the tests to see them pass**

Run: `.venv/Scripts/python -m pytest tests/test_basic_access.py tests/test_team_mode_e2e.py tests/test_utils/test_audit.py tests/test_guard.py -q`
Expected: PASS.

- [ ] **Step 6: Run the full checks, then commit**

```bash
git add src/u2_mcp/utils/audit.py src/u2_mcp/server.py tests/test_basic_access.py tests/test_team_mode_e2e.py
git commit -m "feat(basic): audit logs a summary of source, not the text; access tests and e2e journey

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 6: Docs and the roles page

**Files:**
- Modify: `src/u2_mcp/admin/templates/roles/edit.html:18`
- Modify: `docs/tools.md`, `README.md`, `CHANGELOG.md`, `docs/configuration.md`, `docs/admin.md`, `docs/hardening.md`, `docs/what-is-mcp.md`
- Test: `tests/test_admin/test_roles_groups.py` (append one test)

**Interfaces:** consumes the tool names and messages from Tasks 1–5. Produces no code interface.

- [ ] **Step 1: Write the failing test, appended to `tests/test_admin/test_roles_groups.py`**

The file already has the signed-in `client` and `ctx` fixtures, used by `test_cloning_a_role_deleted_meanwhile_is_not_a_500`:

```python
def test_every_permission_row_names_its_tools(client: TestClient, ctx: AdminContext) -> None:
    owner = ctx.store.get_role_by_name("Owner")
    assert owner is not None

    page = client.get(f"/admin/roles/{owner.id}").text

    for tool in ("list_programs", "read_program", "write_program", "catalog_program"):
        assert tool in page
    assert "Reserved for BASIC tools" not in page
    assert "No tools" not in page
```

- [ ] **Step 2: Run it to see it fail**

Run: `.venv/Scripts/python -m pytest tests/test_admin/test_roles_groups.py -q -k every_permission_row`
Expected: PASS. Tasks 1–5 already mapped every permission, so no row falls back. This test guards the change in Step 3 rather than driving it: the template edit only replaces text that can no longer be shown, which `test_every_permission_has_at_least_one_tool` (Task 1) guarantees.

- [ ] **Step 3: Change the template**

In `src/u2_mcp/admin/templates/roles/edit.html` line 18, replace `or "Reserved for BASIC tools"` with `or "No tools"`.

- [ ] **Step 4: Update the docs**

1. **`docs/tools.md`**
   - Run `.venv/Scripts/python -c "import u2_mcp.server as s; print(len(s.mcp._tool_manager._tools))"`, and put the number it prints in place of `31` in "u2-mcp provides 31 tools".
   - Add this row to the category table, after the Subroutines row: `| [BASIC programs](#basic-programs) | 6 | List, read, search, save, compile and catalog BASIC source |`
   - Add this section after the "BASIC Subroutines" section:

```markdown
## BASIC programs

These tools work only on files whose names match `U2_BASIC_FILES` (default `*BP,BP.*`: `BP`, `XBP`, `SUBS.BP`, `BP.UTIL`), so they never reach ordinary data. File and program names may hold only letters, digits, `.`, `_` and `-`, and start with a letter or digit. Running a program is not here: use `call_subroutine` or `execute_tcl`.

| Tool | Permission | What it does |
|------|-----------|--------------|
| `list_programs(file_name="BP", pattern="*", max_results=500)` | `basic.read` | Program names, each with `compiled` (true, false, or null when it cannot be told: UniVerse looks in `BP.O`, UniData at `_NAME` records) |
| `read_program(file_name, program, start_line=1, max_lines=2000, numbered=True)` | `basic.read` | Source with line numbers (`numbered=False` gives the exact text), and the `hash` of the whole program |
| `search_programs(file_name, text, pattern="*", case_sensitive=False, max_programs=200, max_matches=100)` | `basic.read` | Lines containing `text` (literal, not a regex). Says which limit stopped it |
| `write_program(file_name, program, source, expected_hash=None, confirm=False)` | `basic.write` | Saves source. Leave `expected_hash` out to create; pass the hash from `read_program` to change, and the save is refused if the program changed since |
| `compile_program(file_name, program, confirm=False)` | `basic.compile` | Runs `BASIC <file> <program>`. `status` is `compiled`, `failed` or `unknown`, with `errors` by line and the raw output |
| `catalog_program(file_name, program, confirm=False)` | `basic.catalog` | Runs `CATALOG <file> <program> LOCAL` (this account only) and returns the output |

**An edit, start to finish:**
1. `read_program("BP", "ORD.POST", numbered=False)` returns `source` and `hash`.
2. `write_program("BP", "ORD.POST", <edited source>, expected_hash=<hash>, confirm=True)`
3. `compile_program("BP", "ORD.POST", confirm=True)`. When `failed`, fix the lines listed in `errors` and go back to step 1.
4. `catalog_program("BP", "ORD.POST", confirm=True)`, needed only the first time.

**Rules:**
- The three change tools need `confirm=True`.
- They are refused on a read-only connection, and when `U2_READ_ONLY` is on.
- `compile_program` and `catalog_program` are turned off when the operator lists `BASIC` or `CATALOG` in `U2_BLOCKED_COMMANDS`.
- A compile or catalog that outruns `U2_QUERY_TIMEOUT` is abandoned: the session is closed, and the next call reconnects.
- The audit log records the size and hash of the source that was saved, never its text.
```

2. **`README.md`**: change the line `- **BASIC**: \`call_subroutine\`, \`list_catalog\`` to:
   `- **BASIC**: \`call_subroutine\`, \`list_catalog\`, \`list_programs\`, \`read_program\`, \`search_programs\`, \`write_program\`, \`compile_program\`, \`catalog_program\``

3. **`CHANGELOG.md`**: add these bullets at the top of `### Added` under `## [Unreleased]`:

```markdown
- BASIC program tools: `list_programs`, `read_program`, `search_programs` (`basic.read`), `write_program` (`basic.write`, saves only over the version you read), `compile_program` (`basic.compile`, errors by line on UniVerse and UniData) and `catalog_program` (`basic.catalog`, local catalog only). Built-in roles: Developer reads, writes and compiles; Owner also catalogs.
- `U2_BASIC_FILES`: which files the BASIC tools may use (default `*BP,BP.*`).
- The audit log records BASIC source by size and hash, never its text.
```

4. **`docs/configuration.md`**: add this row after the `U2_BLOCKED_COMMANDS` row of the first table:
   `| \`U2_BASIC_FILES\` | Comma-separated glob patterns naming the files the BASIC tools may use | \`*BP,BP.*\` |`

5. **`docs/admin.md`**:
   - Insert this subsection directly before `## 3. Company sign-in (SSO)`:

```markdown
### Roles

| Role | Permissions |
|------|-------------|
| Viewer | `schema.read`, `records.read`, `query.run` |
| Analyst | Same as Viewer (retained for existing grants) |
| Developer | Analyst + `records.write`, `records.delete`, `tcl.run`, `subroutine.call`, `basic.read`, `basic.write`, `basic.compile` |
| Owner | Developer + `basic.catalog` |

The roles page lists the tools behind each permission. The BASIC permissions cover only files matching `U2_BASIC_FILES`. `basic.write`, `basic.compile` and `basic.catalog` are writes, so they are refused on a read-only connection and when `U2_READ_ONLY` is on. The `Imported access` role created at first start has no BASIC permissions.
```

   - Append these items to the numbered list in `## 8. Before each release: manual acceptance against real U2`:

```markdown
7. BASIC on UniVerse and on UniData:
   - `list_programs("BP")` marks compiled programs (UniVerse from `BP.O`, UniData from `_NAME`).
   - `read_program`, then `write_program` with its hash, saves the program.
   - `compile_program` reports `compiled` for a good program, and `failed` with the right line for a broken one. Check the markers listed in `src/u2_mcp/utils/basic_source.py`.
8. `catalog_program` on each product: the output shows a local catalog entry, and cataloging the same program a second time does not wait for a prompt.
9. On a file with more than 50,000 records (or a lower test limit), `list_programs` reports `truncated`, and the next `execute_query` is not limited by a leftover select list.
10. On an NLS-enabled account, check whether a program containing `ü` or `ÿ` in a string reads and saves back unchanged, or is refused with the mark-character message. Record which, in the CHANGELOG entry for the release.
```

6. **`docs/hardening.md`**: after the paragraph that ends "one tool call away from remote code execution, in the default configuration.", add:

```markdown
`execute_tcl` still refuses `BASIC`, `CATALOG` and `RUN`. Compiling and cataloging
are possible only through `compile_program` and `catalog_program`. Each needs its
own permission (`basic.compile`, `basic.catalog`) and is refused in read-only mode.
Each builds its command itself, from a file name matching `U2_BASIC_FILES` and
program names limited to letters, digits, `.`, `_` and `-`, and catalogs locally
only.
```

7. **`docs/what-is-mcp.md`**:
   - In the "Read-only mode" bullet, change "writes, deletes, transactions, and subroutine calls" to "writes, deletes, transactions, subroutine calls, and saving, compiling or cataloging BASIC programs".
   - Change the list item `- Call BASIC subroutines` in that section's capability list to `- Call BASIC subroutines, and read, edit, compile and catalog BASIC programs`.

- [ ] **Step 5: Check the wording, then run the tests**

Run: `git diff -U0 | grep -i copilot`
Expected: no output. This task adds no Copilot wording.

Run: `.venv/Scripts/python -m pytest tests/test_admin/test_roles_groups.py -q`
Expected: PASS.

- [ ] **Step 6: Run the full checks, plus the browser suite, then commit**

Run the Global Constraints checks, and `.venv/Scripts/python -m pytest -m e2e tests/e2e --browser chromium`, because the template changed.

```bash
git add src/u2_mcp/admin/templates/roles/edit.html tests/test_admin/test_roles_groups.py docs/tools.md README.md CHANGELOG.md docs/configuration.md docs/admin.md docs/hardening.md docs/what-is-mcp.md
git commit -m "docs(basic): tools reference, roles table, configuration, acceptance checks

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

## Self-review (done when writing the plan)

- **Spec coverage:**

  | Spec item | Task |
  |-----------|------|
  | Decisions 1–7, 11 and 12; `U2_BASIC_FILES`; the permission map | Task 1 |
  | Decisions 4 and 5, Decision 14, and the read tools | Task 2 |
  | Decisions 6–9 for saving | Task 3 |
  | Decisions 9–13 for compile and catalog | Task 4 |
  | Decision 15, team-mode permissions, the global and per-connection read-only refusals, the e2e journey | Task 5 |
  | Decision 17 (roles page), docs, manual acceptance | Task 6 |
  | Decision 16 (no role change) | Task 1, whose tests leave `BUILTIN_ROLES` untouched; the existing `test_only_owner_can_catalog_basic` and `test_bootstrap` keep it |

- **Placeholder scan:** none. Task 6, Step 4 computes the tool count with a command instead of hard-coding it.
- **Type consistency:**
  - `_read_problem`, `_change_problem(manager, file_name, program, verb)`, `_read_raw` and `_error(message, file_name, program=None, **extra)` are defined in Task 2 and used unchanged in Tasks 3 and 4.
  - `parse_compile_output` returns `{"status", "errors", "warnings"}`, consumed in Task 4.
  - `summarize_parameters` takes and returns `dict[str, Any]`.
  - `make_manager(**env)` is used in Tasks 2 and 4.
