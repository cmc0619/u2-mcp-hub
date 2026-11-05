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
# Words CATALOG and BASIC read as options when they stand where a name does, so a
# program may not be called one (compared without regard to case).
RESERVED_PROGRAM_NAMES = frozenset(
    {"DIRECT", "GLOBAL", "FORCE", "LOCAL", "NEWVERSION", "COMPLETE", "DEBUG", "LIST", "XREF"}
)
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
    "uvcs": {
        "failed": ("errors detected", "no object code"),
        "compiled": ("compilation complete",),
    },
    "udcs": {
        "failed": ("compilation failed", "syntax error"),
        "compiled": ("compilation finished",),
    },
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
        if kind == "program" and value.upper() in RESERVED_PROGRAM_NAMES:
            return f"program cannot be named {value}: it is a CATALOG/BASIC keyword"
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
