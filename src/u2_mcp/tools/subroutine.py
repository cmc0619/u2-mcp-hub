"""BASIC subroutine integration tools for u2-mcp."""

import logging
import re
from typing import Any

from ..driver import get_driver
from ..guard import guarded
from ..server import get_connection_manager, mcp

logger = logging.getLogger(__name__)

# The pattern is matched here, never sent to the server, but stays a plain name glob.
_CATALOG_PATTERN = re.compile(r"[A-Za-z0-9._*-]{1,64}")

# UniVerse's MAP displays the system catalog space and changes nothing. CATALOG,
# which this tool used to run, is the verb that makes BASIC code live.
_LIST_CATALOG_COMMAND = "MAP"


@mcp.tool()
@guarded()
def call_subroutine(
    name: str,
    args: list[str] | None = None,
    num_args: int | None = None,
    connection: str | None = None,
) -> dict[str, Any]:
    """Call a cataloged BASIC subroutine with arguments.

    Executes a cataloged BASIC program and returns the results.
    Arguments are passed by reference, so output arguments will
    be returned in the response.

    Args:
        name: Name of the cataloged subroutine
        args: List of argument values to pass (input arguments).
              Arguments are passed as strings and converted by the subroutine.
        num_args: Total number of arguments the subroutine expects.
                  If not specified, uses len(args). Required if subroutine
                  has output-only arguments.
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        Dictionary containing:
        - status: success or error
        - args_out: List of argument values after subroutine execution
        - original_args: The input arguments that were passed

    Example:
        # Call GET.CUSTOMER.DATA with customer ID, returns data in args 2-3
        call_subroutine("GET.CUSTOMER.DATA", ["CUST001", "", ""], num_args=3)
    """
    manager = get_connection_manager()

    # Read-only refuses this outright, and this is the tool that most needs it to.
    #
    # A cataloged subroutine is arbitrary BASIC. It can WRITE, DELETE, CLEARFILE
    # or shell out, and nothing here can tell which one will -- the name is the
    # only thing this server sees. Every other write path checked read_only;
    # this one did not, so read-only mode disabled the tools that announce
    # themselves as writes while leaving open the one that could do anything
    # without saying so.
    #
    # The documentation said read-only "prevents all write operations". This is
    # what makes that true rather than nearly true.
    if manager.config.read_only:
        return {
            "error": (
                "Subroutine calls are disabled in read-only mode. A cataloged "
                "subroutine is arbitrary code and may write."
            ),
            "subroutine": name,
        }

    args = args or []
    actual_num_args = num_args if num_args is not None else len(args)

    if actual_num_args < len(args):
        return {
            "error": f"num_args ({actual_num_args}) cannot be less than args length ({len(args)})",
            "subroutine": name,
        }

    try:
        session = manager.get_session()

        # Create subroutine object with specified number of arguments
        sub = get_driver().Subroutine(name, actual_num_args, session=session)

        # Set input arguments
        for i, arg in enumerate(args):
            sub.set_arg(i, str(arg) if arg is not None else "")

        # Initialize remaining args as empty strings
        for i in range(len(args), actual_num_args):
            sub.set_arg(i, "")

        # Call the subroutine
        sub.call()

        # Collect output arguments
        args_out = [sub.get_arg(i) for i in range(actual_num_args)]

        return {
            "status": "success",
            "subroutine": name,
            "args_in": args,
            "args_out": args_out,
            "num_args": actual_num_args,
        }

    except Exception as e:
        logger.error(f"Error calling subroutine {name}: {e}")
        return {"error": str(e), "subroutine": name}


@mcp.tool()
@guarded()
def list_catalog(pattern: str = "*", connection: str | None = None) -> dict[str, Any]:
    """List programs in the UniVerse system catalog (read-only).

    Runs MAP, which displays the global catalog space without changing it; it
    never runs CATALOG, catalogs code or calls a program. Locally cataloged
    programs and UniData are not covered: on UniData this returns an error.
    Program names are read from MAP's printout; `raw_output` holds it whole.

    Args:
        pattern: Program name pattern (supports * wildcard), matched here.
                 Default "*" lists every cataloged program.
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        Dictionary containing the matching program names, their count and the
        MAP output.
    """
    if not _CATALOG_PATTERN.fullmatch(pattern):
        return {"error": "pattern may contain only letters, digits, '.', '_', '-' and '*'"}
    manager = get_connection_manager()
    if manager.config.service != "uvcs":
        return {
            "error": "list_catalog reads the UniVerse catalog (MAP) and is not available "
            "on UniData",
            "pattern": pattern,
        }

    try:
        output, return_code = manager.run_command(_LIST_CATALOG_COMMAND)
        if return_code < 0:
            return {"error": output.strip() or "MAP was rejected", "pattern": pattern}
        programs = [
            name
            for name in _parse_map_output(output)
            if pattern == "*" or _matches_pattern(name, pattern)
        ]
        return {
            "pattern": pattern,
            "programs": programs,
            "count": len(programs),
            "raw_output": output,
        }

    except Exception as e:
        logger.error(f"Error listing catalog: {e}")
        return {"error": str(e), "pattern": pattern}


# A catalog entry line starts with the catalogued name. Global names begin with
# '*', '-', '$' or '!'; names hold letters, digits, '_', '.' and '-'.
_MAP_ENTRY = re.compile(r"^([*$!\-A-Za-z0-9][*$!\w.\-]*)\s+\S")
_MAP_NOT_ENTRIES = ("CATALOG", "NAME", "TYPE", "ENTRIES", "MAP", "TOTAL")


def _parse_map_output(output: str) -> list[str]:
    """The catalogued names in MAP's printout: the first word of each entry line.

    Headings, rules, blank lines and summary lines are skipped.
    """
    names: list[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or set(stripped) <= set("-=* "):
            continue
        match = _MAP_ENTRY.match(stripped)
        if not match:
            continue
        name = match.group(1)
        upper = stripped.upper()
        if name.isdigit() or any(upper.startswith(word) for word in _MAP_NOT_ENTRIES):
            continue
        names.append(name)
    return names


def _matches_pattern(name: str, pattern: str) -> bool:
    """Check if name matches simple wildcard pattern.

    Args:
        name: String to check
        pattern: Pattern with * wildcards

    Returns:
        True if name matches pattern
    """
    import fnmatch

    return fnmatch.fnmatch(name.upper(), pattern.upper().replace("...", "*"))
