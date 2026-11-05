"""What a person can be allowed to do, and which tool needs which permission.

Every tool maps to exactly one permission. That one-to-one rule is what makes the
admin UI's checkboxes honest: ticking "records.read" grants precisely the tools
listed against it, and a new tool cannot appear without someone deciding which
box it belongs under -- the server refuses to start otherwise (see guard.py).
"""

from __future__ import annotations

from collections.abc import Iterable

PERMISSIONS: tuple[str, ...] = (
    "schema.read",
    "records.read",
    "query.run",
    "records.write",
    "records.delete",
    "tcl.run",
    "subroutine.call",
    "basic.read",
    "basic.write",
    "basic.compile",
    "basic.catalog",
)

# Refused on a read-only connection and under U2_READ_ONLY, whatever the role says.
# Read-only protects the U2 database, not notes in this server's own store.
WRITE_PERMISSIONS: frozenset[str] = frozenset(
    {
        "records.write",
        "records.delete",
        "tcl.run",
        "subroutine.call",
        "basic.write",
        "basic.compile",
        "basic.catalog",
    }
)

# Session housekeeping and database knowledge need any grant on the connection.
ANY_GRANT = "connection.use"

# Notes are shared by everyone who can reach a database, so removing them needs
# an admin (and any grant on the connection). It is not a role permission: no
# role can hand it out.
ADMIN_ONLY = "admin"

TOOL_PERMISSIONS: dict[str, str] = {
    # schema.read
    "list_files": "schema.read",
    # Reads the catalog with MAP, never CATALOG, so listing is inspection, not code.
    "list_catalog": "schema.read",
    "get_file_info": "schema.read",
    "list_dictionary": "schema.read",
    "get_field_definition": "schema.read",
    "describe_file": "schema.read",
    "analyze_file_structure": "schema.read",
    "get_account_info": "schema.read",
    # records.read
    "read_record": "records.read",
    "read_records": "records.read",
    "export_to_json": "records.read",
    "export_to_csv": "records.read",
    # query.run
    "execute_query": "query.run",
    "get_select_list": "query.run",
    "validate_query": "query.run",
    # records.write
    "write_record": "records.write",
    "update_value": "records.write",
    "begin_transaction": "records.write",
    "commit_transaction": "records.write",
    "rollback_transaction": "records.write",
    # records.delete
    "delete_record": "records.delete",
    # tcl.run
    "execute_tcl": "tcl.run",
    # subroutine.call
    "call_subroutine": "subroutine.call",
    # knowledge
    "list_knowledge": ANY_GRANT,
    "get_all_knowledge": ANY_GRANT,
    "get_knowledge_topic": ANY_GRANT,
    "search_knowledge": ANY_GRANT,
    "save_knowledge": ANY_GRANT,  # replacing an existing topic needs an admin
    "delete_knowledge": ADMIN_ONLY,
    # basic: BASIC program source. Only files matching U2_BASIC_FILES are reachable, so
    # these never become a second way to read or write ordinary data.
    "list_programs": "basic.read",
    "read_program": "basic.read",
    "search_programs": "basic.read",
    "write_program": "basic.write",
    "compile_program": "basic.compile",
    "catalog_program": "basic.catalog",
    # session housekeeping
    "connect": ANY_GRANT,
    "disconnect": ANY_GRANT,
    "list_sessions": ANY_GRANT,
    "get_transaction_status": ANY_GRANT,
}

# Tools that are not about one connection. list_connections is how a caller
# learns which connections exist for them, so it needs only authentication.
UNSCOPED_TOOLS: frozenset[str] = frozenset({"list_connections"})

_VIEWER = ("schema.read", "records.read", "query.run")
_DEVELOPER = (
    *_VIEWER,
    "records.write",
    "records.delete",
    "tcl.run",
    "subroutine.call",
    "basic.read",
    "basic.write",
    "basic.compile",
)
_OWNER = (*_DEVELOPER, "basic.catalog")

BUILTIN_ROLES: dict[str, tuple[str, ...]] = {
    "Viewer": _VIEWER,
    "Developer": _DEVELOPER,
    "Owner": _OWNER,
}


def is_write(permission: str) -> bool:
    """Return whether a permission changes data or runs code."""
    return permission in WRITE_PERMISSIONS


def unmapped_tools(tool_names: Iterable[str]) -> list[str]:
    """Return the tools that have no permission assigned, sorted.

    Args:
        tool_names: Names of every registered tool

    Returns:
        Tools missing from both TOOL_PERMISSIONS and UNSCOPED_TOOLS
    """
    return sorted(
        name for name in tool_names if name not in TOOL_PERMISSIONS and name not in UNSCOPED_TOOLS
    )
