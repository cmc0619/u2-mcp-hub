"""The permission catalog is the vocabulary every access decision is made in."""

from u2_mcp.permissions import (
    ADMIN_ONLY,
    ANY_GRANT,
    BUILTIN_ROLES,
    PERMISSIONS,
    TOOL_PERMISSIONS,
    UNSCOPED_TOOLS,
    WRITE_PERMISSIONS,
    is_write,
    unmapped_tools,
)


def test_every_mapped_permission_exists() -> None:
    for tool, permission in TOOL_PERMISSIONS.items():
        assert permission in (ANY_GRANT, ADMIN_ONLY) or permission in PERMISSIONS, tool


def test_write_permissions_are_real_permissions() -> None:
    assert set(PERMISSIONS) >= WRITE_PERMISSIONS


def test_reading_is_not_writing() -> None:
    for permission in ("schema.read", "records.read", "query.run", ANY_GRANT):
        assert not is_write(permission)
    for permission in ("records.write", "records.delete", "tcl.run", "basic.compile"):
        assert is_write(permission)


def test_builtin_roles_only_use_known_permissions() -> None:
    for role, permissions in BUILTIN_ROLES.items():
        assert set(permissions) <= set(PERMISSIONS), role


def test_builtin_roles_each_extend_the_one_before() -> None:
    viewer, developer, owner = (
        set(BUILTIN_ROLES[name]) for name in ("Viewer", "Developer", "Owner")
    )
    assert viewer < developer < owner


def test_knowledge_uses_baseline_access_not_separate_permissions() -> None:
    assert not any(p.startswith("knowledge.") for p in PERMISSIONS)
    for name in (
        "list_knowledge",
        "get_all_knowledge",
        "get_knowledge_topic",
        "search_knowledge",
        "save_knowledge",
    ):
        assert TOOL_PERMISSIONS[name] == ANY_GRANT
    # Shared notes are removed only by an admin, whatever role grants the connection.
    assert TOOL_PERMISSIONS["delete_knowledge"] == ADMIN_ONLY
    assert ADMIN_ONLY not in PERMISSIONS


def test_transaction_status_is_baseline_but_mutation_requires_write() -> None:
    assert TOOL_PERMISSIONS["get_transaction_status"] == ANY_GRANT
    for name in ("begin_transaction", "commit_transaction", "rollback_transaction"):
        assert TOOL_PERMISSIONS[name] == "records.write"


def test_viewer_cannot_write_anything() -> None:
    assert not set(BUILTIN_ROLES["Viewer"]) & WRITE_PERMISSIONS


def test_only_owner_can_catalog_basic() -> None:
    holders = [name for name, perms in BUILTIN_ROLES.items() if "basic.catalog" in perms]
    assert holders == ["Owner"]


def test_unmapped_tools_names_strays() -> None:
    assert unmapped_tools(["read_record", "list_connections", "brand_new_tool"]) == [
        "brand_new_tool"
    ]


def test_list_connections_is_the_only_unscoped_tool() -> None:
    assert frozenset({"list_connections"}) == UNSCOPED_TOOLS
    assert "list_connections" not in TOOL_PERMISSIONS


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
