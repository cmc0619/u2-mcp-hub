"""No tool runs without an access check, and each call reaches the right server."""

from collections.abc import Iterator
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

import u2_mcp.server as server
from tests.mocks.mock_uopy import MockSession
from u2_mcp.guard import LOCAL_CONNECTION_NAME, GuardError, check_tool_coverage, guarded
from u2_mcp.identity import LOCAL_CALLER, caller_for_user, use_caller
from u2_mcp.server import get_connection_manager
from u2_mcp.store import install_store
from u2_mcp.store.repo import Store


# Probe tools: real guarded functions whose bodies report where they ran.
@guarded()
def read_record(file_name: str, connection: str | None = None) -> dict[str, Any]:
    manager = get_connection_manager()
    return {"host": manager.config.host, "user": manager.credentials.user}


CALLS: list[str] = []


@guarded()
def write_record(file_name: str, connection: str | None = None) -> dict[str, Any]:
    CALLS.append(file_name)
    return {"written": file_name}


class TestCoverage:
    def test_every_registered_tool_is_guarded_or_unscoped(self) -> None:
        check_tool_coverage(server.mcp)

    def test_every_scoped_tool_accepts_a_connection_argument(self) -> None:
        for name, tool in server.mcp._tool_manager._tools.items():
            properties = tool.parameters.get("properties", {})
            if name == "list_connections":
                assert "connection" not in properties
            else:
                assert "connection" in properties, name

    def test_an_unguarded_tool_stops_startup(self) -> None:
        probe = FastMCP("probe")

        @probe.tool()
        def read_record(connection: str | None = None) -> dict[str, Any]:
            return {}

        with pytest.raises(GuardError, match="read_record is not guarded"):
            check_tool_coverage(probe)

    def test_an_unmapped_tool_stops_startup(self) -> None:
        probe = FastMCP("probe")

        @probe.tool()
        def brand_new_tool() -> dict[str, Any]:
            return {}

        with pytest.raises(GuardError, match="brand_new_tool has no permission"):
            check_tool_coverage(probe)

    def test_a_guarded_tool_must_take_a_connection(self) -> None:
        with pytest.raises(ValueError, match="'connection'"):

            @guarded()
            def read_record() -> dict[str, Any]:
                return {}

    def test_a_guarded_tool_must_have_a_permission(self) -> None:
        with pytest.raises(ValueError, match="TOOL_PERMISSIONS"):

            @guarded()
            def mystery(connection: str | None = None) -> dict[str, Any]:
                return {}


class TestLocalMode:
    """Stdio, and HTTP without U2_SECRET_KEY: one connection called 'default'."""

    def test_omitted_or_default_connection_runs(self, connection_manager: Any) -> None:
        assert read_record("X")["host"] == "test-host.example.com"
        assert read_record("X", connection="default")["host"] == "test-host.example.com"

    def test_any_other_name_is_unknown(self, connection_manager: Any) -> None:
        assert read_record("X", connection="Prod") == {"error": "unknown connection 'Prod'"}


@pytest.fixture
def team(
    store: Store, mock_env: dict[str, str], mock_uopy: MockSession
) -> Iterator[dict[str, Any]]:
    """Team mode with Prod (alice=Viewer, bob=Viewer) and Test (alice=Developer)."""

    def role(name: str) -> int:
        found = store.get_role_by_name(name)
        assert found is not None
        return found.id

    prod = store.add_connection(
        name="Prod",
        host="prod.example",
        port=1,
        service="uvcs",
        account="LIVE",
        shared_user="psvc",
        shared_password="p",
        read_only=False,
    ).id
    test = store.add_connection(
        name="Test",
        host="test.example",
        port=40000,
        service="uvcs",
        account="TRAIN",
        shared_user="tsvc",
        shared_password="t",
        ssl=True,
        read_only=False,
    ).id
    alice = store.get_or_create_sso_user("alice")
    bob = store.get_or_create_sso_user("bob")
    store.add_grant(
        connection_id=prod, subject_type="user", subject_id=alice.id, role_id=role("Viewer")
    )
    store.add_grant(
        connection_id=test, subject_type="user", subject_id=alice.id, role_id=role("Developer")
    )
    store.add_grant(
        connection_id=prod, subject_type="user", subject_id=bob.id, role_id=role("Viewer")
    )
    mock_uopy.add_file("CUSTOMERS", {"1": "SMITH"})
    install_store(store)
    CALLS.clear()
    try:
        yield {
            "alice": caller_for_user(alice, auth_method="token"),
            "bob": caller_for_user(bob, auth_method="token"),
            "session": mock_uopy,
        }
    finally:
        install_store(None)
        server.reset_connection_manager()


class TestTeamMode:
    def test_the_named_connection_is_the_one_reached(self, team: dict[str, Any]) -> None:
        with use_caller(team["alice"]):
            assert read_record("X", connection="Test") == {"host": "test.example", "user": "tsvc"}
            assert read_record("X", connection="Prod") == {"host": "prod.example", "user": "psvc"}

    def test_several_connections_require_a_choice(self, team: dict[str, Any]) -> None:
        with use_caller(team["alice"]):
            assert read_record("X") == {"error": "say which connection to use: Prod, Test"}

    def test_a_single_connection_needs_no_name(self, team: dict[str, Any]) -> None:
        with use_caller(team["bob"]):
            assert read_record("X")["host"] == "prod.example"

    def test_refusals_never_run_the_tool(self, team: dict[str, Any]) -> None:
        with use_caller(team["alice"]):
            refused = write_record("X", connection="Prod")
        assert refused == {"error": "you need records.write on Prod; ask an admin"}
        assert CALLS == []

    def test_hidden_connections_are_unknown(self, team: dict[str, Any]) -> None:
        with use_caller(team["bob"]):
            assert read_record("X", connection="Test") == {"error": "unknown connection 'Test'"}

    def test_an_unsigned_request_is_refused(self, team: dict[str, Any]) -> None:
        with use_caller(LOCAL_CALLER):
            assert read_record("X") == {"error": "this request is not signed in"}

    def test_list_connections_shows_only_mine(self, team: dict[str, Any]) -> None:
        with use_caller(team["bob"]):
            listed = server.list_connections()
        assert [c["name"] for c in listed["connections"]] == ["Prod"]
        assert listed["connections"][0]["roles"] == ["Viewer"]


@pytest.mark.asyncio
async def test_routing_holds_through_fastmcps_own_call_path(team: dict[str, Any]) -> None:
    """The guard's context must survive however FastMCP actually runs a tool."""
    session: MockSession = team["session"]
    arguments = {"file_name": "CUSTOMERS", "record_id": "1"}

    with use_caller(team["alice"]):
        await server.mcp.call_tool("read_record", {**arguments, "connection": "Test"})
        assert session.connect_kwargs["host"] == "test.example"
        assert session.connect_kwargs["user"] == "tsvc"
        assert session.connect_kwargs["port"] == 40000
        assert session.connect_kwargs["ssl"] is True

        await server.mcp.call_tool("read_record", {**arguments, "connection": "Prod"})
        assert session.connect_kwargs["host"] == "prod.example"
        assert session.connect_kwargs["ssl"] is False

    with use_caller(team["bob"]):
        result = await server.mcp.call_tool("read_record", {**arguments, "connection": "Test"})
    assert "unknown connection 'Test'" in str(result)
    assert session.connect_kwargs["host"] == "prod.example"  # bob never reached Test


def test_list_catalog_refuses_patterns_that_could_change_the_command(
    connection_manager: Any,
) -> None:
    from u2_mcp.tools.subroutine import list_catalog

    refused = list_catalog('BP" MYPROG')
    assert refused == {"error": "pattern may contain only letters, digits, '.', '_', '-' and '*'"}
    assert list_catalog("ORD*") != refused  # an ordinary pattern gets past the check


def test_list_connections_outside_team_mode_opens_nothing(mock_env: dict[str, str]) -> None:
    """Listing is not using: it takes no session slot."""
    server.reset_connection_manager()
    try:
        listed = server.list_connections()
        assert listed["connections"] == [
            {
                "name": LOCAL_CONNECTION_NAME,
                "account": "TEST",
                "read_only": False,
                "roles": [],
                "permissions": "all",
            }
        ]
        assert server.get_connection_registry().active_logins() == []
    finally:
        server.reset_connection_manager()


def test_a_refused_call_is_audited_and_never_runs(team: dict[str, Any], store: Store) -> None:
    with use_caller(team["alice"]):
        refused = write_record("X", connection="Prod")
    assert refused == {"error": "you need records.write on Prod; ask an admin"}
    assert CALLS == []

    row = store.recent_audit(1)[0]
    assert (row["action"], row["outcome"], row["kind"]) == ("write_record", "error", "tool")
    assert row["connection_id"] == store.get_connection_by_name("Prod").id
    assert row["actor_label"] == team["alice"].display_name


@pytest.mark.asyncio
async def test_an_allowed_call_runs_on_a_worker_thread_with_its_route(
    team: dict[str, Any], store: Store
) -> None:
    """The one path: guard, route and audit, all on the worker thread."""
    import threading

    from u2_mcp.routing import current_route
    from u2_mcp.threaded import ThreadedFastMCP

    seen: dict[str, Any] = {}

    @guarded()
    def read_record(file_name: str, connection: str | None = None) -> dict[str, Any]:
        route = current_route()
        seen["thread"] = threading.current_thread()
        seen["route"] = route.connection.name if route else None
        return {"ok": True}

    probe = ThreadedFastMCP("probe")
    probe.tool()(read_record)
    with use_caller(team["alice"]):
        await probe.call_tool("read_record", {"file_name": "X", "connection": "Test"})

    assert seen["thread"] is not threading.main_thread()
    assert seen["route"] == "Test"
    row = store.recent_audit(1)[0]
    assert (row["action"], row["outcome"]) == ("read_record", "ok")
    assert row["connection_id"] == store.get_connection_by_name("Test").id
    assert row["params"] == {"file_name": "X", "connection": "Test"}


def test_list_connections_is_audited(team: dict[str, Any], store: Store) -> None:
    with use_caller(team["bob"]):
        server.list_connections()
    assert store.recent_audit(1)[0]["action"] == "list_connections"
