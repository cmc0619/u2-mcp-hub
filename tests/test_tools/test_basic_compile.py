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
