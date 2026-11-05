"""Who may use the BASIC tools where, and what the audit keeps of the source."""

from collections.abc import Iterator
from typing import Any

import pytest

import u2_mcp.server as server
from tests.mocks.mock_uopy import MockSession
from u2_mcp.guard import summarize_parameters
from u2_mcp.identity import caller_for_user, use_caller
from u2_mcp.store import install_store
from u2_mcp.store.repo import Store
from u2_mcp.tools.basic import (
    catalog_program,
    compile_program,
    list_programs,
    read_program,
    search_programs,
    write_program,
)
from u2_mcp.utils.basic_source import source_hash

BP = {"file_name": "BP", "program": "HELLO"}


@pytest.fixture
def team(
    store: Store, mock_env: dict[str, str], mock_uopy: MockSession
) -> Iterator[dict[str, Any]]:
    """Dev (read-write) and Live (read-only); viv=Viewer, dee=Developer, oona=Owner on both."""

    def role(name: str) -> int:
        found = store.get_role_by_name(name)
        assert found is not None
        return found.id

    def connection(name: str, *, read_only: bool) -> int:
        return store.add_connection(
            name=name,
            host=f"{name.lower()}.example",
            port=1,
            service="uvcs",
            account="DEV",
            shared_user="svc",
            shared_password="pw",
            read_only=read_only,
        ).id

    connections = (connection("Dev", read_only=False), connection("Live", read_only=True))
    people = {}
    for person, role_name in (("viv", "Viewer"), ("dee", "Developer"), ("oona", "Owner")):
        user = store.get_or_create_sso_user(person)
        for connection_id in connections:
            store.add_grant(
                connection_id=connection_id,
                subject_type="user",
                subject_id=user.id,
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


def test_the_audit_row_keeps_no_program_text(team: dict[str, Any]) -> None:
    secret = "CRT 'SECRET-WRITE-TEXT'"
    with use_caller(team["people"]["dee"]):
        read = read_program(**BP, connection="Dev")
        write_program(
            **BP, source=secret, expected_hash=read["hash"], confirm=True, connection="Dev"
        )

    rows = team["store"].recent_audit()
    assert "SECRET-WRITE-TEXT" not in str(rows)
    written = next(row for row in rows if row["action"] == "write_program")
    assert set(written["params"]["source"]) == {"chars", "lines", "sha256"}
