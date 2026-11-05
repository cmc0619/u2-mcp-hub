"""Database notes are shared through independently authorized access paths."""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import u2_mcp.server as server
from tests.mocks.mock_uopy import MockSession
from u2_mcp.identity import caller_for_user, use_caller
from u2_mcp.resources.knowledge import get_database_knowledge
from u2_mcp.store import install_store
from u2_mcp.store.crypto import SecretBox
from u2_mcp.store.db import DATABASE_FILENAME, open_database
from u2_mcp.store.knowledge import database_scope
from u2_mcp.store.repo import Store
from u2_mcp.tools.knowledge import (
    delete_knowledge,
    get_all_knowledge,
    get_knowledge_topic,
    list_knowledge,
    save_knowledge,
    search_knowledge,
)


@pytest.fixture
def alice(store: Store, mock_env: dict[str, str], mock_uopy: MockSession) -> Iterator[Any]:
    viewer = store.get_role_by_name("Viewer")
    assert viewer is not None
    user = store.get_or_create_sso_user("alice")
    for name, host, account in (
        ("Prod", "UVHOST01", "DEMO"),
        ("Personal", " uvhost01. ", " demo "),
        ("Test", "other-server", "DEMO"),
        ("Other account", "UVHOST01", "OTHER"),
    ):
        personal = name == "Personal"
        connection = store.add_connection(
            name=name,
            host=host,
            port=1,
            service="uvcs",
            account=account,
            login_mode="per_user" if personal else "shared",
            shared_user=None if personal else "svc",
            shared_password=None if personal else "pw",
            read_only=True,
        )
        store.add_grant(
            connection_id=connection.id,
            subject_type="user",
            subject_id=user.id,
            role_id=viewer.id,
        )
        if personal:
            store.set_u2_login(user.id, connection.id, "alice-db-login", "pw")
    install_store(store)
    try:
        with use_caller(caller_for_user(user, auth_method="token")):
            yield store
    finally:
        install_store(None)
        server.reset_connection_manager()


def _prod_id(store: Store) -> int:
    prod = store.get_connection_by_name("Prod")
    assert prod is not None
    return prod.id


def test_notes_saved_on_one_connection_are_not_seen_on_another(alice: Store) -> None:
    saved = save_knowledge("CUSTOMERS", "Holds customer master records", connection="Prod")
    assert "error" not in saved
    assert "Holds customer master records" in str(get_all_knowledge(connection="Prod"))
    assert "Holds customer master records" not in str(get_all_knowledge(connection="Test"))


def test_notes_live_in_the_settings_database_scoped_by_database(
    alice: Store, stdio_knowledge_database: Path
) -> None:
    save_knowledge("CUSTOMERS", "x", connection="Prod")

    with alice.locked() as conn:
        rows = conn.execute("SELECT scope, topic FROM knowledge").fetchall()
    assert [tuple(row) for row in rows] == [(database_scope("UVHOST01", "DEMO"), "CUSTOMERS")]
    assert not stdio_knowledge_database.exists()  # team mode never opens stdio's file


def test_deleting_a_connection_keeps_database_notes(alice: Store) -> None:
    save_knowledge("CUSTOMERS", "prod note", connection="Prod")
    save_knowledge("CUSTOMERS", "test note", connection="Test")

    alice.delete_connection(_prod_id(alice))

    with alice.locked() as conn:
        rows = conn.execute("SELECT content FROM knowledge").fetchall()
    assert {row[0] for row in rows} == {"prod note", "test note"}
    assert get_knowledge_topic("CUSTOMERS", connection="Personal")["content"] == "prod note"
    assert list_knowledge(connection="Test")["count"] == 1


def _make_alice_admin(store: Store) -> None:
    user = store.get_user_by_subject("alice")
    assert user is not None
    store.set_user_admin(user.id, True)


@pytest.mark.parametrize("global_read_only", [False, True])
def test_viewer_uses_all_six_tools_across_login_modes(alice: Store, global_read_only: bool) -> None:
    install_store(alice, global_read_only=global_read_only)
    assert save_knowledge("CUSTOMERS", "Customer master", connection="Prod")["status"] == "saved"
    assert get_knowledge_topic("CUSTOMERS", connection="Personal")["content"] == "Customer master"
    assert (
        save_knowledge("CUSTOMERS", "Field 1 is name", append=True, connection="Personal")["action"]
        == "appended"
    )
    server.reset_connection_manager()  # A later session, not a session-local cache.
    assert list_knowledge(connection="Personal")["count"] == 1
    assert get_all_knowledge(connection="Prod")["topic_count"] == 1
    assert search_knowledge("Field 1", connection="Prod")["match_count"] == 1
    assert list_knowledge(connection="Other account")["count"] == 0
    _make_alice_admin(alice)  # Deleting a shared note takes an admin.
    assert delete_knowledge("CUSTOMERS", connection="Personal")["status"] == "confirmation_required"
    assert get_knowledge_topic("CUSTOMERS", connection="Prod")["status"] == "found"
    assert delete_knowledge("CUSTOMERS", confirm=True, connection="Personal")["status"] == "deleted"
    assert list_knowledge(connection="Prod")["count"] == 0
    advertised = server.list_connections()
    assert "knowledge.read" not in str(advertised)
    assert "knowledge.write" not in str(advertised)


def test_rename_and_login_changes_do_not_fork_database_memory(alice: Store) -> None:
    save_knowledge("CUSTOMERS", "Customer master", connection="Prod")
    prod = alice.get_connection(_prod_id(alice))
    assert prod is not None
    alice.update_connection(
        prod.id,
        expected_version=prod.version,
        name="Renamed",
        host=prod.host,
        port=prod.port,
        service=prod.service,
        account=prod.account,
        ssl=prod.ssl,
        login_mode="per_user",
        shared_user=None,
        clear_shared_password=True,
        read_only=True,
        enabled=True,
        actor=None,
    )
    user = alice.get_user_by_subject("alice")
    assert user is not None
    alice.set_u2_login(user.id, prod.id, "another-db-login", "new-pw")
    assert get_knowledge_topic("CUSTOMERS", connection="Renamed")["content"] == "Customer master"
    assert get_knowledge_topic("CUSTOMERS", connection="Personal")["content"] == "Customer master"


def test_database_memory_survives_reopening_store_and_changing_caller(alice: Store) -> None:
    save_knowledge("CUSTOMERS", "Customer master", connection="Prod")
    bob = alice.get_or_create_sso_user("bob")
    personal = alice.get_connection_by_name("Personal")
    viewer = alice.get_role_by_name("Viewer")
    assert personal is not None and viewer is not None
    alice.add_grant(
        connection_id=personal.id, subject_type="user", subject_id=bob.id, role_id=viewer.id
    )
    alice.set_u2_login(bob.id, personal.id, "bob-db-login", "pw")
    conn = open_database(alice.data_dir / DATABASE_FILENAME)
    reopened = Store(conn, SecretBox("t" * 40), alice.data_dir)
    try:
        install_store(reopened)
        with use_caller(caller_for_user(bob, auth_method="token")):
            assert get_knowledge_topic("CUSTOMERS", connection="Personal")["content"] == (
                "Customer master"
            )
            assert (
                save_knowledge("CUSTOMERS", "Bob's discovery", append=True, connection="Personal")[
                    "action"
                ]
                == "appended"
            )
    finally:
        install_store(alice)
        conn.close()
    assert "Bob's discovery" in get_knowledge_topic("CUSTOMERS", connection="Prod")["content"]


def test_unauthorized_path_to_same_database_cannot_use_any_knowledge_tool(alice: Store) -> None:
    alice.add_connection(
        name="Hidden",
        host="UVHOST01",
        port=1,
        service="uvcs",
        account="DEMO",
        shared_user="hidden",
        shared_password="pw",
    )
    save_knowledge("CUSTOMERS", "Private database note", connection="Prod")
    results = [
        save_knowledge("CUSTOMERS", "overwrite", connection="Hidden"),
        get_knowledge_topic("CUSTOMERS", connection="Hidden"),
        list_knowledge(connection="Hidden"),
        get_all_knowledge(connection="Hidden"),
        search_knowledge("Private", connection="Hidden"),
        delete_knowledge("CUSTOMERS", confirm=True, connection="Hidden"),
    ]
    assert all(r == {"error": "unknown connection 'Hidden'"} for r in results)
    assert get_knowledge_topic("CUSTOMERS", connection="Prod")["content"] == "Private database note"


def test_any_grant_even_an_empty_custom_role_has_baseline_knowledge_access(alice: Store) -> None:
    role = alice.add_role("Connection only", [])
    prod = _prod_id(alice)
    grant = alice.grants_on_connection(prod)[0]
    alice.update_grant(grant.id, role_id=role.id)
    assert save_knowledge("CUSTOMERS", "note", connection="Prod")["status"] == "saved"


def test_the_resource_does_not_leak_notes_in_team_mode(alice: Store) -> None:
    save_knowledge("CUSTOMERS", "secret-ish note", connection="Prod")
    text = get_database_knowledge()
    assert "secret-ish note" not in text
    assert "list_knowledge" in text


class TestOnlyAdminsRemoveSharedNotes:
    """Notes are shared by everyone on a database, so a Viewer cannot take one away."""

    def test_a_viewer_cannot_delete_a_note(self, alice: Store) -> None:
        save_knowledge("CUSTOMERS", "Customer master", connection="Prod")

        result = delete_knowledge("CUSTOMERS", confirm=True, connection="Prod")

        assert "only an admin" in result["error"]
        assert get_knowledge_topic("CUSTOMERS", connection="Prod")["content"] == "Customer master"

    def test_a_viewer_cannot_empty_a_note_by_replacing_it(self, alice: Store) -> None:
        save_knowledge("CUSTOMERS", "Customer master", connection="Prod")

        result = save_knowledge("CUSTOMERS", "", connection="Prod")

        assert result["status"] == "error"
        assert "append=True" in result["error"]
        assert get_knowledge_topic("CUSTOMERS", connection="Prod")["content"] == "Customer master"

    def test_a_viewer_can_still_add_to_a_note(self, alice: Store) -> None:
        save_knowledge("CUSTOMERS", "Customer master", connection="Prod")

        save_knowledge("CUSTOMERS", "Key is the customer number", append=True, connection="Prod")

        content = get_knowledge_topic("CUSTOMERS", connection="Prod")["content"]
        assert content == "Customer master\n\nKey is the customer number"

    def test_an_admin_can_replace_and_delete(self, alice: Store) -> None:
        save_knowledge("CUSTOMERS", "Customer master", connection="Prod")
        _make_alice_admin(alice)

        assert save_knowledge("CUSTOMERS", "Rewritten", connection="Prod")["status"] == "saved"
        assert get_knowledge_topic("CUSTOMERS", connection="Prod")["content"] == "Rewritten"
        assert delete_knowledge("CUSTOMERS", confirm=True, connection="Prod")["status"] == "deleted"

    def test_an_admin_still_needs_a_grant_on_the_connection(self, alice: Store) -> None:
        """Admin rights do not reveal connections the admin has no grant on."""
        _make_alice_admin(alice)

        result = delete_knowledge("CUSTOMERS", confirm=True, connection="Nowhere")

        assert "unknown connection" in result["error"]
