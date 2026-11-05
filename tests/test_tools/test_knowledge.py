"""Tests for the knowledge tools in stdio mode (notes in ~/.u2-mcp/u2-mcp.db).

What the assistant learns about a database is read again in a later session, so
a mistake here is durable. These tests cover the round trip, exact topic names,
the per-account scope and deletion.
"""

import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

import u2_mcp.utils.knowledge as knowledge_module
from u2_mcp.store.knowledge import database_scope
from u2_mcp.tools.knowledge import (
    delete_knowledge,
    get_all_knowledge,
    get_knowledge_topic,
    list_knowledge,
    save_knowledge,
    search_knowledge,
)


@pytest.fixture(autouse=True)
def stdio(mock_env: dict[str, str]) -> Iterator[None]:
    from u2_mcp.server import reset_connection_manager

    reset_connection_manager()
    try:
        yield
    finally:
        reset_connection_manager()


class TestSavingAndRecall:
    """The round trip that makes the feature worth having."""

    def test_saved_knowledge_lands_in_stdios_own_database(
        self, stdio_knowledge_database: Path
    ) -> None:
        save_knowledge("AR-CUST file", "Customer master file. Key is customer number.")
        knowledge_module.close_stdio_database()

        conn = sqlite3.connect(stdio_knowledge_database)
        rows = conn.execute("SELECT scope, topic, content FROM knowledge").fetchall()
        conn.close()
        assert rows == [
            (
                database_scope("test-host.example.com", "TEST"),
                "AR-CUST file",
                "Customer master file. Key is customer number.",
            )
        ]

    def test_a_saved_topic_can_be_read_back(self) -> None:
        save_knowledge("AR-CUST file", "Customer master file.")

        result = get_knowledge_topic("AR-CUST file")

        assert result["content"] == "Customer master file."

    def test_topics_are_listed(self) -> None:
        save_knowledge("AR-CUST file", "Customer master.")
        save_knowledge("Date formats", "Internal format; use D2/ conversion.")

        topics = list_knowledge()["topics"]

        assert [t["topic"] for t in topics] == ["AR-CUST file", "Date formats"]
        assert topics[0]["summary"] == "Customer master."

    def test_everything_can_be_retrieved_at_once_as_markdown(self) -> None:
        save_knowledge("AR-CUST file", "Customer master.")

        everything = get_all_knowledge()

        assert "## AR-CUST file" in everything["knowledge"]
        assert "Customer master." in everything["knowledge"]
        assert everything["topics"] == ["AR-CUST file"]

    def test_an_unknown_topic_reports_an_error(self) -> None:
        assert "error" in get_knowledge_topic("Never written")


class TestTopicNames:
    def test_names_match_ignoring_case_and_spacing(self) -> None:
        save_knowledge("AR-CUST file", "Key is customer number.")
        saved = save_knowledge("  ar-cust   FILE ", "Field 1 is name.", append=True)

        assert saved["topic"] == "AR-CUST file" and saved["action"] == "appended"
        assert len(list_knowledge()["topics"]) == 1
        assert "Field 1 is name." in get_knowledge_topic("ar-cust file")["content"]

    def test_similar_names_are_separate_topics(self) -> None:
        save_knowledge("AR-CUST - Customer Master", "Key is customer number.")
        save_knowledge("AR-CUST file", "Field 1 is name.")

        assert len(list_knowledge()["topics"]) == 2


class TestReplacingAndAppending:
    def test_saving_again_replaces_the_content(self) -> None:
        save_knowledge("AR-CUST file", "First guess.")
        save_knowledge("AR-CUST file", "Corrected understanding.")

        assert get_knowledge_topic("AR-CUST file")["content"] == "Corrected understanding."

    def test_appending_keeps_both(self) -> None:
        save_knowledge("AR-CUST file", "Key is customer number.")
        save_knowledge("AR-CUST file", "Field 1 is name.", append=True)

        content = get_knowledge_topic("AR-CUST file")["content"]
        assert content == "Key is customer number.\n\nField 1 is name."


class TestSearchAndDeletion:
    def test_search_finds_a_matching_topic(self) -> None:
        save_knowledge("AR-CUST file", "Customer master file. Key is customer number.")
        save_knowledge("Date formats", "Internal format; use D2/ conversion.")

        assert search_knowledge("customer number")["match_count"] == 1

    def test_search_without_matches_returns_nothing(self) -> None:
        save_knowledge("AR-CUST file", "Customer master file.")

        assert search_knowledge("nonexistent term")["match_count"] == 0

    def test_deleting_requires_confirmation(self) -> None:
        save_knowledge("AR-CUST file", "Customer master file.")

        assert delete_knowledge("AR-CUST file")["status"] == "confirmation_required"
        assert list_knowledge()["count"] == 1

    def test_a_confirmed_delete_removes_the_topic(self) -> None:
        save_knowledge("AR-CUST file", "Customer master file.")

        delete_knowledge("ar-cust file", confirm=True)

        assert list_knowledge()["count"] == 0

    def test_deleting_something_absent_reports_an_error(self) -> None:
        assert delete_knowledge("Never written", confirm=True)["status"] == "error"


class TestPerAccountNotes:
    def test_login_and_host_spelling_changes_keep_notes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from u2_mcp.server import reset_connection_manager

        save_knowledge("AR-CUST", "Customer master.")
        knowledge_module.close_stdio_database()
        monkeypatch.setenv("U2_HOST", "TEST-HOST.EXAMPLE.COM.")
        monkeypatch.setenv("U2_USER", "different-login")
        reset_connection_manager()

        assert get_knowledge_topic("AR-CUST")["content"] == "Customer master."

    def test_another_account_has_its_own_notes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from u2_mcp.server import reset_connection_manager

        save_knowledge("AR-CUST file", "Customer master.")
        monkeypatch.setenv("U2_ACCOUNT", "OTHER")
        reset_connection_manager()

        assert list_knowledge()["topics"] == []
        monkeypatch.setenv("U2_ACCOUNT", "TEST")
        reset_connection_manager()
        assert list_knowledge()["count"] == 1


class TestConcurrentSaves:
    def test_saves_at_once_all_survive(self) -> None:
        import threading

        store = knowledge_module.get_knowledge_store()
        threads = [
            threading.Thread(target=store.save_topic, args=(f"F{n:02d} file", f"note {n}"))
            for n in range(20)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(store.list_topics()) == 20
