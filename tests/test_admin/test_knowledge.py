"""Persisted database knowledge is browseable and editable only by admins."""

from collections.abc import Iterator
from urllib.parse import urlencode

import pytest
from starlette.testclient import TestClient

from u2_mcp.admin.context import AdminContext
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import finish_setup
from u2_mcp.store.db import open_database
from u2_mcp.store.knowledge import database_scope
from u2_mcp.utils.knowledge import KnowledgeStore

from .helpers import PASSWORD, admin_client, csrf_from, sign_in


@pytest.fixture
def client(ctx: AdminContext) -> Iterator[TestClient]:
    finish_setup(ctx.store)
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    with admin_client(ctx) as client:
        sign_in(client)
        yield client


def seed(ctx: AdminContext, host: str = " HOST. ", account: str = " DEMO ") -> KnowledgeStore:
    ctx.store.add_connection(name=account, host=host, account=account, port=1, service="uvcs")
    notes = KnowledgeStore(ctx.store.locked, database_scope(host, account))
    notes.save_topic("Customers / & ?", "Keep\nRemove this line\nLast")
    return notes


def url(notes: KnowledgeStore, action: str = "topic") -> str:
    return (
        "/admin/knowledge/"
        + action
        + "?"
        + urlencode({"scope": notes.scope, "topic": "Customers / & ?"})
    )


def revision(page: str) -> str:
    import re

    match = re.search(r'name="revision" value="([^"]+)"', page)
    assert match
    return match[1]


def test_lists_persisted_scopes_even_without_connections(
    client: TestClient, ctx: AdminContext
) -> None:
    notes = seed(ctx)
    connection = ctx.store.list_connections()[0]
    ctx.store.delete_connection(connection.id)
    ctx.store.add_connection(name="Empty", host="empty", account="empty", port=1, service="uvcs")
    page = client.get("/admin/knowledge")
    assert page.status_code == 200
    assert "host / demo" in page.text and "empty / empty" not in page.text
    assert notes.get_topic("Customers / & ?") is not None


def test_multiline_edit_persists_and_is_scope_isolated(
    client: TestClient, ctx: AdminContext
) -> None:
    notes = seed(ctx)
    other = seed(ctx, account="OTHER")
    page = client.get(url(notes)).text
    response = client.post(
        url(notes),
        data={"csrf_token": csrf_from(page), "revision": revision(page), "content": "Keep\nLast"},
    )
    assert response.status_code == 200 and "Saved." in response.text
    assert notes.get_topic("Customers / & ?") == "Keep\nLast"
    assert other.get_topic("Customers / & ?") == "Keep\nRemove this line\nLast"
    conn = open_database(ctx.store.data_dir / "u2-mcp.db")
    try:
        assert (
            conn.execute(
                "SELECT content FROM knowledge WHERE scope = ?", (notes.scope,)
            ).fetchone()[0]
            == "Keep\nLast"
        )
    finally:
        conn.close()
    assert ctx.store.recent_audit(1)[0]["action"] == "knowledge.update"


@pytest.mark.parametrize("action", ["topic", "delete"])
def test_stale_writes_are_refused(client: TestClient, ctx: AdminContext, action: str) -> None:
    notes = seed(ctx)
    page = client.get(url(notes, action)).text
    notes.save_topic("Customers / & ?", "New MCP edit")
    response = client.post(
        url(notes, action),
        data={"csrf_token": csrf_from(page), "revision": revision(page), "content": "My draft"},
    )
    assert response.status_code == 409
    assert "Someone else changed this topic" in response.text
    assert notes.get_topic("Customers / & ?") == "New MCP edit"
    if action == "topic":
        assert "My draft" in response.text


def test_revision_cannot_be_used_on_another_scope(client: TestClient, ctx: AdminContext) -> None:
    notes = seed(ctx)
    other = seed(ctx, account="OTHER")
    page = client.get(url(notes)).text
    response = client.post(
        url(other),
        data={"csrf_token": csrf_from(page), "revision": revision(page), "content": "Wrong scope"},
    )
    assert response.status_code == 409
    assert other.get_topic("Customers / & ?") == "Keep\nRemove this line\nLast"


def test_delete_confirmation_and_missing_empty_states(
    client: TestClient, ctx: AdminContext
) -> None:
    assert "No knowledge has been saved yet." in client.get("/admin/knowledge").text
    notes = seed(ctx)
    page = client.get(url(notes, "delete")).text
    assert "Cancel" in page and "cannot be undone" in page
    assert notes.get_topic("Customers / & ?") is not None
    response = client.post(
        url(notes, "delete"), data={"csrf_token": csrf_from(page), "revision": revision(page)}
    )
    assert response.status_code == 200 and "Deleted." in response.text
    assert notes.get_topic("Customers / & ?") is None
    assert "No knowledge has been saved yet." in response.text
    assert client.get(url(notes)).status_code == 404
    assert client.get("/admin/knowledge?scope=missing").status_code == 404
    assert ctx.store.recent_audit(1)[0]["action"] == "knowledge.delete"


def test_untrusted_content_is_text_not_html(client: TestClient, ctx: AdminContext) -> None:
    notes = seed(ctx)
    notes.save_topic("Customers / & ?", '</textarea><script>alert("bad")</script>\n# Markdown')
    page = client.get(url(notes)).text
    assert "<script>alert" not in page
    assert "&lt;/textarea&gt;&lt;script&gt;" in page and "# Markdown" in page
    assert "<script>alert" not in client.get(url(notes, "delete")).text


@pytest.mark.parametrize("action", ["topic", "delete"])
def test_csrf_required(client: TestClient, ctx: AdminContext, action: str) -> None:
    notes = seed(ctx)
    assert client.post(url(notes, action), data={"content": "bad"}).status_code == 403
    assert notes.get_topic("Customers / & ?") == "Keep\nRemove this line\nLast"


def test_non_admin_cannot_list_read_or_write(client: TestClient, ctx: AdminContext) -> None:
    notes = seed(ctx)
    ctx.store.add_local_user("bob", password_hash=hash_password(PASSWORD))
    with admin_client(ctx) as bob:
        sign_in(bob, "bob")
        page = bob.get("/admin/me").text
        token = csrf_from(page)
        assert 'href="/admin/knowledge"' not in page
        for path in ("/admin/knowledge", url(notes), url(notes, "delete")):
            response = bob.get(path, follow_redirects=False)
            assert response.status_code == 303 and response.headers["location"] == "/admin/me"
            assert "Customers" not in response.text and notes.scope not in response.text
        for path in (url(notes), url(notes, "delete")):
            assert bob.post(path, data={"csrf_token": token}).status_code == 403
    assert notes.get_topic("Customers / & ?") == "Keep\nRemove this line\nLast"


def test_blank_content_is_saved_without_deleting_topic(
    client: TestClient, ctx: AdminContext
) -> None:
    notes = seed(ctx)
    page = client.get(url(notes)).text
    response = client.post(
        url(notes),
        data={"csrf_token": csrf_from(page), "revision": revision(page), "content": ""},
    )
    assert response.status_code == 200 and "Saved." in response.text
    assert notes.get_topic("Customers / & ?") == ""
    assert len(notes.list_topics()) == 1


@pytest.mark.parametrize("action", ["topic", "delete"])
def test_deleted_while_open_does_not_recreate_topic(
    client: TestClient, ctx: AdminContext, action: str
) -> None:
    notes = seed(ctx)
    page = client.get(url(notes, action)).text
    notes.delete_topic("Customers / & ?")
    response = client.post(
        url(notes, action),
        data={"csrf_token": csrf_from(page), "revision": revision(page), "content": "Late"},
    )
    assert response.status_code == 404
    assert not notes.list_topics()


class TestTopicSorting:
    """The topic list sorts by name or by when it was last updated, either way."""

    @pytest.fixture
    def scope(self, ctx: AdminContext) -> str:
        ctx.store.add_connection(name="Dev", host="host", account="DEV", port=1, service="uvcs")
        scope = database_scope("host", "DEV")
        with ctx.store.locked() as conn:
            for topic, updated in (("Beta", 300), ("alpha", 100), ("Gamma", 200)):
                conn.execute(
                    "INSERT INTO knowledge VALUES (?, ?, ?, 'x', ?)",
                    (scope, topic, topic.lower(), updated),
                )
        return scope

    @staticmethod
    def order(page: str) -> list[str]:
        import re

        return re.findall(r"<td>(alpha|Beta|Gamma)</td>", page)

    def get(self, client: TestClient, scope: str, **params: str) -> str:
        response = client.get("/admin/knowledge?" + urlencode({"scope": scope, **params}))
        assert response.status_code == 200
        return response.text

    def test_topics_start_a_to_z(self, client: TestClient, scope: str) -> None:
        page = self.get(client, scope)

        assert self.order(page) == ["alpha", "Beta", "Gamma"]
        assert 'aria-sort="ascending"' in page

    @pytest.mark.parametrize(
        ("sort", "order", "expected"),
        [
            ("topic", "desc", ["Gamma", "Beta", "alpha"]),
            ("updated", "desc", ["Beta", "Gamma", "alpha"]),
            ("updated", "asc", ["alpha", "Gamma", "Beta"]),
        ],
    )
    def test_either_column_sorts_either_way(
        self, client: TestClient, scope: str, sort: str, order: str, expected: list[str]
    ) -> None:
        assert self.order(self.get(client, scope, sort=sort, order=order)) == expected

    def test_clicking_the_sorted_column_reverses_it(self, client: TestClient, scope: str) -> None:
        page = self.get(client, scope, sort="updated", order="desc")

        assert "sort=updated&amp;order=asc" in page
        assert "sort=topic&amp;order=asc" in page  # the other column starts A to Z

    def test_unknown_sort_falls_back_to_topic(self, client: TestClient, scope: str) -> None:
        page = self.get(client, scope, sort="content; DROP", order="sideways")

        assert self.order(page) == ["alpha", "Beta", "Gamma"]
