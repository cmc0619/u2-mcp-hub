"""Knowledge administration in a real browser, using only the isolated test database."""

import pytest
from playwright.sync_api import Page, expect

from .conftest import Server
from .wizard import finish_wizard

pytestmark = pytest.mark.e2e

SEED = """
from u2_mcp.config import U2Config
from u2_mcp.store.bootstrap import open_store_for_cli
from u2_mcp.store.knowledge import database_scope
from u2_mcp.utils.knowledge import KnowledgeStore
store = open_store_for_cli(U2Config())
connection = store.add_connection(
    name="Removed", host=" HOST. ", account=" DEMO ", port=1, service="uvcs"
)
notes = KnowledgeStore(store.locked, database_scope("host", "demo"))
notes.save_topic(
    "Customers / & ?", 'Keep\\nRemove this line\\n</textarea><script>window.injected=1</script>'
)
store.delete_connection(connection.id)
"""


def test_browse_edit_cancel_and_confirm_delete(page: Page, server: Server) -> None:
    finish_wizard(page, server)
    page.get_by_role("link", name="Knowledge", exact=True).click()
    expect(page.get_by_text("No knowledge has been saved yet.")).to_be_visible()
    server.python(SEED)
    page.reload()
    page.get_by_label("Server / account").select_option(label="host / demo (1 topics)")
    page.get_by_role("button", name="Review topics").click()
    page.get_by_role("link", name="Review Customers / & ?").click()
    expect(page.get_by_label("Content")).to_have_value(
        "Keep\nRemove this line\n</textarea><script>window.injected=1</script>"
    )
    assert page.evaluate("window.injected") is None
    page.get_by_label("Content").fill("Keep\nLast")
    page.get_by_role("button", name="Save topic").click()
    expect(page.locator(".notice")).to_have_text("Saved.")
    page.reload()
    expect(page.get_by_label("Content")).to_have_value("Keep\nLast")

    page.get_by_role("link", name="Delete topic", exact=True).click()
    expect(page.locator("pre")).to_have_text("Keep\nLast")
    page.get_by_role("link", name="Cancel", exact=True).click()
    expect(page.get_by_label("Content")).to_have_value("Keep\nLast")
    page.get_by_role("link", name="Delete topic", exact=True).click()
    page.get_by_role("button", name="Confirm delete topic").click()
    expect(page.locator(".notice")).to_have_text("Deleted.")
    expect(page.get_by_text("No knowledge has been saved yet.")).to_be_visible()


def test_browser_stale_edit_keeps_draft(page: Page, server: Server) -> None:
    finish_wizard(page, server)
    server.python(SEED)
    page.get_by_role("link", name="Knowledge", exact=True).click()
    page.get_by_label("Server / account").select_option(label="host / demo (1 topics)")
    page.get_by_role("button", name="Review topics").click()
    page.get_by_role("link", name="Review Customers / & ?").click()
    server.python(
        "from u2_mcp.config import U2Config\n"
        "from u2_mcp.store.bootstrap import open_store_for_cli\n"
        "from u2_mcp.store.knowledge import database_scope\n"
        "from u2_mcp.utils.knowledge import KnowledgeStore\n"
        "store = open_store_for_cli(U2Config())\n"
        "KnowledgeStore(store.locked, database_scope('host', 'demo')).save_topic("
        "'Customers / & ?', 'Concurrent edit')\n"
    )
    page.get_by_label("Content").fill("My unsaved draft")
    with page.expect_response(
        lambda r: "/knowledge/topic" in r.url and r.request.method == "POST"
    ) as r:
        page.get_by_role("button", name="Save topic").click()
    assert r.value.status == 409
    expect(page.get_by_role("alert")).to_contain_text("Someone else changed this topic")
    expect(page.get_by_label("Content")).to_have_value("My unsaved draft")
    page.get_by_role("link", name="reloading the saved topic").click()
    expect(page.get_by_label("Content")).to_have_value("Concurrent edit")
