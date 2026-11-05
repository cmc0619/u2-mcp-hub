"""The everyday admin pages' main paths in a real browser."""

from __future__ import annotations

import csv
import io
import re
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

from .conftest import Server
from .wizard import finish_wizard

pytestmark = pytest.mark.e2e


def test_users_create_grant_and_effective_access(page: Page, server: Server) -> None:
    finish_wizard(page, server)
    page.get_by_role("link", name="Users").click()
    page.get_by_role("link", name="Create a local user").click()
    page.get_by_label("Username").fill("dana")
    page.get_by_label("Password", exact=True).fill("dana's long passphrase")
    page.get_by_label("Password again").fill("dana's long passphrase")
    page.get_by_role("button", name="Create user").click()
    expect(page).to_have_url(re.compile(r"/admin/users/\d+\?notice=saved$"))

    page.get_by_label("Connection").select_option(label="Prod")
    page.get_by_label("Role", exact=True).select_option(label="Developer")
    page.get_by_role("button", name="Add grant").click()
    expect(page.locator(".notice")).to_have_text("Saved.")

    page.get_by_role("link", name="Effective access").click()
    expect(page.get_by_text("user grant (Developer)").first).to_be_visible()

    page.go_back()
    page.get_by_role("button", name="Disable").click()
    expect(page.get_by_role("button", name="Enable")).to_be_visible()


_SEED_GROUP = (
    "from u2_mcp.config import U2Config\n"
    "from u2_mcp.store.bootstrap import open_store_for_cli\n"
    "store = open_store_for_cli(U2Config())\n"
    "user = store.get_or_create_sso_user('sub-e2e', display_name='Sam')\n"
    "store.record_sso_login(user.id, ['eng-team'])\n"
)


def _seed_group(server: Server) -> None:
    """Write what a company sign-in would: a user and their group."""
    server.python(_SEED_GROUP)


def test_roles_clone_edit_and_delete(page: Page, server: Server) -> None:
    finish_wizard(page, server)
    page.get_by_role("link", name="Roles").click()
    page.get_by_role("link", name="Viewer", exact=True).click()
    page.get_by_role("button", name="Clone Viewer").click()
    expect(page.get_by_label("Name")).to_have_value("Copy of Viewer")

    page.get_by_label("Name").fill("Readers")
    expect(page.get_by_label("knowledge.read", exact=True)).to_have_count(0)
    expect(page.get_by_label("knowledge.write", exact=True)).to_have_count(0)
    page.get_by_label("query.run").uncheck()
    page.get_by_role("button", name="Save role").click()
    expect(page.locator(".notice")).to_have_text("Saved.")
    expect(page.get_by_label("query.run")).not_to_be_checked()

    page.get_by_role("button", name="Delete role").click()
    expect(page.locator(".notice")).to_have_text("Deleted.")
    expect(page.get_by_role("link", name="Readers")).to_have_count(0)


def test_groups_label_and_grant(page: Page, server: Server) -> None:
    finish_wizard(page, server)
    _seed_group(server)
    page.reload()  # the Groups tab shows once a group exists (no company sign-in here)
    page.get_by_role("link", name="Groups").click()
    page.get_by_role("link", name="eng-team").click()
    page.get_by_label("Label").fill("Engineering")
    page.get_by_role("button", name="Save label").click()
    expect(page.get_by_role("heading", name="Engineering")).to_be_visible()

    page.get_by_label("Connection").select_option(label="Prod")
    page.get_by_role("button", name="Add grant").click()
    expect(page.locator(".notice")).to_have_text("Saved.")
    expect(page.get_by_role("link", name="Prod")).to_be_visible()


def test_audit_export(page: Page, server: Server) -> None:
    finish_wizard(page, server)
    page.get_by_role("link", name="Audit").click()
    page.get_by_label("Kind").select_option(label="Admin changes")
    expect(page).to_have_url(re.compile(r"kind=admin"))  # the htmx swap has landed
    expect(page.locator("#audit-rows")).to_contain_text("setup.finish")
    expect(page.get_by_role("link", name="Export CSV")).to_have_attribute(
        "href", re.compile(r"kind=admin")
    )
    with page.expect_download() as download:
        page.get_by_role("link", name="Export CSV").click()
    text = Path(download.value.path()).read_text(encoding="utf-8")
    rows = list(csv.reader(io.StringIO(text)))
    assert rows[0][2] == "kind" and len(rows) > 1
    assert {row[2] for row in rows[1:]} == {"admin"}
    assert "setup.finish" in {row[4] for row in rows[1:]}


def test_settings_token_policy_caps_new_tokens(page: Page, server: Server) -> None:
    finish_wizard(page, server)
    page.get_by_role("link", name="Settings").click()
    page.get_by_label("Longest token lifetime, in days").fill("30")
    page.get_by_role("button", name="Save token policy").click()
    expect(page.locator(".notice")).to_have_text("Saved.")
    page.get_by_role("button", name="Turn off sign-in for people who are not admins").click()
    expect(
        page.get_by_role("button", name="Turn on sign-in for people who are not admins")
    ).to_be_visible()

    page.get_by_role("link", name="My access").click()
    expect(page.get_by_label("Lifetime in days")).to_have_value("30")
    expect(page.get_by_text("At most 30 days on this server.")).to_be_visible()
