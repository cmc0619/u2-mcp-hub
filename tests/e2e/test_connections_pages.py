"""The Connections pages in a real browser."""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import Page, expect

from .conftest import Server
from .wizard import fill_connection, finish_wizard, sign_in

pytestmark = pytest.mark.e2e

STALE = "Someone else changed this connection since you opened it. Reload to see their changes."


def test_two_admins_editing_the_same_connection(
    page: Page, other_page: Page, server: Server
) -> None:
    finish_wizard(page, server)
    page.get_by_role("link", name="Prod").click()
    edit_url = page.url

    other = other_page
    sign_in(other, server)
    other.goto(edit_url)

    # A changed host needs the password typed again, or the saved one would go there.
    page.get_by_label("Host").fill("first.example")
    page.get_by_label("Password", exact=True).fill("secret")
    page.get_by_role("button", name="Save", exact=True).click()
    expect(page.locator(".notice")).to_have_text("Saved.")

    other.get_by_label("Host").fill("second.example")
    other.get_by_label("Password", exact=True).fill("secret")
    other.get_by_role("button", name="Save", exact=True).click()
    expect(other.locator(".alert")).to_contain_text(STALE)

    other.goto(edit_url)
    expect(other.get_by_label("Host")).to_have_value("first.example")


def test_add_test_allow_writes_and_delete_a_connection(page: Page, server: Server) -> None:
    finish_wizard(page, server)

    page.get_by_role("link", name="Add a connection").click()
    fill_connection(page, name="Test", host="test.example", account="TEST")
    page.get_by_role("button", name="Test connection").click()
    expect(page.locator("#test-result")).to_contain_text("Test passed")
    page.get_by_role("button", name="Add connection").click()
    expect(page.locator(".notice")).to_have_text("Saved.")

    page.get_by_label("Read-only").uncheck()
    page.get_by_role("button", name="Save", exact=True).click()
    expect(page.locator(".notice")).to_have_text("Saved.")
    page.reload()  # Saved, not just shown.
    expect(page.get_by_label("Read-only")).not_to_be_checked()

    page.get_by_role("link", name="Delete this connection…").click()
    page.get_by_role("button", name="Delete Test").click()
    expect(page.locator(".notice")).to_have_text("Deleted.")
    expect(page.get_by_role("link", name="Test")).to_have_count(0)
    expect(page.get_by_role("link", name="Prod")).to_be_visible()


def test_sign_out_and_back_in(page: Page, server: Server) -> None:
    finish_wizard(page, server)

    page.get_by_role("button", name="Sign out").click()
    expect(page.locator(".notice")).to_have_text("You are signed out.")
    page.goto(server.url("/admin/connections"))
    expect(page).to_have_url(re.compile(r"/admin/sign-in\?next=/admin/connections$"))

    page.get_by_label("Username").fill("admin")
    page.get_by_label("Password").fill("a long admin passphrase")
    page.get_by_role("button", name="Sign in").click()
    expect(page).to_have_url(re.compile(r"/admin/connections$"))


def test_a_wrong_password_on_sign_in(page: Page, server: Server) -> None:
    finish_wizard(page, server)
    page.get_by_role("button", name="Sign out").click()

    page.get_by_label("Username").fill("admin")
    page.get_by_label("Password").fill("not the password")
    page.get_by_role("button", name="Sign in").click()

    expect(page.locator(".alert")).to_have_text("Wrong username or password.")
