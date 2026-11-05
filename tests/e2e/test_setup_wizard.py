"""The setup wizard in a real browser: the part of UOFastMCP that did not work."""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import Page, expect

from tests.mocks import sim_driver

from .conftest import Server
from .wizard import (
    ADMIN_PASSWORD,
    ADMIN_USER,
    create_admin,
    fill_connection,
    finish_wizard,
    reach_done,
)

pytestmark = pytest.mark.e2e

CONFIRM_HTTPS = "I will reach the admin site over https from now on"


def test_the_whole_wizard_from_an_empty_data_directory(page: Page, server: Server) -> None:
    create_admin(page, server)

    fill_connection(page)
    page.get_by_role("button", name="Test connection").click()
    expect(page.locator("#test-result")).to_contain_text(
        f"Test passed: Connected to PROD on u2.example. COUNT VOC: {sim_driver.COUNT_VOC_RESPONSE}"
    )
    page.get_by_role("button", name="Save and continue").click()

    expect(page.locator(".warning")).to_contain_text("This address is not https.")
    page.get_by_label("Server address").fill("https://u2.example.com")
    page.get_by_role("button", name="Save and continue").click()
    expect(page.locator("#e-public_url")).to_contain_text("You are on http now.")
    page.get_by_label("Server address").fill("https://u2.example.com")
    page.get_by_label(CONFIRM_HTTPS).check()  # this browser is on http
    page.get_by_role("button", name="Save and continue").click()
    expect(page).to_have_url(re.compile(r"/admin/setup/sso$"))
    page.get_by_role("button", name="Skip this step").click()

    expect(page.locator("pre")).to_contain_text('"url": "https://u2.example.com/"')
    expect(page.get_by_text("Prod (u2.example, PROD)")).to_be_visible()
    page.get_by_role("button", name="Finish setup").click()

    expect(page.locator(".notice")).to_have_text("Setup is finished.")
    expect(page.get_by_role("link", name="Prod")).to_be_visible()
    page.goto(server.url("/admin/setup"))
    expect(page).to_have_url(re.compile(r"/admin/connections$"))


def test_refresh_and_back_at_every_step(page: Page, server: Server) -> None:
    create_admin(page, server)
    page.reload()
    expect(page).to_have_url(re.compile(r"/admin/setup/connection$"))

    fill_connection(page, host="saved.example")
    page.get_by_role("button", name="Save and continue").click()
    expect(page).to_have_url(re.compile(r"/admin/setup/server_address$"))
    page.reload()
    expect(page).to_have_url(re.compile(r"/admin/setup/server_address$"))

    page.go_back()
    expect(page).to_have_url(re.compile(r"/admin/setup/connection$"))
    expect(page.get_by_label("Host")).to_have_value("saved.example")

    page.get_by_role("link", name="Admin account").click()
    expect(page.get_by_text("The admin account is created")).to_be_visible()

    page.get_by_role("link", name="Server address").click()
    page.get_by_label("Server address").fill("https://u2.example.com")
    page.get_by_label(CONFIRM_HTTPS).check()  # this browser is on http
    page.get_by_role("button", name="Save and continue").click()
    expect(page).to_have_url(re.compile(r"/admin/setup/sso$"))
    page.reload()
    expect(page).to_have_url(re.compile(r"/admin/setup/sso$"))
    page.get_by_role("button", name="Skip this step").click()
    expect(page).to_have_url(re.compile(r"/admin/setup/done$"))
    page.reload()
    expect(page).to_have_url(re.compile(r"/admin/setup/done$"))

    page.go_back()
    expect(page).to_have_url(re.compile(r"/admin/setup/sso$"))
    page.go_back()
    expect(page.get_by_label("Server address")).to_have_value("https://u2.example.com")

    # Back at the connection step and saving again edits, never duplicates.
    page.goto(server.url("/admin/setup/connection"))
    page.get_by_role("button", name="Save and continue").click()
    expect(page).to_have_url(re.compile(r"/admin/setup/server_address$"))
    page.goto(server.url("/admin/setup/done"))
    expect(page.get_by_text("Prod (saved.example, PROD)")).to_be_visible()
    # The Done page shows only the first connection, so count them on the list.
    page.get_by_role("button", name="Finish setup").click()
    expect(page).to_have_url(re.compile(r"/admin/connections\?notice=setup_done$"))
    expect(page.locator("table tbody tr")).to_have_count(1)


def test_a_closed_browser_resumes_after_signing_in(
    page: Page, other_page: Page, server: Server
) -> None:
    create_admin(page, server)

    other = other_page
    other.goto(server.url("/admin/"))
    expect(other).to_have_url(re.compile(r"/admin/sign-in\?next=/admin/setup/connection$"))
    other.get_by_label("Username").fill(ADMIN_USER)
    other.get_by_label("Password").fill(ADMIN_PASSWORD)
    other.get_by_role("button", name="Sign in").click()
    expect(other).to_have_url(re.compile(r"/admin/setup/connection$"))


def test_a_wrong_setup_code(page: Page, server: Server) -> None:
    page.goto(server.url("/admin/setup/admin"))
    page.get_by_label("Setup code").fill("AAAA-AAAA-AAAA")
    page.get_by_label("Username").fill(ADMIN_USER)
    page.get_by_label("Password", exact=True).fill(ADMIN_PASSWORD)
    page.get_by_label("Password again").fill(ADMIN_PASSWORD)
    page.get_by_role("button", name="Create admin and continue").click()

    expect(page.locator(".error")).to_contain_text("That setup code is not right.")
    expect(page).to_have_url(re.compile(r"/admin/setup/admin$"))


def test_a_wrong_u2_password_shows_the_driver_text(page: Page, server: Server) -> None:
    create_admin(page, server)
    fill_connection(page, password=sim_driver.WRONG_PASSWORD)

    page.get_by_role("button", name="Test connection").click()

    expect(page.locator("#test-result")).to_contain_text(
        "Test failed: Failed to connect to u2.example: Login refused: wrong user name or password"
    )


def test_an_unreachable_host_shows_the_driver_text(page: Page, server: Server) -> None:
    create_admin(page, server)
    fill_connection(page, host=sim_driver.UNREACHABLE_HOST)

    page.get_by_role("button", name="Test connection").click()

    expect(page.locator("#test-result")).to_contain_text(
        "Cannot reach unreachable.invalid:31438: connection refused"
    )


def test_testing_needs_the_fields_first(page: Page, server: Server) -> None:
    create_admin(page, server)
    page.get_by_label("Host").fill("")

    page.get_by_role("button", name="Test connection").click()

    expect(page.locator("#test-result")).to_contain_text(
        "Enter the U2 server's host name or address."
    )


def test_finishing_twice_is_harmless(page: Page, server: Server) -> None:
    reach_done(page, server)
    # A second tab still showing the Done page, as when someone opened it twice.
    second = page.context.new_page()
    second.goto(server.url("/admin/setup/done"))

    page.get_by_role("button", name="Finish setup").click()
    expect(page).to_have_url(re.compile(r"/admin/connections\?notice=setup_done$"))

    second.get_by_role("button", name="Finish setup").click()
    expect(second).to_have_url(re.compile(r"/admin/connections$"))
    expect(second.get_by_role("heading", name="Connections")).to_be_visible()
    expect(second.locator("main table tbody tr")).to_have_count(1)


def test_back_after_finishing_lands_on_connections(page: Page, server: Server) -> None:
    finish_wizard(page, server)

    # Back re-asks for the Done page, which is closed now. Before admin redirects
    # were no-store, Chromium replayed its cached /admin/ -> /admin/setup ->
    # /admin/setup/admin redirects and stopped with ERR_TOO_MANY_REDIRECTS.
    page.go_back()

    expect(page).to_have_url(re.compile(r"/admin/connections$"))
    expect(page.get_by_role("heading", name="Connections")).to_be_visible()
    expect(page.locator("main table tbody tr")).to_have_count(1)

    # Once setup is finished, the Done page itself is closed.
    page.goto(server.url("/admin/setup/done"))
    expect(page).to_have_url(re.compile(r"/admin/connections$"))
