"""Company sign-in in a real browser, against the mock identity provider (spec Testing 7).

The mock provider runs on the host at 127.0.0.1. In container mode (U2_E2E_IMAGE) the
server shares the host network, so the same address works for the browser and the server.
"""

from __future__ import annotations

import re

import httpx
import pytest
from playwright.sync_api import Page, expect

from .conftest import Idp, Server, _free_port
from .wizard import (
    create_admin,
    create_token,
    fill_connection,
    finish_wizard,
    grant_on,
    set_up_sso,
    sso_sign_in,
)

pytestmark = pytest.mark.e2e

_AGE_SIGN_IN = (
    "import time\n"
    "from u2_mcp.config import U2Config\n"
    "from u2_mcp.store.bootstrap import open_store_for_cli\n"
    "store = open_store_for_cli(U2Config())\n"
    "user = store.get_user_by_subject('tom')\n"
    "with store._tx() as conn:\n"
    "    conn.execute('UPDATE users SET last_sso_login_at = ? WHERE id = ?',\n"
    "                 (time.time() - 31 * 86400, user.id))\n"
)


def _initialize_status(url: str, token: str) -> int:
    """The HTTP status an MCP client gets for its first request with this token."""
    response = httpx.post(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream",
        },
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "e2e", "version": "1"},
            },
        },
        timeout=30,
    )
    return response.status_code


def _to_sso_step(page: Page, server: Server) -> None:
    create_admin(page, server)
    fill_connection(page)
    page.get_by_role("button", name="Save and continue").click()
    page.get_by_label("Server address").fill(server.base_url)
    page.get_by_role("button", name="Save and continue").click()
    expect(page).to_have_url(re.compile(r"/admin/setup/sso$"))


def test_the_sso_step_tests_a_real_sign_in_and_signs_nobody_in(
    page: Page, server: Server, idp: Idp
) -> None:
    _to_sso_step(page, server)
    set_up_sso(page, idp)
    idp.next_user(sub="tess", email="tess@example.com", name="Tess Ter", groups=["eng-team"])
    with page.expect_popup() as popup_info:
        page.get_by_role("button", name="Test sign-in").click()
    popup = popup_info.value
    expect(popup.get_by_role("heading", name="Company sign-in works")).to_be_visible()
    expect(popup.get_by_text("eng-team")).to_be_visible()
    popup.close()

    page.get_by_role("button", name="Continue").click()
    expect(page.get_by_text("Other OpenID Connect provider")).to_be_visible()  # the checklist
    page.get_by_role("button", name="Finish setup").click()
    page.goto(server.url("/admin/users"))
    expect(page.get_by_text("Tess Ter")).to_have_count(0)


def test_bad_sso_settings_show_the_error_text(page: Page, server: Server, idp: Idp) -> None:
    _to_sso_step(page, server)
    nowhere = f"http://127.0.0.1:{_free_port()}/.well-known/openid-configuration"
    set_up_sso(page, idp, discovery_url=nowhere)
    with page.expect_popup() as popup_info:
        page.get_by_role("button", name="Test sign-in").click()
    expect(
        popup_info.value.get_by_text(
            "Company sign-in failed: Could not reach the identity provider"
        )
    ).to_be_visible()


def test_group_grants_follow_company_sign_in(
    page: Page, other_page: Page, server: Server, idp: Idp
) -> None:
    finish_wizard(page, server, idp=idp)
    idp.next_user(sub="sam", email="sam@example.com", name="Sam", groups=["eng-team"])
    sso_sign_in(other_page, server)
    expect(other_page).to_have_url(re.compile(r"/admin/me$"))
    expect(other_page.get_by_text("You can't use any connection yet.")).to_be_visible()

    page.goto(server.url("/admin/groups"))
    page.get_by_role("link", name="eng-team").click()
    page.get_by_label("Connection").select_option(label="Prod")
    page.get_by_role("button", name="Add grant").click()
    expect(page.locator(".notice")).to_have_text("Saved.")

    other_page.reload()
    expect(other_page.get_by_role("cell", name="Prod")).to_be_visible()

    idp.next_user(sub="sam", email="sam@example.com", name="Sam", groups=[])
    sso_sign_in(other_page, server)  # the next sign-in no longer carries the group
    expect(other_page.get_by_text("You can't use any connection yet.")).to_be_visible()


def test_an_overage_sign_in_is_flagged_for_admins(
    page: Page, other_page: Page, server: Server, idp: Idp
) -> None:
    finish_wizard(page, server, idp=idp)
    idp.next_user(sub="olga", email="olga@example.com", name="Olga", overage=True)
    sso_sign_in(other_page, server)
    expect(other_page).to_have_url(re.compile(r"/admin/me$"))

    page.goto(server.url("/admin/users"))
    expect(page.get_by_text("(groups unavailable)")).to_be_visible()


def test_tokens_pause_without_company_sign_in_and_come_back_with_it(
    page: Page, other_page: Page, server: Server, idp: Idp
) -> None:
    finish_wizard(page, server, idp=idp)
    idp.next_user(sub="tom", email="tom@example.com", name="Tom")
    sso_sign_in(other_page, server)
    token = create_token(other_page, server)
    expect(other_page.get_by_text("at least once every 30 days")).to_be_visible()
    mcp_url = server.url("/")
    assert _initialize_status(mcp_url, token) == 200

    server.python(_AGE_SIGN_IN)
    assert _initialize_status(mcp_url, token) == 401
    page.goto(server.url("/admin/users"))
    page.get_by_role("link", name="Tom").click()
    expect(page.get_by_text("This person's tokens are paused")).to_be_visible()

    idp.next_user(sub="tom", email="tom@example.com", name="Tom")
    sso_sign_in(other_page, server)
    assert _initialize_status(mcp_url, token) == 200


def test_a_person_sets_and_tests_their_own_u2_login(
    page: Page, other_page: Page, server: Server, idp: Idp
) -> None:
    finish_wizard(page, server, idp=idp)
    page.goto(server.url("/admin/connections/new"))
    fill_connection(page, name="Mine", host="mine.example", account="MINE")
    page.get_by_label("Logins").select_option(value="per_user")
    page.get_by_role("button", name="Add connection").click()
    expect(page.locator(".notice")).to_have_text("Saved.")

    idp.next_user(sub="pia", email="pia@example.com", name="Pia")
    sso_sign_in(other_page, server)
    expect(other_page).to_have_url(re.compile(r"/admin/me$"))
    grant_on(page, server, connection="Mine", who="A person", person="Pia")

    other_page.goto(server.url("/admin/me"))
    expect(other_page.get_by_text("you need your own U2 login")).to_be_visible()

    section = other_page.locator("section.u2-login")
    section.get_by_label("U2 user name").fill("pia")
    section.get_by_label("U2 password").fill("wrong-password")
    section.get_by_role("button", name="Test", exact=True).click()
    expect(section.locator(".result")).to_contain_text("Test failed")

    section.get_by_label("U2 password").fill("pia-secret")
    section.get_by_role("button", name="Test", exact=True).click()
    expect(section.locator(".result")).to_contain_text("Test passed")

    section.get_by_role("button", name="Save", exact=True).click()
    expect(other_page.locator(".notice")).to_have_text("Your U2 login is saved.")
    expect(other_page.get_by_text("you need your own U2 login")).to_have_count(0)
    expect(other_page.get_by_text("Set, last updated")).to_be_visible()
