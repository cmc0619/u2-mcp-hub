"""Steps shared by browser tests, written the way a person uses the pages."""

from __future__ import annotations

import re

from playwright.sync_api import Page, expect

from .conftest import Idp, Server

ADMIN_USER = "admin"
ADMIN_PASSWORD = "a long admin passphrase"


def create_admin(page: Page, server: Server) -> None:
    """Open a new server and complete step 1."""
    page.goto(server.url("/admin/"))
    expect(page).to_have_url(re.compile(r"/admin/setup/admin$"))
    page.get_by_label("Setup code").fill(server.setup_code())
    page.get_by_label("Username").fill(ADMIN_USER)
    page.get_by_label("Password", exact=True).fill(ADMIN_PASSWORD)
    page.get_by_label("Password again").fill(ADMIN_PASSWORD)
    page.get_by_role("button", name="Create admin and continue").click()
    expect(page).to_have_url(re.compile(r"/admin/setup/connection$"))


def fill_connection(
    page: Page,
    *,
    name: str = "Prod",
    host: str = "u2.example",
    account: str = "PROD",
    user: str = "svc",
    password: str = "secret",
) -> None:
    """Fill the connection form (wizard or everyday page: it is the same form)."""
    page.get_by_label("Name").fill(name)
    page.get_by_label("Host").fill(host)
    page.get_by_label("Account").fill(account)
    page.get_by_label("U2 user").fill(user)
    page.get_by_label("Password", exact=True).fill(password)


OTHER_OIDC = "Other OpenID Connect provider (Okta, Google, Auth0, Duo, Keycloak)"


def set_up_sso(page: Page, idp: Idp, *, discovery_url: str | None = None) -> None:
    """Fill and save the company sign-in form (wizard or Settings: the same form)."""
    folded = page.get_by_text("Set up company sign-in now")
    if folded.count():  # the wizard folds the form away until it is asked for
        folded.click()
    page.get_by_label("Provider").select_option(label=OTHER_OIDC)
    page.get_by_label("Discovery URL").fill(discovery_url or idp.discovery_url)
    page.locator("#f-client_id").fill(idp.client_id)
    page.locator("#f-client_secret").fill(idp.client_secret)
    page.get_by_role("button", name="Save company sign-in").click()
    expect(page.locator(".notice")).to_have_text("Saved.")


def sso_sign_in(page: Page, server: Server) -> None:
    """Sign in with the company account (the mock provider approves at once)."""
    page.goto(server.url("/admin/sign-in"))
    page.get_by_role("button", name="Sign in with your company account").click()


def finish_wizard(
    page: Page, server: Server, *, public_url: str | None = None, idp: Idp | None = None
) -> None:
    """Run the whole wizard with good values (company sign-in too when idp is given).

    The server address defaults to the test server's own http URL: an https
    address would make later sign-ins set Secure cookies the browser drops over
    plain http.
    """
    reach_done(page, server, public_url=public_url, idp=idp)
    page.get_by_role("button", name="Finish setup").click()
    expect(page).to_have_url(re.compile(r"/admin/connections\?notice=setup_done$"))


def reach_done(
    page: Page, server: Server, *, public_url: str | None = None, idp: Idp | None = None
) -> None:
    """Run the wizard with good values up to, not including, Finish setup."""
    create_admin(page, server)
    fill_connection(page)
    page.get_by_role("button", name="Save and continue").click()
    expect(page).to_have_url(re.compile(r"/admin/setup/server_address$"))
    page.get_by_label("Server address").fill(public_url or server.base_url)
    page.get_by_role("button", name="Save and continue").click()
    expect(page).to_have_url(re.compile(r"/admin/setup/sso$"))
    if idp is None:
        page.get_by_role("button", name="Skip this step").click()
    else:
        set_up_sso(page, idp)
        page.get_by_role("button", name="Continue").click()
    expect(page).to_have_url(re.compile(r"/admin/setup/done$"))


def sign_in(page: Page, server: Server) -> None:
    """Sign in as the admin from the sign-in page."""
    page.goto(server.url("/admin/sign-in"))
    page.get_by_label("Username").fill(ADMIN_USER)
    page.get_by_label("Password").fill(ADMIN_PASSWORD)
    page.get_by_role("button", name="Sign in").click()


def grant_on(
    page: Page,
    server: Server,
    *,
    connection: str = "Prod",
    who: str = "A person",
    person: str | None = ADMIN_USER,
    role: str = "Viewer",
) -> None:
    """Give a person (by default the admin) a role on a connection, from its page."""
    page.goto(server.url("/admin/connections"))
    page.get_by_role("link", name=connection, exact=True).click()
    page.get_by_label("Who").select_option(label=who)
    if person is not None:
        page.get_by_label("Person").select_option(label=person)
    page.get_by_label("Role", exact=True).select_option(label=role)
    page.get_by_role("button", name="Add grant").click()
    expect(page.locator(".notice")).to_have_text("Saved.")


def create_token(page: Page, server: Server, name: str = "laptop") -> str:
    """Create a personal access token on My access and return it."""
    page.goto(server.url("/admin/me"))
    page.get_by_label("Token name").fill(name)
    page.get_by_role("button", name="Create token").click()
    expect(page.locator("#new-token")).to_be_visible()
    return page.locator("#new-token").inner_text().strip()
