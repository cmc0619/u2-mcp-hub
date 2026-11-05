"""The setup wizard, over HTTP: resumable, guarded by the setup code, logic-free."""

import hashlib
from collections.abc import Iterator

import pytest
from starlette.testclient import TestClient

from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.security import SESSION_COOKIE
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import (
    WRONG_SETUP_CODE_MESSAGE,
    completed_step,
    ensure_setup_code,
    is_setup_complete,
    mark_step_done,
)

from .conftest import FakeCheck
from .helpers import PASSWORD, admin_client, csrf_from, sign_in

ADMIN_PASSWORD = "a long admin passphrase"
CONNECTION = {
    "name": "Prod",
    "host": "u2.example",
    "port": "31438",
    "service": "uvcs",
    "account": "PROD",
    "login_mode": "shared",
    "login_user": "svc",
    "login_password": "secret",
    "read_only": "on",
    "enabled": "on",
    "version": "0",
}


@pytest.fixture
def client(ctx: AdminContext) -> Iterator[TestClient]:
    with admin_client(ctx) as test_client:
        yield test_client


def _create_admin(client: TestClient, ctx: AdminContext, code: str | None = None) -> object:
    page = client.get("/admin/setup/admin")
    return client.post(
        "/admin/setup/admin",
        data={
            "csrf_token": csrf_from(page.text),
            "setup_code": code if code is not None else ensure_setup_code(ctx.store),
            "username": "admin",
            "display_name": "Admin",
            "password": ADMIN_PASSWORD,
            "password_again": ADMIN_PASSWORD,
        },
        follow_redirects=False,
    )


def _post(client: TestClient, url: str, data: dict[str, str]) -> object:
    token = csrf_from(client.get(url).text)
    return client.post(url, data={**data, "csrf_token": token}, follow_redirects=False)


def _skip_sso(client: TestClient) -> object:
    """Press Skip on the company sign-in step."""
    token = csrf_from(client.get("/admin/setup/sso").text)
    return client.post("/admin/setup/sso/next", data={"csrf_token": token}, follow_redirects=False)


# The test client talks plain http, so saving an https address needs the box ticked.
HTTPS_CONFIRMED = {"public_url": "https://u2.example.com", "confirm_https": "on"}
HTTPS_OVER_HTTP = (
    "You are on http now. After saving an https address you must reach this site over "
    "https, or sign-in will fail. Tick the box to confirm."
)


def _through_connection(client: TestClient, ctx: AdminContext) -> None:
    _create_admin(client, ctx)
    _post(client, "/admin/setup/connection", {**CONNECTION, "action": "save"})


class TestStart:
    def test_a_new_server_goes_to_the_first_step(self, client: TestClient) -> None:
        first = client.get("/admin/", follow_redirects=False)
        second = client.get(first.headers["location"], follow_redirects=False)

        assert first.headers["location"] == "/admin/setup"
        assert second.headers["location"] == "/admin/setup/admin"

    def test_later_steps_redirect_back(self, client: TestClient) -> None:
        response = client.get("/admin/setup/server_address", follow_redirects=False)

        assert response.headers["location"] == "/admin/setup/admin"

    def test_the_sign_in_page_sends_a_new_server_to_setup(self, client: TestClient) -> None:
        response = client.get("/admin/sign-in", follow_redirects=False)

        assert response.headers["location"] == "/admin/setup"


class TestAdminStep:
    def test_a_wrong_code_creates_nobody(self, client: TestClient, ctx: AdminContext) -> None:
        ensure_setup_code(ctx.store)

        response = _create_admin(client, ctx, code="AAAA-AAAA-AAAA")

        assert response.status_code == 400  # type: ignore[attr-defined]
        assert WRONG_SETUP_CODE_MESSAGE.replace("'", "&#39;") in (response.text)  # type: ignore[attr-defined]
        assert ctx.store.has_local_admin() is False

    def test_the_right_code_creates_the_admin_and_signs_in(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        response = _create_admin(client, ctx)

        assert response.headers["location"] == "/admin/setup/connection"  # type: ignore[attr-defined]
        assert ctx.store.has_local_admin() is True
        assert completed_step(ctx.store) == "admin"
        assert client.get("/admin/setup/connection").status_code == 200

    def test_password_rules_apply(self, client: TestClient, ctx: AdminContext) -> None:
        page = client.get("/admin/setup/admin")
        response = client.post(
            "/admin/setup/admin",
            data={
                "csrf_token": csrf_from(page.text),
                "setup_code": ensure_setup_code(ctx.store),
                "username": "admin",
                "password": "short",
                "password_again": "short",
            },
        )

        assert "Use at least 12 characters." in response.text

    def test_back_to_a_finished_admin_step_shows_it_done(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        _create_admin(client, ctx)

        page = client.get("/admin/setup/admin")

        assert "The admin account is created" in page.text
        assert 'name="setup_code"' not in page.text

    def test_creating_the_admin_replaces_an_earlier_session(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
        sign_in(client)
        old_cookie = client.cookies[SESSION_COOKIE]

        _create_admin(client, ctx)

        assert client.cookies[SESSION_COOKIE] != old_cookie
        assert ctx.store.get_admin_session(hashlib.sha256(old_cookie.encode()).hexdigest()) is None


class TestConnectionStep:
    def test_a_new_browser_must_sign_in_to_continue(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        _create_admin(client, ctx)

        with admin_client(ctx) as other:
            response = other.get("/admin/setup/connection", follow_redirects=False)
            assert response.headers["location"] == ("/admin/sign-in?next=/admin/setup/connection")
            sign_in(
                other, username="admin", password=ADMIN_PASSWORD, next_url="/admin/setup/connection"
            )
            assert other.get("/admin/setup/connection").status_code == 200

    def test_the_environment_is_not_used(self, client: TestClient, ctx: AdminContext) -> None:
        _create_admin(client, ctx)

        page = client.get("/admin/setup/connection").text

        assert ctx.config.host not in page
        assert "U2_PASSWORD" not in page

    def test_test_and_save(self, client: TestClient, ctx: AdminContext, check: FakeCheck) -> None:
        _create_admin(client, ctx)

        tested = _post(client, "/admin/setup/connection", {**CONNECTION, "action": "test"})
        saved = _post(client, "/admin/setup/connection", {**CONNECTION, "action": "save"})

        assert "Test passed: fine" in tested.text  # type: ignore[attr-defined]
        assert saved.headers["location"] == "/admin/setup/server_address"  # type: ignore[attr-defined]
        assert completed_step(ctx.store) == "connection"

    def test_returning_edits_the_same_connection(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        _through_connection(client, ctx)

        page = client.get("/admin/setup/connection").text
        created = ctx.store.get_connection_by_name("Prod")
        assert created is not None
        _post(
            client,
            "/admin/setup/connection",
            {
                **CONNECTION,
                "host": "u2-new.example",
                "login_password": "new-secret",
                "version": str(created.version),
                "action": "save",
            },
        )

        assert 'value="u2.example"' in page
        assert [c.host for c in ctx.store.list_connections()] == ["u2-new.example"]
        assert completed_step(ctx.store) == "connection"


class TestServerAddressAndDone:
    def test_server_address_saves_and_warns_about_http(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        _through_connection(client, ctx)

        page = client.get("/admin/setup/server_address").text
        response = _post(client, "/admin/setup/server_address", HTTPS_CONFIRMED)

        assert "This address is not https." in page  # the default is http://host:port
        assert response.headers["location"] == "/admin/setup/sso"  # type: ignore[attr-defined]

    def test_done_lists_everything_and_finishes(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        _through_connection(client, ctx)
        _post(client, "/admin/setup/server_address", HTTPS_CONFIRMED)

        _skip_sso(client)
        page = client.get("/admin/setup/done").text
        finished = _post(client, "/admin/setup/done", {})

        assert "Prod" in page and "https://u2.example.com/" in page
        assert "Company sign-in (SSO)" in page
        assert finished.headers["location"] == (  # type: ignore[attr-defined]
            "/admin/connections?notice=setup_done"
        )
        assert is_setup_complete(ctx.store) is True
        assert ctx.store.recent_audit(1)[0]["action"] == "setup.finish"
        assert client.get("/admin/setup", follow_redirects=False).headers["location"] == "/admin/"
        assert client.get("/admin/", follow_redirects=False).headers["location"] == (
            "/admin/connections"
        )


class TestHttpsWhileOnHttp:
    """Saving https while on http would drop the Secure sign-in cookies: confirm first."""

    def test_the_wizard_refuses_https_without_the_box(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        _through_connection(client, ctx)

        page = client.get("/admin/setup/server_address").text
        refused = _post(
            client, "/admin/setup/server_address", {"public_url": "https://u2.example.com"}
        )

        assert "I will reach the admin site over https from now on" in page
        assert refused.status_code == 400  # type: ignore[attr-defined]
        assert HTTPS_OVER_HTTP in refused.text  # type: ignore[attr-defined]
        assert ctx.store.get_setting("public_url") is None
        assert completed_step(ctx.store) == "connection"

    def test_the_wizard_saves_https_with_the_box(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        _through_connection(client, ctx)

        saved = _post(client, "/admin/setup/server_address", HTTPS_CONFIRMED)

        assert saved.headers["location"] == "/admin/setup/sso"  # type: ignore[attr-defined]
        assert ctx.store.get_setting("public_url") == "https://u2.example.com"

    def test_an_http_address_needs_no_box(self, client: TestClient, ctx: AdminContext) -> None:
        _through_connection(client, ctx)

        saved = _post(client, "/admin/setup/server_address", {"public_url": "http://10.0.0.5:8080"})

        assert saved.headers["location"] == "/admin/setup/sso"  # type: ignore[attr-defined]

    def test_settings_refuses_https_without_the_box_and_saves_with_it(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        _through_connection(client, ctx)
        _post(client, "/admin/setup/server_address", {"public_url": "http://10.0.0.5:8080"})
        _skip_sso(client)
        _post(client, "/admin/setup/done", {})

        refused = _post(client, "/admin/settings", {"public_url": "https://mcp.example.com"})
        refused_url = ctx.store.get_setting("public_url")
        saved = _post(
            client,
            "/admin/settings",
            {"public_url": "https://mcp.example.com", "confirm_https": "on"},
        )

        assert refused.status_code == 400  # type: ignore[attr-defined]
        assert HTTPS_OVER_HTTP in refused.text  # type: ignore[attr-defined]
        assert refused_url == "http://10.0.0.5:8080"
        assert saved.headers["location"] == "/admin/settings?notice=saved"  # type: ignore[attr-defined]
        assert ctx.store.get_setting("public_url") == "https://mcp.example.com"


class TestSettingsPage:
    def test_settings_saves_the_address_with_the_same_rules(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        _through_connection(client, ctx)
        _post(client, "/admin/setup/server_address", HTTPS_CONFIRMED)
        _skip_sso(client)
        _post(client, "/admin/setup/done", {})

        bad = _post(client, "/admin/settings", {"public_url": "not a url"})
        good = _post(
            client,
            "/admin/settings",
            {"public_url": "https://mcp.example.com/", "confirm_https": "on"},
        )

        assert "Enter the full address people use" in bad.text  # type: ignore[attr-defined]
        assert good.headers["location"] == "/admin/settings?notice=saved"  # type: ignore[attr-defined]
        page = client.get("/admin/settings").text
        assert 'value="https://mcp.example.com"' in page
        assert "Restart the server" in page


class TestSetupClosesBehindItself:
    def test_a_second_admin_cannot_race_step_one(
        self, client: TestClient, ctx: AdminContext, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from u2_mcp.admin import routes_setup

        real_read_form = routes_setup.read_form

        async def read_form_while_another_finishes(request, **kwargs):  # type: ignore[no-untyped-def]
            # Another browser completes step 1 while this one's form is being read.
            mark_step_done(ctx.store, "admin")
            return await real_read_form(request, **kwargs)

        page = client.get("/admin/setup/admin")
        monkeypatch.setattr(routes_setup, "read_form", read_form_while_another_finishes)
        response = client.post(
            "/admin/setup/admin",
            data={
                "csrf_token": csrf_from(page.text),
                "setup_code": ensure_setup_code(ctx.store),
                "username": "late",
                "password": ADMIN_PASSWORD,
                "password_again": ADMIN_PASSWORD,
            },
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert response.headers["location"] == "/admin/setup/connection"
        assert ctx.store.get_user_by_username("late") is None

    @pytest.mark.parametrize(
        ("step", "data"),
        [
            ("admin", {"username": "late", "password": ADMIN_PASSWORD}),
            ("connection", {**CONNECTION, "name": "Late", "action": "save"}),
            ("server_address", {"public_url": "http://late.example"}),
            ("sso", {"provider": "oidc"}),
            ("sso/next", {}),
            ("done", {}),
        ],
    )
    def test_posting_a_step_after_finish_changes_nothing(
        self, client: TestClient, ctx: AdminContext, step: str, data: dict[str, str]
    ) -> None:
        _through_connection(client, ctx)
        _post(client, "/admin/setup/server_address", {"public_url": "http://10.0.0.5:8080"})
        _skip_sso(client)
        _post(client, "/admin/setup/done", {})
        token = csrf_from(client.get("/admin/settings").text)
        audit_rows = len(ctx.store.recent_audit(1000))

        response = client.post(
            f"/admin/setup/{step}", data={**data, "csrf_token": token}, follow_redirects=False
        )

        assert response.status_code == 303
        assert response.headers["location"] == "/admin/"
        assert ctx.store.get_user_by_username("late") is None
        assert [c.name for c in ctx.store.list_connections()] == ["Prod"]
        assert ctx.store.get_setting("public_url") == "http://10.0.0.5:8080"
        assert len(ctx.store.recent_audit(1000)) == audit_rows

    def test_a_signed_out_post_to_a_later_step_goes_to_sign_in(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        _create_admin(client, ctx)

        with admin_client(ctx) as other:
            response = other.post(
                "/admin/setup/connection",
                data={**CONNECTION, "action": "save"},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert response.headers["location"] == "/admin/sign-in?next=/admin/setup/connection"
        assert ctx.store.list_connections() == []
