"""Admin-site sign-in: passwords, sessions, races, cookies and the sign-in limit."""

import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from u2_mcp.admin import routes_auth
from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.routes_auth import RATE_LIMITED
from u2_mcp.admin.security import SESSION_COOKIE
from u2_mcp.admin.services import (
    NON_ADMIN_SIGN_IN_SETTING,
    AuditFilters,
    ConnectionForm,
    ValidationFailed,
    change_password,
    check_connection_form,
)
from u2_mcp.passwords import hash_password, verify_password
from u2_mcp.setup_code import finish_setup
from u2_mcp.store.models import User

from .helpers import PASSWORD, admin_client, csrf_from, sign_in, team_server


@pytest.fixture
def admin_user(ctx: AdminContext) -> User:
    finish_setup(ctx.store)
    return ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)


@pytest.fixture
def client(ctx: AdminContext, admin_user: User) -> Iterator[TestClient]:
    with admin_client(ctx) as test_client:
        yield test_client


class TestSigningIn:
    def test_the_right_password_signs_in(self, client: TestClient) -> None:
        response = sign_in(client)

        assert response.status_code == 303  # type: ignore[attr-defined]
        assert SESSION_COOKIE in client.cookies
        assert client.get("/admin/account/password").status_code == 200

    def test_the_cookie_is_locked_down(self, client: TestClient) -> None:
        response = sign_in(client)

        cookie = response.headers["set-cookie"]  # type: ignore[attr-defined]
        assert "HttpOnly" in cookie and "SameSite=lax" in cookie and "Path=/admin" in cookie

    def test_a_wrong_password_is_refused_and_audited(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        response = sign_in(client, password="wrong password!")

        assert response.status_code == 401  # type: ignore[attr-defined]
        assert "Wrong username or password." in response.text  # type: ignore[attr-defined]
        entry = ctx.store.recent_audit(1)[0]
        assert (entry["kind"], entry["action"], entry["outcome"]) == (
            "auth",
            "admin.sign_in",
            "failed",
        )

    def test_an_unknown_user_gets_the_same_message(self, client: TestClient) -> None:
        response = sign_in(client, username="nobody")

        assert "Wrong username or password." in response.text  # type: ignore[attr-defined]

    def test_a_missing_csrf_token_is_refused(self, client: TestClient) -> None:
        client.get("/admin/sign-in")

        response = client.post("/admin/sign-in", data={"username": "ann", "password": PASSWORD})

        assert response.status_code == 403

    def test_the_sixth_attempt_in_a_minute_is_refused(self, client: TestClient) -> None:
        for _ in range(5):
            sign_in(client, password="wrong password!")

        response = sign_in(client)

        assert response.status_code == 429  # type: ignore[attr-defined]
        assert "Too many sign-in attempts. Wait a minute and try again." in (response.text)  # type: ignore[attr-defined]

    def test_next_is_followed_only_inside_the_admin_site(self, client: TestClient) -> None:
        inside = sign_in(client, next_url="/admin/account/password")
        assert inside.headers["location"] == "/admin/account/password"  # type: ignore[attr-defined]

    def test_local_sign_in_can_be_off_for_non_admins(
        self, ctx: AdminContext, client: TestClient
    ) -> None:
        ctx.store.add_local_user("bob", password_hash=hash_password(PASSWORD))
        ctx.store.set_setting(NON_ADMIN_SIGN_IN_SETTING, False)

        refused = sign_in(client, username="bob")
        allowed = sign_in(client, username="ann")

        assert "Sign-in to this site is turned off for people who are not admins." in (refused.text)  # type: ignore[attr-defined]
        assert allowed.status_code == 303  # type: ignore[attr-defined]


class TestSignedInPages:
    def test_pages_redirect_to_sign_in(self, client: TestClient) -> None:
        response = client.get("/admin/account/password", follow_redirects=False)

        assert response.status_code == 303
        assert response.headers["location"] == "/admin/sign-in?next=/admin/account/password"

    def test_sign_out_ends_the_session(self, client: TestClient, ctx: AdminContext) -> None:
        sign_in(client)
        page = client.get("/admin/account/password")

        client.post("/admin/sign-out", data={"csrf_token": csrf_from(page.text)})

        assert client.get("/admin/account/password", follow_redirects=False).status_code == 303
        assert ctx.store.recent_audit(1)[0]["action"] == "admin.sign_out"

    def test_a_forced_change_comes_first(
        self, client: TestClient, ctx: AdminContext, admin_user: User
    ) -> None:
        ctx.store.set_password_hash(admin_user.id, hash_password(PASSWORD), must_change=True)
        sign_in(client)

        response = client.get("/admin/", follow_redirects=False)

        assert response.headers["location"] == "/admin/account/password"

    def test_changing_the_password(
        self, client: TestClient, ctx: AdminContext, admin_user: User
    ) -> None:
        sign_in(client)
        page = client.get("/admin/account/password")

        response = client.post(
            "/admin/account/password",
            data={
                "csrf_token": csrf_from(page.text),
                "current_password": PASSWORD,
                "new_password": "a brand new passphrase",
                "new_password_again": "a brand new passphrase",
            },
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert verify_password(ctx.store.password_hash(admin_user.id), "a brand new passphrase")
        assert client.get("/admin/account/password").status_code == 200  # still signed in

    def test_a_non_admin_goes_to_my_access(self, ctx: AdminContext, client: TestClient) -> None:
        ctx.store.add_local_user("bob", password_hash=hash_password(PASSWORD))
        sign_in(client, username="bob")

        response = client.get("/admin/", follow_redirects=False)

        assert response.headers["location"] == "/admin/me"


class TestHardening:
    def test_a_planted_presession_cookie_does_not_pass_signed_in_csrf(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        sign_in(client)
        client.cookies.set("u2_admin_presession", "planted", path="/admin")

        response = client.post(
            "/admin/sign-out", data={"csrf_token": "planted"}, follow_redirects=False
        )

        assert response.status_code == 403
        assert client.get("/admin/account/password").status_code == 200  # still signed in

    def test_signing_in_again_ends_the_previous_session(
        self, client: TestClient, ctx: AdminContext, admin_user: User
    ) -> None:
        sign_in(client)
        sign_in(client)

        rows = ctx.store._all(
            "SELECT id_hash FROM admin_sessions WHERE user_id = ?", (admin_user.id,)
        )
        assert len(rows) == 1

    def test_sign_out_works_from_the_sign_in_page(self, client: TestClient) -> None:
        sign_in(client)
        page = client.get("/admin/sign-in")

        response = client.post(
            "/admin/sign-out", data={"csrf_token": csrf_from(page.text)}, follow_redirects=False
        )

        assert response.status_code == 303
        assert client.get("/admin/account/password", follow_redirects=False).status_code == 303


class TestAllowlist:
    def test_other_addresses_are_refused(self, ctx: AdminContext, admin_user: User) -> None:
        ctx.config = ctx.config.model_copy(update={"admin_allowed_ips": "192.168.1.0/24"})

        with admin_client(ctx, client=("10.0.0.1", 5000)) as outside:
            response = outside.get("/admin/sign-in")
        with admin_client(ctx, client=("192.168.1.20", 5000)) as inside:
            allowed = inside.get("/admin/sign-in")

        assert response.status_code == 403
        assert response.text == "Not allowed from this address."
        assert allowed.status_code == 200

    def test_a_dual_stack_ipv4_client_matches_an_ipv4_network(
        self, ctx: AdminContext, admin_user: User
    ) -> None:
        # On a dual-stack bind, IPv4 clients arrive as ::ffff:a.b.c.d.
        ctx.config = ctx.config.model_copy(update={"admin_allowed_ips": "192.168.1.0/24"})

        with admin_client(ctx, client=("::ffff:192.168.1.20", 5000)) as mapped:
            allowed = mapped.get("/admin/sign-in")
        with admin_client(ctx, client=("::ffff:10.0.0.1", 5000)) as outside:
            refused = outside.get("/admin/sign-in")

        assert allowed.status_code == 200
        assert refused.status_code == 403

    def test_an_ipv6_network_entry(self, ctx: AdminContext, admin_user: User) -> None:
        ctx.config = ctx.config.model_copy(update={"admin_allowed_ips": "2001:db8::/32"})

        with admin_client(ctx, client=("2001:db8::5", 5000)) as inside:
            allowed = inside.get("/admin/sign-in")
        with admin_client(ctx, client=("2001:db9::5", 5000)) as outside:
            refused = outside.get("/admin/sign-in")

        assert allowed.status_code == 200
        assert refused.status_code == 403


class TestPasswordChangeEdges:
    def test_a_user_gone_after_the_change_is_signed_out(
        self,
        client: TestClient,
        ctx: AdminContext,
        admin_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        sign_in(client)
        page = client.get("/admin/account/password")
        real_get_user = ctx.store.get_user
        calls = {"n": 0}

        def vanishing_get_user(user_id: int) -> User | None:
            # The guard loads the user first; the handler's re-read finds nobody.
            calls["n"] += 1
            return real_get_user(user_id) if calls["n"] == 1 else None

        monkeypatch.setattr(ctx.store, "get_user", vanishing_get_user)
        response = client.post(
            "/admin/account/password",
            data={
                "csrf_token": csrf_from(page.text),
                "current_password": PASSWORD,
                "new_password": "a brand new passphrase",
                "new_password_again": "a brand new passphrase",
            },
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert response.headers["location"] == "/admin/sign-in"
        assert SESSION_COOKIE not in client.cookies
        rows = ctx.store._all(
            "SELECT id_hash FROM admin_sessions WHERE user_id = ?", (admin_user.id,)
        )
        assert rows == []


class TestSignOutCookie:
    def test_the_cleared_cookie_has_the_same_flags(self, client: TestClient) -> None:
        sign_in(client)
        page = client.get("/admin/account/password")

        response = client.post(
            "/admin/sign-out", data={"csrf_token": csrf_from(page.text)}, follow_redirects=False
        )

        cookie = response.headers["set-cookie"].lower()
        assert cookie.startswith(f"{SESSION_COOKIE}=")
        assert "path=/admin" in cookie and "httponly" in cookie and "samesite=lax" in cookie
        assert "secure" not in cookie  # the test address is http

    def test_the_cleared_cookie_is_secure_on_https(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        sign_in(client)
        page = client.get("/admin/account/password")
        ctx.store.set_setting("public_url", "https://u2.example.com")

        response = client.post(
            "/admin/sign-out", data={"csrf_token": csrf_from(page.text)}, follow_redirects=False
        )

        assert "secure" in response.headers["set-cookie"].lower()


class TestSignInRacesAPasswordReset:
    """An admin reset that lands while sign-in awaits argon2 must win."""

    @staticmethod
    def _reset_during(
        monkeypatch: pytest.MonkeyPatch, ctx: AdminContext, user: User, *, on_call: int
    ) -> None:
        from u2_mcp.admin import routes_auth

        real = routes_auth.argon2_call
        calls = {"n": 0}

        async def racing(fn, *args):  # type: ignore[no-untyped-def]
            calls["n"] += 1
            result = await real(fn, *args)
            if calls["n"] == on_call:
                ctx.store.reset_password(user.id, hash_password("a brand new one!"))
            return result

        monkeypatch.setattr(routes_auth, "argon2_call", racing)

    def test_a_reset_during_the_check_refuses_the_old_password(
        self,
        client: TestClient,
        ctx: AdminContext,
        admin_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        self._reset_during(monkeypatch, ctx, admin_user, on_call=1)

        response = sign_in(client)

        assert response.status_code == 401  # type: ignore[attr-defined]
        assert ctx.store.count_admin_sessions_for(admin_user.id) == 0

    def test_a_disable_during_the_check_refuses(
        self,
        client: TestClient,
        ctx: AdminContext,
        admin_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from u2_mcp.admin import routes_auth

        real = routes_auth.argon2_call

        async def racing(fn, *args):  # type: ignore[no-untyped-def]
            result = await real(fn, *args)
            ctx.store.set_user_disabled(admin_user.id, True)
            return result

        monkeypatch.setattr(routes_auth, "argon2_call", racing)

        response = sign_in(client)

        assert response.status_code == 401  # type: ignore[attr-defined]
        assert ctx.store.count_admin_sessions_for(admin_user.id) == 0

    def test_a_demotion_during_the_check_meets_local_sign_in_off(
        self,
        client: TestClient,
        ctx: AdminContext,
        admin_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from u2_mcp.admin import routes_auth
        from u2_mcp.admin.services import NON_ADMIN_SIGN_IN_SETTING

        ctx.store.set_setting(NON_ADMIN_SIGN_IN_SETTING, False)
        real = routes_auth.argon2_call

        async def racing(fn, *args):  # type: ignore[no-untyped-def]
            result = await real(fn, *args)
            ctx.store.set_user_admin(admin_user.id, False)
            return result

        monkeypatch.setattr(routes_auth, "argon2_call", racing)

        response = sign_in(client)

        assert response.status_code == 403  # type: ignore[attr-defined]
        assert ctx.store.count_admin_sessions_for(admin_user.id) == 0


@pytest.fixture
def set_up_client(ctx: AdminContext) -> Iterator[TestClient]:
    finish_setup(ctx.store)
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    with admin_client(ctx) as test_client:
        yield test_client


def _password_post(set_up_client: TestClient, current: str) -> object:
    token = csrf_from(set_up_client.get("/admin/account/password").text)
    return set_up_client.post(
        "/admin/account/password",
        data={
            "csrf_token": token,
            "current_password": current,
            "new_password": "another long passphrase",
            "new_password_again": "another long passphrase",
        },
    )


def test_wrong_current_passwords_are_audited_and_limited(
    set_up_client: TestClient, ctx: AdminContext
) -> None:
    sign_in(set_up_client)
    for _ in range(5):
        _password_post(set_up_client, "wrong")
    sixth = _password_post(set_up_client, "wrong")

    assert sixth.status_code == 429 and RATE_LIMITED in sixth.text  # type: ignore[attr-defined]
    actions = [e["action"] for e in ctx.store.recent_audit(10)]
    assert actions.count("admin.password_check") == 5


def test_change_password_reports_every_problem(ctx: AdminContext) -> None:
    bob = ctx.store.add_local_user("bob", password_hash=hash_password(PASSWORD))
    with pytest.raises(ValidationFailed) as failed:
        change_password(ctx, bob, current="wrong", new="short", new_again="short")
    assert set(failed.value.errors) == {"current_password", "new_password"}


def test_signing_out_without_a_session_redirects(set_up_client: TestClient) -> None:
    response = set_up_client.post("/admin/sign-out", data={}, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/admin/sign-in"


def test_next_keeps_the_query_string(set_up_client: TestClient) -> None:
    response = set_up_client.get("/admin/users?q=ann", follow_redirects=False)
    assert response.headers["location"] == "/admin/sign-in?next=/admin/users%3Fq%3Dann"


def test_the_local_sign_in_off_refusal_is_audited(
    set_up_client: TestClient, ctx: AdminContext
) -> None:
    ctx.store.add_local_user("bob", password_hash=hash_password(PASSWORD))
    ctx.store.set_setting(NON_ADMIN_SIGN_IN_SETTING, False)

    sign_in(set_up_client, username="bob")

    entry = ctx.store.recent_audit(1)[0]
    assert (entry["action"], entry["outcome"]) == ("admin.sign_in", "refused")


def test_a_long_failed_username_is_capped(set_up_client: TestClient, ctx: AdminContext) -> None:
    sign_in(set_up_client, username="x" * 500, password="nope")
    assert len(ctx.store.recent_audit(1)[0]["actor_label"]) == 64


def test_a_per_user_test_needs_a_password(ctx: AdminContext) -> None:
    form = ConnectionForm(name="Dev", host="h", account="A", login_mode="per_user", login_user="me")
    with pytest.raises(ValidationFailed) as failed:
        check_connection_form(ctx, form)
    assert "login_password" in failed.value.errors


def test_the_stale_edit_reload_link_names_the_page(
    set_up_client: TestClient, ctx: AdminContext
) -> None:
    sign_in(set_up_client)
    connection = ctx.store.add_connection(
        name="P",
        host="h",
        port=1,
        service="uvcs",
        account="A",
        shared_user="s",
        shared_password="p",
    )
    token = csrf_from(set_up_client.get(f"/admin/connections/{connection.id}").text)
    form = {
        "csrf_token": token,
        "name": "P",
        "host": "h",
        "port": "1",
        "service": "uvcs",
        "account": "A",
        "login_mode": "shared",
        "login_user": "s",
        "version": "0",
        "read_only": "on",
        "enabled": "on",
    }

    stale = set_up_client.post(f"/admin/connections/{connection.id}", data=form)

    assert stale.status_code == 409
    assert f'<a href="/admin/connections/{connection.id}">Reload</a>' in stale.text


def test_an_oversized_audit_filter_number_is_ignored() -> None:
    filters = AuditFilters.from_query({"user": "99999999999999999999", "connection": "7"})
    assert filters.user_id is None and filters.connection_id == 7


def test_the_audit_page_ignores_an_oversized_user_filter(set_up_client: TestClient) -> None:
    sign_in(set_up_client)
    assert set_up_client.get("/admin/audit?user=99999999999999999999").status_code == 200


class TestNonAdminSignInOff:
    """Off keeps every non-admin off this site, local or company; MCP is untouched."""

    def test_an_existing_session_ends(self, set_up_client: TestClient, ctx: AdminContext) -> None:
        ctx.store.add_local_user("lou", password_hash=hash_password(PASSWORD))
        sign_in(set_up_client, "lou")
        assert set_up_client.get("/admin/me").status_code == 200

        ctx.store.set_setting(NON_ADMIN_SIGN_IN_SETTING, False)

        response = set_up_client.get("/admin/me", follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].startswith("/admin/sign-in")

    def test_personal_access_tokens_keep_working_for_mcp(self, ctx: AdminContext) -> None:
        from u2_mcp.tokens import create_token, verify_token

        lou = ctx.store.add_local_user("lou", password_hash=hash_password(PASSWORD))
        raw, _ = create_token(ctx.store, lou.id, "laptop")

        ctx.store.set_setting(NON_ADMIN_SIGN_IN_SETTING, False)

        assert verify_token(ctx.store, raw)[0].id == lou.id

    def test_company_accounts_are_kept_off_too_but_admins_are_not(self, ctx: AdminContext) -> None:
        from u2_mcp.admin.services import kept_off_this_site

        admin = ctx.store.add_local_user("ada", password_hash="x", is_admin=True)
        sso = ctx.store.get_or_create_sso_user("sub-sam")
        ctx.store.set_setting(NON_ADMIN_SIGN_IN_SETTING, False)

        assert kept_off_this_site(ctx.store, sso)
        assert not kept_off_this_site(ctx.store, admin)

    def test_it_is_on_by_default(self, ctx: AdminContext) -> None:
        from u2_mcp.admin.services import kept_off_this_site

        lou = ctx.store.add_local_user("lou", password_hash="x")
        sso = ctx.store.get_or_create_sso_user("sub-sam")

        assert not kept_off_this_site(ctx.store, lou)
        assert not kept_off_this_site(ctx.store, sso)


def _ready(ctx: AdminContext, public_url: str | None = None) -> None:
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    finish_setup(ctx.store)
    if public_url:
        ctx.store.set_setting("public_url", public_url)


def test_over_https_the_presession_cookie_is_host_prefixed(ctx: AdminContext) -> None:
    _ready(ctx, "https://u2.example.com")
    with admin_client(ctx, base_url="https://testserver") as client:
        page = client.get("/admin/sign-in")
        cookie = page.headers["set-cookie"]
        assert cookie.startswith("__Host-u2_admin_presession=")
        assert "Path=/;" in cookie and "Secure" in cookie
        assert sign_in(client).status_code == 303  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("base_url", "public_url", "expected"),
    [
        # Over http the plain name is the real cookie, so the same request signs in...
        ("http://testserver", None, 303),
        # ...but over https only the __Host- cookie counts, so a planted plain one is refused.
        ("https://testserver", "https://u2.example.com", 403),
    ],
)
def test_a_planted_unprefixed_cookie_is_a_csrf_token_only_over_http(
    ctx: AdminContext, base_url: str, public_url: str | None, expected: int
) -> None:
    _ready(ctx, public_url)
    with admin_client(ctx, base_url=base_url) as client:
        response = client.post(
            "/admin/sign-in",
            data={"csrf_token": "planted", "username": "ann", "password": PASSWORD, "next": ""},
            headers={"Cookie": "u2_admin_presession=planted"},
            follow_redirects=False,
        )
    assert response.status_code == expected


def test_over_http_the_cookie_keeps_its_plain_name(ctx: AdminContext) -> None:
    _ready(ctx)
    with admin_client(ctx) as client:
        cookie = client.get("/admin/sign-in").headers["set-cookie"]
    assert cookie.startswith("u2_admin_presession=") and "Path=/admin" in cookie


def test_sign_in_checks_the_password_off_the_event_loop(
    ctx: AdminContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    threads: list[str] = []
    real = routes_auth.verify_password

    def spy(stored: str | None, password: str) -> bool:
        threads.append(threading.current_thread().name)
        return real(stored, password)

    monkeypatch.setattr(routes_auth, "verify_password", spy)
    _ready(ctx)
    with admin_client(ctx) as client:
        assert sign_in(client).status_code == 303  # type: ignore[attr-defined]
    assert threads and threads[0].startswith("argon2")


def test_cors_headers_are_never_sent_for_the_admin_site(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    origin = {"Origin": "https://app.example"}
    with team_server(tmp_path, monkeypatch, U2_HTTP_CORS_ORIGINS="https://app.example") as client:
        health = client.get("/health", headers=origin)
        admin = client.get("/admin/sign-in", headers=origin, follow_redirects=False)
    assert health.headers.get("access-control-allow-origin") == "https://app.example"
    assert "access-control-allow-origin" not in admin.headers
