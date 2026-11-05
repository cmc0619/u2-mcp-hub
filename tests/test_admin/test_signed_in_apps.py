"""My access: apps signed in with the company account, and signing one out."""

import dataclasses
import time
from collections.abc import Iterator

import pytest
from starlette.testclient import TestClient

from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.problems import Refused
from u2_mcp.admin.security import SESSION_COOKIE, start_session
from u2_mcp.admin.services import sign_out_app, signed_in_apps
from u2_mcp.auth.storage import AuthStorage, StoredClient, StoredToken
from u2_mcp.setup_code import finish_setup
from u2_mcp.store.models import User

from .helpers import admin_client

ISSUER = "https://login.example.com/tenant/v2.0"


def _client(oauth: AuthStorage, client_id: str, name: str | None) -> None:
    oauth.store_client(
        StoredClient(
            client_id=client_id,
            client_secret=None,
            client_name=name,
            redirect_uris=[f"http://127.0.0.1/{client_id}"],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scope=None,
            token_endpoint_auth_method="none",
        )
    )


def _issue(
    oauth: AuthStorage, client_id: str, subject: str, issuer: str | None = ISSUER, **extra: float
) -> None:
    claims = {"iss": issuer} if issuer else {}
    now = time.time()
    for kind, life in (("access", 3600), ("refresh", 86400)):
        token = StoredToken(
            token=f"{kind}-{client_id}-{subject}-{issuer}",
            token_type=kind,
            client_id=client_id,
            user_subject=subject,
            scope="u2:read",
            expires_at=now + life,
            user_claims=claims,
            **extra,  # type: ignore[arg-type]
        )
        (oauth.store_access_token if kind == "access" else oauth.store_refresh_token)(token)


@pytest.fixture
def oauth(ctx: AdminContext) -> AuthStorage:
    return AuthStorage(ctx.store.locked)


@pytest.fixture
def octx(ctx: AdminContext, oauth: AuthStorage) -> AdminContext:
    return dataclasses.replace(ctx, oauth_storage=oauth)


@pytest.fixture
def sue(octx: AdminContext) -> User:
    return octx.store.get_or_create_sso_user("sub-sue", issuer=ISSUER, display_name="Sue")


@pytest.fixture
def tom(octx: AdminContext) -> User:
    return octx.store.get_or_create_sso_user("sub-tom", issuer=ISSUER, display_name="Tom")


class TestListing:
    def test_lists_the_persons_apps_by_name(
        self, octx: AdminContext, oauth: AuthStorage, sue: User
    ) -> None:
        _client(oauth, "copilot", "GitHub Copilot")
        _client(oauth, "unnamed", None)
        _issue(oauth, "copilot", "sub-sue", signed_in_at=1000.0)
        _issue(oauth, "unnamed", "sub-sue")

        apps = {app.client_id: app for app in signed_in_apps(octx, sue)}

        assert apps["copilot"].name == "GitHub Copilot"
        assert apps["copilot"].signed_in_at == 1000.0
        assert apps["copilot"].expires_at and apps["copilot"].expires_at > time.time() + 3600
        assert apps["unnamed"].name == "unnamed"

    def test_other_peoples_apps_are_not_listed(
        self, octx: AdminContext, oauth: AuthStorage, sue: User, tom: User
    ) -> None:
        _client(oauth, "copilot", "GitHub Copilot")
        _issue(oauth, "copilot", "sub-tom")
        # Same subject from another provider is another person.
        _issue(oauth, "copilot", "sub-sue", issuer="https://other.example.com")

        assert signed_in_apps(octx, sue) == []
        assert [app.client_id for app in signed_in_apps(octx, tom)] == ["copilot"]

    def test_expired_tokens_are_not_listed(
        self, octx: AdminContext, oauth: AuthStorage, sue: User
    ) -> None:
        oauth.store_refresh_token(
            StoredToken(
                token="old",
                token_type="refresh",
                client_id="copilot",
                user_subject="sub-sue",
                scope="",
                expires_at=time.time() - 1,
                user_claims={"iss": ISSUER},
            )
        )

        assert signed_in_apps(octx, sue) == []

    def test_a_local_user_has_no_signed_in_apps(self, octx: AdminContext, admin: User) -> None:
        assert signed_in_apps(octx, admin) == []


class TestSignOut:
    def test_signing_out_revokes_only_that_app_for_that_person(
        self, octx: AdminContext, oauth: AuthStorage, sue: User, tom: User
    ) -> None:
        _client(oauth, "copilot", "GitHub Copilot")
        _issue(oauth, "copilot", "sub-sue")
        _issue(oauth, "vscode", "sub-sue")
        _issue(oauth, "copilot", "sub-tom")

        sign_out_app(octx, sue, "copilot")

        assert [app.client_id for app in signed_in_apps(octx, sue)] == ["vscode"]
        assert [app.client_id for app in signed_in_apps(octx, tom)] == ["copilot"]
        assert oauth.get_access_token(f"access-copilot-sub-sue-{ISSUER}") is None
        assert oauth.get_refresh_token(f"refresh-copilot-sub-sue-{ISSUER}") is None
        entry = octx.store.recent_audit(1)[0]
        assert entry["action"] == "oauth_app.sign_out"
        assert entry["actor_user_id"] == sue.id

    def test_nobody_signs_out_another_persons_app(
        self, octx: AdminContext, oauth: AuthStorage, sue: User, tom: User
    ) -> None:
        _issue(oauth, "copilot", "sub-tom")

        with pytest.raises(Refused) as refused:
            sign_out_app(octx, sue, "copilot")

        assert refused.value.code == "gone"
        assert [app.client_id for app in signed_in_apps(octx, tom)] == ["copilot"]


@pytest.fixture
def sue_client(octx: AdminContext, sue: User) -> Iterator[tuple[TestClient, str]]:
    finish_setup(octx.store)
    raw_id, session = start_session(octx.store, sue, "10.0.0.1")
    with admin_client(octx) as client:
        client.cookies.set(SESSION_COOKIE, raw_id)
        yield client, session.csrf_token


class TestPage:
    def test_my_access_lists_the_app_with_a_sign_out_button(
        self, sue_client: tuple[TestClient, str], oauth: AuthStorage
    ) -> None:
        client, _ = sue_client
        _client(oauth, "copilot", "GitHub Copilot")
        _issue(oauth, "copilot", "sub-sue")

        page = client.get("/admin/me").text

        assert "Signed-in apps" in page
        assert "Sign out GitHub Copilot" in page
        assert "for scripts and clients that cannot sign in with a browser" in page

    def test_signing_out_through_the_page(
        self, sue_client: tuple[TestClient, str], oauth: AuthStorage, octx: AdminContext, sue: User
    ) -> None:
        client, csrf = sue_client
        _client(oauth, "copilot", "GitHub Copilot")
        _issue(oauth, "copilot", "sub-sue")

        response = client.post(
            "/admin/me/apps/sign-out",
            data={"csrf_token": csrf, "client_id": "copilot"},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert "notice=app_signed_out" in response.headers["location"]
        assert signed_in_apps(octx, sue) == []
        assert "No apps are signed in" in client.get("/admin/me").text

    def test_another_persons_app_is_refused_through_the_page(
        self, sue_client: tuple[TestClient, str], oauth: AuthStorage, octx: AdminContext, tom: User
    ) -> None:
        client, csrf = sue_client
        _issue(oauth, "copilot", "sub-tom")

        response = client.post(
            "/admin/me/apps/sign-out",
            data={"csrf_token": csrf, "client_id": "copilot"},
            follow_redirects=False,
        )

        assert response.headers["location"] == "/admin/me?problem=gone"
        assert [app.client_id for app in signed_in_apps(octx, tom)] == ["copilot"]

    def test_sign_out_needs_the_csrf_token(
        self, sue_client: tuple[TestClient, str], oauth: AuthStorage, octx: AdminContext, sue: User
    ) -> None:
        client, _ = sue_client
        _issue(oauth, "copilot", "sub-sue")

        response = client.post(
            "/admin/me/apps/sign-out", data={"client_id": "copilot"}, follow_redirects=False
        )

        assert response.status_code == 403
        assert [app.client_id for app in signed_in_apps(octx, sue)] == ["copilot"]


@pytest.fixture
def admin_session(octx: AdminContext, admin: User) -> Iterator[tuple[TestClient, str]]:
    finish_setup(octx.store)
    raw_id, session = start_session(octx.store, admin, "10.0.0.1")
    with admin_client(octx) as client:
        client.cookies.set(SESSION_COOKIE, raw_id)
        yield client, session.csrf_token


class TestAdminSignsOutSomeoneElse:
    """An admin can sign any person's apps out, one app or all of them."""

    def test_users_list_has_a_sign_out_button_only_for_people_with_apps(
        self, admin_session: tuple[TestClient, str], oauth: AuthStorage, sue: User, tom: User
    ) -> None:
        client, _ = admin_session
        _issue(oauth, "copilot", "sub-sue")

        page = client.get("/admin/users").text

        assert f'action="/admin/users/{sue.id}/apps/sign-out"' in page
        assert f'action="/admin/users/{tom.id}/apps/sign-out"' not in page

    def test_the_list_button_signs_out_every_app_and_returns_to_the_list(
        self,
        admin_session: tuple[TestClient, str],
        oauth: AuthStorage,
        octx: AdminContext,
        sue: User,
        tom: User,
        admin: User,
    ) -> None:
        client, csrf = admin_session
        _issue(oauth, "copilot", "sub-sue")
        _issue(oauth, "vscode", "sub-sue")
        _issue(oauth, "copilot", "sub-tom")

        response = client.post(
            f"/admin/users/{sue.id}/apps/sign-out",
            data={"csrf_token": csrf, "next": "/admin/users?q=s"},
            follow_redirects=False,
        )

        assert response.headers["location"].startswith("/admin/users?q=s")
        assert "notice=apps_signed_out" in response.headers["location"]
        assert signed_in_apps(octx, sue) == []
        assert [app.client_id for app in signed_in_apps(octx, tom)] == ["copilot"]
        entries = octx.store.recent_audit(2)
        assert {e["action"] for e in entries} == {"oauth_app.sign_out"}
        assert {e["actor_user_id"] for e in entries} == {admin.id}

    def test_the_person_page_signs_out_one_app(
        self,
        admin_session: tuple[TestClient, str],
        oauth: AuthStorage,
        octx: AdminContext,
        sue: User,
    ) -> None:
        client, csrf = admin_session
        _client(oauth, "copilot", "GitHub Copilot")
        _issue(oauth, "copilot", "sub-sue")
        _issue(oauth, "vscode", "sub-sue")
        assert "GitHub Copilot" in client.get(f"/admin/users/{sue.id}").text

        client.post(
            f"/admin/users/{sue.id}/apps/sign-out",
            data={"csrf_token": csrf, "client_id": "copilot"},
            follow_redirects=False,
        )

        assert [app.client_id for app in signed_in_apps(octx, sue)] == ["vscode"]

    def test_nothing_to_sign_out_is_reported(
        self, admin_session: tuple[TestClient, str], sue: User
    ) -> None:
        client, csrf = admin_session

        response = client.post(
            f"/admin/users/{sue.id}/apps/sign-out",
            data={"csrf_token": csrf},
            follow_redirects=False,
        )

        assert "problem=gone" in response.headers["location"]

    def test_a_non_admin_cannot_sign_out_someone_else(
        self,
        sue_client: tuple[TestClient, str],
        oauth: AuthStorage,
        octx: AdminContext,
        tom: User,
    ) -> None:
        client, csrf = sue_client
        _issue(oauth, "copilot", "sub-tom")

        response = client.post(
            f"/admin/users/{tom.id}/apps/sign-out",
            data={"csrf_token": csrf},
            follow_redirects=False,
        )

        assert response.status_code == 403
        assert [app.client_id for app in signed_in_apps(octx, tom)] == ["copilot"]

    def test_a_cross_site_next_is_ignored(
        self, admin_session: tuple[TestClient, str], oauth: AuthStorage, sue: User
    ) -> None:
        client, csrf = admin_session
        _issue(oauth, "copilot", "sub-sue")

        response = client.post(
            f"/admin/users/{sue.id}/apps/sign-out",
            data={"csrf_token": csrf, "next": "https://evil.example/"},
            follow_redirects=False,
        )

        assert response.headers["location"].startswith("/admin/")


def test_the_person_page_names_an_sso_user_not_their_subject(
    admin_session: tuple[TestClient, str], sue: User
) -> None:
    """Issue #25: the Sign-in row shows the person's name, not the provider's opaque ID."""
    client, _ = admin_session

    page = client.get(f"/admin/users/{sue.id}").text

    assert "Company (SSO): Sue" in page
    assert "Company (SSO): sub-sue" not in page


def test_users_with_apps_reads_the_tokens_once(
    octx: AdminContext, oauth: AuthStorage, sue: User, tom: User, admin: User
) -> None:
    from u2_mcp.admin.services import users_with_apps

    _issue(oauth, "copilot", "sub-sue")
    _issue(oauth, "copilot", "sub-tom", issuer="https://other.example.com")  # not Tom's issuer
    calls = 0
    original = oauth.people_with_tokens

    def counting() -> set[tuple[str | None, str]]:
        nonlocal calls
        calls += 1
        return original()

    oauth.people_with_tokens = counting  # type: ignore[method-assign]

    assert users_with_apps(octx, [sue, tom, admin]) == {sue.id}
    assert calls == 1
