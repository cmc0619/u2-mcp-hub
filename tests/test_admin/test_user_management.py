"""Users: reset a password, edit details, delete a person."""

import re
from collections.abc import Iterator

import pytest
from starlette.testclient import TestClient

from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.problems import Refused
from u2_mcp.admin.services import delete_person
from u2_mcp.passwords import hash_password, verify_password
from u2_mcp.setup_code import finish_setup
from u2_mcp.store.models import User

from .conftest import FakeRegistry
from .helpers import PASSWORD, admin_client, csrf_from, sign_in

TEMP = "temporary pass 1"


@pytest.fixture
def client(ctx: AdminContext) -> Iterator[TestClient]:
    finish_setup(ctx.store)
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    with admin_client(ctx) as test_client:
        sign_in(test_client)
        yield test_client


def _post(client: TestClient, user: User, action: str, **data: str):  # type: ignore[no-untyped-def]
    page = client.get(f"/admin/users/{user.id}").text
    return client.post(
        f"/admin/users/{user.id}/{action}",
        data={"csrf_token": csrf_from(page), **data},
        follow_redirects=False,
    )


def _bob(ctx: AdminContext) -> User:
    return ctx.store.add_local_user("bob", password_hash=hash_password("old password 123"))


def _actions(ctx: AdminContext) -> list[str]:
    return [entry["action"] for entry in ctx.store.recent_audit(50)]


class TestResetPassword:
    def test_a_typed_password_works_and_forces_a_change(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        bob = _bob(ctx)
        ctx.store.add_admin_session(id_hash="b1", user_id=bob.id, csrf_token="c", ip=None)
        token = ctx.store.add_token(user_id=bob.id, name="t", token_hash="h" * 64, expires_at=9e9)

        response = _post(client, bob, "reset-password", password=TEMP)

        assert response.status_code == 303
        assert response.headers["location"] == f"/admin/users/{bob.id}?notice=password_reset"
        assert verify_password(ctx.store.password_hash(bob.id), TEMP)
        after = ctx.store.get_user(bob.id)
        assert after is not None and after.must_change_password
        assert ctx.store.get_admin_session("b1") is None
        kept = ctx.store.get_token(token.id)
        assert kept is not None and kept.revoked_at is None
        with admin_client(ctx) as other:
            sign_in(other, "bob", TEMP)
            assert other.get("/admin/me", follow_redirects=False).headers["location"] == (
                "/admin/account/password"
            )

    def test_the_audit_names_the_person_never_the_password(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        bob = _bob(ctx)
        _post(client, bob, "reset-password", password=TEMP)

        entry = ctx.store.recent_audit(1)[0]
        assert entry["action"] == "password_reset"
        assert entry["params"] == {"user_id": bob.id, "username": "bob", "generated": False}
        assert TEMP not in str(ctx.store.recent_audit(50))

    def test_a_short_password_stays_on_the_page(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        bob = _bob(ctx)

        response = _post(client, bob, "reset-password", password="short")

        assert response.status_code == 400 and "Use at least 12 characters." in response.text
        assert verify_password(ctx.store.password_hash(bob.id), "old password 123")

    def test_generate_shows_the_password_once(self, client: TestClient, ctx: AdminContext) -> None:
        bob = _bob(ctx)

        response = _post(client, bob, "reset-password", generate="yes")

        assert response.status_code == 200
        shown = re.search(r'<code id="new-password">([^<]+)</code>', response.text)
        assert shown and len(shown.group(1)) == 16
        assert "data-copy" in response.text
        assert verify_password(ctx.store.password_hash(bob.id), shown.group(1))
        assert shown.group(1) not in client.get(f"/admin/users/{bob.id}").text
        assert shown.group(1) not in str(ctx.store.recent_audit(50))
        assert ctx.store.recent_audit(1)[0]["params"]["generated"] is True

    def test_you_cannot_reset_your_own_password_here(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        ann = ctx.store.get_user_by_username("ann")
        assert ann is not None

        response = _post(client, ann, "reset-password", password=TEMP)

        assert response.headers["location"] == f"/admin/users/{ann.id}?problem=reset_self"
        assert verify_password(ctx.store.password_hash(ann.id), PASSWORD)
        assert "password_reset" not in _actions(ctx)

    def test_an_sso_user_has_no_password_to_reset(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        sue = ctx.store.get_or_create_sso_user("sub-1", display_name="Sue")
        page = client.get(f"/admin/users/{sue.id}").text
        assert "Signs in with company sign-in; no password here." in page
        assert "Reset password" not in page

        response = _post(client, sue, "reset-password", password=TEMP)

        assert response.headers["location"] == f"/admin/users/{sue.id}?problem=reset_sso"
        assert ctx.store.password_hash(sue.id) is None

    def test_a_local_users_page_offers_the_form_and_says_tokens_stay(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        page = client.get(f"/admin/users/{_bob(ctx).id}").text

        assert "Reset password" in page and "Generate" in page
        assert "Tokens stay valid" in page


class TestEditDetails:
    def test_name_and_email_are_saved_and_audited(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        bob = _bob(ctx)

        response = _post(
            client, bob, "details", username="bob", display_name="Bob B", email="bob@x.io"
        )

        assert response.headers["location"] == f"/admin/users/{bob.id}?notice=saved"
        after = ctx.store.get_user(bob.id)
        assert after is not None and (after.display_name, after.email) == ("Bob B", "bob@x.io")
        assert ctx.store.recent_audit(1)[0]["action"] == "user_edited"

    def test_a_local_user_is_renamed(self, client: TestClient, ctx: AdminContext) -> None:
        bob = _bob(ctx)

        _post(client, bob, "details", username="robert", display_name="", email="")

        assert ctx.store.get_user_by_username("bob") is None
        renamed = ctx.store.get_user_by_username("robert")
        assert renamed is not None and renamed.id == bob.id
        entry = ctx.store.recent_audit(1)[0]
        assert entry["action"] == "user_renamed"
        assert entry["params"] == {"user_id": bob.id, "from": "bob", "to": "robert"}

    def test_a_taken_or_invalid_username_stays_on_the_form(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        bob = _bob(ctx)

        taken = _post(client, bob, "details", username="ann", display_name="", email="")
        invalid = _post(client, bob, "details", username="no spaces", display_name="", email="")

        assert taken.status_code == 400 and "already exists" in taken.text
        assert invalid.status_code == 400 and "Use 1 to 64 letters" in invalid.text
        assert ctx.store.get_user_by_username("bob") is not None

    def test_a_bad_email_is_refused(self, client: TestClient, ctx: AdminContext) -> None:
        bob = _bob(ctx)

        response = _post(client, bob, "details", username="bob", display_name="", email="nope")

        assert response.status_code == 400 and "Enter an email address" in response.text

    def test_an_sso_user_edits_names_only_with_a_note_about_sign_in(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        sue = ctx.store.get_or_create_sso_user("sub-1", display_name="Sue", email="s@x.io")
        page = client.get(f"/admin/users/{sue.id}").text
        assert 'name="username"' not in page
        assert "next company sign-in" in page

        _post(client, sue, "details", display_name="Susan", email="s@x.io", username="evil")

        after = ctx.store.get_user(sue.id)
        assert after is not None and after.display_name == "Susan" and after.username is None


class TestDelete:
    def _everything(self, ctx: AdminContext) -> tuple[User, int]:
        bob = _bob(ctx)
        connection = ctx.store.add_connection(
            name="Dev", host="h", port=1, service="uvcs", account="A", login_mode="per_user"
        )
        viewer = ctx.store.get_role_by_name("Viewer")
        assert viewer is not None
        ctx.store.add_grant(
            connection_id=connection.id, subject_type="user", subject_id=bob.id, role_id=viewer.id
        )
        ctx.store.set_u2_login(bob.id, connection.id, "bob_u2", "pw")
        ctx.store.add_token(user_id=bob.id, name="a", token_hash="a" * 64, expires_at=9e9)
        ctx.store.add_token(user_id=bob.id, name="b", token_hash="b" * 64, expires_at=9e9)
        ctx.store.add_admin_session(id_hash="b1", user_id=bob.id, csrf_token="c", ip=None)
        return bob, connection.id

    def test_the_confirmation_page_lists_what_goes(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        bob, _ = self._everything(ctx)

        page = client.get(f"/admin/users/{bob.id}/delete").text

        assert "Delete bob" in page
        assert "2 tokens (deleted)" in page
        assert "1 grant" in page
        assert "1 personal U2 login" in page
        assert "1 sign-in session" in page
        assert "Audit history stays" in page
        assert "disable them instead" not in page
        assert ctx.store.get_user(bob.id) is not None

    def test_deleting_an_sso_person_suggests_disabling_instead(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        sue = ctx.store.get_or_create_sso_user("sub-1", display_name="Sue")

        page = client.get(f"/admin/users/{sue.id}/delete").text

        assert (
            "To keep them out, disable them instead. Deleting doesn't stop them signing in "
            "again with company sign-in, and they then get any access their groups (or an "
            "everyone grant) give."
        ) in page

    def test_deleting_removes_them_and_closes_their_sessions(
        self, client: TestClient, ctx: AdminContext, registry: FakeRegistry
    ) -> None:
        bob, connection_id = self._everything(ctx)
        page = client.get(f"/admin/users/{bob.id}/delete").text

        response = client.post(
            f"/admin/users/{bob.id}/delete",
            data={"csrf_token": csrf_from(page)},
            follow_redirects=False,
        )

        assert response.headers["location"] == "/admin/users?notice=user_deleted"
        assert ctx.store.get_user(bob.id) is None
        assert ctx.store.list_tokens(bob.id) == []
        assert ctx.store.grants_for_subject("user", bob.id) == []
        assert ctx.store.list_u2_logins_for_user(bob.id) == []
        assert ctx.store.get_admin_session("b1") is None
        assert registry.owners_evicted == [(connection_id, bob.id)]
        entry = ctx.store.recent_audit(1)[0]
        assert entry["action"] == "user_deleted"
        assert entry["params"]["username"] == "bob" and entry["params"]["user_id"] == bob.id

    def test_their_earlier_audit_rows_stay(self, client: TestClient, ctx: AdminContext) -> None:
        bob = _bob(ctx)
        ctx.store.add_audit(
            kind="admin", action="note", outcome="ok", actor_user_id=bob.id, actor_label="bob"
        )
        page = client.get(f"/admin/users/{bob.id}/delete").text
        client.post(f"/admin/users/{bob.id}/delete", data={"csrf_token": csrf_from(page)})

        assert any(e["actor_label"] == "bob" for e in ctx.store.recent_audit(50))

    def test_you_cannot_delete_yourself(self, client: TestClient, ctx: AdminContext) -> None:
        ann = ctx.store.get_user_by_username("ann")
        assert ann is not None
        ctx.store.add_local_user("cy", is_admin=True)
        assert f"/admin/users/{ann.id}/delete" not in client.get(f"/admin/users/{ann.id}").text

        response = _post(client, ann, "delete")

        assert response.headers["location"] == f"/admin/users/{ann.id}?problem=delete_self"
        assert ctx.store.get_user(ann.id) is not None
        assert "user_deleted" not in _actions(ctx)

    def test_the_last_enabled_local_admin_cannot_be_deleted(
        self, ctx: AdminContext, admin: User
    ) -> None:
        sso = ctx.store.get_or_create_sso_user("sub-1")
        ctx.store.set_user_admin(sso.id, True)
        actor = ctx.store.get_user(sso.id)
        assert actor is not None

        with pytest.raises(Refused) as refused:
            delete_person(ctx, admin.id, actor=actor)

        assert refused.value.code == "last_admin"
        assert ctx.store.get_user(admin.id) is not None
        assert "user_deleted" not in _actions(ctx)

    def test_a_disabled_admin_goes_freely(self, client: TestClient, ctx: AdminContext) -> None:
        dee = ctx.store.add_local_user("dee", is_admin=True)
        ctx.store.set_user_flags(dee.id, disabled=True)
        page = client.get(f"/admin/users/{dee.id}/delete").text

        response = client.post(
            f"/admin/users/{dee.id}/delete",
            data={"csrf_token": csrf_from(page)},
            follow_redirects=False,
        )

        assert response.headers["location"] == "/admin/users?notice=user_deleted"

    def test_a_missing_person_is_a_404(self, client: TestClient) -> None:
        assert client.get("/admin/users/999/delete").status_code == 404


def test_deleting_an_sso_person_revokes_their_oauth_tokens(
    ctx: AdminContext,
) -> None:
    import dataclasses

    from u2_mcp.auth.storage import AuthStorage, StoredToken

    oauth = AuthStorage(ctx.store.locked)
    ctx = dataclasses.replace(ctx, oauth_storage=oauth)
    admin = ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    sue = ctx.store.get_or_create_sso_user("sub-1", display_name="Sue")
    for kind in ("access", "refresh"):
        token = StoredToken(
            token=f"{kind}-sue", token_type=kind, client_id="vscode", user_subject="sub-1", scope=""
        )
        getattr(oauth, f"store_{kind}_token")(token)

    delete_person(ctx, sue.id, actor=admin)

    assert oauth.get_access_token("access-sue") is None
    assert oauth.get_refresh_token("refresh-sue") is None
    # Signing in again afresh brings them back as a new person; the old token stays dead.
    from unittest.mock import patch

    from mcp.server.auth.provider import AccessToken

    from u2_mcp.auth.idp.base import TokenInfo
    from u2_mcp.team_auth import make_identity_resolver, record_sign_in

    record_sign_in(ctx.store, TokenInfo(subject="sub-1"), [], via="mcp", issuer="https://i")
    old = AccessToken(token="access-sue", client_id="vscode", scopes=["u2:read"])
    with patch("mcp.server.auth.middleware.auth_context.get_access_token", return_value=old):
        assert make_identity_resolver(ctx.store, oauth)() is None
