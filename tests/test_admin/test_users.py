"""Users: list, create, flags, tokens, grants and effective access."""

from collections.abc import Iterator

import pytest
from starlette.testclient import TestClient

from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.problems import PROBLEMS, Refused
from u2_mcp.admin.security import SESSION_COOKIE, start_session
from u2_mcp.admin.services import create_personal_token, set_user_flags
from u2_mcp.config import U2Config
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import finish_setup
from u2_mcp.store.models import User
from u2_mcp.store.repo import LastAdmin

from .helpers import PASSWORD, admin_client, csrf_from, sign_in


class TestFlags:
    def test_you_cannot_demote_or_disable_yourself(self, ctx: AdminContext, admin: User) -> None:
        for change in ({"is_admin": False}, {"disabled": True}):
            with pytest.raises(Refused) as refused:
                set_user_flags(ctx, admin.id, actor=admin, **change)  # type: ignore[arg-type]
            assert refused.value.code == "user_self"

    def test_the_last_enabled_local_admin_stays(self, ctx: AdminContext, admin: User) -> None:
        sso_admin = ctx.store.get_or_create_sso_user("sub-1")
        ctx.store.set_user_admin(sso_admin.id, True)
        acting = ctx.store.get_user(sso_admin.id)
        assert acting is not None

        with pytest.raises(Refused) as refused:
            set_user_flags(ctx, admin.id, disabled=True, actor=acting)

        assert refused.value.code == "last_admin"

    def test_disabling_ends_sessions_and_is_audited(self, ctx: AdminContext, admin: User) -> None:
        bob = ctx.store.add_local_user("bob")
        ctx.store.add_admin_session(id_hash="b", user_id=bob.id, csrf_token="c", ip=None)

        set_user_flags(ctx, bob.id, disabled=True, actor=admin)

        assert ctx.store.get_admin_session("b") is None
        entry = ctx.store.recent_audit(1)[0]
        assert entry["action"] == "user.flags" and entry["params"] == {
            "user_id": bob.id,
            "disabled": True,
        }

    def test_a_store_refusal_is_reported_as_last_admin(
        self, ctx: AdminContext, admin: User, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bob = ctx.store.add_local_user("bob", is_admin=True)

        def refuse(*_args: object, **_kwargs: object) -> None:
            raise LastAdmin("none left")

        monkeypatch.setattr(ctx.store, "set_user_flags", refuse)
        with pytest.raises(Refused) as refused:
            set_user_flags(ctx, bob.id, disabled=True, actor=admin)

        assert refused.value.code == "last_admin"

    def test_an_actor_who_lost_admin_is_refused(self, ctx: AdminContext, admin: User) -> None:
        bob = ctx.store.add_local_user("bob")
        ctx.store.add_local_user("cy", is_admin=True)
        ctx.store.set_user_disabled(admin.id, True)

        with pytest.raises(Refused) as refused:
            set_user_flags(ctx, bob.id, is_admin=True, actor=admin)

        assert refused.value.code == "not_admin"
        unchanged = ctx.store.get_user(bob.id)
        assert unchanged is not None and not unchanged.is_admin

    def test_no_change_writes_no_audit(self, ctx: AdminContext, admin: User) -> None:
        bob = ctx.store.add_local_user("bob")
        before = len(ctx.store.recent_audit(1000))

        set_user_flags(ctx, bob.id, actor=admin)

        assert len(ctx.store.recent_audit(1000)) == before


@pytest.fixture
def client(ctx: AdminContext) -> Iterator[TestClient]:
    finish_setup(ctx.store)
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    with admin_client(ctx) as test_client:
        sign_in(test_client)
        yield test_client


class TestPages:
    def test_the_list_filters_and_escapes(self, client: TestClient, ctx: AdminContext) -> None:
        ctx.store.add_local_user("bob", display_name="<b>Bob</b>")
        ctx.store.add_local_user("cy")

        page = client.get("/admin/users?q=bob").text

        assert "&lt;b&gt;Bob&lt;/b&gt;" in page and "<b>Bob</b>" not in page
        assert ">cy<" not in page
        assert "&lt;b&gt;Bob" not in client.get("/admin/users?admin=yes").text

    def test_creating_a_local_user(self, client: TestClient, ctx: AdminContext) -> None:
        token = csrf_from(client.get("/admin/users/new").text)
        response = client.post(
            "/admin/users/new",
            data={
                "csrf_token": token,
                "username": "dee",
                "password": "long enough pass",
                "password_again": "long enough pass",
            },
            follow_redirects=False,
        )

        dee = ctx.store.get_user_by_username("dee")
        assert dee is not None and not dee.is_admin
        assert response.headers["location"] == f"/admin/users/{dee.id}?notice=saved"

    def test_problems_stay_on_the_form(self, client: TestClient) -> None:
        token = csrf_from(client.get("/admin/users/new").text)
        response = client.post(
            "/admin/users/new",
            data={
                "csrf_token": token,
                "username": "dee",
                "password": "short",
                "password_again": "short",
            },
        )

        assert response.status_code == 400 and "Use at least 12 characters." in response.text

    def test_an_admin_revokes_someone_elses_token(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        bob = ctx.store.add_local_user("bob")
        _value, record = create_personal_token(ctx, bob, name="bobs-laptop", days="9")
        page = client.get(f"/admin/users/{bob.id}").text
        assert "bobs-laptop" in page

        client.post(
            f"/admin/users/{bob.id}/tokens/{record.id}/revoke",
            data={"csrf_token": csrf_from(page)},
        )

        stored = ctx.store.get_token(record.id)
        assert stored is not None and stored.revoked_at is not None

    def test_effective_access_names_each_source(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        connection = ctx.store.add_connection(
            name="Prod",
            host="h",
            port=1,
            service="uvcs",
            account="A",
            shared_user="s",
            shared_password="p",
        )
        sso = ctx.store.get_or_create_sso_user("sub-9", display_name="Sue")
        ctx.store.record_sso_login(sso.id, ["eng"])
        group = ctx.store.list_groups()[0]
        viewer = ctx.store.get_role_by_name("Viewer")
        analyst = ctx.store.get_role_by_name("Developer")
        assert viewer is not None and analyst is not None
        ctx.store.add_grant(
            connection_id=connection.id, subject_type="user", subject_id=sso.id, role_id=viewer.id
        )
        ctx.store.add_grant(
            connection_id=connection.id,
            subject_type="group",
            subject_id=group.id,
            role_id=analyst.id,
        )

        page = client.get(f"/admin/users/{sso.id}/access").text

        assert "user grant (Viewer)" in page and "group eng (Developer)" in page
        assert "query.run" in page
        assert "knowledge.write" not in page and "knowledge.read" not in page
        assert "Add grant" in client.get(f"/admin/users/{sso.id}").text

    def test_changing_your_own_flags_shows_the_problem(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        ann = ctx.store.get_user_by_username("ann")
        assert ann is not None
        page = client.get(f"/admin/users/{ann.id}").text

        response = client.post(
            f"/admin/users/{ann.id}/flags",
            data={"csrf_token": csrf_from(page), "is_admin": "off"},
            follow_redirects=False,
        )

        assert response.headers["location"] == f"/admin/users/{ann.id}?problem=user_self"
        shown = client.get(response.headers["location"]).text
        assert PROBLEMS["user_self"].replace("'", "&#39;") in shown

    def test_a_flags_post_without_a_valid_field_changes_nothing(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        bob = ctx.store.add_local_user("bob")
        page = client.get(f"/admin/users/{bob.id}").text
        before = len(ctx.store.recent_audit(1000))

        response = client.post(
            f"/admin/users/{bob.id}/flags",
            data={"csrf_token": csrf_from(page), "disabled": "maybe"},
            follow_redirects=False,
        )

        assert response.headers["location"] == f"/admin/users/{bob.id}"
        assert len(ctx.store.recent_audit(1000)) == before
        unchanged = ctx.store.get_user(bob.id)
        assert unchanged is not None and not unchanged.disabled

    def test_effective_access_shows_everyone_and_read_only(
        self, client: TestClient, ctx: AdminContext, mock_config_read_only: U2Config
    ) -> None:
        connection = ctx.store.add_connection(
            name="Prod",
            host="h",
            port=1,
            service="uvcs",
            account="A",
            shared_user="s",
            shared_password="p",
        )
        analyst = ctx.store.get_role_by_name("Developer")
        assert analyst is not None
        ctx.store.add_grant(
            connection_id=connection.id, subject_type="everyone", role_id=analyst.id
        )
        bob = ctx.store.add_local_user("bob")
        ctx.config = mock_config_read_only

        page = client.get(f"/admin/users/{bob.id}/access").text

        assert "everyone (Developer)" in page
        assert "knowledge.write" not in page
        assert "knowledge.read" not in page


def test_the_last_local_admin_shows_the_problem(ctx: AdminContext) -> None:
    finish_setup(ctx.store)
    ann = ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    sue = ctx.store.get_or_create_sso_user("sub-1", display_name="Sue")
    ctx.store.set_user_admin(sue.id, True)
    acting = ctx.store.get_user(sue.id)
    assert acting is not None
    raw_id, session = start_session(ctx.store, acting, "10.0.0.1")

    with admin_client(ctx) as sso_client:
        sso_client.cookies.set(SESSION_COOKIE, raw_id)
        response = sso_client.post(
            f"/admin/users/{ann.id}/flags",
            data={"csrf_token": session.csrf_token, "disabled": "on"},
            follow_redirects=False,
        )

        assert response.headers["location"] == f"/admin/users/{ann.id}?problem=last_admin"
        assert PROBLEMS["last_admin"] in sso_client.get(response.headers["location"]).text
    kept = ctx.store.get_user(ann.id)
    assert kept is not None and not kept.disabled
