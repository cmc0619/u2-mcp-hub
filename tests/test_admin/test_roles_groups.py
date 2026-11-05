"""Roles (clone, edit, delete) and Groups (labels, grants)."""

from collections.abc import Iterator

import pytest
from starlette.testclient import TestClient

from u2_mcp.admin import routes_roles
from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.problems import PROBLEMS, Refused
from u2_mcp.admin.services import clone_role, remove_role, save_role
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import finish_setup
from u2_mcp.store.models import User

from .helpers import PASSWORD, admin_client, csrf_from, sign_in


def _viewer_id(ctx: AdminContext) -> int:
    role = ctx.store.get_role_by_name("Viewer")
    assert role is not None
    return role.id


class TestRoleService:
    def test_cloning_names_the_copy_and_audits(self, ctx: AdminContext, admin: User) -> None:
        first = clone_role(ctx, _viewer_id(ctx), actor=admin)
        second = clone_role(ctx, _viewer_id(ctx), actor=admin)

        assert (first.name, second.name) == ("Copy of Viewer", "Copy of Viewer 2")
        assert not first.builtin and ctx.store.recent_audit(1)[0]["action"] == "role.create"

    def test_builtin_roles_are_refused(self, ctx: AdminContext, admin: User) -> None:
        with pytest.raises(Refused) as refused:
            save_role(ctx, _viewer_id(ctx), name="Viewer", permissions=[], version=1, actor=admin)
        assert refused.value.code == "role_builtin"

    def test_a_role_in_use_stays(self, ctx: AdminContext, admin: User) -> None:
        role = clone_role(ctx, _viewer_id(ctx), actor=admin)
        connection = ctx.store.add_connection(
            name="P",
            host="h",
            port=1,
            service="uvcs",
            account="A",
            shared_user="s",
            shared_password="p",
        )
        ctx.store.add_grant(connection_id=connection.id, subject_type="everyone", role_id=role.id)

        with pytest.raises(Refused) as refused:
            remove_role(ctx, role.id, actor=admin)
        assert refused.value.code == "role_in_use"


@pytest.fixture
def client(ctx: AdminContext) -> Iterator[TestClient]:
    finish_setup(ctx.store)
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    with admin_client(ctx) as test_client:
        sign_in(test_client)
        yield test_client


class TestPages:
    def test_two_admins_editing_one_role(
        self, client: TestClient, ctx: AdminContext, admin: User
    ) -> None:
        role = clone_role(ctx, _viewer_id(ctx), actor=admin)
        page = client.get(f"/admin/roles/{role.id}").text
        data = {
            "csrf_token": csrf_from(page),
            "name": "Readers",
            "version": str(role.version),
            "permissions": ["schema.read"],
        }
        assert (
            client.post(f"/admin/roles/{role.id}", data=data, follow_redirects=False).status_code
            == 303
        )

        stale = client.post(f"/admin/roles/{role.id}", data={**data, "name": "Late"})

        assert stale.status_code == 409
        assert "Someone else changed this role since you opened it." in stale.text

    def test_the_group_page_edits_the_label_and_offers_grants(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        user = ctx.store.get_or_create_sso_user("s")
        ctx.store.record_sso_login(user.id, ["eng"])
        group = ctx.store.list_groups()[0]
        page = client.get(f"/admin/groups/{group.id}").text
        assert "Add grant" in page

        client.post(
            f"/admin/groups/{group.id}",
            data={"csrf_token": csrf_from(page), "label": "Engineering"},
        )

        assert "Engineering" in client.get("/admin/groups").text

    def test_each_group_lists_its_access_under_it(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        user = ctx.store.get_or_create_sso_user("s", issuer="https://idp.example")
        ctx.store.record_sso_login(user.id, ["eng", "ops"])
        eng = next(g for g in ctx.store.list_groups() if g.external_id == "eng")
        prod = ctx.store.add_connection(name="Prod", host="h", port=1, service="uvcs", account="A")
        viewer = ctx.store.get_role_by_name("Viewer")
        assert viewer is not None
        ctx.store.add_grant(
            connection_id=prod.id, subject_type="group", subject_id=eng.id, role_id=viewer.id
        )

        page = client.get("/admin/groups").text

        assert f'href="/admin/connections/{prod.id}">Prod</a>: Viewer' in page
        assert "No access" in page  # ops has none
        assert "https://idp.example" not in page  # one provider: nothing to tell apart
        assert "https://idp.example" not in client.get(f"/admin/connections/{prod.id}").text

    def test_groups_show_the_provider_that_named_them(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        for issuer in ("https://old-idp.example", "https://new-idp.example"):
            user = ctx.store.get_or_create_sso_user("s", issuer=issuer)
            ctx.store.record_sso_login(user.id, ["Developers"])

        page = client.get("/admin/groups").text

        assert "https://old-idp.example" in page and "https://new-idp.example" in page


def test_an_unknown_permission_is_its_own_problem(ctx: AdminContext, admin: User) -> None:
    role = clone_role(ctx, _viewer_id(ctx), actor=admin)

    with pytest.raises(Refused) as refused:
        save_role(
            ctx, role.id, name="X", permissions=["no.such"], version=role.version, actor=admin
        )

    assert refused.value.code == "unknown_permission"
    assert PROBLEMS["unknown_permission"] == "That permission does not exist."


def test_cloning_a_role_deleted_meanwhile_is_not_a_500(
    client: TestClient, ctx: AdminContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    page = client.get(f"/admin/roles/{_viewer_id(ctx)}").text

    def deleted_meanwhile(*_args: object, **_kwargs: object) -> None:
        raise Refused("gone")

    monkeypatch.setattr(routes_roles, "clone_role", deleted_meanwhile)
    response = client.post(
        f"/admin/roles/{_viewer_id(ctx)}/clone",
        data={"csrf_token": csrf_from(page)},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/roles?problem=gone"


def test_every_permission_row_names_its_tools(client: TestClient, ctx: AdminContext) -> None:
    owner = ctx.store.get_role_by_name("Owner")
    assert owner is not None

    page = client.get(f"/admin/roles/{owner.id}").text

    for tool in ("list_programs", "read_program", "write_program", "catalog_program"):
        assert tool in page
    assert "Reserved for BASIC tools" not in page
    assert "No tools" not in page


class TestDeletingGroups:
    """Old or gone groups can be found by filter and deleted, with or without access."""

    @staticmethod
    def _groups(ctx: AdminContext) -> dict[str, int]:
        user = ctx.store.get_or_create_sso_user("s", issuer="https://idp.example")
        ctx.store.record_sso_login(user.id, ["eng", "old"])
        return {g.external_id: g.id for g in ctx.store.list_groups()}

    def test_a_group_with_no_access_is_deleted_at_once(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        ids = self._groups(ctx)
        token = csrf_from(client.get("/admin/groups").text)

        response = client.post(
            f"/admin/groups/{ids['old']}/delete",
            data={"csrf_token": token, "next": "/admin/groups?access=none"},
            follow_redirects=False,
        )

        assert response.headers["location"] == "/admin/groups?access=none&notice=group_deleted"
        assert ctx.store.get_group(ids["old"]) is None
        assert ctx.store.recent_audit(1)[0]["action"] == "group.delete"

    def test_a_group_with_access_is_confirmed_and_its_grants_go_too(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        ids = self._groups(ctx)
        prod = ctx.store.add_connection(name="Prod", host="h", port=1, service="uvcs", account="A")
        viewer = ctx.store.get_role_by_name("Viewer")
        assert viewer is not None
        grant = ctx.store.add_grant(
            connection_id=prod.id, subject_type="group", subject_id=ids["eng"], role_id=viewer.id
        )
        listing = client.get("/admin/groups").text
        assert f'href="/admin/groups/{ids["eng"]}/delete?next=' in listing  # asks first

        confirm = client.get(f"/admin/groups/{ids['eng']}/delete").text
        assert "Prod: Viewer" in confirm
        client.post(f"/admin/groups/{ids['eng']}/delete", data={"csrf_token": csrf_from(confirm)})

        assert ctx.store.get_group(ids["eng"]) is None
        assert ctx.store.get_grant(grant.id) is None

    @pytest.mark.parametrize(
        ("query", "shown", "hidden"),
        [
            ("access=none", "old", "eng"),
            ("access=with", "eng", "old"),
            ("q=OL", "old", "eng"),
            ("unseen=30", "old", "eng"),
        ],
    )
    def test_the_filters(
        self, client: TestClient, ctx: AdminContext, query: str, shown: str, hidden: str
    ) -> None:
        ids = self._groups(ctx)
        prod = ctx.store.add_connection(name="Prod", host="h", port=1, service="uvcs", account="A")
        viewer = ctx.store.get_role_by_name("Viewer")
        assert viewer is not None
        ctx.store.add_grant(
            connection_id=prod.id, subject_type="group", subject_id=ids["eng"], role_id=viewer.id
        )
        with ctx.store.locked() as conn:  # "old" was last seen 60 days ago
            conn.execute(
                "UPDATE groups SET last_seen_at = last_seen_at - 60 * 86400 WHERE id = ?",
                (ids["old"],),
            )

        page = client.get(f"/admin/groups?{query}").text

        assert f"<code>{shown}</code>" in page
        assert f"<code>{hidden}</code>" not in page

    def test_groups_with_no_provider_can_be_picked_apart_from_any(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        ids = self._groups(ctx)
        with ctx.store.locked() as conn:
            conn.execute("UPDATE groups SET issuer = NULL WHERE id = ?", (ids["old"],))

        page = client.get("/admin/groups?provider=-").text

        assert "<code>old</code>" in page
        assert "<code>eng</code>" not in page
        assert '<option value="-" selected>' in page
