"""The grants service and the grants routes."""

from collections.abc import Iterator

import pytest
from starlette.testclient import TestClient

from u2_mcp.access import decide
from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.problems import Refused, with_query
from u2_mcp.admin.services import (
    EVERYONE_WARNING,
    ConnectionForm,
    delete_grant,
    grant_rows,
    save_connection,
    save_grant,
    update_grant,
)
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import finish_setup
from u2_mcp.store.models import User

from .helpers import PASSWORD, admin_client, csrf_from, sign_in


def _role(ctx: AdminContext, name: str) -> int:
    role = ctx.store.get_role_by_name(name)
    assert role is not None
    return role.id


def _connection(ctx: AdminContext, *, per_user: bool = False) -> int:
    return ctx.store.add_connection(
        name="Dev" if per_user else "Prod",
        host="u2.example",
        port=31438,
        service="uvcs",
        account="DEV",
        login_mode="per_user" if per_user else "shared",
        shared_user=None if per_user else "svc",
        shared_password=None if per_user else "pw",
    ).id


class TestService:
    def test_a_user_grant_is_saved_and_audited(self, ctx: AdminContext, admin: User) -> None:
        connection_id = _connection(ctx)

        grant = save_grant(
            ctx,
            connection_id=connection_id,
            subject_type="user",
            subject_id=admin.id,
            role_id=_role(ctx, "Viewer"),
            actor=admin,
        )

        assert grant.subject_id == admin.id
        entry = ctx.store.recent_audit(1)[0]
        assert (entry["action"], entry["connection_id"]) == ("grant.create", connection_id)
        assert entry["params"]["role"] == "Viewer"

    def test_a_second_grant_for_the_same_subject_is_refused(
        self, ctx: AdminContext, admin: User
    ) -> None:
        connection_id = _connection(ctx)
        values = dict(
            connection_id=connection_id,
            subject_type="everyone",
            subject_id=None,
            role_id=_role(ctx, "Viewer"),
            actor=admin,
        )
        save_grant(ctx, **values)  # type: ignore[arg-type]

        with pytest.raises(Refused) as refused:
            save_grant(ctx, **values)  # type: ignore[arg-type]

        assert refused.value.code == "grant_duplicate"

    def test_a_user_grant_on_a_per_user_connection_needs_no_login(
        self, ctx: AdminContext, admin: User
    ) -> None:
        connection_id = _connection(ctx, per_user=True)

        grant = save_grant(
            ctx,
            connection_id=connection_id,
            subject_type="user",
            subject_id=admin.id,
            role_id=_role(ctx, "Viewer"),
            actor=admin,
        )

        # The person sets their own U2 login on My access.
        assert ctx.store.get_u2_login(admin.id, connection_id) is None
        update_grant(ctx, grant.id, role_id=_role(ctx, "Developer"), actor=admin)
        assert ctx.store.get_grant(grant.id).role_id == _role(ctx, "Developer")  # type: ignore[union-attr]

    def test_delete_and_rows(self, ctx: AdminContext, admin: User) -> None:
        connection_id = _connection(ctx)
        grant = save_grant(
            ctx,
            connection_id=connection_id,
            subject_type="everyone",
            subject_id=None,
            role_id=_role(ctx, "Viewer"),
            actor=admin,
        )

        rows = grant_rows(ctx, connection_id=connection_id)
        assert [(r.subject_label, r.role.name) for r in rows] == [("Everyone", "Viewer")]

        delete_grant(ctx, grant.id, actor=admin)
        assert grant_rows(ctx, connection_id=connection_id) == []
        assert ctx.store.recent_audit(1)[0]["action"] == "grant.delete"
        with pytest.raises(Refused) as refused:
            delete_grant(ctx, grant.id, actor=admin)
        assert refused.value.code == "gone"

    def test_a_group_grant_names_its_provider(self, ctx: AdminContext, admin: User) -> None:
        """Two providers can both send "Developers"; the grant list tells them apart."""
        connection_id = _connection(ctx)
        user = ctx.store.get_or_create_sso_user("s", issuer="https://old-idp.example")
        ctx.store.record_sso_login(user.id, ["Developers"])
        group = ctx.store.list_groups()[0]
        save_grant(
            ctx,
            connection_id=connection_id,
            subject_type="group",
            subject_id=group.id,
            role_id=_role(ctx, "Viewer"),
            actor=admin,
        )

        rows = grant_rows(ctx, connection_id=connection_id)

        assert rows[0].subject_label == "Developers (https://old-idp.example)"

    def test_moving_a_per_user_connection_forgets_its_u2_logins(
        self, ctx: AdminContext, admin: User
    ) -> None:
        connection_id = _connection(ctx, per_user=True)
        ctx.store.set_u2_login(admin.id, connection_id, "root", "pw")
        saved = ctx.store.get_connection(connection_id)
        assert saved is not None
        form = ConnectionForm.from_connection(saved)
        form.host = "elsewhere.example"

        save_connection(ctx, form, actor=admin, connection_id=connection_id)

        assert ctx.store.get_u2_login(admin.id, connection_id) is None
        assert ctx.store.recent_audit(1)[0]["params"]["cleared_u2_logins"] == 1

    def test_a_detour_through_shared_mode_still_forgets_the_u2_logins(
        self, ctx: AdminContext, admin: User
    ) -> None:
        connection_id = _connection(ctx, per_user=True)
        ctx.store.set_u2_login(admin.id, connection_id, "root", "pw")
        saved = ctx.store.get_connection(connection_id)
        assert saved is not None
        form = ConnectionForm.from_connection(saved)
        form.login_mode, form.login_user, form.login_password = "shared", "svc", "svc-pw"
        saved = save_connection(ctx, form, actor=admin, connection_id=connection_id)
        assert ctx.store.get_u2_login(admin.id, connection_id) is not None  # same host: kept

        form = ConnectionForm.from_connection(saved)
        form.host, form.login_password = "elsewhere.example", "svc-pw"
        save_connection(ctx, form, actor=admin, connection_id=connection_id)

        assert ctx.store.get_u2_login(admin.id, connection_id) is None


def test_with_query_appends_safely() -> None:
    assert with_query("/admin/users/3", problem="gone") == "/admin/users/3?problem=gone"
    assert with_query("/admin/x?a=1", notice="saved") == "/admin/x?a=1&notice=saved"


@pytest.fixture
def client(ctx: AdminContext) -> Iterator[TestClient]:
    finish_setup(ctx.store)
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    with admin_client(ctx) as test_client:
        sign_in(test_client)
        yield test_client


class TestRoutes:
    def test_the_connection_page_adds_a_grant(self, client: TestClient, ctx: AdminContext) -> None:
        connection_id = _connection(ctx)
        page = client.get(f"/admin/connections/{connection_id}").text
        assert "Add grant" in page

        ann = ctx.store.get_user_by_username("ann")
        assert ann is not None
        response = client.post(
            "/admin/grants",
            data={
                "csrf_token": csrf_from(page),
                "return_to": f"/admin/connections/{connection_id}",
                "connection_id": str(connection_id),
                "subject_type": "user",
                "user_id": str(ann.id),
                "role_id": str(_role(ctx, "Viewer")),
            },
            follow_redirects=False,
        )

        assert response.headers["location"] == f"/admin/connections/{connection_id}?notice=saved"
        [grant] = ctx.store.grants_on_connection(connection_id)
        assert (grant.subject_type, grant.subject_id, grant.role_id) == (
            "user",
            ann.id,
            _role(ctx, "Viewer"),
        )
        assert "Remove" in client.get(response.headers["location"]).text

    def test_a_refusal_comes_back_as_a_fixed_problem(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        connection_id = _connection(ctx)
        page = client.get(f"/admin/connections/{connection_id}").text
        data = {
            "csrf_token": csrf_from(page),
            "return_to": f"/admin/connections/{connection_id}",
            "connection_id": str(connection_id),
            "subject_type": "everyone",
            "role_id": str(_role(ctx, "Viewer")),
        }
        client.post("/admin/grants", data=data)

        again = client.post("/admin/grants", data=data, follow_redirects=False)

        assert again.headers["location"].endswith("?problem=grant_duplicate")
        shown = client.get(again.headers["location"]).text
        assert "already has a grant on this connection" in shown

    def test_return_to_outside_the_admin_site_is_ignored(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        connection_id = _connection(ctx)
        page = client.get(f"/admin/connections/{connection_id}").text
        response = client.post(
            "/admin/grants",
            data={
                "csrf_token": csrf_from(page),
                "return_to": "https://evil.example/",
                "connection_id": str(connection_id),
                "subject_type": "everyone",
                "role_id": str(_role(ctx, "Viewer")),
            },
            follow_redirects=False,
        )

        assert response.headers["location"] == "/admin/?notice=saved"


def _post_grant(client: TestClient, connection_id: int, **fields: str) -> str:
    """Add a grant through the connection page's form; returns the redirect target."""
    page = client.get(f"/admin/connections/{connection_id}").text
    data = {
        "csrf_token": csrf_from(page),
        "return_to": f"/admin/connections/{connection_id}",
        "connection_id": str(connection_id),
        **fields,
    }
    response = client.post("/admin/grants", data=data, follow_redirects=False)
    return str(response.headers["location"])


class TestMoreRoutes:
    def test_an_everyone_grant_shows_its_warning(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        connection_id = _connection(ctx)
        shown = f'<p class="warning">{EVERYONE_WARNING}</p>'
        assert shown not in client.get(f"/admin/connections/{connection_id}").text

        _post_grant(
            client, connection_id, subject_type="everyone", role_id=str(_role(ctx, "Viewer"))
        )

        assert shown in client.get(f"/admin/connections/{connection_id}").text

    def test_a_group_grant(self, client: TestClient, ctx: AdminContext) -> None:
        connection_id = _connection(ctx)
        sso = ctx.store.get_or_create_sso_user("sub-1", email="sam@example.com")
        ctx.store.record_sso_login(sso.id, ["finance-team"])
        [group] = ctx.store.list_groups()

        target = _post_grant(
            client,
            connection_id,
            subject_type="group",
            group_id=str(group.id),
            role_id=str(_role(ctx, "Developer")),
        )

        assert target.endswith("?notice=saved")
        [grant] = ctx.store.grants_on_connection(connection_id)
        assert (grant.subject_type, grant.subject_id) == ("group", group.id)
        assert "finance-team" in client.get(target).text
        allowed = decide(ctx.store, sso.id, "Prod", "query.run", global_read_only=False)
        assert allowed.allowed and "query.run" in allowed.permissions
        assert not any(p.startswith("knowledge.") for p in allowed.permissions)

    def test_a_grant_made_on_the_page_lets_the_person_use_the_connection(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        connection_id = _connection(ctx)
        bob = ctx.store.add_local_user("bob")
        before = decide(ctx.store, bob.id, "Prod", "records.read", global_read_only=False)
        assert not before.allowed

        _post_grant(
            client,
            connection_id,
            subject_type="user",
            user_id=str(bob.id),
            role_id=str(_role(ctx, "Viewer")),
        )

        after = decide(ctx.store, bob.id, "Prod", "records.read", global_read_only=False)
        assert after.allowed and after.connection is not None
        assert after.connection.id == connection_id
        write = decide(ctx.store, bob.id, "Prod", "records.write", global_read_only=False)
        assert not write.allowed


@pytest.fixture
def bob_client(ctx: AdminContext) -> Iterator[TestClient]:
    finish_setup(ctx.store)
    ctx.store.add_local_user("bob", password_hash=hash_password(PASSWORD))
    with admin_client(ctx) as test_client:
        sign_in(test_client, username="bob")
        yield test_client


def test_a_non_admin_is_refused_on_the_grants_editor(
    bob_client: TestClient, ctx: AdminContext
) -> None:
    connection_id = _connection(ctx)
    grant = ctx.store.add_grant(
        connection_id=connection_id, subject_type="everyone", role_id=_role(ctx, "Viewer")
    )
    page = bob_client.get(f"/admin/connections/{connection_id}", follow_redirects=False)
    assert page.headers["location"] == "/admin/me"
    token = csrf_from(bob_client.get("/admin/me").text)
    before = len(ctx.store.recent_audit(1000))

    for path, fields in (
        (
            "/admin/grants",
            {
                "connection_id": str(connection_id),
                "subject_type": "everyone",
                "role_id": str(_role(ctx, "Owner")),
            },
        ),
        (f"/admin/grants/{grant.id}", {"role_id": str(_role(ctx, "Owner"))}),
        (f"/admin/grants/{grant.id}/delete", {}),
    ):
        response = bob_client.post(path, data={"csrf_token": token, **fields})
        assert response.status_code == 403, path
        assert "Only admins can use this page." in response.text

    assert ctx.store.grants_on_connection(connection_id) == [grant]
    assert len(ctx.store.recent_audit(1000)) == before


class TestHugeIds:
    """Ids beyond SQLite's 64-bit range are not found, never a 500."""

    def test_an_admin_id_route_answers_404(self, client: TestClient) -> None:
        token = csrf_from(client.get("/admin/").text)

        assert client.get("/admin/connections/99999999999999999999").status_code == 404
        gone = client.post(
            "/admin/connections/99999999999999999999/delete", data={"csrf_token": token}
        )
        assert gone.status_code == 404

    def test_a_huge_form_id_is_refused_with_a_problem(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        connection_id = _connection(ctx)

        target = _post_grant(
            client,
            connection_id,
            subject_type="user",
            user_id="99999999999999999999",
            role_id="9223372036854775808",
        )

        assert "problem=" in target

    def test_form_int_bounds(self) -> None:
        from u2_mcp.admin.routes_grants import form_int

        assert form_int("9223372036854775807") == 2**63 - 1
        assert form_int("9223372036854775808") is None
        assert form_int("9" * 5000) is None
        assert form_int("12") == 12
