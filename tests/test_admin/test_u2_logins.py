"""People set their own U2 login on My access; admins can only see that it is set and clear it."""

import pytest

from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.problems import Refused
from u2_mcp.admin.services import (
    check_my_u2_login,
    clear_u2_login,
    remove_my_u2_login,
    save_my_u2_login,
)
from u2_mcp.connection_check import CheckResult
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import finish_setup
from u2_mcp.store.models import User

from .conftest import FakeCheck, FakeRegistry
from .helpers import PASSWORD, admin_client, csrf_from, sign_in

SECRET = "s3cret-u2-pw"


def _per_user(ctx: AdminContext, name: str = "Dev") -> int:
    return ctx.store.add_connection(
        name=name,
        host="dev.example",
        port=31438,
        service="uvcs",
        account="DEVACC",
        login_mode="per_user",
    ).id


def _viewer(ctx: AdminContext) -> int:
    role = ctx.store.get_role_by_name("Viewer")
    assert role is not None
    return role.id


@pytest.fixture
def bob(ctx: AdminContext) -> User:
    return ctx.store.add_local_user("bob", password_hash=hash_password(PASSWORD))


@pytest.fixture
def dev(ctx: AdminContext) -> int:
    """A per-person connection everyone can see (no user grant: group/everyone access)."""
    connection_id = _per_user(ctx)
    ctx.store.add_grant(connection_id=connection_id, subject_type="everyone", role_id=_viewer(ctx))
    return connection_id


def _audit(ctx: AdminContext, action: str) -> list[dict]:
    return [row for row in ctx.store.recent_audit(100) if row["action"] == action]


class TestService:
    def test_save_keep_and_evict(
        self, ctx: AdminContext, bob: User, dev: int, registry: FakeRegistry
    ) -> None:
        save_my_u2_login(ctx, bob, dev, u2_user=" bob_u2 ", u2_password=SECRET)
        assert ctx.store.get_u2_login_password(bob.id, dev) == SECRET
        assert registry.owners_evicted == [(dev, bob.id)]

        save_my_u2_login(ctx, bob, dev, u2_user="bob_u2", u2_password="")
        assert ctx.store.get_u2_login_password(bob.id, dev) == SECRET

        [row, _] = _audit(ctx, "u2_login_set")
        assert row["params"] == {"connection": "Dev", "u2_user": "bob_u2"}
        assert SECRET not in str(ctx.store.recent_audit(100))

    def test_a_first_save_needs_a_user_and_a_password(
        self, ctx: AdminContext, bob: User, dev: int
    ) -> None:
        with pytest.raises(Refused) as no_user:
            save_my_u2_login(ctx, bob, dev, u2_user=" ", u2_password=SECRET)
        with pytest.raises(Refused) as no_password:
            save_my_u2_login(ctx, bob, dev, u2_user="bob_u2", u2_password="")
        assert (no_user.value.code, no_password.value.code) == (
            "u2_login_user",
            "u2_login_password",
        )

    def test_a_changed_user_needs_the_password_again(
        self, ctx: AdminContext, bob: User, dev: int
    ) -> None:
        save_my_u2_login(ctx, bob, dev, u2_user="bob_u2", u2_password=SECRET)
        with pytest.raises(Refused) as refused:
            save_my_u2_login(ctx, bob, dev, u2_user="other", u2_password="")
        assert refused.value.code == "u2_login_password_again"

    def test_only_visible_per_person_connections(self, ctx: AdminContext, bob: User) -> None:
        hidden = _per_user(ctx, "Hidden")
        shared = ctx.store.add_connection(
            name="Shared",
            host="h",
            port=1,
            service="uvcs",
            account="A",
            shared_user="svc",
            shared_password="pw",
        ).id
        ctx.store.add_grant(connection_id=shared, subject_type="everyone", role_id=_viewer(ctx))
        for connection_id in (hidden, shared, 999):
            with pytest.raises(Refused) as refused:
                save_my_u2_login(ctx, bob, connection_id, u2_user="b", u2_password="p")
            assert refused.value.code == "gone"
            with pytest.raises(Refused):
                check_my_u2_login(ctx, bob, connection_id, u2_user="b", u2_password="p")

    def test_test_uses_the_saved_connection_and_the_stored_password(
        self, ctx: AdminContext, bob: User, dev: int, check: FakeCheck
    ) -> None:
        save_my_u2_login(ctx, bob, dev, u2_user="bob_u2", u2_password=SECRET)

        result = check_my_u2_login(ctx, bob, dev, u2_user="bob_u2", u2_password="")

        assert result.ok
        [(connection, credentials)] = check.calls
        assert (connection.host, connection.account) == ("dev.example", "DEVACC")
        assert (credentials.user, credentials.password, credentials.is_shared) == (
            "bob_u2",
            SECRET,
            False,
        )
        [row] = _audit(ctx, "u2_login_test")
        assert row["outcome"] == "ok" and row["params"]["u2_user"] == "bob_u2"

    def test_test_with_a_typed_password_does_not_save(
        self, ctx: AdminContext, bob: User, dev: int, check: FakeCheck
    ) -> None:
        check.result = CheckResult(False, "bad login", 2.0)

        result = check_my_u2_login(ctx, bob, dev, u2_user="bob_u2", u2_password="typed")

        assert not result.ok and check.calls[0][1].password == "typed"
        assert ctx.store.get_u2_login(bob.id, dev) is None
        assert _audit(ctx, "u2_login_test")[0]["outcome"] == "failed"

    def test_test_without_any_password_is_refused(
        self, ctx: AdminContext, bob: User, dev: int
    ) -> None:
        with pytest.raises(Refused) as refused:
            check_my_u2_login(ctx, bob, dev, u2_user="bob_u2", u2_password="")
        assert refused.value.code == "u2_login_password"

    def test_remove_and_clear(
        self, ctx: AdminContext, bob: User, admin: User, dev: int, registry: FakeRegistry
    ) -> None:
        save_my_u2_login(ctx, bob, dev, u2_user="bob_u2", u2_password=SECRET)
        remove_my_u2_login(ctx, bob, dev)
        assert ctx.store.get_u2_login(bob.id, dev) is None
        assert _audit(ctx, "u2_login_removed")[0]["params"]["u2_user"] == "bob_u2"
        with pytest.raises(Refused):
            remove_my_u2_login(ctx, bob, dev)

        save_my_u2_login(ctx, bob, dev, u2_user="bob_u2", u2_password=SECRET)
        clear_u2_login(ctx, bob.id, dev, actor=admin)
        assert ctx.store.get_u2_login(bob.id, dev) is None
        [row] = _audit(ctx, "u2_login_cleared")
        assert row["params"] == {"connection": "Dev", "u2_user": "bob_u2", "user_id": bob.id}
        assert registry.owners_evicted.count((dev, bob.id)) == 4


class TestMyAccessPage:
    def _client(self, ctx: AdminContext):  # type: ignore[no-untyped-def]
        ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
        finish_setup(ctx.store)
        client = admin_client(ctx)
        sign_in(client, "bob")
        return client

    def test_a_non_admin_saves_tests_and_removes_their_own_login(
        self, ctx: AdminContext, bob: User, dev: int, check: FakeCheck
    ) -> None:
        other = ctx.store.add_local_user("carol", password_hash="x")
        with self._client(ctx) as client:
            page = client.get("/admin/me").text
            assert "Your U2 login" in page and "Not set" in page
            token = csrf_from(page)

            saved = client.post(
                f"/admin/me/u2-logins/{dev}",
                data={
                    "csrf_token": token,
                    "u2_user": "bob_u2",
                    "u2_password": SECRET,
                    "user_id": str(other.id),
                },
                follow_redirects=False,
            )
            assert saved.status_code == 303
            assert ctx.store.get_u2_login(bob.id, dev) is not None
            assert ctx.store.get_u2_login(other.id, dev) is None  # the forged id is ignored

            page = client.get("/admin/me").text
            assert "bob_u2" in page and "Set" in page and SECRET not in page

            tested = client.post(
                f"/admin/me/u2-logins/{dev}/test",
                data={"csrf_token": token, "u2_user": "bob_u2", "u2_password": ""},
                headers={"HX-Request": "true"},
            )
            assert "Test passed: fine" in tested.text and "<html" not in tested.text
            assert check.calls[-1][1].password == SECRET

            removed = client.post(
                f"/admin/me/u2-logins/{dev}/remove",
                data={"csrf_token": token},
                follow_redirects=False,
            )
            assert removed.status_code == 303
            assert ctx.store.get_u2_login(bob.id, dev) is None
        assert SECRET not in str(ctx.store.recent_audit(100))

    def test_without_the_csrf_token_nothing_is_saved(
        self, ctx: AdminContext, bob: User, dev: int
    ) -> None:
        with self._client(ctx) as client:
            response = client.post(
                f"/admin/me/u2-logins/{dev}",
                data={"u2_user": "bob_u2", "u2_password": SECRET},
                follow_redirects=False,
            )
        assert response.status_code == 403
        assert ctx.store.get_u2_login(bob.id, dev) is None

    def test_a_missing_login_links_to_its_section(
        self, ctx: AdminContext, bob: User, dev: int
    ) -> None:
        with self._client(ctx) as client:
            page = client.get("/admin/me").text
        assert f'href="#u2-login-{dev}"' in page and f'id="u2-login-{dev}"' in page


class TestAdminSide:
    def test_the_grants_editor_offers_no_password_fields(
        self, ctx: AdminContext, admin: User, dev: int
    ) -> None:
        ctx.store.set_password_hash(admin.id, hash_password(PASSWORD), must_change=False)
        finish_setup(ctx.store)
        with admin_client(ctx) as client:
            sign_in(client, "root")
            page = client.get(f"/admin/connections/{dev}").text
        assert 'name="u2_password"' not in page and 'name="u2_user"' not in page

    def test_admins_see_whether_a_login_is_set_and_can_clear_it(
        self, ctx: AdminContext, admin: User, bob: User, dev: int
    ) -> None:
        ctx.store.set_password_hash(admin.id, hash_password(PASSWORD), must_change=False)
        save_my_u2_login(ctx, bob, dev, u2_user="bob_u2", u2_password=SECRET)
        finish_setup(ctx.store)
        with admin_client(ctx) as client:
            sign_in(client, "root")
            connection_page = client.get(f"/admin/connections/{dev}").text
            user_page = client.get(f"/admin/users/{bob.id}").text
            for page in (connection_page, user_page):
                assert "bob_u2" in page and SECRET not in page
            access = client.get(f"/admin/users/{admin.id}/access").text
            assert "They can set it on My access" in access
            cleared = client.post(
                f"/admin/users/{bob.id}/u2-logins/{dev}/clear",
                data={"csrf_token": csrf_from(user_page), "return_to": f"/admin/users/{bob.id}"},
                follow_redirects=False,
            )
        assert cleared.status_code == 303
        assert cleared.headers["location"].startswith(f"/admin/users/{bob.id}")
        assert ctx.store.get_u2_login(bob.id, dev) is None

    def test_a_non_admin_cannot_clear(self, ctx: AdminContext, bob: User, dev: int) -> None:
        save_my_u2_login(ctx, bob, dev, u2_user="bob_u2", u2_password=SECRET)
        ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
        finish_setup(ctx.store)
        with admin_client(ctx) as client:
            sign_in(client, "bob")
            token = csrf_from(client.get("/admin/me").text)
            response = client.post(
                f"/admin/users/{bob.id}/u2-logins/{dev}/clear",
                data={"csrf_token": token},
                follow_redirects=False,
            )
        assert response.status_code == 403
        assert ctx.store.get_u2_login(bob.id, dev) is not None
