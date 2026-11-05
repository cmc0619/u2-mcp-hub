"""My access: connections, tokens shown once, client configuration, non-admin landing."""

import json
import re
from collections.abc import Iterator

import pytest
from starlette.testclient import TestClient

from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.problems import Refused
from u2_mcp.admin.reveal import OneTimeReveal
from u2_mcp.admin.services import (
    TOKEN_MAX_LIFETIME_SETTING,
    create_personal_token,
    curl_example,
    default_token_days,
    revoke_personal_token,
)
from u2_mcp.admin.templating import when
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import finish_setup, mark_step_done
from u2_mcp.store.models import User
from u2_mcp.tokens import hash_token

from .helpers import PASSWORD, admin_client, csrf_from, sign_in


class TestReveal:
    def test_a_value_is_taken_once_and_only_by_its_owner(self) -> None:
        reveal = OneTimeReveal()
        reveal_id = reveal.put("session-a", "u2pat_x")

        assert reveal.take("session-b", reveal_id) is None
        assert reveal.take("session-a", reveal_id) == "u2pat_x"
        assert reveal.take("session-a", reveal_id) is None

    def test_values_expire(self) -> None:
        now = [0.0]
        reveal = OneTimeReveal(ttl_seconds=10, clock=lambda: now[0])
        reveal_id = reveal.put("s", "v")
        now[0] = 11.0

        assert reveal.take("s", reveal_id) is None

    def test_expired_values_are_pruned_on_every_read(self) -> None:
        now = [0.0]
        reveal = OneTimeReveal(ttl_seconds=10, clock=lambda: now[0])
        reveal.put("s", "v")
        now[0] = 11.0

        reveal.prune()

        assert reveal._items == {}


def test_when_formats_and_tolerates_huge_timestamps() -> None:
    assert when(None) == ""
    assert when(0.0) == "1970-01-01 00:00 UTC"
    assert when(1e20) == "far future"


class TestTokenService:
    def test_creating_stores_only_the_hash_and_audits_without_the_token(
        self, ctx: AdminContext, admin: User
    ) -> None:
        token, record = create_personal_token(ctx, admin, name=" laptop ", days="30")

        assert record.token_hash == hash_token(token) and record.name == "laptop"
        entry = ctx.store.recent_audit(1)[0]
        assert entry["action"] == "token.create"
        assert token not in json.dumps(entry)

    @pytest.mark.parametrize(
        ("name", "days", "code"),
        [
            ("", "30", "token_name"),
            ("x" * 65, "30", "token_name"),
            ("ok", "0", "token_days"),
            ("ok", "abc", "token_days"),
            ("ok", "31", "token_days"),
        ],
    )
    def test_bad_values_are_refused(
        self, ctx: AdminContext, admin: User, name: str, days: str, code: str
    ) -> None:
        ctx.store.set_setting(TOKEN_MAX_LIFETIME_SETTING, 30)

        with pytest.raises(Refused) as refused:
            create_personal_token(ctx, admin, name=name, days=days)

        assert refused.value.code == code

    @pytest.mark.parametrize("days", ["400000", "9" * 400])
    def test_huge_lifetimes_are_refused_without_a_cap(
        self, ctx: AdminContext, admin: User, days: str
    ) -> None:
        with pytest.raises(Refused) as refused:
            create_personal_token(ctx, admin, name="ok", days=days)

        assert refused.value.code == "token_days"

    def test_a_cap_of_zero_is_a_cap(self, ctx: AdminContext, admin: User) -> None:
        ctx.store.set_setting(TOKEN_MAX_LIFETIME_SETTING, 0)

        with pytest.raises(Refused):
            create_personal_token(ctx, admin, name="ok", days="1")
        assert default_token_days(ctx) == 0

    def test_nobody_revokes_another_persons_token_here(
        self, ctx: AdminContext, admin: User
    ) -> None:
        bob = ctx.store.add_local_user("bob")
        _token, record = create_personal_token(ctx, bob, name="bob's", days="30")

        with pytest.raises(Refused):
            revoke_personal_token(ctx, record.id, owner_id=admin.id, actor=admin)

        stored = ctx.store.get_token(record.id)
        assert stored is not None and stored.revoked_at is None


def test_the_curl_example_names_the_server_and_keeps_the_token_a_placeholder() -> None:
    command = curl_example("https://u2.example.com")

    assert command.startswith("curl -X POST https://u2.example.com/ ")
    assert '"Authorization: Bearer <token>"' in command
    assert '"protocolVersion":"2025-06-18"' in command


@pytest.fixture
def bob_client(ctx: AdminContext) -> Iterator[TestClient]:
    finish_setup(ctx.store)
    ctx.store.add_local_user("bob", password_hash=hash_password(PASSWORD))
    with admin_client(ctx) as client:
        sign_in(client, username="bob")
        yield client


def _location(client: TestClient, path: str) -> str:
    return str(client.get(path, follow_redirects=False).headers["location"])


class TestPages:
    def test_a_non_admin_lands_on_my_access(self, bob_client: TestClient) -> None:
        assert _location(bob_client, "/admin/") == "/admin/me"
        assert _location(bob_client, "/admin/connections") == "/admin/me"
        page = bob_client.get("/admin/me")
        assert page.status_code == 200 and "My access" in page.text

    def test_a_non_admin_post_to_an_admin_page_is_refused(self, bob_client: TestClient) -> None:
        token = csrf_from(bob_client.get("/admin/me").text)

        response = bob_client.post("/admin/connections/new", data={"csrf_token": token})

        assert response.status_code == 403
        assert "Only admins can use this page." in response.text

    def test_my_connections_show_role_and_permissions(
        self, bob_client: TestClient, ctx: AdminContext
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
        bob = ctx.store.get_user_by_username("bob")
        viewer = ctx.store.get_role_by_name("Viewer")
        assert bob is not None and viewer is not None
        ctx.store.add_grant(
            connection_id=connection.id,
            subject_type="user",
            subject_id=bob.id,
            role_id=viewer.id,
        )

        page = bob_client.get("/admin/me").text

        assert "Prod" in page and "Viewer" in page and "records.read" in page

    def test_a_new_token_is_shown_exactly_once(
        self, bob_client: TestClient, ctx: AdminContext
    ) -> None:
        token = csrf_from(bob_client.get("/admin/me").text)
        created = bob_client.post(
            "/admin/me/tokens",
            data={"csrf_token": token, "name": "laptop", "days": "90"},
            follow_redirects=False,
        )
        location = created.headers["location"]
        assert location.startswith("/admin/me?notice=token_created&reveal=")

        first = bob_client.get(location).text
        shown = re.search(r'<pre id="new-token">(u2pat_[^<]+)</pre>', first)
        assert shown and "It is shown only once." in first
        assert ctx.store.get_token_by_hash(hash_token(shown.group(1))) is not None
        assert "u2pat_" not in bob_client.get(location).text

    def test_revoking_my_token(self, bob_client: TestClient, ctx: AdminContext) -> None:
        bob = ctx.store.get_user_by_username("bob")
        assert bob is not None
        _value, record = create_personal_token(ctx, bob, name="old", days="5")
        token = csrf_from(bob_client.get("/admin/me").text)

        response = bob_client.post(
            f"/admin/me/tokens/{record.id}/revoke",
            data={"csrf_token": token},
            follow_redirects=False,
        )

        assert response.headers["location"] == "/admin/me?notice=revoked"
        stored = ctx.store.get_token(record.id)
        assert stored is not None and stored.revoked_at is not None
        page = bob_client.get("/admin/me").text
        assert "Revoke old" not in page and "<td>old</td>" not in page

    def test_a_huge_token_id_is_not_found_rather_than_a_500(self, bob_client: TestClient) -> None:
        token = csrf_from(bob_client.get("/admin/me").text)

        response = bob_client.post(
            "/admin/me/tokens/99999999999999999999/revoke",
            data={"csrf_token": token},
            follow_redirects=False,
        )

        assert response.status_code == 404

    def test_revoking_someone_elses_token_by_id_is_refused(
        self, bob_client: TestClient, ctx: AdminContext
    ) -> None:
        carol = ctx.store.add_local_user("carol")
        _value, record = create_personal_token(ctx, carol, name="carol's", days="5")
        token = csrf_from(bob_client.get("/admin/me").text)

        response = bob_client.post(
            f"/admin/me/tokens/{record.id}/revoke",
            data={"csrf_token": token},
            follow_redirects=False,
        )

        assert response.headers["location"] == "/admin/me?problem=gone"
        stored = ctx.store.get_token(record.id)
        assert stored is not None and stored.revoked_at is None

    def test_client_setup_is_the_address_and_one_example(self, bob_client: TestClient) -> None:
        page = bob_client.get("/admin/me").text

        assert "Connect your MCP client" in page
        address = re.search(r"<pre>(https?://[^<\s]+/)</pre>", page)
        assert address and f"curl -X POST {address.group(1)} " in page
        assert "company sign-in for MCP clients is not set up" in page
        assert "Authorization: Bearer &lt;token&gt;" in page
        assert page.count("<pre>") == 2
        for gone in ("mcp.json", "VS Code", "Visual Studio", "JetBrains"):
            assert gone not in page


def test_the_wizard_sends_a_forced_password_change_first(ctx: AdminContext) -> None:
    """Review M-1: the wizard's own guard honours must_change_password."""
    root = ctx.store.add_local_user("root", password_hash=hash_password(PASSWORD), is_admin=True)
    mark_step_done(ctx.store, "admin")
    with admin_client(ctx) as client:
        sign_in(client, username="root")
        ctx.store.set_password_hash(root.id, hash_password(PASSWORD), must_change=True)

        location = _location(client, "/admin/setup/connection")

    assert location == "/admin/account/password"


def test_the_done_page_no_longer_says_grants_are_coming(ctx: AdminContext) -> None:
    ctx.store.add_local_user("root", password_hash=hash_password(PASSWORD), is_admin=True)
    for step in ("admin", "connection", "server_address", "sso"):
        mark_step_done(ctx.store, step)
    with admin_client(ctx) as client:
        sign_in(client, username="root")
        page = client.get("/admin/setup/done").text

    assert "next version" not in page
    assert "add one under Access" in page
