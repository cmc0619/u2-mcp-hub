"""Settings: token policy, non-admin sign-in, the setup checklist, URL hygiene."""

from collections.abc import Iterator

import pytest
from starlette.testclient import TestClient

from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.services import (
    TOKEN_POLICY_PROBLEM,
    ValidationFailed,
    clean_public_url,
    non_admin_sign_in_enabled,
    save_token_policy,
    set_non_admin_sign_in,
    token_max_lifetime,
)
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import finish_setup
from u2_mcp.store.models import User

from .helpers import PASSWORD, admin_client, csrf_from, sign_in


class TestServices:
    def test_token_policy_saves_clears_and_validates(self, ctx: AdminContext, admin: User) -> None:
        assert save_token_policy(ctx, "30", actor=admin) == 30
        assert token_max_lifetime(ctx) == 30
        assert ctx.store.recent_audit(1)[0]["action"] == "settings.token_policy"
        assert save_token_policy(ctx, " ", actor=admin) is None
        assert token_max_lifetime(ctx) is None
        for bad in ("0", "3651", "ten", "-1", "1.5"):
            with pytest.raises(ValidationFailed, match=TOKEN_POLICY_PROBLEM):
                save_token_policy(ctx, bad, actor=admin)
        assert token_max_lifetime(ctx) is None

    def test_non_admin_sign_in_switch(self, ctx: AdminContext, admin: User) -> None:
        set_non_admin_sign_in(ctx, False, actor=admin)

        assert non_admin_sign_in_enabled(ctx.store) is False
        assert ctx.store.recent_audit(1)[0]["params"] == {"enabled": False}

    def test_a_public_url_with_a_password_is_refused(self) -> None:
        """Review M-3."""
        for url in ("https://user:secret@u2.example.com", "https://user@u2.example.com"):
            with pytest.raises(ValidationFailed):
                clean_public_url(url)


@pytest.fixture
def client(ctx: AdminContext) -> Iterator[TestClient]:
    finish_setup(ctx.store)
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    with admin_client(ctx) as test_client:
        sign_in(test_client)
        yield test_client


def test_the_settings_page_saves_each_section(client: TestClient, ctx: AdminContext) -> None:
    page = client.get("/admin/settings").text
    assert "Token policy" in page and "Sign-in for people who are not admins" in page
    token = csrf_from(page)

    saved = client.post(
        "/admin/settings/tokens",
        data={"csrf_token": token, "token_max_days": "60"},
        follow_redirects=False,
    )
    refused = client.post(
        "/admin/settings/tokens", data={"csrf_token": token, "token_max_days": "-1"}
    )
    client.post("/admin/settings/non-admin-sign-in", data={"csrf_token": token, "enabled": "off"})

    assert saved.headers["location"] == "/admin/settings?notice=saved"
    assert refused.status_code == 400 and TOKEN_POLICY_PROBLEM in refused.text
    assert token_max_lifetime(ctx) == 60
    assert non_admin_sign_in_enabled(ctx.store) is False


def test_an_invalid_non_admin_sign_in_value_changes_nothing_and_is_not_saved(
    client: TestClient, ctx: AdminContext
) -> None:
    token = csrf_from(client.get("/admin/settings").text)

    response = client.post(
        "/admin/settings/non-admin-sign-in",
        data={"csrf_token": token, "enabled": "maybe"},
        follow_redirects=False,
    )

    assert "notice=saved" not in response.headers["location"]
    assert non_admin_sign_in_enabled(ctx.store) is True
