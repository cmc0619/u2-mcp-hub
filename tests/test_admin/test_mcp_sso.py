"""Company sign-in saved on the admin site turns on VS Code's OAuth sign-in after a restart."""

from pathlib import Path

import pytest

from u2_mcp.admin.services import RESTART_NOTE
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import finish_setup
from u2_mcp.sso_config import SsoSettings, store_sso
from u2_mcp.store import get_store

from .helpers import PASSWORD, sign_in, team_server

HTTPS_URL = "https://u2.example.com"
METADATA = "/.well-known/oauth-authorization-server"
SNIPPET = "It opens your company sign-in automatically."


def _save_sso(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, secret: str | None = "s3cret", **env: str
) -> None:
    """A first start that saves company sign-in, as an admin would on the admin site."""
    with team_server(tmp_path, monkeypatch, **env):
        store_sso(
            get_store(),
            SsoSettings(
                "oidc",
                "https://idp.example/.well-known/openid-configuration",
                "u2-mcp",
                "groups",
                False,
            ),
            secret,
        )


def test_saved_company_sign_in_turns_on_oauth_after_a_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with team_server(tmp_path, monkeypatch, U2_PUBLIC_URL=HTTPS_URL) as client:
        assert client.get(METADATA).status_code != 200
    _save_sso(tmp_path, monkeypatch, U2_PUBLIC_URL=HTTPS_URL)
    with team_server(tmp_path, monkeypatch, U2_PUBLIC_URL=HTTPS_URL) as client:
        metadata = client.get(METADATA)
    assert metadata.status_code == 200
    assert metadata.json()["issuer"].rstrip("/") == HTTPS_URL


def test_an_http_address_keeps_vs_code_sign_in_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    address = "http://10.0.0.5:8080"
    _save_sso(tmp_path, monkeypatch, U2_PUBLIC_URL=address)
    with (
        caplog.at_level("WARNING"),
        team_server(tmp_path, monkeypatch, U2_PUBLIC_URL=address) as client,
    ):
        assert client.get(METADATA).status_code != 200
    assert "needs an https server address" in caplog.text


def test_a_missing_secret_keeps_vs_code_sign_in_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _save_sso(tmp_path, monkeypatch, secret=None, U2_PUBLIC_URL=HTTPS_URL)
    with (
        caplog.at_level("WARNING"),
        team_server(tmp_path, monkeypatch, U2_PUBLIC_URL=HTTPS_URL) as client,
    ):
        assert client.get(METADATA).status_code != 200
    assert "client secret is missing or unreadable" in caplog.text


@pytest.mark.parametrize(
    ("discovery_url", "client_id", "missing"),
    [("", "u2-mcp", "discovery URL"), ("https://idp.example/x", "", "client ID")],
)
def test_incomplete_stored_settings_keep_vs_code_sign_in_off(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    discovery_url: str,
    client_id: str,
    missing: str,
) -> None:
    with team_server(tmp_path, monkeypatch, U2_PUBLIC_URL=HTTPS_URL):
        store_sso(
            get_store(), SsoSettings("oidc", discovery_url, client_id, "groups", False), "s3cret"
        )
    with (
        caplog.at_level("WARNING"),
        team_server(tmp_path, monkeypatch, U2_PUBLIC_URL=HTTPS_URL) as client,
    ):
        assert client.get(METADATA).status_code != 200
    assert missing in caplog.text
    assert "s3cret" not in caplog.text


def test_my_access_offers_the_oauth_snippet_only_when_the_bridge_is_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def my_access_page() -> str:
        with team_server(
            tmp_path, monkeypatch, base_url="https://testserver", U2_PUBLIC_URL=HTTPS_URL
        ) as client:
            store = get_store()
            if store.get_user_by_username("ann") is None:
                store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
                finish_setup(store)
            sign_in(client)
            return client.get("/admin/me").text

    assert SNIPPET not in my_access_page()
    _save_sso(tmp_path, monkeypatch, U2_PUBLIC_URL=HTTPS_URL)
    assert SNIPPET in my_access_page()


def test_the_restart_note_mentions_company_sign_in() -> None:
    assert "company sign-in" in RESTART_NOTE
