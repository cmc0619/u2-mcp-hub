"""The admin site is mounted beside MCP without disturbing it."""

import os
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest
from starlette.testclient import TestClient

import u2_mcp.server as server
from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.templating import _environment
from u2_mcp.config import U2Config
from u2_mcp.identity import set_identity_resolver
from u2_mcp.store import install_store


@pytest.fixture
def team_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    for name in ("U2_HOST", "U2_USER", "U2_PASSWORD", "U2_ACCOUNT"):
        monkeypatch.delenv(name, raising=False)
    env = {
        "U2_SECRET_KEY": "a" * 40,
        "U2_DATA_DIR": str(tmp_path),
    }
    with patch.dict(os.environ, env):
        app = server.build_streamable_http_app(U2Config())
        try:
            with TestClient(app) as client:
                yield client
        finally:
            # Team mode installs a store and an identity resolver; undo both, as
            # tests/test_team_mode_e2e.py does, or later tests see this server's state.
            install_store(None)
            set_identity_resolver(None)
            server.reset_connection_manager()


def test_health_answers_without_authentication(team_app: TestClient) -> None:
    response = team_app.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_the_admin_site_is_served(team_app: TestClient) -> None:
    response = team_app.get("/admin/", follow_redirects=False)

    assert response.status_code in (200, 302, 303)


def test_static_files_are_served(team_app: TestClient) -> None:
    assert team_app.get("/admin/static/htmx.min.js").status_code == 200
    assert team_app.get("/admin/static/styles.css").status_code == 200


def test_mcp_still_requires_a_token(team_app: TestClient) -> None:
    response = team_app.post("/", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})

    assert response.status_code == 401


def test_streamable_http_refuses_to_start_without_a_secret_key(
    mock_env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("U2_SECRET_KEY", raising=False)

    with pytest.raises(SystemExit, match="U2_SECRET_KEY"):
        server.build_streamable_http_app(U2Config())
    assert server.get_store() is None


def test_a_wildcard_cors_origin_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = {"U2_SECRET_KEY": "a" * 40, "U2_DATA_DIR": str(tmp_path), "U2_HTTP_CORS_ORIGINS": "*"}
    with patch.dict(os.environ, env), pytest.raises(SystemExit, match="CORS"):
        server.build_streamable_http_app(U2Config())


def test_the_setup_code_is_logged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    for name in ("U2_HOST", "U2_USER", "U2_PASSWORD", "U2_ACCOUNT"):
        monkeypatch.delenv(name, raising=False)
    env = {
        "U2_SECRET_KEY": "a" * 40,
        "U2_DATA_DIR": str(tmp_path),
    }
    with patch.dict(os.environ, env), caplog.at_level("WARNING"):
        server.build_streamable_http_app(U2Config())
    install_store(None)
    set_identity_resolver(None)

    assert "/admin/setup" in caplog.text
    assert "setup code" in caplog.text


def test_templates_escape_user_text() -> None:
    template = _environment().from_string("{{ value }}")

    assert template.render(value="<script>") == "&lt;script&gt;"


def test_render_supplies_the_context(store: object, mock_config: U2Config) -> None:
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.routing import Route

    from u2_mcp.admin.templating import render

    async def page(request: Request):  # type: ignore[no-untyped-def]
        return render(request, "message.html", title="Hello", message="Body text")

    app = Starlette(routes=[Route("/", page)])
    app.state.ctx = AdminContext(
        store=store,  # type: ignore[arg-type]
        config=mock_config,
        registry=lambda: None,  # type: ignore[arg-type,return-value]
    )
    response = TestClient(app).get("/?notice=saved")

    assert "Body text" in response.text
    assert "Saved." in response.text
    assert response.headers["cache-control"] == "no-store"


def test_admin_redirects_are_never_cached(team_app: TestClient) -> None:
    # Browsers replay cached redirects on Back; once setup finished, the stale
    # /admin/ -> /admin/setup -> /admin/setup/admin chain looped forever.
    for path in ("/admin/", "/admin/setup", "/admin/connections"):
        response = team_app.get(path, follow_redirects=False)

        assert response.status_code == 303, path
        assert response.headers["cache-control"] == "no-store", path


def test_static_files_stay_cacheable(team_app: TestClient) -> None:
    response = team_app.get("/admin/static/htmx.min.js")

    assert "no-store" not in response.headers.get("cache-control", "")


def _team_env(tmp_path: Path) -> dict[str, str]:
    return {
        "U2_SECRET_KEY": "a" * 40,
        "U2_DATA_DIR": str(tmp_path),
    }


def _undo_team_mode() -> None:
    install_store(None)
    set_identity_resolver(None)
    server.reset_connection_manager()


def test_a_saved_address_names_the_token_resource_after_a_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from u2_mcp.store.bootstrap import open_store_for_cli

    for name in ("U2_HOST", "U2_USER", "U2_PASSWORD", "U2_ACCOUNT"):
        monkeypatch.delenv(name, raising=False)
    resources: list[str | None] = []
    real_verifier = server.PatVerifier

    def recording_verifier(*args: object, resource: str | None, **kwargs: object) -> object:
        resources.append(resource)
        return real_verifier(*args, resource=resource, **kwargs)  # type: ignore[arg-type]

    env = {**_team_env(tmp_path), "U2_PUBLIC_URL": "https://from-env.example"}
    monkeypatch.setattr(server, "PatVerifier", recording_verifier)
    with patch.dict(os.environ, env):
        server.build_streamable_http_app(U2Config())  # first start creates the database
        _undo_team_mode()
        store = open_store_for_cli(U2Config())
        store.set_setting("public_url", "https://saved-in-ui.example")
        with caplog.at_level("WARNING"):
            server.build_streamable_http_app(U2Config())  # the restart
        _undo_team_mode()

    assert resources == ["https://from-env.example", "https://saved-in-ui.example"]
    assert "https://saved-in-ui.example/admin/setup" in caplog.text


def test_the_footer_names_the_version_for_signed_in_people_only(ctx: AdminContext) -> None:
    from u2_mcp.passwords import hash_password
    from u2_mcp.setup_code import finish_setup
    from u2_mcp.version import running_version

    from .helpers import PASSWORD, admin_client, sign_in

    finish_setup(ctx.store)
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    with admin_client(ctx) as client:
        assert "u2-mcp " + running_version() not in client.get("/admin/sign-in").text
        sign_in(client)
        assert "u2-mcp " + running_version() in client.get("/admin/connections").text
