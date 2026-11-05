"""Helpers for admin-site HTTP tests."""

import contextlib
import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from starlette.applications import Starlette
from starlette.routing import Mount
from starlette.testclient import TestClient

from u2_mcp import server
from u2_mcp.admin.app import build_admin_app
from u2_mcp.admin.context import AdminContext
from u2_mcp.config import U2Config
from u2_mcp.identity import set_identity_resolver
from u2_mcp.store import install_store

PASSWORD = "correct horse battery"


def admin_client(
    ctx: AdminContext,
    client: tuple[str, int] = ("10.0.0.1", 5000),
    base_url: str = "http://testserver",
) -> TestClient:
    """A test client for the admin site mounted at /admin, as the server mounts it."""
    app = Starlette(routes=[Mount("/admin", app=build_admin_app(ctx))])
    return TestClient(app, client=client, base_url=base_url)


def csrf_from(page: str) -> str:
    """Return the CSRF token embedded in a rendered form."""
    match = re.search(r'name="csrf_token" value="([^"]+)"', page)
    assert match, "no CSRF token on the page"
    return match.group(1)


def sign_in(
    client: TestClient, username: str = "ann", password: str = PASSWORD, next_url: str = ""
) -> object:
    """Sign in through the real form."""
    page = client.get("/admin/sign-in")
    data = {
        "csrf_token": csrf_from(page.text),
        "username": username,
        "password": password,
        "next": next_url,
    }
    return client.post("/admin/sign-in", data=data, follow_redirects=False)


@contextlib.contextmanager
def team_server(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    client: tuple[str, int] = ("testclient", 50000),
    base_url: str = "http://testserver",
    **env: str,
) -> Iterator[TestClient]:
    """The whole server in team mode, as `u2-mcp --streamable-http` serves it.

    Global state the server installs (store, identity resolver, registry) is undone
    afterwards, as tests/test_admin/test_app.py's team_app fixture does.
    """
    for name in ("U2_HOST", "U2_USER", "U2_PASSWORD", "U2_ACCOUNT"):
        monkeypatch.delenv(name, raising=False)
    base = {
        "U2_SECRET_KEY": "a" * 40,
        "U2_DATA_DIR": str(tmp_path),
    }
    for key, value in {**base, **env}.items():
        monkeypatch.setenv(key, value)
    app = server.build_streamable_http_app(U2Config())
    try:
        with TestClient(app, client=client, base_url=base_url) as test_client:
            yield test_client
    finally:
        install_store(None)
        set_identity_resolver(None)
        server.reset_connection_manager()
