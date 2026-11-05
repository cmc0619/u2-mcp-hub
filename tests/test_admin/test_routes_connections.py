"""The Connections pages, over HTTP."""

from collections.abc import Iterator

import pytest
from starlette.testclient import TestClient

from u2_mcp.admin.context import AdminContext
from u2_mcp.connection_check import CheckResult
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import finish_setup
from u2_mcp.store.models import Connection

from .conftest import FakeCheck, FakeRegistry
from .helpers import PASSWORD, admin_client, csrf_from, sign_in

FORM = {
    "name": "Prod",
    "host": "u2.example",
    "port": "31438",
    "service": "uvcs",
    "account": "PROD",
    "login_mode": "shared",
    "login_user": "svc",
    "login_password": "secret",
    "read_only": "on",
    "enabled": "on",
    "version": "0",
}


@pytest.fixture
def client(ctx: AdminContext) -> Iterator[TestClient]:
    finish_setup(ctx.store)
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    with admin_client(ctx) as test_client:
        sign_in(test_client)
        yield test_client


def _post(client: TestClient, url: str, data: dict[str, str], **kwargs: object) -> object:
    token = csrf_from(client.get("/admin/connections/new").text)
    return client.post(
        url,
        data={**data, "csrf_token": token},
        follow_redirects=False,
        **kwargs,  # type: ignore[arg-type]
    )


def _create(client: TestClient, ctx: AdminContext) -> Connection:
    _post(client, "/admin/connections/new", {**FORM, "action": "save"})
    created = ctx.store.get_connection_by_name("Prod")
    assert created is not None
    return created


def test_the_list_needs_an_admin(ctx: AdminContext) -> None:
    finish_setup(ctx.store)
    with admin_client(ctx) as anonymous:
        response = anonymous.get("/admin/connections", follow_redirects=False)

    assert response.status_code == 303


def test_adding_a_connection(client: TestClient, ctx: AdminContext) -> None:
    response = _post(client, "/admin/connections/new", {**FORM, "action": "save"})

    created = ctx.store.get_connection_by_name("Prod")
    assert created is not None
    assert response.headers["location"] == (  # type: ignore[attr-defined]
        f"/admin/connections/{created.id}?notice=saved"
    )
    assert "Prod" in client.get("/admin/connections").text


def test_problems_are_shown_beside_the_fields(client: TestClient) -> None:
    response = _post(
        client,
        "/admin/connections/new",
        {**FORM, "host": "", "login_password": "typed-secret", "action": "save"},
    )

    assert response.status_code == 400  # type: ignore[attr-defined]
    assert "Enter the U2 server&#39;s host name or address." in response.text  # type: ignore[attr-defined]
    assert "typed-secret" not in response.text  # type: ignore[attr-defined]


def test_testing_with_htmx_returns_only_the_result(client: TestClient, check: FakeCheck) -> None:
    check.result = CheckResult(True, "Connected to PROD on u2.example. COUNT VOC: 7", 3.0)

    response = _post(
        client, "/admin/connections/new", {**FORM, "action": "test"}, headers={"HX-Request": "true"}
    )

    assert response.status_code == 200  # type: ignore[attr-defined]
    assert 'id="test-result"' in response.text  # type: ignore[attr-defined]
    assert "COUNT VOC: 7" in response.text  # type: ignore[attr-defined]
    assert "<html" not in response.text  # type: ignore[attr-defined]


def test_testing_without_javascript_shows_the_whole_page(
    client: TestClient, check: FakeCheck
) -> None:
    check.result = CheckResult(False, "Login refused: wrong user name or password", 3.0)

    response = _post(client, "/admin/connections/new", {**FORM, "action": "test"})

    assert "Test failed: Login refused: wrong user name or password" in (
        response.text  # type: ignore[attr-defined]
    )
    assert 'value="u2.example"' in response.text  # type: ignore[attr-defined]


def test_testing_does_not_save(client: TestClient, ctx: AdminContext) -> None:
    _post(client, "/admin/connections/new", {**FORM, "action": "test"})

    assert ctx.store.get_connection_by_name("Prod") is None


def test_editing_keeps_a_blank_password(client: TestClient, ctx: AdminContext) -> None:
    created = _create(client, ctx)

    _post(
        client,
        f"/admin/connections/{created.id}",
        {
            **FORM,
            "name": "Production",
            "login_password": "",
            "version": str(created.version),
            "action": "save",
        },
    )

    assert ctx.store.shared_password(created.id) == "secret"
    edited = ctx.store.get_connection(created.id)
    assert edited is not None and edited.name == "Production"


def test_a_changed_host_needs_the_password_again(
    client: TestClient, ctx: AdminContext, check: FakeCheck
) -> None:
    created = _create(client, ctx)
    changed = {
        **FORM,
        "host": "attacker.example",
        "login_password": "",
        "version": str(created.version),
    }

    saved = _post(client, f"/admin/connections/{created.id}", {**changed, "action": "save"})
    tested = _post(client, f"/admin/connections/{created.id}", {**changed, "action": "test"})

    for response in (saved, tested):
        assert response.status_code == 400  # type: ignore[attr-defined]
        assert "Enter the password again: the server details changed." in response.text  # type: ignore[attr-defined]
    assert check.calls == []
    unchanged = ctx.store.get_connection(created.id)
    assert unchanged is not None and unchanged.host == "u2.example"


def test_a_stale_edit_is_refused_with_the_message(client: TestClient, ctx: AdminContext) -> None:
    created = _create(client, ctx)
    _post(
        client,
        f"/admin/connections/{created.id}",
        {**FORM, "host": "first.example", "version": str(created.version), "action": "save"},
    )

    response = _post(
        client,
        f"/admin/connections/{created.id}",
        {**FORM, "host": "second.example", "version": str(created.version), "action": "save"},
    )

    assert response.status_code == 409  # type: ignore[attr-defined]
    assert (
        "Someone else changed this connection since you opened it. Reload to see their changes."
    ) in response.text  # type: ignore[attr-defined]
    saved = ctx.store.get_connection(created.id)
    assert saved is not None and saved.host == "first.example"


def test_disconnect(client: TestClient, ctx: AdminContext, registry: FakeRegistry) -> None:
    created = _create(client, ctx)
    registry.live[created.id] = ["svc@PROD"]
    assert "svc@PROD" in client.get(f"/admin/connections/{created.id}").text

    response = _post(client, f"/admin/connections/{created.id}/disconnect", {})

    assert response.headers["location"] == (  # type: ignore[attr-defined]
        f"/admin/connections/{created.id}?notice=disconnected"
    )
    assert registry.live == {}


def test_a_login_live_twice_is_shown_once(
    client: TestClient, ctx: AdminContext, registry: FakeRegistry
) -> None:
    created = _create(client, ctx)
    registry.live[created.id] = ["svc@PROD", "svc@PROD"]

    page = client.get(f"/admin/connections/{created.id}").text

    assert page.count("<li>svc@PROD</li>") == 1


def test_delete_asks_first(client: TestClient, ctx: AdminContext) -> None:
    created = _create(client, ctx)

    page = client.get(f"/admin/connections/{created.id}/delete")
    response = _post(client, f"/admin/connections/{created.id}/delete", {})

    assert "Delete Prod?" in page.text
    assert response.headers["location"] == (  # type: ignore[attr-defined]
        "/admin/connections?notice=deleted"
    )
    assert ctx.store.get_connection(created.id) is None


def test_an_unknown_connection_is_404(client: TestClient) -> None:
    assert client.get("/admin/connections/999").status_code == 404


@pytest.mark.parametrize("suffix", ["/disconnect", "/delete"])
def test_a_connection_deleted_meanwhile_is_404(
    client: TestClient, ctx: AdminContext, monkeypatch: pytest.MonkeyPatch, suffix: str
) -> None:
    from u2_mcp.admin import routes_connections

    created = _create(client, ctx)
    token = csrf_from(client.get(f"/admin/connections/{created.id}").text)
    real = routes_connections._connection_or_404

    def loaded_then_deleted(request: object) -> Connection:
        connection = real(request)  # type: ignore[arg-type]
        ctx.store.delete_connection(connection.id)  # someone else deletes it just now
        return connection

    monkeypatch.setattr(routes_connections, "_connection_or_404", loaded_then_deleted)

    response = client.post(
        f"/admin/connections/{created.id}{suffix}",
        data={"csrf_token": token, "read_only": "off"},
        follow_redirects=False,
    )

    assert response.status_code == 404


@pytest.mark.parametrize("suffix", ["/new", "", "/disconnect", "/delete"])
def test_every_post_needs_the_csrf_token(
    client: TestClient, ctx: AdminContext, suffix: str
) -> None:
    created = _create(client, ctx)
    url = (
        "/admin/connections/new" if suffix == "/new" else f"/admin/connections/{created.id}{suffix}"
    )

    response = client.post(url, data={**FORM, "action": "save"}, follow_redirects=False)

    assert response.status_code == 403


def test_a_typed_password_is_never_echoed(
    client: TestClient, ctx: AdminContext, check: FakeCheck
) -> None:
    created = _create(client, ctx)
    typed = {**FORM, "login_password": "typed-Secret-42"}
    url = f"/admin/connections/{created.id}"
    _post(
        client,
        url,
        {**typed, "host": "first.example", "version": str(created.version), "action": "save"},
    )

    stale = _post(client, url, {**typed, "version": str(created.version), "action": "save"})
    htmx = _post(client, url, {**typed, "action": "test"}, headers={"HX-Request": "true"})
    check.result = CheckResult(False, "Login refused", 1.0)
    full = _post(client, url, {**typed, "action": "test"})

    assert stale.status_code == 409  # type: ignore[attr-defined]
    for response in (stale, htmx, full):
        assert "typed-Secret-42" not in response.text  # type: ignore[attr-defined]
