"""Every admin route: sign-in required, CSRF on POST, never cached (review M-6)."""

import re

from starlette.routing import Mount, Route

from u2_mcp.admin.app import build_admin_app
from u2_mcp.admin.context import AdminContext
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import finish_setup, mark_step_done

from .helpers import PASSWORD, admin_client, csrf_from, sign_in

PUBLIC_GETS = {"/sign-in", "/sign-in/sso/callback"}
# POST routes that answer before reading the form, each with the reason. Keep this
# to routes that truly cannot reach read_form once setup is finished.
_SETUP_CLOSED = "setup is finished: redirects home before reading any form (see the next test)"
POSTS_REFUSED_BEFORE_THE_FORM: dict[str, str] = {
    "/setup/admin": _SETUP_CLOSED,
    "/setup/connection": _SETUP_CLOSED,
    "/setup/server_address": _SETUP_CLOSED,
    "/setup/sso": _SETUP_CLOSED,
    "/setup/sso/next": _SETUP_CLOSED,
    "/setup/done": _SETUP_CLOSED,
}


def _routes(ctx: AdminContext) -> list[tuple[str, str]]:
    """Every (method, path) the site serves, with each {param} filled in as 1."""
    found = []
    for route in build_admin_app(ctx).routes:
        if isinstance(route, Mount):
            # Only static files are mounted; a mounted sub-app would hide its routes.
            assert route.path == "/static", route.path
            continue
        assert isinstance(route, Route), route
        path = re.sub(r"\{[^}]+\}", "1", route.path)
        found += [(method, path) for method in sorted(route.methods or ()) if method != "HEAD"]
    return found


def _seed(ctx: AdminContext) -> None:
    """Make id 1 exist for every {id} route, so each one reaches read_form."""
    ann = ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    connection = ctx.store.add_connection(
        name="Prod",
        host="u2.example",
        port=31438,
        service="uvcs",
        account="DEV",
        shared_user="svc",
        shared_password="pw",
    )
    viewer = ctx.store.get_role_by_name("Viewer")
    assert viewer is not None
    grant = ctx.store.add_grant(
        connection_id=connection.id, subject_type="everyone", role_id=viewer.id
    )
    token = ctx.store.add_token(
        user_id=ann.id, name="laptop", token_hash="x" * 64, expires_at=ctx.store.clock() + 3600
    )
    sam = ctx.store.get_or_create_sso_user("sub-sam")
    ctx.store.record_sso_login(sam.id, ["eng"])
    assert ann.id == connection.id == grant.id == token.id == ctx.store.list_groups()[0].id == 1
    assert ctx.store.get_role(1) is not None


def test_every_page_needs_sign_in_and_is_never_cached(ctx: AdminContext) -> None:
    finish_setup(ctx.store)
    with admin_client(ctx) as anonymous:
        for method, path in _routes(ctx):
            if method != "GET" or path in PUBLIC_GETS:
                continue
            response = anonymous.get(f"/admin{path}", follow_redirects=False)
            assert response.status_code == 303, path
            assert response.headers["cache-control"] == "no-store", path


def test_no_post_changes_anything_without_the_csrf_token(ctx: AdminContext) -> None:
    finish_setup(ctx.store)
    _seed(ctx)
    with admin_client(ctx) as client:
        sign_in(client)
        before = len(ctx.store.recent_audit(1000))
        posts = [path for method, path in _routes(ctx) if method == "POST"]
        assert "/grants/1" in posts
        for path in posts:
            if path in POSTS_REFUSED_BEFORE_THE_FORM:
                continue
            response = client.post(f"/admin{path}", data={}, follow_redirects=False)
            assert response.status_code == 403, path
            assert response.headers["cache-control"] == "no-store", path
        assert len(ctx.store.recent_audit(1000)) == before


def test_each_setup_step_refuses_a_post_without_the_csrf_token(ctx: AdminContext) -> None:
    steps = [path for path in POSTS_REFUSED_BEFORE_THE_FORM if path.startswith("/setup/")]
    assert steps == [
        "/setup/admin",
        "/setup/connection",
        "/setup/server_address",
        "/setup/sso",
        "/setup/sso/next",
        "/setup/done",
    ]
    with admin_client(ctx) as client:
        # Step 1 is shown before sign-in: it is the first admin's creation.
        response = client.post("/admin/setup/admin", data={}, follow_redirects=False)
        assert response.status_code == 403
        assert ctx.store.get_user_by_username("ann") is None
        ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
        mark_step_done(ctx.store, "admin")
        sign_in(client)
        for done, path in (
            ("admin", "/setup/connection"),
            ("connection", "/setup/server_address"),
            ("server_address", "/setup/sso"),
            ("server_address", "/setup/sso/next"),
            ("sso", "/setup/done"),
        ):
            mark_step_done(ctx.store, done)
            before = len(ctx.store.recent_audit(1000))
            response = client.post(f"/admin{path}", data={}, follow_redirects=False)
            assert response.status_code == 403, path
            assert len(ctx.store.recent_audit(1000)) == before, path


NON_ADMIN_GETS = {"/sign-in", "/sign-in/sso/callback", "/me", "/account/password"}
NON_ADMIN_POSTS = {
    "/sign-in",
    "/sign-in/sso",
    "/sign-out",
    "/me/tokens",
    "/me/tokens/1/revoke",
    "/me/apps/sign-out",
    "/me/u2-logins/1",
    "/me/u2-logins/1/test",
    "/me/u2-logins/1/remove",
    "/account/password",
}


def test_people_who_are_not_admins_reach_only_their_own_pages(ctx: AdminContext) -> None:
    finish_setup(ctx.store)
    _seed(ctx)
    ctx.store.add_local_user("bob", password_hash=hash_password(PASSWORD))
    with admin_client(ctx) as client:
        sign_in(client, "bob")
        token = csrf_from(client.get("/admin/me").text)
        before = len(ctx.store.recent_audit(1000))
        for method, path in _routes(ctx):
            if path.startswith("/setup"):
                continue  # setup is finished: those answer with a redirect home
            if method == "GET" and path not in NON_ADMIN_GETS:
                response = client.get(f"/admin{path}", follow_redirects=False)
                assert response.status_code == 303, path
                assert response.headers["location"] == "/admin/me", path
            elif method == "POST" and path not in NON_ADMIN_POSTS:
                response = client.post(
                    f"/admin{path}", data={"csrf_token": token}, follow_redirects=False
                )
                assert response.status_code == 403, path
                assert "Only admins can use this page." in response.text, path
        assert len(ctx.store.recent_audit(1000)) == before
