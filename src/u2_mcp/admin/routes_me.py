"""My access: every signed-in person's connections, tokens and editor setup."""

from __future__ import annotations

import anyio
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from ..access import visible_connections
from ..connection_check import CheckResult
from ..tokens import fresh_until
from .problems import Refused, with_query
from .reveal import OneTimeReveal
from .security import read_form, signed_in
from .services import (
    check_my_u2_login,
    create_personal_token,
    curl_example,
    default_token_days,
    effective_public_url,
    my_u2_logins,
    remove_my_u2_login,
    revoke_personal_token,
    save_my_u2_login,
    sign_out_app,
    signed_in_apps,
    token_max_lifetime,
    token_views,
)
from .templating import admin_context, render

_reveals = OneTimeReveal()


def _login_attempt_allowed(request: Request, action: str, connection_id: int) -> bool:
    """Count one test or save against this person; audit a refusal.

    Every attempt counts, successful or not: a check that answers is a guess oracle.
    Only signed-in people get here, so the per-person key is enough; a per-address
    key would throttle a whole office behind one NAT address.
    """
    ctx = admin_context(request)
    user = request.state.user
    if ctx.limiter.allow(f"u2-login:{user.id}"):
        return True
    connection = ctx.store.get_connection(connection_id)
    ctx.store.add_audit(
        kind="admin",
        action=action,
        outcome="refused",
        actor_user_id=user.id,
        actor_label=user.label,
        connection_id=connection.id if connection else None,
        params={"connection": connection.name if connection else None, "reason": "rate_limited"},
    )
    return False


def _back(code: str) -> RedirectResponse:
    return RedirectResponse(with_query("/admin/me", problem=code), status_code=303)


def _page(
    request: Request,
    *,
    tested: int | None = None,
    result: CheckResult | None = None,
    test_errors: list[str] | None = None,
    limited: bool = False,
    status_code: int = 200,
) -> Response:
    """Render My access; tested names the connection whose login test is shown."""
    ctx = admin_context(request)
    user = request.state.user
    new_token = None
    _reveals.prune()
    reveal_id = request.query_params.get("reveal")
    if reveal_id and request.state.session is not None:
        new_token = _reveals.take(request.state.session.id_hash, reveal_id)
    public_url = effective_public_url(ctx)
    return render(
        request,
        "me.html",
        status_code=status_code,
        connections=visible_connections(ctx.store, user.id, global_read_only=ctx.config.read_only),
        u2_logins=my_u2_logins(ctx, user),
        tested=tested,
        result=result,
        test_errors=test_errors or [],
        limited=limited,
        tokens=[view for view in token_views(ctx, user.id) if view.revocable],
        apps=signed_in_apps(ctx, user),
        oauth=ctx.oauth_storage is not None,
        new_token=new_token,
        server_url=public_url.rstrip("/") + "/",
        mcp_sign_in=ctx.mcp_oauth,
        curl_example=curl_example(public_url),
        freshness_days=ctx.config.token_freshness_days,
        fresh_until=fresh_until(user, freshness_days=ctx.config.token_freshness_days),
        max_days=token_max_lifetime(ctx),
        default_days=default_token_days(ctx),
    )


@signed_in
async def my_access(request: Request) -> Response:
    """The signed-in person's connections, tokens and client configuration."""
    return _page(request)


def _login_back(connection_id: int, *, notice: str = "", problem: str = "") -> RedirectResponse:
    params = {"notice": notice} if notice else {"problem": problem}
    target = with_query("/admin/me", **params) + f"#u2-login-{connection_id}"
    return RedirectResponse(target, status_code=303)


@signed_in
async def save_login(request: Request) -> Response:
    """Save the signed-in person's own U2 login. The user id comes from the session."""
    data = await read_form(request)
    connection_id = request.path_params["id"]
    if not _login_attempt_allowed(request, "u2_login_set", connection_id):
        return _login_back(connection_id, problem="u2_login_rate_limited")
    try:
        save_my_u2_login(
            admin_context(request),
            request.state.user,
            connection_id,
            u2_user=str(data.get("u2_user", "")),
            u2_password=str(data.get("u2_password", "")),
        )
    except Refused as refused:
        return _login_back(connection_id, problem=refused.code)
    return _login_back(connection_id, notice="u2_login_saved")


@signed_in
async def test_login(request: Request) -> Response:
    """Test the typed (or stored) login against the connection; nothing is saved."""
    ctx = admin_context(request)
    data = await read_form(request)
    connection_id = request.path_params["id"]
    user = request.state.user
    result: CheckResult | None = None
    errors: list[str] = []
    limited = not _login_attempt_allowed(request, "u2_login_test", connection_id)
    try:
        if limited:
            raise Refused("u2_login_rate_limited")
        result = await anyio.to_thread.run_sync(
            lambda: check_my_u2_login(
                ctx,
                user,
                connection_id,
                u2_user=str(data.get("u2_user", "")),
                u2_password=str(data.get("u2_password", "")),
            )
        )
    except Refused as refused:
        errors = [str(refused)]
    if request.headers.get("HX-Request"):
        return render(
            request,
            "partials/test_result.html",
            result=result,
            test_errors=errors,
            result_id=f"u2-login-test-{connection_id}",
            limited=limited,
        )
    return _page(
        request,
        tested=connection_id,
        result=result,
        test_errors=errors,
        limited=limited,
        status_code=429 if limited else 400 if errors else 200,
    )


@signed_in
async def remove_login(request: Request) -> Response:
    """Forget the signed-in person's own U2 login on one connection."""
    await read_form(request)
    connection_id = request.path_params["id"]
    try:
        remove_my_u2_login(admin_context(request), request.state.user, connection_id)
    except Refused as refused:
        return _login_back(connection_id, problem=refused.code)
    return _login_back(connection_id, notice="u2_login_removed")


@signed_in
async def create(request: Request) -> Response:
    """Create a token and send the browser to see it once."""
    ctx = admin_context(request)
    data = await read_form(request)
    session = request.state.session
    if session is None:
        # signed_in guarantees a session today; never create a token nobody can see.
        raise HTTPException(403, "Sign in first.")
    try:
        token, _record = create_personal_token(
            ctx,
            request.state.user,
            name=str(data.get("name", "")),
            days=str(data.get("days", "")).strip(),
        )
    except Refused as refused:
        return _back(refused.code)
    reveal_id = _reveals.put(session.id_hash, token)
    return RedirectResponse(
        with_query("/admin/me", notice="token_created", reveal=reveal_id), status_code=303
    )


@signed_in
async def revoke(request: Request) -> Response:
    """Revoke one of the signed-in person's own tokens."""
    await read_form(request)
    user = request.state.user
    try:
        revoke_personal_token(
            admin_context(request), request.path_params["id"], owner_id=user.id, actor=user
        )
    except Refused as refused:
        return _back(refused.code)
    return RedirectResponse("/admin/me?notice=revoked", status_code=303)


@signed_in
async def sign_out(request: Request) -> Response:
    """Sign one MCP app out of the signed-in person's account."""
    data = await read_form(request)
    try:
        sign_out_app(admin_context(request), request.state.user, str(data.get("client_id", "")))
    except Refused as refused:
        return _back(refused.code)
    return RedirectResponse("/admin/me?notice=app_signed_out#signed-in-apps", status_code=303)


routes = [
    Route("/me", my_access, methods=["GET"]),
    Route("/me/apps/sign-out", sign_out, methods=["POST"]),
    Route("/me/tokens", create, methods=["POST"]),
    Route("/me/tokens/{id:id}/revoke", revoke, methods=["POST"]),
    Route("/me/u2-logins/{id:id}", save_login, methods=["POST"]),
    Route("/me/u2-logins/{id:id}/test", test_login, methods=["POST"]),
    Route("/me/u2-logins/{id:id}/remove", remove_login, methods=["POST"]),
]
