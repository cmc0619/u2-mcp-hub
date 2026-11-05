"""Company sign-in (OIDC) for the admin site: start, callback, and the Settings test.

The round trip is bound to the browser that started it. State, nonce and the
PKCE verifier travel in a sealed, short-lived cookie: SameSite=Lax, so it comes
back on the identity provider's redirect, and `__Host-` over https. The callback
deletes it whatever happens, so a code cannot be replayed.
"""

from __future__ import annotations

import hmac
import json
import logging
from typing import Any

from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from ..auth.idp.base import TokenInfo
from ..auth.oidc_client import OidcClient, OidcError, PendingLogin
from ..sso_config import ADMIN_CALLBACK_PATH, load_sso, oidc_client, overage_resolver
from ..store.crypto import SecretUnreadable
from ..store.models import User
from ..team_auth import SignInRefused, groups_for_sign_in, record_sign_in
from .context import AdminContext
from .routes_auth import NON_ADMIN_SIGN_IN_OFF, RATE_LIMITED
from .security import (
    admin_only,
    client_ip,
    cookie_name,
    cookie_path,
    is_secure,
    read_form,
    safe_next,
    set_session_cookie,
    start_session,
)
from .services import effective_public_url, non_admin_sign_in_enabled
from .templating import admin_context, render

SSO_COOKIE = "u2_admin_sso"
SSO_COOKIE_SECONDS = 600
SSO_EXPIRED = (
    "This sign-in expired or was started in another browser. Start again from the sign-in page."
)
SSO_FAILED = "Company sign-in failed: {reason}"
SSO_UNAVAILABLE = "Company sign-in is not available right now. Try again later or ask an admin."
SSO_NOT_SET_UP = "Company sign-in is not set up."
SSO_DISABLED = "This account is disabled. Ask an admin."
SSO_REFUSED = "Company sign-in was refused."
logger = logging.getLogger(__name__)
_TITLE = "Company sign-in"
_PENDING_KEYS = ("state", "nonce", "verifier", "purpose", "next")


def _message(request: Request, text: str, status_code: int) -> Response:
    return render(request, "message.html", status_code=status_code, title=_TITLE, message=text)


def _redirect_uri(ctx: AdminContext) -> str:
    return effective_public_url(ctx) + ADMIN_CALLBACK_PATH


def _forget(response: Response, secure: bool) -> Response:
    response.delete_cookie(
        cookie_name(SSO_COOKIE, secure),
        path=cookie_path(secure),
        secure=secure,
        httponly=True,
        samesite="lax",
    )
    return response


def _audit(
    ctx: AdminContext, *, testing: bool, outcome: str, actor: User | None, params: dict[str, Any]
) -> None:
    ctx.store.add_audit(
        kind="admin" if testing else "auth",
        action="settings.sso_test" if testing else "admin.sign_in",
        outcome=outcome,
        actor_user_id=actor.id if actor else None,
        actor_label=actor.label if actor else None,
        params={"method": "sso", **params},
    )


async def _begin(request: Request, *, purpose: str, next_url: str) -> Response:
    ctx = admin_context(request)
    testing = purpose == "test"
    viewer: User | None = request.state.user if testing else None
    client = oidc_client(ctx.store, ctx.http)
    if client is None:
        return _message(request, SSO_NOT_SET_UP, 400)
    login = PendingLogin.new()
    try:
        url = await client.authorization_url(_redirect_uri(ctx), login)
    except OidcError as exc:
        logger.warning(f"Starting company sign-in failed: {exc}")
        _audit(
            ctx,
            testing=testing,
            outcome="failed",
            actor=viewer,
            params={"ip": client_ip(request), "reason": str(exc)[:200], "stage": "start"},
        )
        # Only an admin running the Test may see the provider's detail.
        text = SSO_FAILED.format(reason=exc) if testing else SSO_UNAVAILABLE
        return _message(request, text, 400)
    pending = {
        "state": login.state,
        "nonce": login.nonce,
        "verifier": login.verifier,
        "purpose": purpose,
        "next": next_url,
    }
    secure = is_secure(ctx)
    response = RedirectResponse(url, status_code=303)
    response.set_cookie(
        cookie_name(SSO_COOKIE, secure),
        ctx.store.seal(json.dumps(pending)),
        max_age=SSO_COOKIE_SECONDS,
        path=cookie_path(secure),
        httponly=True,
        samesite="lax",
        secure=secure,
    )
    return response


async def sign_in_start(request: Request) -> Response:
    """Start a company sign-in from the sign-in page (pre-session CSRF token)."""
    form = await read_form(request, presession=True)
    ctx = admin_context(request)
    if not ctx.sso_start_limiter.allow(f"sso-start:{client_ip(request)}"):
        return _message(request, RATE_LIMITED, 429)
    return await _begin(request, purpose="sign_in", next_url=safe_next(str(form.get("next", ""))))


@admin_only
async def test_start(request: Request) -> Response:
    """Settings and the wizard: a real round trip that signs nobody in."""
    await read_form(request)
    return await _begin(request, purpose="test", next_url="/admin/settings")


def _pending(ctx: AdminContext, raw: str | None) -> dict[str, str] | None:
    if not raw:
        return None
    try:
        data = json.loads(ctx.store.unseal(raw, max_age_seconds=SSO_COOKIE_SECONDS))
    except (SecretUnreadable, ValueError):
        return None
    if not isinstance(data, dict) or not all(isinstance(data.get(k), str) for k in _PENDING_KEYS):
        return None
    return {key: data[key] for key in _PENDING_KEYS}


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


async def callback(request: Request) -> Response:
    """The identity provider's redirect back: check, then sign in (or show the test).

    Whatever goes wrong, the pending-login cookie is deleted and the failure is
    audited; nothing unexpected becomes a 500.
    """
    try:
        return await _callback(request)
    except Exception as exc:  # noqa: BLE001 - never leak a 500 from the sign-in round trip
        logger.exception("Company sign-in callback failed")
        ctx = admin_context(request)
        secure = is_secure(ctx)
        pending = _pending(ctx, request.cookies.get(cookie_name(SSO_COOKIE, secure)))
        testing = pending is not None and pending["purpose"] == "test"
        viewer: User | None = request.state.user
        _audit(
            ctx,
            testing=testing,
            outcome="failed",
            actor=viewer if testing else None,
            params={"ip": client_ip(request), "reason": f"unexpected {type(exc).__name__}"},
        )
        return _forget(_message(request, SSO_FAILED.format(reason="unexpected error"), 400), secure)


async def _callback(request: Request) -> Response:
    ctx = admin_context(request)
    secure = is_secure(ctx)
    pending = _pending(ctx, request.cookies.get(cookie_name(SSO_COOKIE, secure)))
    presented = request.query_params.get("state", "")
    if pending is None or not hmac.compare_digest(
        pending["state"].encode(), presented.encode("utf-8", "replace")
    ):
        return _forget(_message(request, SSO_EXPIRED, 400), secure)
    testing = pending["purpose"] == "test"
    ip = client_ip(request)
    viewer: User | None = request.state.user
    settings = load_sso(ctx.store)
    client = oidc_client(ctx.store, ctx.http)
    try:
        login = PendingLogin(pending["state"], pending["nonce"], pending["verifier"])
        code = OidcClient.callback_code(request.query_params, login)
        if settings is None or client is None:
            raise OidcError(SSO_NOT_SET_UP)
        claims = await client.sign_in(code, _redirect_uri(ctx), login)
    except OidcError as exc:
        _audit(
            ctx,
            testing=testing,
            outcome="failed",
            actor=viewer if testing else None,
            params={"ip": ip, "reason": str(exc)[:200]},
        )
        return _forget(_message(request, SSO_FAILED.format(reason=exc), 400), secure)

    groups = await groups_for_sign_in(
        claims, settings.groups_claim, overage_resolver(ctx.store, settings, ctx.http)
    )
    if testing:
        _audit(
            ctx,
            testing=True,
            outcome="ok",
            actor=viewer,
            params={"groups": None if groups is None else len(groups)},
        )
        page = render(
            request,
            "sso_test.html",
            subject=claims["sub"],
            email=_text(claims.get("email")),
            name=_text(claims.get("name")),
            groups=groups,
            groups_claim=settings.groups_claim,
            graph_overage=settings.graph_overage,
        )
        return _forget(page, secure)

    info = TokenInfo(
        subject=claims["sub"],
        email=_text(claims.get("email")),
        name=_text(claims.get("name")),
        raw_claims=claims,
    )
    # Checked before the sign-in is recorded: a refused sign-in here neither creates
    # the person nor keeps their tokens fresh. MCP app sign-in records its own.
    known = ctx.store.get_sso_user(claims["iss"], info.subject) or ctx.store.get_sso_user(
        None, info.subject
    )
    if not non_admin_sign_in_enabled(ctx.store) and (known is None or not known.is_admin):
        _audit(
            ctx,
            testing=False,
            outcome="refused",
            actor=known,
            params={"ip": ip, "reason": "non-admin sign-in off"},
        )
        return _forget(_message(request, NON_ADMIN_SIGN_IN_OFF, 403), secure)
    try:
        user = record_sign_in(
            ctx.store,
            info,
            groups,
            via="admin",
            issuer=claims["iss"],
        )
    except SignInRefused as exc:
        refused = ctx.store.get_sso_user(claims["iss"], info.subject) or ctx.store.get_sso_user(
            None, info.subject
        )
        _audit(
            ctx,
            testing=False,
            outcome="refused",
            actor=refused,
            params={"ip": ip, "reason": exc.reason},
        )
        message = SSO_DISABLED if exc.reason == "disabled" else SSO_REFUSED
        return _forget(_message(request, message, 403), secure)
    previous = request.state.session
    if previous is not None:
        ctx.store.delete_admin_session(previous.id_hash)  # one browser, one session
    raw_id, _ = start_session(ctx.store, user, ip)
    _audit(ctx, testing=False, outcome="ok", actor=user, params={"ip": ip})
    response = RedirectResponse(safe_next(pending["next"]), status_code=303)
    set_session_cookie(response, raw_id, secure=secure)
    return _forget(response, secure)


routes = [
    Route("/sign-in/sso", sign_in_start, methods=["POST"]),
    Route("/sign-in/sso/callback", callback, methods=["GET"]),
    Route("/settings/sso/test", test_start, methods=["POST"]),
]
