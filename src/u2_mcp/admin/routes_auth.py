"""Signing in to and out of the admin site with a local account."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import TypeVar

from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from ..passwords import verify_password
from ..setup_code import is_setup_complete
from ..sso_config import load_sso
from .security import (
    clear_session_cookie,
    client_ip,
    is_secure,
    presession_token,
    read_form,
    safe_next,
    set_presession_cookie,
    set_session_cookie,
    signed_in,
    start_session,
)
from .services import ValidationFailed, change_password, kept_off_this_site
from .templating import admin_context, render

WRONG_CREDENTIALS = "Wrong username or password."
RATE_LIMITED = "Too many sign-in attempts. Wait a minute and try again."
NON_ADMIN_SIGN_IN_OFF = "Sign-in to this site is turned off for people who are not admins."

T = TypeVar("T")

# Each argon2 hash takes ~64 MiB and tens of milliseconds. Running them on the event
# loop let a burst of sign-ins stall MCP traffic; four threads bound both the stall
# and the memory.
ARGON2_THREADS = 4
_argon2_pool = ThreadPoolExecutor(max_workers=ARGON2_THREADS, thread_name_prefix="argon2")


async def argon2_call[T](fn: Callable[..., T], *args: object) -> T:
    """Run a password hash or check in the argon2 pool."""
    return await asyncio.get_running_loop().run_in_executor(_argon2_pool, fn, *args)


def _sign_in_page(
    request: Request,
    *,
    error: str = "",
    username: str = "",
    next_url: str = "",
    status_code: int = 200,
) -> Response:
    ctx = admin_context(request)
    token = presession_token(request, secure=is_secure(ctx))
    response = render(
        request,
        "sign_in.html",
        status_code=status_code,
        # The sign-in form accepts either token. A signed-in visitor gets the session's,
        # so the page's Sign out button (session token only) still works.
        csrf_token=request.state.csrf_token or token,
        error=error,
        username=username,
        next_url=next_url,
        sso_enabled=load_sso(ctx.store) is not None,
    )
    set_presession_cookie(response, token, secure=is_secure(ctx))
    return response


async def sign_in_form(request: Request) -> Response:
    """Show the sign-in form (or send a brand-new server to setup)."""
    ctx = admin_context(request)
    if not is_setup_complete(ctx.store) and not ctx.store.has_local_admin():
        return RedirectResponse("/admin/setup", status_code=303)
    return _sign_in_page(request, next_url=request.query_params.get("next", ""))


async def sign_in(request: Request) -> Response:
    """Check a username and password and start a session."""
    ctx = admin_context(request)
    form = await read_form(request, presession=True)
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))
    next_url = str(form.get("next", ""))
    ip = client_ip(request)

    if not ctx.limiter.allow(f"ip:{ip}", f"user:{username.casefold()}"):
        return _sign_in_page(
            request, error=RATE_LIMITED, username=username, next_url=next_url, status_code=429
        )

    user = ctx.store.get_user_by_username(username) if username else None
    stored_hash = ctx.store.password_hash(user.id) if user is not None else None
    checked = await argon2_call(verify_password, stored_hash, password)
    if not checked or user is None or user.disabled:
        ctx.store.add_audit(
            kind="auth",
            action="admin.sign_in",
            outcome="failed",
            actor_label=username[:64] or None,
            params={"ip": ip},
        )
        return _sign_in_page(
            request, error=WRONG_CREDENTIALS, username=username, next_url=next_url, status_code=401
        )
    if kept_off_this_site(ctx.store, user):
        ctx.store.add_audit(
            kind="auth",
            action="admin.sign_in",
            outcome="refused",
            actor_user_id=user.id,
            actor_label=user.label,
            params={"ip": ip, "reason": "non-admin sign-in off"},
        )
        return _sign_in_page(
            request,
            error=NON_ADMIN_SIGN_IN_OFF,
            username=username,
            next_url=next_url,
            status_code=403,
        )
    # The checks above awaited argon2. A reset, disable or deletion that landed
    # meanwhile wins: nothing awaits between this re-read and the session.
    current = ctx.store.get_user(user.id)
    if current is None or current.disabled or ctx.store.password_hash(user.id) != stored_hash:
        ctx.store.add_audit(
            kind="auth",
            action="admin.sign_in",
            outcome="failed",
            actor_label=username[:64] or None,
            params={"ip": ip, "reason": "changed during sign-in"},
        )
        return _sign_in_page(
            request, error=WRONG_CREDENTIALS, username=username, next_url=next_url, status_code=401
        )
    user = current
    # Checked again on fresh data: a demotion that landed during argon2 wins.
    if kept_off_this_site(ctx.store, user):
        ctx.store.add_audit(
            kind="auth",
            action="admin.sign_in",
            outcome="refused",
            actor_user_id=user.id,
            actor_label=user.label,
            params={"ip": ip, "reason": "non-admin sign-in off"},
        )
        return _sign_in_page(
            request,
            error=NON_ADMIN_SIGN_IN_OFF,
            username=username,
            next_url=next_url,
            status_code=403,
        )
    previous = request.state.session
    if previous is not None:
        # One browser, one session: the one it had before ends here.
        ctx.store.delete_admin_session(previous.id_hash)
    raw_id, _ = start_session(ctx.store, user, ip)
    ctx.store.add_audit(
        kind="auth",
        action="admin.sign_in",
        outcome="ok",
        actor_user_id=user.id,
        actor_label=user.label,
        params={"ip": ip},
    )
    response = RedirectResponse(safe_next(next_url), status_code=303)
    set_session_cookie(response, raw_id, secure=is_secure(ctx))
    return response


async def sign_out(request: Request) -> Response:
    """End the current session."""
    ctx = admin_context(request)
    session = request.state.session
    if session is None:
        # Already signed out or expired: nothing to end, so no form to check.
        gone = RedirectResponse("/admin/sign-in", status_code=303)
        clear_session_cookie(gone, secure=is_secure(ctx))
        return gone
    await read_form(request)
    user = request.state.user
    ctx.store.delete_admin_session(session.id_hash)
    ctx.store.add_audit(
        kind="auth",
        action="admin.sign_out",
        outcome="ok",
        actor_user_id=user.id,
        actor_label=user.label,
    )
    response = RedirectResponse("/admin/sign-in?notice=signed_out", status_code=303)
    clear_session_cookie(response, secure=is_secure(ctx))
    return response


@signed_in
async def password_form(request: Request) -> Response:
    """Show the change-password form."""
    return render(request, "change_password.html", errors={})


@signed_in
async def password_save(request: Request) -> Response:
    """Change the signed-in user's password; other sessions end."""
    ctx = admin_context(request)
    form = await read_form(request)
    user = request.state.user
    if not ctx.limiter.allow(f"password:{user.id}"):
        return render(
            request,
            "change_password.html",
            status_code=429,
            errors={"current_password": RATE_LIMITED},
        )
    try:
        change_password(
            ctx,
            user,
            current=str(form.get("current_password", "")),
            new=str(form.get("new_password", "")),
            new_again=str(form.get("new_password_again", "")),
        )
    except ValidationFailed as failed:
        if "current_password" in failed.errors:
            ctx.store.add_audit(
                kind="auth",
                action="admin.password_check",
                outcome="failed",
                actor_user_id=user.id,
                actor_label=user.label,
                params={"ip": client_ip(request)},
            )
        return render(request, "change_password.html", status_code=400, errors=failed.errors)
    # Every session this user had, including stolen ones, ends; this browser gets a new one.
    ctx.store.delete_admin_sessions_for(user.id)
    refreshed = ctx.store.get_user(user.id)
    if refreshed is None:
        # Removed meanwhile: its sessions are gone, so this browser is signed out.
        gone = RedirectResponse("/admin/sign-in", status_code=303)
        clear_session_cookie(gone, secure=is_secure(ctx))
        return gone
    raw_id, _ = start_session(ctx.store, refreshed, client_ip(request))
    response = RedirectResponse("/admin/?notice=password_changed", status_code=303)
    set_session_cookie(response, raw_id, secure=is_secure(ctx))
    return response


routes = [
    Route("/sign-in", sign_in_form, methods=["GET"]),
    Route("/sign-in", sign_in, methods=["POST"]),
    Route("/sign-out", sign_out, methods=["POST"]),
    Route("/account/password", password_form, methods=["GET"]),
    Route("/account/password", password_save, methods=["POST"]),
]
