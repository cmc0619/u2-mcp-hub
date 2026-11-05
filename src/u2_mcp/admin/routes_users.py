"""Users: list with filters, create a local user, flags, tokens, grants, effective access."""

from __future__ import annotations

from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from ..access import effective_access
from ..store.models import User
from ..tokens import is_fresh
from .problems import Refused, with_query
from .routes_grants import grant_editor
from .security import admin_only, read_form, safe_next
from .services import (
    ValidationFailed,
    clear_u2_login,
    create_local_user,
    delete_person,
    deletion_summary,
    edit_person,
    reset_password,
    revoke_personal_token,
    set_user_flags,
    sign_out_all_apps,
    sign_out_app,
    signed_in_apps,
    token_views,
    u2_logins_of_person,
    user_groups,
    users_with_apps,
)
from .templating import admin_context, render

_YES_NO = {"yes": True, "no": False}
_STATUS = {"disabled": True, "enabled": False}


def _user_or_404(request: Request) -> User:
    user = admin_context(request).store.get_user(request.path_params["id"])
    if user is None:
        raise HTTPException(404, "There is no such user.")
    return user


@admin_only
async def list_users(request: Request) -> Response:
    """Every user, filtered by text, admin flag and status."""
    query = request.query_params
    users = admin_context(request).store.list_users(
        search=query.get("q", "").strip(),
        is_admin=_YES_NO.get(query.get("admin", "")),
        disabled=_STATUS.get(query.get("status", "")),
    )
    ctx = admin_context(request)
    # Only people with an app signed in get the button.
    with_apps = users_with_apps(ctx, users)
    back = request.url.path + ("?" + request.url.query if request.url.query else "")
    return render(
        request,
        "users/list.html",
        users=users,
        filters=dict(query),
        with_apps=with_apps,
        back=back,
    )


def _new_page(
    request: Request, values: dict[str, str], errors: dict[str, str], status: int
) -> Response:
    return render(
        request,
        "users/new.html",
        status_code=status,
        values=values,
        errors=errors,
        action_url="/admin/users/new",
        submit_label="Create user",
        show_setup_code=False,
        show_admin_flag=True,
    )


@admin_only
async def new_user_form(request: Request) -> Response:
    """An empty new-user form."""
    return _new_page(request, {}, {}, 200)


@admin_only
async def new_user(request: Request) -> Response:
    """Create a local user."""
    data = await read_form(request)
    values = {key: str(value) for key, value in data.items() if "password" not in key}
    try:
        user = create_local_user(
            admin_context(request),
            username=str(data.get("username", "")),
            password=str(data.get("password", "")),
            password_again=str(data.get("password_again", "")),
            display_name=str(data.get("display_name", "")),
            is_admin=data.get("is_admin") == "on",
            actor=request.state.user,
        )
    except ValidationFailed as failed:
        return _new_page(request, values, failed.errors, 400)
    return RedirectResponse(f"/admin/users/{user.id}?notice=saved", status_code=303)


def _detail_page(request: Request, user: User, *, status: int = 200, **extra: object) -> Response:
    ctx = admin_context(request)
    context: dict[str, object] = {
        "person": user,
        "groups": user_groups(ctx, user.id),
        "tokens": token_views(ctx, user.id),
        "paused": not is_fresh(
            user, now=ctx.store.clock(), freshness_days=ctx.config.token_freshness_days
        ),
        "freshness_days": ctx.config.token_freshness_days,
        "u2_logins": u2_logins_of_person(ctx, user),
        "apps": signed_in_apps(ctx, user),
        "u2_logins_by_connection": True,
        "u2_logins_return_to": f"/admin/users/{user.id}",
        "is_self": user.id == request.state.user.id,
        "edit_values": {
            "username": user.username or "",
            "display_name": user.display_name or "",
            "email": user.email or "",
        },
        "edit_errors": {},
        "reset_errors": {},
    }
    context.update(
        grant_editor(
            ctx, return_to=f"/admin/users/{user.id}", subject_type="user", subject_id=user.id
        )
    )
    context.update(extra)
    return render(request, "users/detail.html", status_code=status, **context)


@admin_only
async def user_detail(request: Request) -> Response:
    """One user's details, flags, groups, tokens and grants."""
    return _detail_page(request, _user_or_404(request))


@admin_only
async def reset_user_password(request: Request) -> Response:
    """Set a temporary password, typed or generated (generated ones are shown once)."""
    data = await read_form(request)
    user = _user_or_404(request)
    target = f"/admin/users/{user.id}"
    try:
        generated = reset_password(
            admin_context(request),
            user.id,
            password=str(data.get("password", "")),
            generate=data.get("generate") == "yes",
            actor=request.state.user,
        )
    except Refused as refused:
        return RedirectResponse(with_query(target, problem=refused.code), status_code=303)
    except ValidationFailed as failed:
        return _detail_page(request, user, status=400, reset_errors=failed.errors)
    if generated is None:
        return RedirectResponse(with_query(target, notice="password_reset"), status_code=303)
    return render(request, "users/password_generated.html", person=user, password=generated)


@admin_only
async def edit_details(request: Request) -> Response:
    """Change display name, email and (local users) username."""
    data = await read_form(request)
    user = _user_or_404(request)
    target = f"/admin/users/{user.id}"
    values = {key: str(data.get(key, "")) for key in ("username", "display_name", "email")}
    try:
        edit_person(admin_context(request), user.id, actor=request.state.user, **values)
    except Refused as refused:
        return RedirectResponse(with_query(target, problem=refused.code), status_code=303)
    except ValidationFailed as failed:
        return _detail_page(
            request, user, status=400, edit_values=values, edit_errors=failed.errors
        )
    return RedirectResponse(with_query(target, notice="saved"), status_code=303)


@admin_only
async def delete_confirm(request: Request) -> Response:
    """List what goes with a person, and ask before deleting them."""
    ctx = admin_context(request)
    user = _user_or_404(request)
    return render(request, "users/delete.html", person=user, summary=deletion_summary(ctx, user))


@admin_only
async def delete_user(request: Request) -> Response:
    """Delete a person."""
    await read_form(request)
    user = _user_or_404(request)
    try:
        delete_person(admin_context(request), user.id, actor=request.state.user)
    except Refused as refused:
        return RedirectResponse(
            with_query(f"/admin/users/{user.id}", problem=refused.code), status_code=303
        )
    return RedirectResponse(with_query("/admin/users", notice="user_deleted"), status_code=303)


@admin_only
async def flags(request: Request) -> Response:
    """Turn admin or disabled on or off."""
    data = await read_form(request)
    user = _user_or_404(request)

    def flag(name: str) -> bool | None:
        return {"on": True, "off": False}.get(str(data.get(name)))

    target = f"/admin/users/{user.id}"
    is_admin, disabled = flag("is_admin"), flag("disabled")
    if is_admin is None and disabled is None:
        return RedirectResponse(target, status_code=303)
    try:
        set_user_flags(
            admin_context(request),
            user.id,
            is_admin=is_admin,
            disabled=disabled,
            actor=request.state.user,
        )
    except Refused as refused:
        return RedirectResponse(with_query(target, problem=refused.code), status_code=303)
    return RedirectResponse(with_query(target, notice="saved"), status_code=303)


@admin_only
async def revoke_token(request: Request) -> Response:
    """Revoke one of this user's tokens."""
    await read_form(request)
    user = _user_or_404(request)
    target = f"/admin/users/{user.id}"
    try:
        revoke_personal_token(
            admin_context(request),
            request.path_params["token_id"],
            owner_id=user.id,
            actor=request.state.user,
        )
    except Refused as refused:
        return RedirectResponse(with_query(target, problem=refused.code), status_code=303)
    return RedirectResponse(with_query(target, notice="revoked"), status_code=303)


@admin_only
async def clear_login(request: Request) -> Response:
    """Clear one person's own U2 login on a connection. The password is never shown."""
    data = await read_form(request)
    user = _user_or_404(request)
    back = str(data.get("return_to", ""))
    target = safe_next(back) if back else f"/admin/users/{user.id}"
    try:
        clear_u2_login(
            admin_context(request),
            user.id,
            request.path_params["connection_id"],
            actor=request.state.user,
        )
    except Refused as refused:
        return RedirectResponse(with_query(target, problem=refused.code), status_code=303)
    return RedirectResponse(with_query(target, notice="u2_login_cleared"), status_code=303)


@admin_only
async def access(request: Request) -> Response:
    """For every connection: each permission and the grant or group that gives it."""
    ctx = admin_context(request)
    user = _user_or_404(request)
    report = effective_access(ctx.store, user.id, global_read_only=ctx.config.read_only)
    return render(
        request, "users/access.html", person=user, report=report, groups=user_groups(ctx, user.id)
    )


@admin_only
async def sign_out_apps(request: Request) -> Response:
    """Sign out one of this person's apps (client_id), or all of them (none given)."""
    data = await read_form(request)
    user = _user_or_404(request)
    back = str(data.get("next", ""))
    target = safe_next(back) if back else f"/admin/users/{user.id}"
    client_id = str(data.get("client_id", ""))
    ctx = admin_context(request)
    try:
        if client_id:
            sign_out_app(ctx, user, client_id, actor=request.state.user)
        else:
            sign_out_all_apps(ctx, user, actor=request.state.user)
    except Refused as refused:
        return RedirectResponse(with_query(target, problem=refused.code), status_code=303)
    notice = "app_signed_out" if client_id else "apps_signed_out"
    return RedirectResponse(with_query(target, notice=notice), status_code=303)


routes = [
    Route("/users", list_users, methods=["GET"]),
    Route("/users/new", new_user_form, methods=["GET"]),
    Route("/users/new", new_user, methods=["POST"]),
    Route("/users/{id:id}", user_detail, methods=["GET"]),
    Route("/users/{id:id}/flags", flags, methods=["POST"]),
    Route("/users/{id:id}/reset-password", reset_user_password, methods=["POST"]),
    Route("/users/{id:id}/details", edit_details, methods=["POST"]),
    Route("/users/{id:id}/delete", delete_confirm, methods=["GET"]),
    Route("/users/{id:id}/delete", delete_user, methods=["POST"]),
    Route("/users/{id:id}/tokens/{token_id:id}/revoke", revoke_token, methods=["POST"]),
    Route("/users/{id:id}/apps/sign-out", sign_out_apps, methods=["POST"]),
    Route("/users/{id:id}/access", access, methods=["GET"]),
    Route("/users/{id:id}/u2-logins/{connection_id:id}/clear", clear_login, methods=["POST"]),
]
