"""Groups (labels and grants) and Roles (built-in read-only; clone, edit, delete)."""

from __future__ import annotations

from collections.abc import Callable

from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from ..permissions import PERMISSIONS, TOOL_PERMISSIONS, WRITE_PERMISSIONS
from ..store.models import Connection, Group, Role
from ..store.repo import StaleEdit, Store
from .problems import Refused, with_query
from .routes_grants import form_int, grant_editor
from .security import admin_only, read_form, safe_next
from .services import (
    ValidationFailed,
    clone_role,
    delete_group,
    remove_role,
    save_role,
    set_group_label,
)
from .templating import admin_context, render

TOOLS_BY_PERMISSION = {
    p: sorted(tool for tool, needed in TOOL_PERMISSIONS.items() if needed == p) for p in PERMISSIONS
}


def _group_or_404(request: Request) -> Group:
    group = admin_context(request).store.get_group(request.path_params["id"])
    if group is None:
        raise HTTPException(404, "There is no such group.")
    return group


def _role_or_404(request: Request) -> Role:
    role = admin_context(request).store.get_role(request.path_params["id"])
    if role is None:
        raise HTTPException(404, "There is no such role.")
    return role


def _redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


_UNSEEN_DAYS = ("30", "90", "180")
_DAY = 86400


_NO_PROVIDER = "-"  # the filter value for groups with no issuer


def _grant_lookup(store: Store) -> Callable[[Group], list[tuple[Connection, str]]]:
    """Load connections and roles once; the result gives a group's grants by connection name."""
    connections = {c.id: c for c in store.list_connections()}
    roles = {r.id: r.name for r in store.list_roles()}

    def grants_of(group: Group) -> list[tuple[Connection, str]]:
        grants = [
            (connections[g.connection_id], roles.get(g.role_id, "?"))
            for g in store.grants_for_subject("group", group.id)
            if g.connection_id in connections
        ]
        return sorted(grants, key=lambda pair: pair[0].name.lower())

    return grants_of


@admin_only
async def list_groups(request: Request) -> Response:
    """Groups seen at sign-in, filtered by text, access, last seen and provider."""
    store = admin_context(request).store
    query = request.query_params
    text = query.get("q", "").strip().lower()
    access = query.get("access", "")
    unseen = query.get("unseen", "")
    provider = query.get("provider", "")
    groups = store.list_groups()
    providers = sorted({g.issuer or "" for g in groups})
    now = store.clock()
    grants_of = _grant_lookup(store)
    rows = []
    for group in groups:
        grants = grants_of(group)
        if (
            text
            and text not in (group.label or "").lower()
            and text not in group.external_id.lower()
        ):
            continue
        if (access == "with" and not grants) or (access == "none" and grants):
            continue
        if unseen in _UNSEEN_DAYS and (group.last_seen_at or 0) > now - int(unseen) * _DAY:
            continue
        if len(providers) > 1 and provider and (group.issuer or _NO_PROVIDER) != provider:
            continue
        rows.append((group, grants))
    back = request.url.path + ("?" + request.url.query if request.url.query else "")
    return render(
        request,
        "groups/list.html",
        rows=rows,
        filters=dict(query),
        providers=providers,
        no_provider=_NO_PROVIDER,
        unseen_days=_UNSEEN_DAYS,
        back=back,
        # The provider tells groups apart only when there is more than one.
        several_providers=len(providers) > 1,
    )


def _group_page(request: Request, group: Group, errors: dict[str, str], status: int) -> Response:
    ctx = admin_context(request)
    return render(
        request,
        "groups/detail.html",
        status_code=status,
        group=group,
        errors=errors,
        several_providers=len({g.issuer for g in ctx.store.list_groups()}) > 1,
        **grant_editor(
            ctx, return_to=f"/admin/groups/{group.id}", subject_type="group", subject_id=group.id
        ),
    )


@admin_only
async def group_detail(request: Request) -> Response:
    """A group's label and grants."""
    return _group_page(request, _group_or_404(request), {}, 200)


@admin_only
async def group_delete_confirm(request: Request) -> Response:
    """Show what goes with a group that has access, and ask first."""
    group = _group_or_404(request)
    store = admin_context(request).store
    return render(
        request,
        "groups/delete.html",
        group=group,
        grants=_grant_lookup(store)(group),
        back=safe_next(request.query_params.get("next") or "/admin/groups"),
    )


@admin_only
async def group_delete(request: Request) -> Response:
    """Delete a group and its grants."""
    data = await read_form(request)
    group = _group_or_404(request)
    back = safe_next(str(data.get("next", "")) or "/admin/groups")
    try:
        delete_group(admin_context(request), group.id, actor=request.state.user)
    except Refused as refused:
        return _redirect(with_query(back, problem=refused.code))
    return _redirect(with_query(back, notice="group_deleted"))


@admin_only
async def group_save(request: Request) -> Response:
    """Save a group's label."""
    group = _group_or_404(request)
    data = await read_form(request)
    try:
        set_group_label(
            admin_context(request), group.id, str(data.get("label", "")), actor=request.state.user
        )
    except ValidationFailed as failed:
        return _group_page(request, group, failed.errors, 400)
    except Refused as refused:
        return _redirect(with_query("/admin/groups", problem=refused.code))
    return _redirect(f"/admin/groups/{group.id}?notice=saved")


@admin_only
async def list_roles(request: Request) -> Response:
    """Every role, with how many grants use each."""
    store = admin_context(request).store
    roles = store.list_roles()
    return render(
        request,
        "roles/list.html",
        roles=roles,
        in_use={r.id: store.role_in_use(r.id) for r in roles},
    )


def _role_page(
    request: Request,
    role: Role,
    *,
    name: str,
    chosen: set[str],
    version: int,
    errors: dict[str, str],
    status: int,
) -> Response:
    return render(
        request,
        "roles/edit.html",
        status_code=status,
        role=role,
        name=name,
        chosen=chosen,
        version=version,
        errors=errors,
        permissions=PERMISSIONS,
        tools=TOOLS_BY_PERMISSION,
        writes=WRITE_PERMISSIONS,
        in_use=admin_context(request).store.role_in_use(role.id),
    )


@admin_only
async def role_detail(request: Request) -> Response:
    """A role: read-only when built-in, editable otherwise."""
    role = _role_or_404(request)
    return _role_page(
        request,
        role,
        name=role.name,
        chosen=set(role.permissions),
        version=role.version,
        errors={},
        status=200,
    )


@admin_only
async def role_save(request: Request) -> Response:
    """Save a custom role."""
    role = _role_or_404(request)
    data = await read_form(request)
    name = str(data.get("name", ""))
    chosen = [str(p) for p in data.getlist("permissions")]
    version = form_int(data.get("version")) or 0
    try:
        save_role(
            admin_context(request),
            role.id,
            name=name,
            permissions=chosen,
            version=version,
            actor=request.state.user,
        )
    except ValidationFailed as failed:
        return _role_page(
            request,
            role,
            name=name,
            chosen=set(chosen),
            version=version,
            errors=failed.errors,
            status=400,
        )
    except StaleEdit as stale:
        return _role_page(
            request,
            role,
            name=name,
            chosen=set(chosen),
            version=version,
            errors={"_stale": str(stale)},
            status=409,
        )
    except Refused as refused:
        return _redirect(with_query(f"/admin/roles/{role.id}", problem=refused.code))
    return _redirect(f"/admin/roles/{role.id}?notice=saved")


@admin_only
async def role_clone(request: Request) -> Response:
    """Copy a role into a new custom role and open it."""
    role = _role_or_404(request)
    await read_form(request)
    try:
        copy = clone_role(admin_context(request), role.id, actor=request.state.user)
    except Refused as refused:
        return _redirect(with_query("/admin/roles", problem=refused.code))
    return _redirect(f"/admin/roles/{copy.id}?notice=saved")


@admin_only
async def role_delete(request: Request) -> Response:
    """Delete a custom role nobody uses."""
    role = _role_or_404(request)
    await read_form(request)
    try:
        remove_role(admin_context(request), role.id, actor=request.state.user)
    except Refused as refused:
        return _redirect(with_query(f"/admin/roles/{role.id}", problem=refused.code))
    return _redirect("/admin/roles?notice=deleted")


routes = [
    Route("/groups", list_groups, methods=["GET"]),
    Route("/groups/{id:id}", group_detail, methods=["GET"]),
    Route("/groups/{id:id}", group_save, methods=["POST"]),
    Route("/groups/{id:id}/delete", group_delete_confirm, methods=["GET"]),
    Route("/groups/{id:id}/delete", group_delete, methods=["POST"]),
    Route("/roles", list_roles, methods=["GET"]),
    Route("/roles/{id:id}", role_detail, methods=["GET"]),
    Route("/roles/{id:id}", role_save, methods=["POST"]),
    Route("/roles/{id:id}/clone", role_clone, methods=["POST"]),
    Route("/roles/{id:id}/delete", role_delete, methods=["POST"]),
]
