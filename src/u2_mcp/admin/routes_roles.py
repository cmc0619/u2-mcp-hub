"""Groups (labels and grants) and Roles (built-in read-only; clone, edit, delete)."""

from __future__ import annotations

from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from ..permissions import PERMISSIONS, TOOL_PERMISSIONS, WRITE_PERMISSIONS
from ..store.models import Group, Role
from ..store.repo import StaleEdit
from .problems import Refused, with_query
from .routes_grants import form_int, grant_editor
from .security import admin_only, read_form
from .services import ValidationFailed, clone_role, remove_role, save_role, set_group_label
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


@admin_only
async def list_groups(request: Request) -> Response:
    """Groups seen at sign-in."""
    return render(request, "groups/list.html", groups=admin_context(request).store.list_groups())


def _group_page(request: Request, group: Group, errors: dict[str, str], status: int) -> Response:
    ctx = admin_context(request)
    return render(
        request,
        "groups/detail.html",
        status_code=status,
        group=group,
        errors=errors,
        **grant_editor(
            ctx, return_to=f"/admin/groups/{group.id}", subject_type="group", subject_id=group.id
        ),
    )


@admin_only
async def group_detail(request: Request) -> Response:
    """A group's label and grants."""
    return _group_page(request, _group_or_404(request), {}, 200)


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
    Route("/roles", list_roles, methods=["GET"]),
    Route("/roles/{id:id}", role_detail, methods=["GET"]),
    Route("/roles/{id:id}", role_save, methods=["POST"]),
    Route("/roles/{id:id}/clone", role_clone, methods=["POST"]),
    Route("/roles/{id:id}/delete", role_delete, methods=["POST"]),
]
