"""The grants editor: one component on the connection, user and group pages."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from starlette.datastructures import FormData
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from ..store.models import Connection, Group, Role, User
from .context import AdminContext
from .ids import parse_id
from .problems import Refused, with_query
from .security import admin_only, read_form, safe_next
from .services import EVERYONE_WARNING, delete_grant, grant_rows, save_grant, update_grant
from .templating import admin_context


@dataclass(frozen=True)
class GrantEditor:
    """What the grants partial needs besides the rows.

    A fixed connection hides the connection picker; a fixed subject hides the
    "who" pickers. return_to is where every form on the editor comes back to.
    """

    return_to: str
    connection: Connection | None
    subject_type: str | None
    subject_id: int | None
    roles: list[Role]
    users: list[User]
    groups: list[Group]
    connections: list[Connection]


def grant_editor(
    ctx: AdminContext,
    *,
    return_to: str,
    connection: Connection | None = None,
    subject_type: str | None = None,
    subject_id: int | None = None,
) -> dict[str, Any]:
    """Template values for partials/grants_editor.html."""
    rows = (
        grant_rows(ctx, connection_id=connection.id)
        if connection is not None
        else grant_rows(ctx, subject_type=subject_type, subject_id=subject_id)
    )
    editor = GrantEditor(
        return_to=return_to,
        connection=connection,
        subject_type=subject_type,
        subject_id=subject_id,
        roles=ctx.store.list_roles(),
        users=ctx.store.list_users(disabled=False),
        groups=ctx.store.list_groups(),
        connections=ctx.store.list_connections(),
    )
    return {"grants": rows, "editor": editor, "everyone_warning": EVERYONE_WARNING}


def form_int(value: object) -> int | None:
    """A submitted id as an int, or None."""
    return parse_id(value)


def _back(data: FormData) -> str:
    return safe_next(str(data.get("return_to", "")))


def _done(back: str, refused: Refused | None = None) -> Response:
    target = with_query(back, problem=refused.code) if refused else with_query(back, notice="saved")
    return RedirectResponse(target, status_code=303)


@admin_only
async def add(request: Request) -> Response:
    """Create a grant from the editor's add form."""
    data = await read_form(request)
    subject_type = str(data.get("subject_type", ""))
    subject_id = form_int(
        {"user": data.get("user_id"), "group": data.get("group_id")}.get(subject_type)
    )
    try:
        save_grant(
            admin_context(request),
            connection_id=form_int(data.get("connection_id")) or 0,
            subject_type=subject_type,
            subject_id=subject_id,
            role_id=form_int(data.get("role_id")) or 0,
            actor=request.state.user,
        )
    except Refused as refused:
        return _done(_back(data), refused)
    return _done(_back(data))


@admin_only
async def change(request: Request) -> Response:
    """Change one grant's role."""
    data = await read_form(request)
    try:
        update_grant(
            admin_context(request),
            request.path_params["id"],
            role_id=form_int(data.get("role_id")) or 0,
            actor=request.state.user,
        )
    except Refused as refused:
        return _done(_back(data), refused)
    return _done(_back(data))


@admin_only
async def remove(request: Request) -> Response:
    """Remove one grant."""
    data = await read_form(request)
    try:
        delete_grant(admin_context(request), request.path_params["id"], actor=request.state.user)
    except Refused as refused:
        return _done(_back(data), refused)
    return _done(_back(data))


routes = [
    Route("/grants", add, methods=["POST"]),
    Route("/grants/{id:id}", change, methods=["POST"]),
    Route("/grants/{id:id}/delete", remove, methods=["POST"]),
]
