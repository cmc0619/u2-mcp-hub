"""Connections: list, add, edit, test, live sessions and delete."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager

import anyio
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from ..connection_check import CheckResult
from ..store.models import Connection
from ..store.repo import StaleEdit, StoreError
from .routes_grants import grant_editor
from .security import admin_only, read_form
from .services import (
    ConnectionForm,
    ValidationFailed,
    check_connection_form,
    delete_connection,
    disconnect_connection,
    save_connection,
    u2_logins_on_connection,
)
from .templating import admin_context, render

Page = Callable[[ConnectionForm, dict[str, str], CheckResult | None, int], Response]


def password_hint(connection: Connection | None) -> str:
    """Explain what a blank password box means on this form."""
    if connection is not None and connection.has_shared_password:
        return "Leave blank to keep the saved password."
    return ""


async def connection_submission(
    request: Request,
    *,
    connection_id: int | None,
    page: Page,
    on_saved: Callable[[Connection], Response],
) -> Response:
    """Handle a connection form POST: Test (action=test) or Save.

    Used by the Connections pages and the setup wizard alike, so both behave the
    same way and the wizard has no logic of its own.
    """
    ctx = admin_context(request)
    data = await read_form(request)
    form = ConnectionForm.from_form({key: str(value) for key, value in data.items()})

    if data.get("action") == "test":
        try:
            result = await anyio.to_thread.run_sync(
                lambda: check_connection_form(ctx, form, connection_id=connection_id)
            )
            errors: dict[str, str] = {}
        except ValidationFailed as failed:
            result, errors = None, failed.errors
        if request.headers.get("HX-Request"):
            return render(
                request,
                "partials/test_result.html",
                result=result,
                test_errors=list(errors.values()),
            )
        return page(form, errors, result, 200 if not errors else 400)

    try:
        saved = save_connection(
            ctx,
            form,
            actor=request.state.user,
            connection_id=connection_id,
        )
    except ValidationFailed as failed:
        return page(form, failed.errors, None, 400)
    except StaleEdit as stale:
        return page(form, {"_stale": str(stale)}, None, 409)
    except StoreError as exc:
        raise HTTPException(404, str(exc)) from exc
    return on_saved(saved)


@contextmanager
def _gone_is_404() -> Iterator[None]:
    """Turn "the connection was deleted meanwhile" from a service into a 404."""
    try:
        yield
    except StoreError as exc:
        raise HTTPException(404, str(exc)) from exc


def _connection_or_404(request: Request) -> Connection:
    connection = admin_context(request).store.get_connection(request.path_params["id"])
    if connection is None:
        raise HTTPException(404, "There is no such connection.")
    return connection


@admin_only
async def list_connections(request: Request) -> Response:
    """All connections with their settings and live session counts."""
    ctx = admin_context(request)
    connections = ctx.store.list_connections()
    registry = ctx.registry()
    sessions = {c.id: len(set(registry.sessions_for_connection(c.id))) for c in connections}
    return render(request, "connections/list.html", connections=connections, sessions=sessions)


def _edit_page(request: Request, connection: Connection | None) -> Page:
    def page(
        form: ConnectionForm, errors: dict[str, str], result: CheckResult | None, status: int
    ) -> Response:
        ctx = admin_context(request)
        sessions = (
            sorted(set(ctx.registry().sessions_for_connection(connection.id))) if connection else []
        )
        grants = (
            grant_editor(
                ctx, return_to=f"/admin/connections/{connection.id}", connection=connection
            )
            if connection
            else {}
        )
        return render(
            request,
            "connections/edit.html",
            status_code=status,
            connection=connection,
            form=form,
            errors=errors,
            result=result,
            test_errors=[],
            sessions=sessions,
            action_url=(
                f"/admin/connections/{connection.id}" if connection else "/admin/connections/new"
            ),
            submit_label="Save" if connection else "Add connection",
            password_hint=password_hint(connection),
            u2_logins=u2_logins_on_connection(ctx, connection) if connection else [],
            u2_logins_by_connection=False,
            u2_logins_return_to=f"/admin/connections/{connection.id}" if connection else "",
            **grants,
        )

    return page


def _saved(connection: Connection) -> Response:
    return RedirectResponse(f"/admin/connections/{connection.id}?notice=saved", status_code=303)


@admin_only
async def new_connection_form(request: Request) -> Response:
    """An empty connection form."""
    return _edit_page(request, None)(ConnectionForm(), {}, None, 200)


@admin_only
async def new_connection(request: Request) -> Response:
    """Test or save a new connection."""
    return await connection_submission(
        request,
        connection_id=None,
        page=_edit_page(request, None),
        on_saved=_saved,
    )


@admin_only
async def edit_connection_form(request: Request) -> Response:
    """A saved connection's form and live sessions."""
    connection = _connection_or_404(request)
    return _edit_page(request, connection)(
        ConnectionForm.from_connection(connection), {}, None, 200
    )


@admin_only
async def edit_connection(request: Request) -> Response:
    """Test or save changes to a connection."""
    connection = _connection_or_404(request)
    return await connection_submission(
        request,
        connection_id=connection.id,
        page=_edit_page(request, connection),
        on_saved=_saved,
    )


@admin_only
async def disconnect(request: Request) -> Response:
    """Close every live session on the connection."""
    connection = _connection_or_404(request)
    await read_form(request)
    with _gone_is_404():
        disconnect_connection(admin_context(request), connection.id, actor=request.state.user)
    return RedirectResponse(
        f"/admin/connections/{connection.id}?notice=disconnected", status_code=303
    )


@admin_only
async def delete_form(request: Request) -> Response:
    """Ask before deleting."""
    return render(request, "connections/delete.html", connection=_connection_or_404(request))


@admin_only
async def delete(request: Request) -> Response:
    """Delete the connection, its grants, sessions and notes."""
    connection = _connection_or_404(request)
    await read_form(request)
    with _gone_is_404():
        delete_connection(admin_context(request), connection.id, actor=request.state.user)
    return RedirectResponse("/admin/connections?notice=deleted", status_code=303)


routes = [
    Route("/connections", list_connections, methods=["GET"]),
    Route("/connections/new", new_connection_form, methods=["GET"]),
    Route("/connections/new", new_connection, methods=["POST"]),
    Route("/connections/{id:id}", edit_connection_form, methods=["GET"]),
    Route("/connections/{id:id}", edit_connection, methods=["POST"]),
    Route("/connections/{id:id}/disconnect", disconnect, methods=["POST"]),
    Route("/connections/{id:id}/delete", delete_form, methods=["GET"]),
    Route("/connections/{id:id}/delete", delete, methods=["POST"]),
]
