"""The one wrapper every tool call passes through.

ThreadedFastMCP runs the tool on a worker thread; there, the guard works out who
is calling and which connection they mean, asks access.decide() whether the
tool's permission is held, installs the route the connection registry will use,
runs the tool and, in team mode, records the call in the audit table. A refusal is
returned as the tool's result (and audited); the tool body never runs.

Outside team mode (stdio) there is no settings store, the caller is the local
operator, the only connection is "default", and nothing is audited.

check_tool_coverage() is called at startup. A tool registered without the guard,
or without a permission, stops the server rather than shipping unprotected.
"""

from __future__ import annotations

import functools
import inspect
import logging
import time
from collections.abc import Callable
from typing import Any, TypeVar, cast

from .access import decide, visible_connections
from .identity import IdentityError, current_caller
from .permissions import TOOL_PERMISSIONS, UNSCOPED_TOOLS, unmapped_tools
from .routing import Route, RouteError, resolve_route, use_route
from .store import get_store, is_global_read_only
from .store.models import Connection
from .utils.basic_source import record_to_lines, source_hash, source_to_record

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., dict[str, Any]])

LOCAL_CONNECTION_NAME = "default"
_GUARD_MARK = "__u2_guarded__"


class GuardError(Exception):
    """Raised at startup when a tool would be served without an access check."""

    pass


class _Refused(Exception):
    """A refusal whose message is returned to the caller as the tool's error."""

    pass


def _route_for(permission: str, requested: str | None) -> Route | None:
    """Decide a call and return its route; None means run as the local operator.

    Raises:
        _Refused: With the message to show the caller
    """
    store = get_store()
    if store is None:
        if requested not in (None, LOCAL_CONNECTION_NAME):
            raise _Refused(f"unknown connection '{requested}'")
        return None

    try:
        caller = current_caller()
    except IdentityError as exc:
        raise _Refused(str(exc)) from exc
    if caller.user_id is None:
        raise _Refused("this request is not signed in")

    global_read_only = is_global_read_only()
    name = requested
    if name is None:
        names = [
            visible.connection.name
            for visible in visible_connections(
                store, caller.user_id, global_read_only=global_read_only
            )
        ]
        if not names:
            raise _Refused("you have no connections; ask an admin")
        if len(names) > 1:
            raise _Refused(f"say which connection to use: {', '.join(names)}")
        name = names[0]

    decision = decide(store, caller.user_id, name, permission, global_read_only=global_read_only)
    if not decision.allowed:
        raise _Refused(decision.reason)
    try:
        return resolve_route(store, decision)
    except RouteError as exc:
        raise _Refused(str(exc)) from exc


def summarize_parameters(params: dict[str, Any]) -> dict[str, Any]:
    """Return tool parameters as they may be audited: BASIC source becomes a summary.

    Program source is the business logic itself, so the audit table never keeps
    it. Its size and the hash it is stored with tie the row to a read_program result.
    Secret-named parameters are redacted by Store.add_audit.
    """
    source = params.get("source")
    if not isinstance(source, str):
        return params
    summary = {
        "chars": len(source),
        "lines": len(record_to_lines(source_to_record(source))),
        "sha256": source_hash(source),
    }
    return {**params, "source": summary}


def _record(
    tool_name: str,
    params: dict[str, Any],
    result: Any,
    error: str | None,
    duration_ms: float,
    route: Route | None,
) -> None:
    """Write one tool call to the audit table, in team mode."""
    store = get_store()
    if store is None:
        return
    try:
        try:
            caller = current_caller()
        except IdentityError:
            caller = None
        connection: Connection | None
        if route is not None:
            connection = route.connection
        else:
            requested = params.get("connection")
            connection = store.get_connection_by_name(requested) if requested else None
        refused = isinstance(result, dict) and "error" in result
        store.add_audit(
            kind="tool",
            action=tool_name,
            outcome="error" if error or refused else "ok",
            actor_user_id=caller.user_id if caller else None,
            actor_label=caller.display_name if caller else None,
            connection_id=connection.id if connection else None,
            params=summarize_parameters(params),
            duration_ms=duration_ms,
        )
    except Exception as exc:  # noqa: BLE001 - auditing must not break the call it records
        logger.warning(f"Could not write the audit row for {tool_name}: {exc}")


def guarded() -> Callable[[F], F]:
    """Put a tool behind the access check for its permission in TOOL_PERMISSIONS.

    Place directly under @mcp.tool(). A scoped tool must accept `connection: str |
    None = None`; the guard reads it, and the tool body may ignore it. A tool in
    UNSCOPED_TOOLS (list_connections) is only audited.

    Raises:
        ValueError: At import, if the tool has no permission or no connection argument
    """

    def decorate(fn: F) -> F:
        name = fn.__name__
        permission = TOOL_PERMISSIONS.get(name)
        unscoped = name in UNSCOPED_TOOLS
        if permission is None and not unscoped:
            raise ValueError(f"{name} has no entry in permissions.TOOL_PERMISSIONS")
        signature = inspect.signature(fn)
        if not unscoped and "connection" not in signature.parameters:
            raise ValueError(f"{name} must accept a 'connection' argument to be guarded")

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> dict[str, Any]:
            params = dict(signature.bind_partial(*args, **kwargs).arguments)
            started = time.monotonic()
            route: Route | None = None
            result: Any = None
            error: str | None = None
            try:
                if permission is not None:
                    try:
                        route = _route_for(permission, params.get("connection"))
                    except _Refused as refusal:
                        result = {"error": str(refusal)}
                        return cast(dict[str, Any], result)
                if route is None:
                    result = fn(*args, **kwargs)
                else:
                    with use_route(route):
                        result = fn(*args, **kwargs)
                return cast(dict[str, Any], result)
            except Exception as exc:
                error = str(exc)
                raise
            finally:
                duration_ms = (time.monotonic() - started) * 1000
                _record(name, params, result, error, duration_ms, route)

        setattr(wrapper, _GUARD_MARK, True)
        return cast(F, wrapper)

    return decorate


def check_tool_coverage(mcp_instance: Any) -> None:
    """Refuse to serve any tool that lacks a permission or the guard.

    Args:
        mcp_instance: A FastMCP instance with its tools registered

    Raises:
        GuardError: Naming every offending tool
    """
    tools = mcp_instance._tool_manager._tools
    problems = [f"{name} has no permission" for name in unmapped_tools(tools)]
    problems += [
        f"{name} is not guarded"
        for name, tool in sorted(tools.items())
        if not getattr(tool.fn, _GUARD_MARK, False)
    ]
    if problems:
        raise GuardError("Refusing to serve tools without an access check: " + "; ".join(problems))
