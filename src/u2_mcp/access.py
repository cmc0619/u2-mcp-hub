"""Who may do what, on which connection.

There is exactly one place that answers that question, and both the MCP tools
and the admin UI ask it. Two implementations of a permission rule eventually
disagree, and the disagreement is always found by the person it lets through.

Decisions are made from the settings database on every call. Nothing about a
person's rights is cached in their token or session, so revoking a grant takes
effect on the very next request.

A connection the caller has no grant on is reported exactly as a connection that
does not exist. Telling the two apart would let anyone enumerate the names of
systems they are not allowed to know about.
"""

from __future__ import annotations

from collections.abc import Container
from dataclasses import dataclass, field

from .identity import current_caller
from .permissions import ADMIN_ONLY, ANY_GRANT, WRITE_PERMISSIONS, is_write
from .store import get_store
from .store.models import Connection, Grant, Role
from .store.repo import Store


@dataclass(frozen=True)
class Decision:
    """The answer to "may this person do this here?".

    Attributes:
        allowed: Whether the action may proceed
        reason: Empty when allowed; otherwise the message to show the caller
        connection: The connection, once it is known the caller may see it
        user_id: The caller, on an allowed decision: a per-user connection uses
            their own U2 login, whichever grant (user, group or everyone) let them in
        permissions: Every permission the caller's grants give on the connection
    """

    allowed: bool
    reason: str = ""
    connection: Connection | None = None
    user_id: int | None = None
    permissions: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class VisibleConnection:
    """A connection a caller can use, with what they can do there right now."""

    connection: Connection
    roles: tuple[str, ...]
    permissions: frozenset[str]
    needs_personal_login: bool = False


@dataclass(frozen=True)
class EffectiveAccess:
    """For one connection: each permission a person holds and which grants supply it."""

    connection: Connection
    sources: dict[str, tuple[str, ...]]
    blocked_by_read_only: tuple[str, ...]
    needs_personal_login: bool = False


def _roles_for(store: Store, grants: list[Grant]) -> dict[int, Role]:
    roles: dict[int, Role] = {}
    for grant in grants:
        if grant.role_id not in roles:
            role = store.get_role(grant.role_id)
            if role is not None:
                roles[grant.role_id] = role
    return roles


def _grants_on(store: Store, user_id: int, connection_id: int | None) -> list[Grant]:
    group_ids = store.group_ids_for_user(user_id)
    return store.grants_for(user_id, group_ids, connection_id)


def _capped(permissions: frozenset[str], read_only: bool) -> frozenset[str]:
    return permissions - WRITE_PERMISSIONS if read_only else permissions


def decide(
    store: Store,
    user_id: int,
    connection_name: str,
    permission: str,
    *,
    global_read_only: bool,
) -> Decision:
    """Decide whether a user may exercise a permission on a named connection.

    Args:
        store: The settings database
        user_id: The caller's user id
        connection_name: The connection the caller asked for, as they typed it
        permission: A permission from permissions.py, ANY_GRANT for housekeeping, or
            ADMIN_ONLY for what only an admin with a grant on the connection may do
        global_read_only: The U2_READ_ONLY switch

    Returns:
        The decision, with the exact message to show when refused
    """
    user = store.get_user(user_id)
    if user is None or user.disabled:
        return Decision(allowed=False, reason="account disabled")

    unknown = Decision(allowed=False, reason=f"unknown connection '{connection_name}'")
    connection = store.get_connection_by_name(connection_name)
    if connection is None or not connection.enabled:
        return unknown

    grants = _grants_on(store, user_id, connection.id)
    if not grants:
        return unknown

    roles = _roles_for(store, grants)
    permissions: frozenset[str] = frozenset().union(*(r.permissions for r in roles.values()))
    if permission == ADMIN_ONLY:
        if not user.is_admin:
            return Decision(
                allowed=False,
                reason=f"only an admin can do this on {connection.name}",
                connection=connection,
                permissions=permissions,
            )
    elif permission != ANY_GRANT and permission not in permissions:
        return Decision(
            allowed=False,
            reason=f"you need {permission} on {connection.name}; ask an admin",
            connection=connection,
            permissions=permissions,
        )

    if is_write(permission) and (connection.read_only or global_read_only):
        return Decision(
            allowed=False,
            reason=f"{connection.name} is read-only",
            connection=connection,
            permissions=permissions,
        )

    return Decision(
        allowed=True,
        connection=connection,
        user_id=user_id,
        permissions=permissions,
    )


def needs_personal_login(connection: Connection, login_connection_ids: Container[int]) -> bool:
    """Whether a person must still set their own U2 login on a per-person connection.

    Args:
        connection: The connection
        login_connection_ids: Ids of the connections the person has set a U2 login
            on (Store.list_u2_logins_for_user)

    Returns:
        True on a per_user connection the person has no U2 login on. They set it
        themselves on My access, whatever grant gives them the connection.
    """
    return connection.login_mode == "per_user" and connection.id not in login_connection_ids


def visible_connections(
    store: Store, user_id: int, *, global_read_only: bool
) -> list[VisibleConnection]:
    """List the connections a user can use, with their effective permissions on each.

    Args:
        store: The settings database
        user_id: The user
        global_read_only: The U2_READ_ONLY switch

    Returns:
        Enabled connections the user has any grant on, ordered by name. Disabled
        users see nothing.
    """
    user = store.get_user(user_id)
    if user is None or user.disabled:
        return []

    grants = _grants_on(store, user_id, None)
    roles = _roles_for(store, grants)
    by_connection: dict[int, list[Grant]] = {}
    for grant in grants:
        by_connection.setdefault(grant.connection_id, []).append(grant)

    with_login = {login.connection_id for login in store.list_u2_logins_for_user(user_id)}
    visible = []
    for connection in store.list_connections():
        mine = by_connection.get(connection.id)
        if not connection.enabled or not mine:
            continue
        held = [roles[g.role_id] for g in mine if g.role_id in roles]
        permissions: frozenset[str] = frozenset().union(*(role.permissions for role in held))
        visible.append(
            VisibleConnection(
                connection=connection,
                roles=tuple(sorted({role.name for role in held})),
                permissions=_capped(permissions, connection.read_only or global_read_only),
                needs_personal_login=needs_personal_login(connection, with_login),
            )
        )
    return visible


def effective_access(
    store: Store, user_id: int, *, global_read_only: bool
) -> list[EffectiveAccess]:
    """Explain, per connection, each permission a user holds and which grant gives it.

    This answers "why can't Bob...?" in the admin UI without anyone reading code.

    Args:
        store: The settings database
        user_id: The user
        global_read_only: The U2_READ_ONLY switch

    Returns:
        One entry per connection the user can see, ordered by connection name
    """
    group_labels = {g.id: g.label or g.external_id for g in store.list_groups()}
    grants = _grants_on(store, user_id, None)
    roles = _roles_for(store, grants)
    report = []

    for visible in visible_connections(store, user_id, global_read_only=global_read_only):
        connection = visible.connection
        sources: dict[str, list[str]] = {}
        for grant in grants:
            if grant.connection_id != connection.id or grant.role_id not in roles:
                continue
            role = roles[grant.role_id]
            if grant.subject_type == "user":
                origin = f"user grant ({role.name})"
            elif grant.subject_type == "group":
                label = group_labels.get(grant.subject_id or 0, str(grant.subject_id))
                origin = f"group {label} ({role.name})"
            else:
                origin = f"everyone ({role.name})"
            for permission in role.permissions:
                sources.setdefault(permission, []).append(origin)

        read_only = connection.read_only or global_read_only
        blocked = tuple(sorted(p for p in sources if read_only and p in WRITE_PERMISSIONS))
        report.append(
            EffectiveAccess(
                connection=connection,
                sources={p: tuple(sorted(o)) for p, o in sorted(sources.items())},
                blocked_by_read_only=blocked,
                needs_personal_login=visible.needs_personal_login,
            )
        )
    return report


def caller_is_admin() -> bool:
    """Whether the caller of the current tool call is an admin.

    In stdio there are no admins and no one else: the local operator owns the
    notes in their own database, so they count as one.
    """
    store = get_store()
    if store is None:
        return True
    caller = current_caller()
    if caller.user_id is None:
        return False
    user = store.get_user(caller.user_id)
    return user is not None and user.is_admin and not user.disabled
