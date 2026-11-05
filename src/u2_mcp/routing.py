"""Which U2 server, and which U2 login, the current tool call uses.

Once access.py has said yes, this module turns that decision into a route: the
connection's address plus the database login to present there. The route is held
in a context variable for the duration of the call, and the connection registry
reads it to hand out the matching session. A tool never chooses its own server.

Synchronous tools run on a worker thread (threaded.py) in a copy of the request's
context, and the guard sets the route inside that thread, so it is visible to
everything the tool calls.
"""

from __future__ import annotations

import contextlib
import contextvars
from collections.abc import Iterator
from dataclasses import dataclass

from .access import Decision
from .config import U2Config
from .credentials import U2Credentials
from .store.crypto import SecretUnreadable
from .store.models import Connection
from .store.repo import Store

# The admin site's saved server address (admin.services.PUBLIC_URL_SETTING). Read
# here directly: importing the admin package from routing would be circular.
PUBLIC_URL_SETTING = "public_url"


class RouteError(Exception):
    """Raised when an allowed call has no usable U2 login. The message is safe to show."""

    pass


@dataclass(frozen=True)
class Route:
    """The connection a call targets and the login it presents there.

    owner_id is set on per-user connections: the person whose own login this is.
    It is part of the key, so two people who type the same U2 user name never
    share a session -- a session opened with one person's password is never handed
    to someone else who merely knows the user name.
    """

    connection: Connection
    credentials: U2Credentials
    owner_id: int | None = None

    @property
    def key(self) -> str:
        """Return the key that keeps one route's session apart from every other."""
        owner = "" if self.owner_id is None else f"u{self.owner_id}:"
        return f"{self.connection.id}:v{self.connection.version}:{owner}{self.credentials.pool_key}"


_route_var: contextvars.ContextVar[Route | None] = contextvars.ContextVar("u2_route", default=None)


def current_route() -> Route | None:
    """Return the route of the call in progress, or None outside team mode."""
    return _route_var.get()


@contextlib.contextmanager
def use_route(route: Route) -> Iterator[Route]:
    """Install a route for the duration of the block."""
    token = _route_var.set(route)
    try:
        yield route
    finally:
        _route_var.reset(token)


def resolve_route(store: Store, decision: Decision) -> Route:
    """Turn an allowed decision into a route.

    Args:
        store: The settings database
        decision: An allowed Decision from access.decide()

    Returns:
        The route for the call

    Raises:
        RouteError: If the connection has no usable login for this caller
    """
    connection = decision.connection
    if connection is None or not decision.allowed:
        raise ValueError("resolve_route needs an allowed decision")

    if connection.login_mode != "shared":
        return _personal_route(store, connection, decision.user_id)

    try:
        password = store.shared_password(connection.id)
    except SecretUnreadable as exc:
        raise RouteError(
            f"the stored U2 password for {connection.name} cannot be read; "
            "ask an admin to re-enter it"
        ) from exc
    if connection.shared_user is None or password is None:
        raise RouteError(f"{connection.name} has no U2 login configured; ask an admin")
    credentials = U2Credentials(
        user=connection.shared_user,
        password=password,
        account=connection.account,
        is_shared=True,
    )
    return Route(connection=connection, credentials=credentials)


def _my_access_link(store: Store) -> str:
    """Return " (<public URL>/admin/me)", or "" when no server address is saved."""
    saved = store.get_setting(PUBLIC_URL_SETTING)
    return f" ({str(saved).rstrip('/')}/admin/me)" if saved else ""


def _personal_route(store: Store, connection: Connection, user_id: int | None) -> Route:
    """The caller's own login on a per-user connection, whatever grant let them in.

    Raises:
        RouteError: If the caller has not set a login there, or it cannot be read
    """
    login = None if user_id is None else store.get_u2_login(user_id, connection.id)
    if user_id is None or login is None:
        raise RouteError(
            f"no U2 login set for you on {connection.name}; "
            f"set it on My access{_my_access_link(store)}"
        )
    try:
        password = store.get_u2_login_password(user_id, connection.id)
    except SecretUnreadable as exc:
        raise RouteError(
            f"your stored U2 password for {connection.name} cannot be read; "
            f"set it again on My access{_my_access_link(store)}"
        ) from exc
    if password is None:  # removed between the two reads
        raise RouteError(
            f"no U2 login set for you on {connection.name}; "
            f"set it on My access{_my_access_link(store)}"
        )
    credentials = U2Credentials(
        user=login.u2_user, password=password, account=connection.account, is_shared=False
    )
    return Route(connection=connection, credentials=credentials, owner_id=user_id)


def config_for(base: U2Config, connection: Connection) -> U2Config:
    """Return a copy of the server configuration pointed at one connection.

    Safety settings (timeouts, blocked commands, row limits) carry over from the
    base. Read-only is the stricter of the server switch and the connection's.
    """
    return base.model_copy(
        update={
            "host": connection.host,
            "port": connection.port,
            "service": connection.service,
            "ssl": connection.ssl,
            "account": connection.account,
            "read_only": base.read_only or connection.read_only,
        }
    )
