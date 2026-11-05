"""Who is calling: the authenticated person behind an MCP request.

Signing in to this server and being known to the database are two different
things. Without the second, an operator could prove who they were to the MCP server
and every query would still arrive at Universe under one shared account, with an
audit trail that recorded a per-process session id rather than a name.

This module carries the caller through a request so the rest of the server can
answer "who asked for this?" -- for the audit trail, and for choosing which
database credentials to use.
"""

from __future__ import annotations

import contextlib
import contextvars
import logging
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .store.models import User

logger = logging.getLogger(__name__)


class IdentityError(Exception):
    """Raised when the caller of an authenticated request cannot be identified."""

    pass


@dataclass(frozen=True)
class CallerIdentity:
    """The person or client behind the current request.

    Attributes:
        subject: Stable identifier from the identity provider
        email: Email address, when the provider supplied one
        name: Human-readable name, when the provider supplied one
        client_id: The OAuth client that presented the token
        scopes: Scopes granted to this caller
        is_authenticated: False for local stdio use, where no OAuth takes place
        user_id: The settings-database user, in team mode; None otherwise
        auth_method: How the caller proved who they are: "oauth", "token",
            "local" or "stdio"
    """

    subject: str
    email: str | None = None
    name: str | None = None
    client_id: str | None = None
    scopes: tuple[str, ...] = ()
    is_authenticated: bool = True
    user_id: int | None = None
    auth_method: str = "oauth"
    claims: dict[str, Any] = field(default_factory=dict, compare=False)

    @property
    def identity_key(self) -> str:
        """Return the key used to keep one caller's resources apart from another's."""
        return self.subject

    @property
    def display_name(self) -> str:
        """Return the most human-readable label available for this caller."""
        return self.name or self.email or self.subject


# Stdio mode has no OAuth: the caller is whoever started the process.
LOCAL_CALLER = CallerIdentity(
    subject="local",
    name="local operator",
    is_authenticated=False,
    auth_method="stdio",
)

# Set by the HTTP server, which knows how to turn a bearer token into a person.
_identity_resolver: Callable[[], CallerIdentity | None] | None = None

# Set for the duration of one request, or by tests.
_caller_var: contextvars.ContextVar[CallerIdentity | None] = contextvars.ContextVar(
    "u2_caller", default=None
)


def set_identity_resolver(resolver: Callable[[], CallerIdentity | None] | None) -> None:
    """Install the function that identifies the caller of the current request.

    Args:
        resolver: Returns the authenticated caller, or None when there is none.
            Pass None to remove the resolver.
    """
    global _identity_resolver
    _identity_resolver = resolver


def current_caller() -> CallerIdentity:
    """Return the caller behind the current request.

    Where no resolver is installed there is no authentication in play -- stdio
    mode -- and the caller is the local operator. Where a resolver *is* installed,
    the server is running authenticated, and a failure to identify the caller is
    refused rather than downgraded: falling back to the local operator would let
    someone launder their identity out of the audit trail by making resolution
    fail, and would hand them whatever the unauthenticated path is allowed.

    Returns:
        The current CallerIdentity, never None

    Raises:
        IdentityError: If authentication is in force and the caller cannot be named
    """
    scoped = _caller_var.get()
    if scoped is not None:
        return scoped

    if _identity_resolver is None:
        return LOCAL_CALLER

    try:
        resolved = _identity_resolver()
    except Exception as exc:
        logger.error(f"Could not identify the caller of an authenticated request: {exc}")
        raise IdentityError("The caller of this request could not be identified") from exc

    if resolved is None:
        logger.error("An authenticated request presented a token that names no known user")
        raise IdentityError("The caller of this request could not be identified")

    return resolved


def current_access_token() -> Any | None:
    """Return the access token verified for the request carrying the current message.

    The MCP SDK starts each session's server task inside the request that opened
    the session, so the SDK's own auth_context.get_access_token() keeps returning
    that first request's token for every later message in the session. Reading it
    would let a call made with Bob's token run as Alice, and would fail every call
    once the opening token expired, whatever fresh token the client now sends.

    The SDK does set a per-message request context whose request is the HTTP
    request that delivered the message; its "user" is what the bearer-auth
    middleware verified for that request. That is the token to trust.

    Returns:
        The current request's AccessToken; the auth context's token only when no
        message is being handled; None when the current request carries none
    """
    from mcp.server.auth.middleware import auth_context
    from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
    from mcp.server.lowlevel.server import request_ctx

    message = request_ctx.get(None)
    request = message.request if message is not None else None
    if request is None:
        return auth_context.get_access_token()
    # A message that came over HTTP is judged by its own request alone: falling
    # back to the auth context here would bring the opening request's token back.
    scope = getattr(request, "scope", None) or {}
    user = scope.get("user")
    return user.access_token if isinstance(user, AuthenticatedUser) else None


@contextlib.contextmanager
def use_caller(caller: CallerIdentity) -> Iterator[CallerIdentity]:
    """Treat the given identity as the caller for the duration of the block.

    Args:
        caller: The identity to install

    Yields:
        The installed identity
    """
    token = _caller_var.set(caller)
    try:
        yield caller
    finally:
        _caller_var.reset(token)


def caller_for_user(
    user: User, *, auth_method: str, client_id: str | None = None
) -> CallerIdentity:
    """Build the caller for a settings-database user.

    Args:
        user: The user the request was authenticated as
        auth_method: "oauth", "token" or "local"
        client_id: The OAuth client, when there is one

    Returns:
        The caller, carrying the user's id for access decisions
    """
    subject = user.sso_subject or f"local:{user.username}"
    return CallerIdentity(
        subject=subject,
        email=user.email,
        name=user.display_name,
        client_id=client_id,
        is_authenticated=True,
        user_id=user.id,
        auth_method=auth_method,
    )
