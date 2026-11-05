"""What every admin-site handler and service needs, passed explicitly."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..auth.oidc_client import HttpFactory, default_http
from ..config import U2Config
from ..connection_check import CheckResult, check_connection
from ..credentials import U2Credentials
from ..registry import ConnectionRegistry
from ..store.models import Connection
from ..store.repo import Store

if TYPE_CHECKING:
    from .security import RateLimiter


# Starting company sign-in is anonymous, so it is limited per address -- but a
# whole office can share one NAT address, and the provider guards the passwords.
SSO_START_FACTOR = 20


@dataclass
class AdminContext:
    """The admin site's dependencies.

    Attributes:
        store: The settings database
        config: Server configuration
        registry: Returns the live connection registry (created lazily by the server)
        check: Tests a connection; replaced in tests
        limiter: Sign-in and password-check rate limiter, built from
            U2_ADMIN_SIGNIN_LIMIT when the context is created
        sso_start_limiter: Per-address limit on starting company sign-in, at
            SSO_START_FACTOR times U2_ADMIN_SIGNIN_LIMIT (0 still means off)
        http: Makes the HTTP client for identity providers; replaced in tests
        mcp_oauth: Whether VS Code's OAuth sign-in (the MCP OAuth bridge) was built at startup
        oauth_storage: The MCP OAuth bridge's token store, or None without the bridge.
            Deleting a person revokes the tokens it issued them.
    """

    store: Store
    config: U2Config
    registry: Callable[[], ConnectionRegistry]
    check: Callable[[U2Config, Connection, U2Credentials], CheckResult] = check_connection
    http: HttpFactory = default_http
    mcp_oauth: bool = False
    oauth_storage: Any | None = None

    limiter: RateLimiter = field(init=False, repr=False)
    sso_start_limiter: RateLimiter = field(init=False, repr=False)

    def __post_init__(self) -> None:
        from .security import RateLimiter

        self.limiter = RateLimiter(limit=self.config.admin_signin_limit)
        self.sso_start_limiter = RateLimiter(
            limit=self.config.admin_signin_limit * SSO_START_FACTOR
        )
