"""Personal access tokens, for MCP clients that cannot do a browser sign-in.

A token proves who is calling and nothing more. What that person may do is
decided afresh on every call (access.py), so changing someone's role never
requires reissuing their token.

Only a SHA-256 hash is stored. The tokens are 256 bits of randomness, so a fast
hash is the right tool: there is nothing to brute-force, and verifying must be
cheap because it happens on every request.

An SSO user's token stops working when that user has not signed in through SSO
for a while. Without that rule, someone IT disabled -- or removed from a group --
would keep their access through a token until it expired, because tokens never
pass through the identity provider. Signing in again refreshes both their
standing and their group membership.
"""

from __future__ import annotations

import hashlib
import secrets

from .store.models import TokenRecord, User
from .store.repo import Store

TOKEN_PREFIX = "u2pat_"
DEFAULT_LIFETIME_DAYS = 90
# A hard ceiling, with or without an admin cap: far-future expiries overflow dates.
MAX_LIFETIME_DAYS = 3650
DEFAULT_FRESHNESS_DAYS = 30
_TOUCH_INTERVAL_SECONDS = 60.0
_DAY_SECONDS = 86400.0


class TokenRejected(Exception):
    """Raised when a presented token cannot be used. The message is safe to show."""

    pass


def generate_token() -> str:
    """Return a new random token: the prefix plus 43 url-safe characters."""
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Return the hex SHA-256 of a token, the only form that is stored."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def looks_like_token(value: str) -> bool:
    """Return whether a bearer value is a personal access token rather than OAuth."""
    return value.startswith(TOKEN_PREFIX)


def create_token(
    store: Store,
    user_id: int,
    name: str,
    *,
    lifetime_days: int = DEFAULT_LIFETIME_DAYS,
    max_lifetime_days: int | None = None,
) -> tuple[str, TokenRecord]:
    """Create a token for a user.

    Args:
        store: The settings database
        user_id: Owner of the token
        name: A label the owner chose, such as "work laptop"
        lifetime_days: How long the token lasts
        max_lifetime_days: The admin's cap, if any

    Returns:
        The token (show it once, never store it) and its stored record

    Raises:
        ValueError: If the lifetime is not positive or exceeds the cap or MAX_LIFETIME_DAYS
    """
    if lifetime_days < 1:
        raise ValueError("A token must last at least 1 day")
    cap = (
        MAX_LIFETIME_DAYS
        if max_lifetime_days is None
        else min(max_lifetime_days, MAX_LIFETIME_DAYS)
    )
    if lifetime_days > cap:
        raise ValueError(f"Tokens may last at most {cap} days")
    token = generate_token()
    record = store.add_token(
        user_id=user_id,
        name=name,
        token_hash=hash_token(token),
        expires_at=store.clock() + lifetime_days * _DAY_SECONDS,
    )
    return token, record


def is_fresh(user: User, *, now: float, freshness_days: int) -> bool:
    """Whether a user's tokens may be used now.

    Always true for local users; for SSO users, only within freshness_days of
    their last company sign-in.
    """
    if user.kind != "sso":
        return True
    last = user.last_sso_login_at
    return last is not None and now - last <= freshness_days * _DAY_SECONDS


def fresh_until(user: User, *, freshness_days: int) -> float | None:
    """When an SSO user's tokens pause without another sign-in; None for local users."""
    if user.kind != "sso" or user.last_sso_login_at is None:
        return None
    return user.last_sso_login_at + freshness_days * _DAY_SECONDS


def verify_token(
    store: Store,
    token: str,
    *,
    freshness_days: int = DEFAULT_FRESHNESS_DAYS,
    ip: str | None = None,
) -> tuple[User, TokenRecord]:
    """Check a presented token and return its owner.

    Args:
        store: The settings database
        token: The bearer value presented
        freshness_days: How recently an SSO owner must have signed in
        ip: The caller's address, recorded as last-used

    Returns:
        The token's owner and the token record

    Raises:
        TokenRejected: With a message safe to show the caller
    """
    if not looks_like_token(token):
        raise TokenRejected("not a personal access token")

    record = store.get_token_by_hash(hash_token(token))
    if record is None:
        raise TokenRejected("unknown token")

    now = store.clock()
    if record.revoked_at is not None:
        raise TokenRejected("token revoked")
    if now >= record.expires_at:
        raise TokenRejected("token expired")

    user = store.get_user(record.user_id)
    if user is None or user.disabled:
        raise TokenRejected("account disabled")

    if not is_fresh(user, now=now, freshness_days=freshness_days):
        raise TokenRejected("sign in to the admin site to reactivate your tokens")

    if record.last_used_at is None or now - record.last_used_at >= _TOUCH_INTERVAL_SECONDS:
        store.touch_token(record.id, at=now, ip=ip)

    return user, record


def revoke(store: Store, token_id: int) -> None:
    """Revoke a token immediately."""
    store.revoke_token(token_id, at=store.clock())
