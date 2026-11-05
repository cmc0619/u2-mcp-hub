"""Authentication in team mode: personal access tokens, OAuth callers and sign-ins.

Three jobs, all about turning a request into a settings-database user:

- PatVerifier lets the MCP SDK's bearer-auth middleware accept personal access
  tokens, with or without an OAuth provider alongside.
- The identity resolver tells the rest of the server which user is calling, so
  access.decide() can answer for them.
- The sign-in handler runs once per completed SSO sign-in: it creates the user on
  first sight, replaces their groups, and restarts their token freshness window.
"""

from __future__ import annotations

import contextvars
import logging
from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from mcp.server.auth.provider import AccessToken

from .auth.idp.base import TokenInfo
from .auth.storage import token_issuer
from .identity import CallerIdentity, caller_for_user, current_access_token
from .proxy import Network, resolve
from .store.models import User
from .store.repo import Store
from .tokens import TokenRejected, hash_token, looks_like_token, verify_token

logger = logging.getLogger(__name__)

# Scopes a personal access token carries. Permissions are decided per call by
# access.py; these only satisfy the transport's required_scopes check.
PAT_SCOPES = ["u2:read", "u2:write"]

_client_ip: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "u2_client_ip", default=None
)


class ClientAddressMiddleware:
    """Resolve the caller's real address and scheme, and record the address.

    Outermost on the app, so the admin allowlist, the sign-in limiter, audit rows,
    https detection and token last-used addresses all see the client behind a
    trusted proxy (U2_TRUSTED_PROXIES), never the proxy. Pure ASGI rather than
    BaseHTTPMiddleware, so the context variable is set in the same task the
    authentication middleware runs in.
    """

    def __init__(self, app: Any, trusted_proxies: Sequence[Network] = ()) -> None:
        self.app = app
        self.trusted = list(trusted_proxies)

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        peer = client[0] if client else None
        address, scheme = resolve(
            peer, scope.get("headers") or [], scope.get("scheme", "http"), self.trusted
        )
        if address != peer or scheme != scope.get("scheme"):
            scope = dict(scope)
            scope["client"] = (address, client[1] if client else 0)
            scope["scheme"] = scheme
        token = _client_ip.set(address)
        try:
            await self.app(scope, receive, send)
        finally:
            _client_ip.reset(token)


class PatVerifier:
    """Accept personal access tokens as MCP bearer tokens.

    Args:
        store: The settings database
        freshness_days: How recently an SSO owner must have signed in
        resource: This server's URL, reported as the token's resource
    """

    def __init__(self, store: Store, *, freshness_days: int, resource: str | None) -> None:
        self._store = store
        self._freshness_days = freshness_days
        self._resource = resource

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return an AccessToken for a valid personal token, otherwise None."""
        if not looks_like_token(token):
            return None
        try:
            _user, record = verify_token(
                self._store, token, freshness_days=self._freshness_days, ip=_client_ip.get()
            )
        except TokenRejected as exc:
            logger.info(f"Personal access token refused: {exc}")
            return None
        return AccessToken(
            token=token,
            client_id=f"pat-{record.id}",
            scopes=list(PAT_SCOPES),
            expires_at=int(record.expires_at),
            resource=self._resource,
            # The SDK lets only the principal that opened an MCP session use it
            # again; the subject makes that principal a person, not a client.
            subject=f"user:{record.user_id}",
        )


def groups_from_claims(claims: dict[str, Any], claim_name: str) -> list[str] | None:
    """Read group membership from identity-provider claims.

    Returns:
        The groups; [] when the provider sends none; None when the provider says
        there are groups but left them out (Microsoft Entra's "group overage")
    """
    value = claims.get(claim_name)
    if value is None:
        claim_sources = claims.get("_claim_names") or {}
        overage = claim_name in claim_sources or bool(claims.get("hasgroups"))
        return None if overage else []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return []


OverageResolver = Callable[[dict[str, Any]], Awaitable[list[str] | None]]


async def groups_for_sign_in(
    claims: dict[str, Any], claim_name: str, resolver: OverageResolver | None
) -> list[str] | None:
    """The groups to record for a sign-in.

    The token's own claim wins. On an overage (None from groups_from_claims) the
    resolver, when configured, is asked. A failing resolver means "unknown", never
    a failed sign-in.
    """
    groups = groups_from_claims(claims, claim_name)
    if groups is None and resolver is not None:
        try:
            groups = await resolver(claims)
        except Exception as exc:  # noqa: BLE001 - a failed lookup must not block sign-in
            logger.warning(f"Looking up an overage user's groups failed: {exc}")
            groups = None
    return groups


MAX_GROUPS = 500
MAX_CLAIM_LENGTH = 256
MAX_SUBJECT_LENGTH = 255


class SignInRefused(Exception):
    """The person completed company sign-in but may not sign in (disabled, or bad subject).

    Attributes:
        reason: "disabled" or "subject_too_long", as audited
    """

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


def _capped_groups(groups: list[str] | None) -> list[str] | None:
    """Keep what a token may write: overlong ids dropped, more than MAX_GROUPS as overage.

    Overlong ids are dropped rather than cut, so two ids sharing a prefix never
    collapse into one group and inherit its grants.
    """
    if groups is None:
        return None
    kept = {g for g in groups if 0 < len(g) <= MAX_CLAIM_LENGTH}
    return None if len(kept) > MAX_GROUPS else sorted(kept)


def record_sign_in(
    store: Store,
    info: TokenInfo,
    groups: list[str] | None,
    *,
    via: str,
    issuer: str,
) -> User:
    """Record a completed company sign-in: the one place for the admin site and MCP.

    A person is the provider's issuer plus its subject: two providers (or a
    provider change) may issue one subject to different people.

    Creates the user on first sight (with no access), replaces their groups (None
    flags them groups-unavailable) and restarts their token freshness window. A
    disabled user is refused before anything about them changes.

    Args:
        store: The settings database
        info: Who signed in, with the validated claims in raw_claims
        groups: From groups_for_sign_in; more than MAX_GROUPS counts as unavailable
        via: "admin" (admin-site sign-in) or "mcp" (an MCP client's OAuth sign-in)
        issuer: The provider's issuer, from the validated ID token (or its discovery)

    Raises:
        SignInRefused: If the user is disabled or the subject is over 255 characters
            (audited as refused; nothing is written to the users table)
    """
    if len(info.subject) > MAX_SUBJECT_LENGTH:
        # Refused, not cut: a cut subject could collide with another person's.
        store.add_audit(
            kind="auth",
            action="sso_sign_in",
            outcome="refused",
            params={"via": via, "reason": "subject_too_long"},
        )
        raise SignInRefused("The subject is too long.", reason="subject_too_long")
    # An email too long to be real is ignored, not cut.
    email = info.email if info.email and len(info.email) <= MAX_CLAIM_LENGTH else None
    name = info.name[:MAX_CLAIM_LENGTH] if info.name else info.name
    groups = _capped_groups(groups)
    known = store.get_sso_user(issuer, info.subject)
    if known is not None and known.disabled:
        store.add_audit(
            kind="auth",
            action="sso_sign_in",
            outcome="refused",
            actor_user_id=known.id,
            actor_label=known.label,
            params={"via": via, "reason": "disabled"},
        )
        raise SignInRefused("This user is disabled.", reason="disabled")
    user = store.get_or_create_sso_user(info.subject, issuer=issuer, email=email, display_name=name)
    store.record_sso_login(user.id, groups)
    store.add_audit(
        kind="auth",
        action="sso_sign_in",
        outcome="ok",
        actor_user_id=user.id,
        actor_label=user.label,
        params={"groups": None if groups is None else len(groups), "via": via},
    )
    return store.get_user(user.id) or user


IssuerSource = str | Callable[[], Awaitable[str]]


def make_sign_in_handler(
    store: Store,
    groups_claim: str,
    resolver: OverageResolver | None = None,
    *,
    issuer: IssuerSource,
) -> Callable[[TokenInfo], Awaitable[None]]:
    """Build the MCP OAuth provider's on_sign_in hook for team mode.

    Args:
        store: The settings database
        groups_claim: Name of the claim that lists groups
        resolver: Looks up groups on an Entra overage (Microsoft Graph), or None
        issuer: The provider's issuer (or a coroutine that discovers it), used when
            the claims carry no validated ID token's iss
    """

    async def on_sign_in(info: TokenInfo) -> None:
        claims = dict(info.raw_claims or {})
        if groups_claim not in claims and groups_claim == "groups" and info.groups is not None:
            claims["groups"] = info.groups
        groups = await groups_for_sign_in(claims, groups_claim, resolver)
        named = claims.get("iss")
        if not isinstance(named, str) or not named:
            named = issuer if isinstance(issuer, str) else await issuer()
            # The bridge keeps these claims on the tokens it issues; with the issuer
            # among them, the identity resolver finds this same person later.
            info.raw_claims = {**(info.raw_claims or {}), "iss": named}
        record_sign_in(store, info, groups, via="mcp", issuer=named)

    return on_sign_in


def make_identity_resolver(
    store: Store, oauth_storage: Any | None
) -> Callable[[], CallerIdentity | None]:
    """Build the resolver that names the settings-database user behind a request.

    Args:
        store: The settings database
        oauth_storage: The OAuth provider's token store, or None in token-only mode
    """

    def resolve() -> CallerIdentity | None:
        access = current_access_token()
        if access is None:
            return None

        if looks_like_token(access.token):
            record = store.get_token_by_hash(hash_token(access.token))
            if record is None or record.revoked_at is not None:
                return None
            user = store.get_user(record.user_id)
            if user is None:
                return None
            return caller_for_user(user, auth_method="token", client_id=access.client_id)

        if oauth_storage is None:
            return None
        stored = oauth_storage.get_access_token(access.token)
        if stored is None:
            return None
        # The person is the token's issuer plus subject.
        user = store.get_sso_user(token_issuer(stored.user_claims), stored.user_subject)
        if user is None:
            # Deleted (or never recorded): a leftover token never brings a person
            # back. Only a fresh company sign-in (record_sign_in) creates users.
            return None
        return caller_for_user(user, auth_method="oauth", client_id=stored.client_id)

    return resolve
