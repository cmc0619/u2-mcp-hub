"""Rows of the settings database, as read by the rest of the server.

Secrets never appear on these objects. A Connection says *whether* it has a
shared password; reading the password is a separate, deliberate call on the
Store, so a row can be logged, rendered or compared without leaking it.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Connection:
    """A U2 server and account this deployment can reach."""

    id: int
    name: str
    host: str
    port: int
    service: str
    account: str
    ssl: bool
    login_mode: str  # "shared" or "per_user"
    shared_user: str | None
    has_shared_password: bool
    read_only: bool
    enabled: bool
    version: int = 1


@dataclass(frozen=True)
class User:
    """A person who can sign in, through SSO or with a local password."""

    id: int
    kind: str  # "sso" or "local"
    username: str | None
    sso_subject: str | None
    email: str | None
    display_name: str | None
    is_admin: bool
    disabled: bool
    last_sso_login_at: float | None
    groups_unavailable: bool
    created_at: float
    must_change_password: bool = False
    sso_issuer: str | None = None  # None: from before identities named their issuer

    @property
    def label(self) -> str:
        """Return the most human-readable name available."""
        return self.display_name or self.email or self.username or self.sso_subject or str(self.id)


@dataclass(frozen=True)
class Group:
    """An SSO group, as named by the identity provider's groups claim."""

    id: int
    issuer: str | None
    external_id: str
    label: str | None


@dataclass(frozen=True)
class Role:
    """A named set of permissions."""

    id: int
    name: str
    builtin: bool
    permissions: frozenset[str]
    version: int = 1


@dataclass(frozen=True)
class Grant:
    """A role on one connection, given to a user, a group or everyone."""

    id: int
    connection_id: int
    subject_type: str  # "user", "group" or "everyone"
    subject_id: int | None
    role_id: int


@dataclass(frozen=True)
class U2Login:
    """A person's own U2 login on one per-user connection. The password is not here."""

    user_id: int
    connection_id: int
    u2_user: str
    updated_at: float


@dataclass(frozen=True)
class TokenRecord:
    """A personal access token, as stored: the hash, never the token."""

    id: int
    user_id: int
    name: str
    token_hash: str
    created_at: float
    expires_at: float
    last_used_at: float | None
    last_used_ip: str | None
    revoked_at: float | None


@dataclass(frozen=True)
class AdminSession:
    """A signed-in admin-site session. The id itself is only ever in the cookie."""

    id_hash: str
    user_id: int
    csrf_token: str
    created_at: float
    last_seen_at: float
    ip: str | None
