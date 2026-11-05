"""What the identity-provider adapter hands the OAuth bridge."""

from dataclasses import dataclass
from typing import Any


@dataclass
class TokenResponse:
    """Response from token exchange with IdP."""

    access_token: str
    token_type: str
    expires_in: int | None = None
    refresh_token: str | None = None
    id_token: str | None = None
    scope: str | None = None


@dataclass
class TokenInfo:
    """Information about a validated token."""

    subject: str  # User identifier
    email: str | None = None
    name: str | None = None
    groups: list[str] | None = None
    expires_at: int | None = None
    scopes: list[str] | None = None
    raw_claims: dict[str, Any] | None = None


class AuthenticationError(Exception):
    """Raised when authentication with the IdP fails."""

    def __init__(self, message: str, error_code: str | None = None):
        super().__init__(message)
        self.error_code = error_code
