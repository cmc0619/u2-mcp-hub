"""The MCP OAuth bridge's adapter for the admin site's company sign-in.

It talks to the provider through the admin site's OidcClient, so both sign-ins
make the same choices: discovery checks, HTTP Basic client authentication when
the provider offers it, and an injectable HTTP client for tests.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any
from urllib.parse import urlencode

from ..oidc_client import OidcClient, OidcError
from .base import AuthenticationError, TokenInfo, TokenResponse


class StoredSsoAdapter:
    """An IdP adapter backed by an OidcClient.

    Args:
        client: The OIDC client for the saved company sign-in
    """

    def __init__(self, client: OidcClient) -> None:
        self.client = client
        self.discovery_url = client.discovery_url
        self.client_id = client.client_id

    async def get_oidc_config(self) -> dict[str, Any]:
        """The checked discovery document's fields (issuer, endpoints)."""
        try:
            return asdict(await self.client.discover())
        except OidcError as exc:
            raise AuthenticationError(str(exc)) from exc

    async def get_authorization_url(
        self,
        redirect_uri: str,
        state: str,
        code_challenge: str | None = None,
        code_challenge_method: str | None = None,
        additional_params: dict[str, str] | None = None,
    ) -> str:
        """The provider URL that starts a sign-in (code flow, with PKCE when given)."""
        config = await self.get_oidc_config()
        params = {
            "response_type": "code",
            "client_id": self.client.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(self.client.scopes),
            "state": state,
        }
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = code_challenge_method or "S256"
        if additional_params:
            params.update(additional_params)
        endpoint = str(config["authorization_endpoint"])
        separator = "&" if "?" in endpoint else "?"
        return f"{endpoint}{separator}{urlencode(params)}"

    async def exchange_code(
        self, code: str, redirect_uri: str, code_verifier: str | None = None
    ) -> TokenResponse:
        """Exchange the callback's code, authenticating as discovery offers."""
        try:
            body = await self.client.token_request(
                await self.client.discover(), code, redirect_uri, code_verifier
            )
        except OidcError as exc:
            raise AuthenticationError(str(exc)) from exc
        access_token = body.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise AuthenticationError("The identity provider sent no access token.")
        return TokenResponse(
            access_token=access_token,
            token_type=str(body.get("token_type", "Bearer")),
            expires_in=body.get("expires_in"),
            refresh_token=body.get("refresh_token"),
            id_token=body.get("id_token"),
            scope=body.get("scope"),
        )

    async def validate_token(self, access_token: str) -> TokenInfo | None:
        """Who the provider says the access token belongs to (its userinfo)."""
        try:
            claims = await self.client.userinfo(access_token)
        except OidcError:
            return None
        if not claims or not isinstance(claims.get("sub"), str) or not claims["sub"]:
            return None
        groups = claims.get("groups")
        return TokenInfo(
            subject=claims["sub"],
            email=claims.get("email"),
            name=claims.get("name"),
            groups=groups if isinstance(groups, list) else None,
            raw_claims=claims,
        )

    async def refresh_token(self, refresh_token: str) -> TokenResponse:
        """Not used: the bridge issues and rotates its own refresh tokens."""
        raise AuthenticationError("Refreshing at the identity provider is not supported.")
