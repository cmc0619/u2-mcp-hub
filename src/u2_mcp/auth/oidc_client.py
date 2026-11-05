"""OpenID Connect sign-in: authorization code with PKCE, state and nonce.

The identity provider is believed only through what it signs. The ID token's
signature is checked against the keys the provider publishes (JWKS, found through
discovery), and its issuer, audience, expiry and nonce are checked before any
claim is used. HTTP goes through an injected client factory, so tests can point
it at tests/mocks/oidc_provider.py without a network.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

import httpx
import jwt

HttpFactory = Callable[[], httpx.AsyncClient]
ALGORITHMS = ["RS256"]
LEEWAY_SECONDS = 60
HTTP_TIMEOUT_SECONDS = 10.0
DISCOVERY_SUFFIX = "/.well-known/openid-configuration"


def default_http() -> httpx.AsyncClient:
    """The HTTP client used outside tests."""
    return httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS)


class OidcError(Exception):
    """Company sign-in failed. The message is safe to show an admin."""


@dataclass(frozen=True)
class Discovery:
    """The parts of a provider's discovery document this client uses."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    basic_auth: bool
    userinfo_endpoint: str | None = None


@dataclass(frozen=True)
class PendingLogin:
    """What a sign-in carries from its start to its callback."""

    state: str
    nonce: str
    verifier: str

    @classmethod
    def new(cls) -> PendingLogin:
        """Fresh random state, nonce and PKCE verifier."""
        return cls(secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(48))

    @property
    def challenge(self) -> str:
        """The PKCE S256 code challenge for this verifier."""
        digest = hashlib.sha256(self.verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _error_text(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return f"HTTP {response.status_code}: {response.text[:200]}"
    if isinstance(body, dict):
        return str(body.get("error_description") or body.get("error") or response.status_code)
    return f"HTTP {response.status_code}"


_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
_ENDPOINT_FIELDS = ("authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint")


def _require_https(doc: dict[str, Any]) -> None:
    """Refuse a provider that would send the client secret or keys over plain http.

    A provider on http://localhost or http://127.0.0.1 (a development one) may use http.
    """
    issuer = str(doc["issuer"])
    parts = urlsplit(issuer)
    if parts.scheme == "http" and parts.hostname in _LOOPBACK_HOSTS:
        return
    if parts.scheme != "https":
        raise OidcError(f"The provider's issuer must be https: {issuer}")
    for name in _ENDPOINT_FIELDS:
        value = doc.get(name)
        if value is not None and (not isinstance(value, str) or not value.startswith("https://")):
            raise OidcError(f"The discovery document's {name} must be https.")


class OidcClient:
    """One provider, as configured on the admin site.

    Args:
        discovery_url: The provider's /.well-known/openid-configuration URL
        client_id: This server's client (application) id at the provider
        client_secret: Its secret; None when none is saved
        http: Makes the HTTP client (replaced in tests)
        scopes: Scopes requested; openid is required for an ID token
    """

    def __init__(
        self,
        discovery_url: str,
        client_id: str,
        client_secret: str | None,
        *,
        http: HttpFactory = default_http,
        scopes: tuple[str, ...] = ("openid", "profile", "email"),
    ) -> None:
        self.discovery_url = discovery_url
        self.client_id = client_id
        self.client_secret = client_secret
        self._http = http
        self.scopes = scopes

    async def _get_json(self, client: httpx.AsyncClient, url: str) -> dict[str, Any]:
        try:
            response = await client.get(url)
        except httpx.HTTPError as exc:
            raise OidcError(f"Could not reach the identity provider at {url}: {exc}") from exc
        if response.status_code != 200:
            raise OidcError(f"The identity provider answered {response.status_code} for {url}")
        try:
            data = response.json()
        except ValueError as exc:
            raise OidcError(
                f"The identity provider sent something other than JSON from {url}"
            ) from exc
        if not isinstance(data, dict):
            raise OidcError(f"The identity provider sent an unexpected document from {url}")
        return data

    async def discover(self) -> Discovery:
        """Fetch and check the discovery document.

        Raises:
            OidcError: If it cannot be fetched, lacks an endpoint, or is a
                multi-tenant template (Entra's /common), whose issuer cannot be checked
        """
        async with self._http() as client:
            doc = await self._get_json(client, self.discovery_url)
        names = ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri")
        missing = [name for name in names if not isinstance(doc.get(name), str) or not doc[name]]
        if missing:
            raise OidcError(f"The discovery document lacks {', '.join(missing)}")
        if "{" in doc["issuer"]:
            raise OidcError(
                "The discovery document is a multi-tenant template (its issuer contains "
                "{tenantid}). Use your tenant's own discovery URL."
            )
        _require_https(doc)
        methods = doc.get("token_endpoint_auth_methods_supported") or ["client_secret_basic"]
        return Discovery(
            issuer=doc["issuer"],
            authorization_endpoint=doc["authorization_endpoint"],
            token_endpoint=doc["token_endpoint"],
            jwks_uri=doc["jwks_uri"],
            basic_auth="client_secret_basic" in methods,
            userinfo_endpoint=doc.get("userinfo_endpoint") or None,
        )

    async def authorization_url(self, redirect_uri: str, login: PendingLogin) -> str:
        """The provider URL that starts a sign-in (code flow, PKCE S256, state, nonce)."""
        discovery = await self.discover()
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(self.scopes),
            "state": login.state,
            "nonce": login.nonce,
            "code_challenge": login.challenge,
            "code_challenge_method": "S256",
        }
        separator = "&" if "?" in discovery.authorization_endpoint else "?"
        return f"{discovery.authorization_endpoint}{separator}{urlencode(params)}"

    @staticmethod
    def callback_code(params: Mapping[str, str], login: PendingLogin) -> str:
        """The authorization code from the provider's callback query, once it is trustworthy.

        Args:
            params: The callback's query parameters
            login: The sign-in this callback should answer

        Raises:
            OidcError: If the provider reported an error (such as access_denied), the
                state does not match, or no code came back
        """
        error = params.get("error")
        if error:
            description = params.get("error_description")
            detail = f"{error}: {description}" if description else error
            raise OidcError(f"The identity provider refused the sign-in ({detail}).")
        if not hmac.compare_digest(params.get("state", ""), login.state):
            raise OidcError("The sign-in response does not match the sign-in that was started.")
        code = params.get("code")
        if not code:
            raise OidcError("The identity provider sent no authorization code.")
        return code

    async def sign_in(self, code: str, redirect_uri: str, login: PendingLogin) -> dict[str, Any]:
        """Exchange the callback's code and return the validated ID token's claims.

        Raises:
            OidcError: With the reason, safe to show an admin
        """
        discovery = await self.discover()
        id_token = await self._exchange(discovery, code, redirect_uri, login.verifier)
        return await self._validate(discovery, id_token, nonce=login.nonce)

    async def validate_id_token(self, id_token: str, *, nonce: str | None = None) -> dict[str, Any]:
        """Validate an ID token obtained elsewhere (the MCP OAuth bridge) and return its claims."""
        return await self._validate(await self.discover(), id_token, nonce=nonce)

    async def _exchange(
        self, discovery: Discovery, code: str, redirect_uri: str, verifier: str
    ) -> str:
        body = await self.token_request(discovery, code, redirect_uri, verifier)
        id_token = body.get("id_token")
        if not isinstance(id_token, str) or not id_token:
            raise OidcError(
                "The identity provider sent no ID token. Check that the openid scope is allowed."
            )
        return id_token

    async def token_request(
        self, discovery: Discovery, code: str, redirect_uri: str, verifier: str | None
    ) -> dict[str, Any]:
        """Exchange an authorization code and return the provider's whole token answer.

        The client authenticates the way discovery offers: HTTP Basic when the
        provider lists client_secret_basic (or lists nothing), else form fields.
        Both the admin site and the MCP OAuth bridge exchange codes here.

        Raises:
            OidcError: With the reason, safe to show an admin
        """
        if not self.client_secret:
            raise OidcError("No client secret is saved for company sign-in.")
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
        }
        if verifier:
            data["code_verifier"] = verifier
        options: dict[str, Any] = {}
        if discovery.basic_auth:
            # RFC 6749 2.3.1: form-encode the id and secret before Basic encoding.
            options["auth"] = httpx.BasicAuth(
                quote(self.client_id, safe=""), quote(self.client_secret, safe="")
            )
        else:
            data["client_id"] = self.client_id
            data["client_secret"] = self.client_secret
        async with self._http() as client:
            try:
                response = await client.post(discovery.token_endpoint, data=data, **options)
            except httpx.HTTPError as exc:
                raise OidcError(
                    f"Could not reach the identity provider's token endpoint: {exc}"
                ) from exc
        if response.status_code != 200:
            raise OidcError(f"The identity provider refused the code: {_error_text(response)}")
        try:
            body = response.json()
        except ValueError as exc:
            raise OidcError("The identity provider's token answer was not JSON") from exc
        if not isinstance(body, dict):
            raise OidcError("The identity provider's token answer was not a JSON object")
        return body

    async def userinfo(self, access_token: str) -> dict[str, Any] | None:
        """The provider's userinfo for an access token; None when it refuses or has none."""
        discovery = await self.discover()
        if not discovery.userinfo_endpoint:
            return None
        async with self._http() as client:
            try:
                response = await client.get(
                    discovery.userinfo_endpoint,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
            except httpx.HTTPError:
                return None
        if response.status_code != 200:
            return None
        try:
            body = response.json()
        except ValueError:
            return None
        return body if isinstance(body, dict) else None

    def _decode(self, id_token: str, candidates: list[jwt.PyJWK], issuer: str) -> dict[str, Any]:
        failure: Exception | None = None
        for key in candidates:
            try:
                claims: dict[str, Any] = jwt.decode(
                    id_token,
                    key.key,
                    algorithms=ALGORITHMS,
                    audience=self.client_id,
                    issuer=issuer,
                    leeway=LEEWAY_SECONDS,
                    options={"require": ["exp", "iat", "iss", "aud", "sub"]},
                )
                return claims
            except jwt.InvalidSignatureError as exc:
                failure = exc  # another published key may be the one that signed it
            except (jwt.PyJWTError, TypeError, ValueError) as exc:
                raise OidcError(f"The ID token is not valid: {exc}") from exc
        raise OidcError(f"The ID token is not valid: {failure}") from failure

    async def _validate(
        self, discovery: Discovery, id_token: str, *, nonce: str | None
    ) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as exc:
            raise OidcError(f"The ID token is malformed: {exc}") from exc
        if header.get("alg") not in ALGORITHMS:
            raise OidcError(
                f"The ID token is signed with {header.get('alg')}; only RS256 is accepted."
            )
        async with self._http() as client:
            published = await self._get_json(client, discovery.jwks_uri)
        try:
            key_set = jwt.PyJWKSet.from_dict(published)
        except jwt.PyJWTError as exc:
            raise OidcError(f"The identity provider's keys are unusable: {exc}") from exc
        kid = header.get("kid")
        # Only RSA signing keys can verify an RS256 token. With a kid, the key it names;
        # without one, every RSA signing key is tried (a key set can list several).
        candidates = [
            key
            for key in key_set.keys
            if key.key_type == "RSA"
            and key.public_key_use in (None, "sig")
            and (kid is None or key.key_id == kid)
        ]
        if not candidates:
            raise OidcError(
                "The ID token was signed with a key the identity provider does not publish."
            )
        claims = self._decode(id_token, candidates, discovery.issuer)
        if nonce is not None and not hmac.compare_digest(
            str(claims.get("nonce", "")).encode(), nonce.encode()
        ):
            raise OidcError("The ID token's nonce does not match this sign-in.")
        audience = claims.get("aud")
        if isinstance(audience, list) and len(audience) > 1 and claims.get("azp") != self.client_id:
            raise OidcError("The ID token was issued to another client (azp).")
        if not isinstance(claims.get("sub"), str) or not claims["sub"]:
            raise OidcError("The ID token has no subject.")
        return claims
