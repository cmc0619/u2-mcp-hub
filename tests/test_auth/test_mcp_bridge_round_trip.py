"""The MCP OAuth bridge, built from the admin site's company sign-in, end to end.

An MCP client registers, is sent to the strict mock provider (which demands PKCE),
comes back through /oauth/callback, exchanges its code and calls with the token.
"""

from typing import Any
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from mcp.server.auth.provider import AuthorizationParams
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyUrl

from tests.mocks.oidc_provider import MockIdP, Person, build_app
from u2_mcp import server
from u2_mcp.auth.provider import U2OAuthProvider
from u2_mcp.auth.storage import AuthStorage
from u2_mcp.config import U2Config
from u2_mcp.sso_config import SsoSettings, store_sso
from u2_mcp.store.repo import Store
from u2_mcp.team_auth import make_identity_resolver

ISSUER = "http://localhost"
DISCOVERY = f"{ISSUER}/.well-known/openid-configuration"
PUBLIC = "https://u2.example.com"
CLIENT_CALLBACK = "http://127.0.0.1:33418/callback"


def _http(idp: MockIdP, *, basic_only: bool = False) -> Any:
    """Reach the mock over ASGI; basic_only makes it a provider that refuses form secrets."""
    inner = httpx.ASGITransport(app=build_app(idp))

    async def handler(request: httpx.Request) -> httpx.Response:
        if basic_only and request.url.path.endswith("openid-configuration"):
            response = await inner.handle_async_request(request)
            await response.aread()
            doc = response.json()
            doc["token_endpoint_auth_methods_supported"] = ["client_secret_basic"]
            return httpx.Response(200, json=doc)
        if basic_only and request.url.path == "/token":
            body = request.content
            if b"client_secret=" in body or "authorization" not in request.headers:
                return httpx.Response(401, json={"error": "invalid_client"})
        return await inner.handle_async_request(request)

    return lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _bridge(store: Store, config: U2Config, http: Any) -> U2OAuthProvider:
    store_sso(store, SsoSettings("oidc", DISCOVERY, "u2-mcp", "groups", False), "s3cret")
    adapter = server._stored_sso_adapter(store, PUBLIC, http=http)
    assert adapter is not None
    return U2OAuthProvider(
        idp_adapter=adapter,
        issuer_url=PUBLIC,
        storage=AuthStorage(store.locked),
        on_sign_in=server._team_sign_in(store, adapter),
        id_token_claims=adapter.client.validate_id_token,
    )


async def _round_trip(provider: U2OAuthProvider, http: Any) -> str:
    client = OAuthClientInformationFull(
        client_id="vscode",
        client_secret=None,
        redirect_uris=[AnyUrl(CLIENT_CALLBACK)],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        token_endpoint_auth_method="none",
    )
    await provider.register_client(client)
    url = await provider.authorize(
        client,
        AuthorizationParams(
            state="client-state",
            scopes=["u2:read"],
            code_challenge="c" * 43,
            redirect_uri=AnyUrl(CLIENT_CALLBACK),
            redirect_uri_provided_explicitly=True,
        ),
    )
    async with http() as browser:
        answer = await browser.get(url)
    back = parse_qs(urlsplit(answer.headers["location"]).query)
    assert "error" not in back, back
    to_client = await provider.handle_idp_callback(back["code"][0], back["state"][0])
    our_code = parse_qs(urlsplit(to_client).query)["code"][0]
    loaded = await provider.load_authorization_code(client, our_code)
    assert loaded is not None
    issued = await provider.exchange_authorization_code(client, loaded)
    return issued.access_token


@pytest.mark.asyncio
@pytest.mark.parametrize("basic_only", [False, True], ids=["post-or-basic", "basic-only"])
async def test_an_mcp_client_signs_in_through_the_strict_provider(
    store: Store, mock_config: U2Config, basic_only: bool
) -> None:
    idp = MockIdP(ISSUER, {"u2-mcp": "s3cret"}, [f"{PUBLIC}/oauth/callback"])
    idp.next_user(Person(sub="sam", name="Sam", groups=["eng"]))
    http = _http(idp, basic_only=basic_only)
    provider = _bridge(store, mock_config, http)

    access_token = await _round_trip(provider, http)

    loaded = await provider.load_access_token(access_token)
    assert loaded is not None and loaded.subject == "sam"
    person = store.get_sso_user(ISSUER, "sam")
    assert person is not None and person.display_name == "Sam"
    assert [g.external_id for g in store.list_groups()] == ["eng"]
    with patch("mcp.server.auth.middleware.auth_context.get_access_token", return_value=loaded):
        caller = make_identity_resolver(store, provider.storage)()
    assert caller is not None and caller.user_id == person.id
