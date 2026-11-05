"""Client authentication at /register, /token and /revoke.

Public clients (token_endpoint_auth_method "none") prove themselves with PKCE
alone. If the server forces a secret on them, the SDK demands it at /token and
the client — which never received one it would send — is refused with 401.
"""

import base64
import hashlib
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
import pytest_asyncio
from mcp.server.auth.routes import create_auth_routes
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from pydantic import AnyHttpUrl
from starlette.applications import Starlette

from u2_mcp.auth.basic_client_id import BasicClientIdMiddleware
from u2_mcp.auth.provider import U2OAuthProvider
from u2_mcp.auth.storage import StoredAuthCode, StoredClient

ISSUER = "https://u2-mcp.example.com"
CALLBACK = "http://127.0.0.1:33418/callback"
VERIFIER = "v" * 64
CHALLENGE = (
    base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).decode().rstrip("=")
)


class StubIdP:
    """An identity provider these tests never reach."""

    async def get_authorization_url(self, *args: Any, **kwargs: Any) -> str:
        raise AssertionError("the identity provider must not be contacted")


@pytest_asyncio.fixture
async def http(oauth_storage: Any) -> AsyncIterator[httpx.AsyncClient]:
    provider = U2OAuthProvider(
        idp_adapter=StubIdP(),  # type: ignore[arg-type]
        issuer_url=ISSUER,
        storage=oauth_storage,
    )
    routes = create_auth_routes(
        provider,
        AnyHttpUrl(ISSUER),
        client_registration_options=ClientRegistrationOptions(enabled=True),
        revocation_options=RevocationOptions(enabled=True),
    )
    transport = httpx.ASGITransport(app=BasicClientIdMiddleware(Starlette(routes=routes)))
    async with httpx.AsyncClient(transport=transport, base_url=ISSUER) as client:
        yield client


def _store_client(storage: Any, client_id: str, method: str, secret: str | None) -> None:
    storage.store_client(
        StoredClient(
            client_id=client_id,
            client_secret=secret,
            client_name=client_id,
            redirect_uris=[CALLBACK],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scope=None,
            token_endpoint_auth_method=method,
        )
    )


def _store_code(storage: Any, client_id: str, code: str = "the-code") -> str:
    storage.store_auth_code(
        StoredAuthCode(
            code=code,
            client_id=client_id,
            redirect_uri=CALLBACK,
            scope="u2:read",
            state="s",
            code_challenge=CHALLENGE,
            code_challenge_method="S256",
            user_subject="alice",
            user_claims={},
        )
    )
    return code


def _exchange(client_id: str, code: str, verifier: str = VERIFIER, **extra: str) -> dict[str, str]:
    return {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "redirect_uri": CALLBACK,
        "code_verifier": verifier,
        **extra,
    }


async def _register(http: httpx.AsyncClient, method: str) -> dict[str, Any]:
    response = await http.post(
        "/register",
        json={
            "client_name": "GitHub Copilot",
            "redirect_uris": [CALLBACK],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": method,
        },
    )
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


class TestPublicClients:
    @pytest.mark.asyncio
    async def test_registration_issues_no_secret(
        self, http: httpx.AsyncClient, oauth_storage: Any
    ) -> None:
        body = await _register(http, "none")

        assert body.get("client_secret") is None
        assert body.get("client_secret_expires_at") is None
        stored = oauth_storage.get_client(body["client_id"])
        assert stored.client_secret is None
        assert stored.token_endpoint_auth_method == "none"

    @pytest.mark.asyncio
    async def test_registered_client_exchanges_code_with_pkce_only(
        self, http: httpx.AsyncClient, oauth_storage: Any
    ) -> None:
        client_id = (await _register(http, "none"))["client_id"]
        code = _store_code(oauth_storage, client_id)

        response = await http.post("/token", data=_exchange(client_id, code))

        assert response.status_code == 200, response.text
        assert response.json()["access_token"]


class TestConfidentialClients:
    @pytest.mark.asyncio
    async def test_registration_issues_a_secret(
        self, http: httpx.AsyncClient, oauth_storage: Any
    ) -> None:
        body = await _register(http, "client_secret_post")

        assert body["client_secret"]
        assert oauth_storage.get_client(body["client_id"]).client_secret == body["client_secret"]

    @pytest.mark.asyncio
    async def test_token_requires_the_secret(
        self, http: httpx.AsyncClient, oauth_storage: Any
    ) -> None:
        _store_client(oauth_storage, "conf", "client_secret_post", "s3cret")
        code = _store_code(oauth_storage, "conf")

        missing = await http.post("/token", data=_exchange("conf", code))
        wrong = await http.post("/token", data=_exchange("conf", code, client_secret="nope"))

        assert missing.status_code == 401
        assert wrong.status_code == 401

    @pytest.mark.asyncio
    async def test_token_accepts_the_secret(
        self, http: httpx.AsyncClient, oauth_storage: Any
    ) -> None:
        _store_client(oauth_storage, "conf", "client_secret_post", "s3cret")
        code = _store_code(oauth_storage, "conf")

        response = await http.post("/token", data=_exchange("conf", code, client_secret="s3cret"))

        assert response.status_code == 200, response.text

    @pytest.mark.asyncio
    async def test_basic_auth_requires_the_secret(
        self, http: httpx.AsyncClient, oauth_storage: Any
    ) -> None:
        _store_client(oauth_storage, "basic", "client_secret_basic", "s3cret")
        code = _store_code(oauth_storage, "basic")

        missing = await http.post("/token", data=_exchange("basic", code))
        good = await http.post("/token", data=_exchange("basic", code), auth=("basic", "s3cret"))

        assert missing.status_code == 401
        assert good.status_code == 200, good.text

    @pytest.mark.asyncio
    async def test_revoke_requires_the_secret(
        self, http: httpx.AsyncClient, oauth_storage: Any
    ) -> None:
        _store_client(oauth_storage, "conf", "client_secret_post", "s3cret")

        missing = await http.post("/revoke", data={"client_id": "conf", "token": "t"})
        good = await http.post(
            "/revoke", data={"client_id": "conf", "client_secret": "s3cret", "token": "t"}
        )

        assert missing.status_code == 401
        assert good.status_code == 200


def _without_client_id(code: str, verifier: str = VERIFIER) -> dict[str, str]:
    """A token request that names its client only in the Basic header."""
    form = _exchange("unused", code, verifier)
    del form["client_id"]
    return form


class TestBasicCredentialsCarryTheClientId:
    """RFC 6749 2.3.1: a client may send client_id only in Authorization: Basic."""

    @pytest.mark.asyncio
    async def test_public_client_with_an_empty_basic_secret(
        self, http: httpx.AsyncClient, oauth_storage: Any
    ) -> None:
        _store_client(oauth_storage, "public", "none", None)

        response = await http.post("/token", data=_without_client_id("bogus"), auth=("public", ""))

        assert response.status_code == 400
        assert response.json()["error"] == "invalid_grant"

    @pytest.mark.asyncio
    async def test_pkce_still_applies(self, http: httpx.AsyncClient, oauth_storage: Any) -> None:
        _store_client(oauth_storage, "public", "none", None)
        code = _store_code(oauth_storage, "public")

        response = await http.post(
            "/token", data=_without_client_id(code, verifier="w" * 64), auth=("public", "")
        )

        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_confidential_basic_client_good_and_bad_secret(
        self, http: httpx.AsyncClient, oauth_storage: Any
    ) -> None:
        _store_client(oauth_storage, "basic", "client_secret_basic", "s3cret")
        code = _store_code(oauth_storage, "basic")

        bad = await http.post("/token", data=_without_client_id(code), auth=("basic", "nope"))
        good = await http.post("/token", data=_without_client_id(code), auth=("basic", "s3cret"))

        assert bad.status_code == 401
        assert good.status_code == 200, good.text

    @pytest.mark.asyncio
    async def test_revoke_takes_the_client_id_from_basic(
        self, http: httpx.AsyncClient, oauth_storage: Any
    ) -> None:
        _store_client(oauth_storage, "basic", "client_secret_basic", "s3cret")

        bad = await http.post("/revoke", data={"token": "t"}, auth=("basic", "nope"))
        good = await http.post("/revoke", data={"token": "t"}, auth=("basic", "s3cret"))

        assert bad.status_code == 401
        assert good.status_code == 200
