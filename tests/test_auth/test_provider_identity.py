"""Tokens issued by the OAuth flow must name the signed-in person.

The authorization code records who signed in at the identity provider. Every
later step -- code load, exchange, token load, refresh -- has to carry that
person forward. If any step substitutes the OAuth client id, every caller of
that client is the same "user": per-person access, mapped-mode logins and audit
names all break.
"""

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest
from mcp.server.auth.provider import AccessToken, RefreshToken
from mcp.shared.auth import OAuthClientInformationFull

from tests.mocks.oauth import scratch_auth_storage
from u2_mcp.auth.idp.base import TokenInfo
from u2_mcp.auth.provider import U2OAuthProvider
from u2_mcp.auth.storage import PendingAuthorization
from u2_mcp.store.repo import Store
from u2_mcp.team_auth import make_identity_resolver, make_sign_in_handler

CLIENT_ID = "claude-dcr"
CLAIMS = {"email": "p@x.com", "name": "Person One"}
CALLBACK = "https://claude.ai/api/mcp/auth_callback"


def _person() -> TokenInfo:
    return TokenInfo(subject="person-1", email="p@x.com", name="Person One", raw_claims=CLAIMS)


def _provider(on_sign_in: Any = None) -> U2OAuthProvider:
    idp = MagicMock()
    idp.exchange_code = AsyncMock(return_value=MagicMock(access_token="idp-access"))
    idp.validate_token = AsyncMock(return_value=_person())
    provider = U2OAuthProvider(
        idp_adapter=idp,
        issuer_url="https://u2-mcp.example.com",
        storage=scratch_auth_storage(),
        on_sign_in=on_sign_in,
    )
    provider.storage.store_pending_auth(
        PendingAuthorization(
            state="state-1",
            client_id=CLIENT_ID,
            redirect_uri=CALLBACK,
            scope="u2:read",
            code_challenge="challenge",
            code_challenge_method="S256",
            claude_redirect_uri=CALLBACK,
            claude_state="claude-state",
        )
    )
    return provider


@pytest.fixture
def client() -> OAuthClientInformationFull:
    return OAuthClientInformationFull(
        client_id=CLIENT_ID,
        client_secret="secret",
        redirect_uris=[CALLBACK],  # type: ignore[list-item]
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope="u2:read",
    )


async def _sign_in_and_exchange(
    provider: U2OAuthProvider, client: OAuthClientInformationFull
) -> Any:
    redirect = await provider.handle_idp_callback("idp-code", "state-1")
    code = parse_qs(urlparse(redirect).query)["code"][0]
    loaded = await provider.load_authorization_code(client, code)
    assert loaded is not None
    return await provider.exchange_authorization_code(client, loaded)


@pytest.mark.asyncio
async def test_issued_tokens_name_the_person_not_the_client(
    client: OAuthClientInformationFull,
) -> None:
    provider = _provider()
    issued = await _sign_in_and_exchange(provider, client)

    stored = provider.storage.get_access_token(issued.access_token)
    assert stored is not None
    assert stored.user_subject == "person-1"
    assert stored.user_claims["email"] == "p@x.com"

    stored_refresh = provider.storage.get_refresh_token(issued.refresh_token)
    assert stored_refresh is not None
    assert stored_refresh.user_subject == "person-1"
    assert stored_refresh.user_claims["email"] == "p@x.com"

    loaded = await provider.load_access_token(issued.access_token)
    assert loaded is not None
    assert loaded.subject == "person-1"


@pytest.mark.asyncio
async def test_refreshed_tokens_still_name_the_person(
    client: OAuthClientInformationFull,
) -> None:
    provider = _provider()
    issued = await _sign_in_and_exchange(provider, client)

    presented = RefreshToken(token=issued.refresh_token, client_id=CLIENT_ID, scopes=["u2:read"])
    rotated = await provider.exchange_refresh_token(client, presented, ["u2:read"])

    stored = provider.storage.get_access_token(rotated.access_token)
    assert stored is not None
    assert stored.user_subject == "person-1"
    assert stored.user_claims["email"] == "p@x.com"
    loaded = await provider.load_access_token(rotated.access_token)
    assert loaded is not None
    assert loaded.subject == "person-1"


@pytest.mark.asyncio
async def test_team_mode_resolves_the_token_to_the_signed_in_user(
    store: Store, client: OAuthClientInformationFull
) -> None:
    provider = _provider(
        on_sign_in=make_sign_in_handler(store, "groups", issuer="https://idp.example")
    )
    issued = await _sign_in_and_exchange(provider, client)

    person = store.get_user_by_subject("person-1")
    assert person is not None

    access = AccessToken(token=issued.access_token, client_id=CLIENT_ID, scopes=["u2:read"])
    resolve = make_identity_resolver(store, provider.storage)
    with patch("mcp.server.auth.middleware.auth_context.get_access_token", return_value=access):
        caller = resolve()

    assert caller is not None
    assert caller.user_id == person.id
    assert store.get_user_by_subject(CLIENT_ID) is None


def _provider_with_id_token(id_claims: dict[str, Any], on_sign_in: Any) -> U2OAuthProvider:
    provider = _provider(on_sign_in=on_sign_in)
    provider.idp_adapter.exchange_code = AsyncMock(
        return_value=MagicMock(access_token="idp-access", id_token="id-token-1")
    )

    async def claims(token: str) -> dict[str, Any]:
        assert token == "id-token-1"
        return id_claims

    provider.id_token_claims = claims
    return provider


@pytest.mark.asyncio
async def test_id_token_groups_reach_the_settings_database(store: Store) -> None:
    provider = _provider_with_id_token(
        {"sub": "person-1", "groups": ["eng"]},
        make_sign_in_handler(store, "groups", issuer="https://idp.example"),
    )
    await provider.handle_idp_callback("idp-code", "state-1")
    person = store.get_user_by_subject("person-1")
    assert person is not None
    assert [g.external_id for g in store.list_groups()] == ["eng"]


@pytest.mark.asyncio
async def test_an_id_token_for_someone_else_is_refused(store: Store) -> None:
    from mcp.server.auth.provider import AuthorizeError

    provider = _provider_with_id_token(
        {"sub": "intruder"}, make_sign_in_handler(store, "groups", issuer="https://idp.example")
    )
    with pytest.raises(AuthorizeError):
        await provider.handle_idp_callback("idp-code", "state-1")
    assert store.get_user_by_subject("person-1") is None


@pytest.mark.asyncio
async def test_a_disabled_person_gets_no_mcp_sign_in(store: Store) -> None:
    from mcp.server.auth.provider import AuthorizeError

    person = store.get_or_create_sso_user("person-1", issuer="https://idp.example")
    store.set_user_disabled(person.id, True)
    provider = _provider_with_id_token(
        {"sub": "person-1", "groups": ["eng"]},
        make_sign_in_handler(store, "groups", issuer="https://idp.example"),
    )
    with pytest.raises(AuthorizeError) as refused:
        await provider.handle_idp_callback("idp-code", "state-1")
    assert refused.value.error == "access_denied"
    assert refused.value.error_description == "Your account is disabled; ask an admin."
    after = store.get_user_by_subject("person-1")
    assert after is not None and after.last_sso_login_at is None
    assert store.list_groups() == []


@pytest.mark.asyncio
async def test_no_id_token_means_no_sign_in_when_the_issuer_must_be_validated(
    store: Store,
) -> None:
    from mcp.server.auth.provider import AuthorizeError

    provider = _provider_with_id_token(
        {"sub": "person-1", "iss": "https://idp.example"},
        make_sign_in_handler(store, "groups", issuer="https://idp.example"),
    )
    provider.idp_adapter.exchange_code = AsyncMock(
        return_value=MagicMock(access_token="idp-access", id_token=None)
    )
    with pytest.raises(AuthorizeError) as refused:
        await provider.handle_idp_callback("idp-code", "state-1")
    assert refused.value.error == "access_denied"
    assert "ID token" in (refused.value.error_description or "")
    assert store.get_user_by_subject("person-1") is None
