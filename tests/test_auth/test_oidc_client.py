"""ID tokens are believed only after signature, issuer, audience, expiry and nonce checks."""

import dataclasses
import json
import time
from datetime import datetime
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from tests.mocks.oidc_provider import KID, IdTokenOptions, MockIdP, Person, build_app
from u2_mcp.auth.oidc_client import OidcClient, OidcError, PendingLogin

ISSUER = "http://localhost"
DISCOVERY = f"{ISSUER}/.well-known/openid-configuration"
REDIRECT = "http://u2.test/admin/sign-in/sso/callback"


@pytest.fixture
def idp() -> MockIdP:
    return MockIdP(ISSUER, {"u2-mcp": "s3cret"}, [REDIRECT])


def _http(idp: MockIdP) -> Any:
    app = build_app(idp)
    return lambda: httpx.AsyncClient(transport=httpx.ASGITransport(app=app))


def _client(idp: MockIdP, secret: str = "s3cret") -> OidcClient:
    return OidcClient(DISCOVERY, "u2-mcp", secret, http=_http(idp))


async def _code(idp: MockIdP, client: OidcClient, login: PendingLogin) -> str:
    url = await client.authorization_url(REDIRECT, login)
    query = parse_qs(urlsplit(url).query)
    assert query["code_challenge_method"] == ["S256"] and query["nonce"] == [login.nonce]
    async with _http(idp)() as http:
        response = await http.get(url)
    location = parse_qs(urlsplit(response.headers["location"]).query)
    assert location["state"] == [login.state]
    return location["code"][0]


@pytest.mark.asyncio
async def test_a_round_trip_returns_the_validated_claims(idp: MockIdP) -> None:
    idp.next_user(Person(sub="sam", groups=["eng"]))
    client, login = _client(idp), PendingLogin.new()
    claims = await client.sign_in(await _code(idp, client, login), REDIRECT, login)
    assert claims["sub"] == "sam" and claims["groups"] == ["eng"]


@pytest.mark.asyncio
async def test_a_wrong_secret_is_reported(idp: MockIdP) -> None:
    client, login = _client(idp, secret="nope"), PendingLogin.new()
    with pytest.raises(OidcError, match="refused the code"):
        await client.sign_in(await _code(idp, client, login), REDIRECT, login)


@pytest.mark.asyncio
async def test_a_different_nonce_is_refused(idp: MockIdP) -> None:
    client, login = _client(idp), PendingLogin.new()
    code = await _code(idp, client, login)
    with pytest.raises(OidcError, match="nonce"):
        await client.sign_in(code, REDIRECT, dataclasses.replace(login, nonce="other"))


@pytest.mark.asyncio
async def test_a_different_pkce_verifier_is_refused(idp: MockIdP) -> None:
    client, login = _client(idp), PendingLogin.new()
    code = await _code(idp, client, login)
    with pytest.raises(OidcError, match="refused the code"):
        await client.sign_in(code, REDIRECT, dataclasses.replace(login, verifier="x" * 50))


def _claims(idp: MockIdP, **changes: Any) -> dict[str, Any]:
    claims = idp.claims_for(Person(), client_id="u2-mcp", nonce=None)
    claims.update(changes)
    return claims


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("make", "message"),
    [
        (lambda idp: idp.sign(_claims(idp, exp=int(time.time()) - 600)), "not valid"),
        (lambda idp: idp.sign(_claims(idp, aud="someone-else")), "not valid"),
        (lambda idp: idp.sign(_claims(idp, iss="http://evil.test")), "not valid"),
        (
            lambda idp: idp.sign(_claims(idp), key=rsa.generate_private_key(65537, 2048)),
            "not valid",
        ),
        (lambda idp: idp.sign(_claims(idp), kid="unknown"), "does not publish"),
        (lambda idp: idp.sign(_claims(idp), key="k" * 32, alg="HS256"), "only RS256"),
        (lambda idp: idp.sign(_claims(idp, aud=["u2-mcp", "other"], azp="other")), "azp"),
        (lambda idp: "not-a-token", "malformed"),
    ],
)
async def test_bad_id_tokens_are_refused(idp: MockIdP, make: Any, message: str) -> None:
    with pytest.raises(OidcError, match=message):
        await _client(idp).validate_id_token(make(idp))


@pytest.mark.asyncio
async def test_entra_common_discovery_is_refused() -> None:
    doc = {
        "issuer": "https://login.microsoftonline.com/{tenantid}/v2.0",
        "authorization_endpoint": "https://a",
        "token_endpoint": "https://t",
        "jwks_uri": "https://j",
    }
    http = lambda: httpx.AsyncClient(  # noqa: E731
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json=doc))
    )
    with pytest.raises(OidcError, match="tenantid"):
        await OidcClient(
            "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
            "id",
            "s",
            http=http,
        ).discover()


@pytest.mark.asyncio
async def test_an_unreachable_provider_names_the_url() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    http = lambda: httpx.AsyncClient(transport=httpx.MockTransport(refuse))  # noqa: E731
    with pytest.raises(
        OidcError, match="Could not reach the identity provider at http://localhost"
    ):
        await OidcClient(DISCOVERY, "id", "s", http=http).discover()


@pytest.mark.asyncio
async def test_post_auth_is_used_when_basic_is_not_offered() -> None:
    seen: list[httpx.Request] = []
    doc = {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/a",
        "token_endpoint": f"{ISSUER}/t",
        "jwks_uri": f"{ISSUER}/j",
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
    }

    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(200, json=doc)
        return httpx.Response(400, json={"error": "invalid_grant"})

    http = lambda: httpx.AsyncClient(transport=httpx.MockTransport(answer))  # noqa: E731
    with pytest.raises(OidcError):
        await OidcClient(DISCOVERY, "id", "sec", http=http).sign_in(
            "c", REDIRECT, PendingLogin.new()
        )
    token_request = seen[-1]
    assert "authorization" not in token_request.headers
    assert b"client_secret=sec" in token_request.content


# --- negative tests through the strict mock provider -------------------------------------


async def _failed_sign_in(
    idp: MockIdP, options: IdTokenOptions, match: str, secret: str = "s3cret"
) -> None:
    """Run a whole sign-in whose ID token is made bad; it must fail clearly and leak nothing."""
    idp.next_token(options)
    client, login = _client(idp, secret=secret), PendingLogin.new()
    code = await _code(idp, client, login)
    with pytest.raises(OidcError, match=match) as raised:
        await client.sign_in(code, REDIRECT, login)
    text = str(raised.value)
    assert secret not in text and code not in text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("options", "match"),
    [
        (IdTokenOptions(alg="none"), "only RS256"),
        (IdTokenOptions(alg="HS256"), "only RS256"),
        (IdTokenOptions(kid="rotated-away"), "does not publish"),
        (IdTokenOptions(iss="http://evil.test"), "not valid"),
        (IdTokenOptions(aud="someone-else"), "not valid"),
        (IdTokenOptions(expired=True), "not valid"),
        (IdTokenOptions(nonce="forged"), "nonce"),
        (IdTokenOptions(drop_nonce=True), "nonce"),
    ],
    ids=[
        "alg-none",
        "hs256-confusion",
        "wrong-kid",
        "wrong-iss",
        "wrong-aud",
        "expired",
        "bad-nonce",
        "no-nonce",
    ],
)
async def test_a_bad_id_token_from_the_token_endpoint_is_refused(
    idp: MockIdP, options: IdTokenOptions, match: str
) -> None:
    await _failed_sign_in(idp, options, match)


@pytest.mark.asyncio
async def test_a_token_endpoint_error_is_reported_without_the_secret_or_code(
    idp: MockIdP,
) -> None:
    client, login = _client(idp), PendingLogin.new()
    code = await _code(idp, client, login)
    idp.fail_next_token("invalid_grant")
    with pytest.raises(OidcError, match="refused the code: invalid_grant") as raised:
        await client.sign_in(code, REDIRECT, login)
    assert "s3cret" not in str(raised.value) and code not in str(raised.value)


@pytest.mark.asyncio
async def test_an_access_denied_callback_is_refused_with_the_provider_reason(
    idp: MockIdP,
) -> None:
    client, login = _client(idp), PendingLogin.new()
    idp.fail_next_authorize("access_denied")
    url = await client.authorization_url(REDIRECT, login)
    async with _http(idp)() as http:
        response = await http.get(url)
    params = {k: v[0] for k, v in parse_qs(urlsplit(response.headers["location"]).query).items()}
    assert params["error"] == "access_denied" and params["state"] == login.state
    with pytest.raises(OidcError, match="access_denied") as raised:
        client.callback_code(params, login)
    assert "s3cret" not in str(raised.value)


@pytest.mark.parametrize(
    ("params", "match"),
    [
        ({"code": "c", "state": "other"}, "does not match"),
        ({"code": "c"}, "does not match"),
        ({"state": "STATE"}, "no authorization code"),
    ],
)
def test_a_callback_needs_the_right_state_and_a_code(params: dict[str, str], match: str) -> None:
    login = PendingLogin("STATE", "n", "v" * 50)
    with pytest.raises(OidcError, match=match) as raised:
        OidcClient.callback_code(params, login)
    assert str(raised.value) != "c"  # the code itself is never echoed
    assert OidcClient.callback_code({"code": "c", "state": "STATE"}, login) == "c"


# --- claim-level checks, pinned one by one ----------------------------------------------


def _claims_at(idp: MockIdP, **changes: Any) -> dict[str, Any]:
    claims = _claims(idp)
    for key, value in changes.items():
        if value is None:
            claims.pop(key, None)
        else:
            claims[key] = value
    return claims


@pytest.mark.asyncio
@pytest.mark.parametrize("claim", ["exp", "iat", "sub"])
async def test_a_token_missing_a_required_claim_is_refused(idp: MockIdP, claim: str) -> None:
    token = idp.sign(_claims_at(idp, **{claim: None}))
    with pytest.raises(OidcError, match="not valid"):
        await _client(idp).validate_id_token(token)


@pytest.mark.asyncio
async def test_a_token_with_no_nonce_claim_is_refused_when_one_is_expected(idp: MockIdP) -> None:
    assert "nonce" not in _claims(idp)
    with pytest.raises(OidcError, match="nonce"):
        await _client(idp).validate_id_token(idp.sign(_claims(idp)), nonce="expected")


@pytest.mark.asyncio
async def test_a_matching_nonce_is_accepted(idp: MockIdP) -> None:
    token = idp.sign(_claims_at(idp, nonce="expected"))
    claims = await _client(idp).validate_id_token(token, nonce="expected")
    assert claims["nonce"] == "expected"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("claim", "offset", "accepted"),
    [
        ("exp", -59, True),
        ("exp", -61, False),
        ("nbf", 59, True),
        ("nbf", 61, False),
        ("iat", 59, True),
        ("iat", 61, False),
    ],
)
async def test_the_sixty_second_leeway_boundary(
    idp: MockIdP, monkeypatch: pytest.MonkeyPatch, claim: str, offset: int, accepted: bool
) -> None:
    # PyJWT reads the clock from datetime.now() in jwt.api_jwt; freeze it so the
    # 59 s and 61 s cases cannot drift across the boundary on a slow machine.
    frozen = int(time.time())

    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> "FrozenDatetime":
            return cls.fromtimestamp(frozen, tz)

    monkeypatch.setattr(jwt.api_jwt, "datetime", FrozenDatetime)
    claims = _claims_at(idp, **{claim: frozen + offset})
    token = idp.sign(claims)
    if accepted:
        assert (await _client(idp).validate_id_token(token))["sub"] == "user-1"
    else:
        with pytest.raises(OidcError, match="not valid"):
            await _client(idp).validate_id_token(token)


@pytest.mark.asyncio
async def test_nbf_far_in_the_future_and_iat_far_in_the_future_are_refused(idp: MockIdP) -> None:
    for claim in ("nbf", "iat"):
        token = idp.sign(_claims_at(idp, **{claim: int(time.time()) + 3600}))
        with pytest.raises(OidcError, match="not valid"):
            await _client(idp).validate_id_token(token)


@pytest.mark.asyncio
async def test_several_audiences_need_our_client_id_as_azp(idp: MockIdP) -> None:
    ours = idp.sign(_claims_at(idp, aud=["u2-mcp", "other"], azp="u2-mcp"))
    assert (await _client(idp).validate_id_token(ours))["azp"] == "u2-mcp"
    for azp in ("other", None):
        token = idp.sign(_claims_at(idp, aud=["u2-mcp", "other"], azp=azp))
        with pytest.raises(OidcError, match="azp"):
            await _client(idp).validate_id_token(token)


# --- edge cases from review: keys, nonce text and https endpoints ------------------------


def _published(idp: MockIdP, keys: list[dict[str, Any]]) -> Any:
    """An HTTP factory serving the mock's discovery document but this exact key set."""
    app = build_app(idp)
    inner = httpx.ASGITransport(app=app)

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/jwks":
            return httpx.Response(200, json={"keys": keys})
        return await inner.handle_async_request(request)

    return lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _public_jwk(key: Any, kid: str, **extra: str) -> dict[str, Any]:
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": kid, "alg": "RS256", **extra})
    return jwk


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "foreign",
    [
        {"kty": "oct", "kid": KID, "k": "c2VjcmV0c2VjcmV0c2VjcmV0"},
        {
            "kty": "EC",
            "kid": KID,
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        },
    ],
    ids=["oct", "ec"],
)
async def test_a_non_rsa_key_with_the_right_kid_is_an_oidc_error(
    idp: MockIdP, foreign: dict[str, Any]
) -> None:
    client = OidcClient(DISCOVERY, "u2-mcp", "s3cret", http=_published(idp, [foreign]))
    with pytest.raises(OidcError, match="does not publish"):
        await client.validate_id_token(idp.sign(_claims(idp)))


@pytest.mark.asyncio
async def test_a_non_ascii_nonce_is_an_oidc_error_not_a_type_error(idp: MockIdP) -> None:
    token = idp.sign(_claims_at(idp, nonce="né"))
    with pytest.raises(OidcError, match="nonce"):
        await _client(idp).validate_id_token(token, nonce="plain")
    assert (await _client(idp).validate_id_token(token, nonce="né"))["nonce"] == "né"


@pytest.mark.asyncio
async def test_a_token_without_kid_is_tried_against_every_rsa_signing_key(idp: MockIdP) -> None:
    other = rsa.generate_private_key(65537, 2048)
    keys = [
        _public_jwk(other, "other"),
        _public_jwk(idp.key, "ours", use="enc"),  # an encryption key is never a signing key
        _public_jwk(idp.key, KID),
    ]
    token = jwt.encode(_claims(idp), idp.key, algorithm="RS256")  # no kid header
    assert "kid" not in jwt.get_unverified_header(token)
    client = OidcClient(DISCOVERY, "u2-mcp", "s3cret", http=_published(idp, keys))
    assert (await client.validate_id_token(token))["sub"] == "user-1"


@pytest.mark.asyncio
async def test_a_token_without_kid_signed_by_an_unpublished_key_is_refused(idp: MockIdP) -> None:
    other = rsa.generate_private_key(65537, 2048)
    keys = [_public_jwk(other, "other"), _public_jwk(idp.key, KID)]
    token = jwt.encode(_claims(idp), rsa.generate_private_key(65537, 2048), algorithm="RS256")
    client = OidcClient(DISCOVERY, "u2-mcp", "s3cret", http=_published(idp, keys))
    with pytest.raises(OidcError, match="not valid"):
        await client.validate_id_token(token)


def _discovery_doc(issuer: str, **overrides: str) -> dict[str, str]:
    doc = {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "jwks_uri": f"{issuer}/jwks",
        "userinfo_endpoint": f"{issuer}/userinfo",
    }
    doc.update(overrides)
    return doc


def _serving(doc: dict[str, str]) -> Any:
    return lambda: httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=doc))
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field", ["authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint"]
)
async def test_an_http_endpoint_from_an_https_issuer_is_refused(field: str) -> None:
    doc = _discovery_doc("https://idp.example", **{field: "http://idp.example/x"})
    with pytest.raises(OidcError, match=f"{field}.*https"):
        await OidcClient(DISCOVERY, "id", "s", http=_serving(doc)).discover()


@pytest.mark.asyncio
async def test_an_http_issuer_that_is_not_loopback_is_refused() -> None:
    with pytest.raises(OidcError, match="issuer.*https"):
        await OidcClient(
            DISCOVERY, "id", "s", http=_serving(_discovery_doc("http://idp.example"))
        ).discover()


@pytest.mark.asyncio
@pytest.mark.parametrize("issuer", ["http://localhost:8901", "http://127.0.0.1:8901"])
async def test_a_loopback_http_issuer_may_use_http_endpoints(issuer: str) -> None:
    found = await OidcClient(DISCOVERY, "id", "s", http=_serving(_discovery_doc(issuer))).discover()
    assert found.token_endpoint == f"{issuer}/token"


@pytest.mark.asyncio
async def test_an_https_provider_is_accepted() -> None:
    doc = _discovery_doc("https://idp.example")
    found = await OidcClient(DISCOVERY, "id", "s", http=_serving(doc)).discover()
    assert found.jwks_uri == "https://idp.example/jwks"
