"""A small OpenID Connect provider for tests: discovery, JWKS, authorize, token, userinfo.

It signs RS256 ID tokens with a key made at start. Who signs in next, and with
which claims, is queued over POST /_control/next-user, so a browser test can
script a person and their groups (or an Entra-style group overage). It approves
every authorization request at once: there is no login page.

It is strict like a real provider: /authorize needs a registered, exactly matching
redirect_uri (otherwise a 400 page, never a redirect), response_type=code, the
openid scope and a PKCE S256 challenge (otherwise an error redirect). Tests can
make the next /authorize or /token fail (POST /_control/fail) and make the next ID
token bad (POST /_control/next-token): unsigned, HS256 signed with the public key,
wrong kid, issuer or audience, expired, or with a wrong or missing nonce.

Run: python -m tests.mocks.oidc_provider --port 8901 --client-id u2-mcp --client-secret s3cret \\
    --redirect-uri http://127.0.0.1:8080/admin/sign-in/sso/callback
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Iterable
from dataclasses import dataclass, field, fields
from typing import Any
from urllib.parse import unquote_plus, urlencode

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

KID = "mock-key-1"


@dataclass
class Person:
    """Who signs in, and what the provider says about them."""

    sub: str = "user-1"
    email: str | None = "user1@example.com"
    name: str | None = "User One"
    groups: list[str] = field(default_factory=list)
    overage: bool = False  # Entra-style: groups left out, _claim_names says where
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class IdTokenOptions:
    """How to mint the next ID token wrongly (the defaults mint a good one).

    Attributes:
        alg: RS256, "none" (unsigned) or HS256 (signed with the public key's bytes)
        kid: The kid in the token header
        iss: Issuer to put in the token instead of the provider's
        aud: Audience to put in the token instead of the client id
        expired: Expired ten minutes ago, beyond any leeway
        nonce: A nonce to put in the token instead of the one authorize saw
        drop_nonce: Leave the nonce out altogether
    """

    alg: str = "RS256"
    kid: str = KID
    iss: str | None = None
    aud: str | list[str] | None = None
    expired: bool = False
    nonce: str | None = None
    drop_nonce: bool = False


@dataclass
class _Code:
    client_id: str
    redirect_uri: str
    person: Person
    nonce: str | None
    challenge: str


def _b64(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def _signing_input(header: dict[str, Any], claims: dict[str, Any]) -> bytes:
    parts = (json.dumps(header, separators=(",", ":")), json.dumps(claims, separators=(",", ":")))
    return b".".join(_b64(part.encode()) for part in parts)


class MockIdP:
    """The provider's state: its key, clients, queued people and issued codes.

    Args:
        issuer: The issuer URL
        clients: client id -> secret
        redirect_uris: The registered redirect URIs; /authorize accepts only exact matches
    """

    def __init__(
        self, issuer: str, clients: dict[str, str], redirect_uris: Iterable[str] = ()
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.clients = dict(clients)
        self.redirect_uris = set(redirect_uris)
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.queue: list[Person] = []
        self.default = Person()
        self.codes: dict[str, _Code] = {}
        self.access_tokens: dict[str, Person] = {}
        self.authorize_errors: list[str] = []
        self.token_errors: list[str] = []
        self.token_options: list[IdTokenOptions] = []

    def next_user(self, person: Person) -> None:
        """Queue the person the next authorization request signs in."""
        self.queue.append(person)

    def register_redirect_uri(self, uri: str) -> None:
        """Register a redirect URI (authorize accepts only exact matches)."""
        self.redirect_uris.add(uri)

    def fail_next_authorize(self, error: str = "access_denied") -> None:
        """Make the next /authorize redirect back with this error and the original state."""
        self.authorize_errors.append(error)

    def fail_next_token(self, error: str = "invalid_grant") -> None:
        """Make the next /token answer HTTP 400 with this OAuth error."""
        self.token_errors.append(error)

    def next_token(self, options: IdTokenOptions) -> None:
        """Mint the next ID token as `options` says (usually a bad one)."""
        self.token_options.append(options)

    def reset(self) -> None:
        """Forget queued people, failures, token options and codes (for a shared server)."""
        self.queue.clear()
        self.authorize_errors.clear()
        self.token_errors.clear()
        self.token_options.clear()
        self.codes.clear()

    def claims_for(
        self,
        person: Person,
        *,
        client_id: str,
        nonce: str | None,
        iss: str | None = None,
        aud: str | list[str] | None = None,
        expires_in: int = 300,
    ) -> dict[str, Any]:
        """The ID token's claims for this person."""
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": iss if iss is not None else self.issuer,
            "aud": aud if aud is not None else client_id,
            "sub": person.sub,
            "iat": now,
            "exp": now + expires_in,
        }
        if nonce:
            claims["nonce"] = nonce
        if person.email:
            claims["email"] = person.email
        if person.name:
            claims["name"] = person.name
        if person.overage:
            claims["_claim_names"] = {"groups": "src1"}
            claims["_claim_sources"] = {
                "src1": {"endpoint": "https://graph.windows.net/t/users/u/getMemberObjects"}
            }
        else:
            claims["groups"] = list(person.groups)
        claims.update(person.extra)
        return claims

    def sign(
        self, claims: dict[str, Any], *, key: Any = None, kid: str = KID, alg: str = "RS256"
    ) -> str:
        """Sign claims as an ID token (another key, kid or algorithm makes a bad one).

        alg="none" gives an unsigned token. alg="HS256" without a key signs with the
        provider's public key bytes: the classic algorithm-confusion token, which
        PyJWT itself refuses to build.
        """
        if alg == "none":
            header = {"alg": "none", "typ": "JWT", "kid": kid}
            return (_signing_input(header, claims) + b".").decode()
        if alg == "HS256" and key is None:
            secret = self.key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            header = {"alg": "HS256", "typ": "JWT", "kid": kid}
            signing_input = _signing_input(header, claims)
            digest = hmac.new(secret, signing_input, hashlib.sha256).digest()
            return (signing_input + b"." + _b64(digest)).decode()
        return jwt.encode(
            claims, key if key is not None else self.key, algorithm=alg, headers={"kid": kid}
        )

    def mint(
        self,
        person: Person,
        *,
        client_id: str,
        nonce: str | None,
        options: IdTokenOptions | None = None,
    ) -> str:
        """The ID token for this person, made wrongly when `options` says so."""
        options = options or IdTokenOptions()
        if options.drop_nonce:
            nonce = None
        elif options.nonce is not None:
            nonce = options.nonce
        claims = self.claims_for(
            person,
            client_id=client_id,
            nonce=nonce,
            iss=options.iss,
            aud=options.aud,
            expires_in=-600 if options.expired else 300,
        )
        return self.sign(claims, kid=options.kid, alg=options.alg)

    def jwks(self) -> dict[str, Any]:
        """The public key set."""
        jwk = json.loads(RSAAlgorithm.to_jwk(self.key.public_key()))
        jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})
        return {"keys": [jwk]}


def _idp(request: Request) -> MockIdP:
    idp: MockIdP = request.app.state.idp
    return idp


async def discovery(request: Request) -> Response:
    issuer = _idp(request).issuer
    return JSONResponse(
        {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "jwks_uri": f"{issuer}/jwks",
            "userinfo_endpoint": f"{issuer}/userinfo",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        }
    )


async def jwks(request: Request) -> Response:
    return JSONResponse(_idp(request).jwks())


def _bad_request_page(message: str) -> Response:
    """Like a real provider: a page for the person, never a redirect to an unvetted URI."""
    return HTMLResponse(f"<h1>Sign-in error</h1><p>{message}</p>", status_code=400)


def _redirect_with(redirect_uri: str, params: dict[str, str]) -> Response:
    separator = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{separator}{urlencode(params)}", status_code=302)


async def authorize(request: Request) -> Response:
    idp = _idp(request)
    query = request.query_params
    if query.get("client_id") not in idp.clients:
        return _bad_request_page("Unknown client.")
    redirect_uri = query.get("redirect_uri", "")
    if redirect_uri not in idp.redirect_uris:
        return _bad_request_page("The redirect URI is not registered for this client.")
    state = query.get("state")

    def refuse(error: str, description: str | None = None) -> Response:
        params = {"error": error}
        if description:
            params["error_description"] = description
        if state is not None:
            params["state"] = state
        return _redirect_with(redirect_uri, params)

    if idp.authorize_errors:
        return refuse(idp.authorize_errors.pop(0))
    if query.get("response_type") != "code":
        return refuse("unsupported_response_type")
    if "openid" not in query.get("scope", "").split():
        return refuse("invalid_scope", "The openid scope is required")
    if not query.get("code_challenge"):
        return refuse("invalid_request", "code_challenge is required")
    if query.get("code_challenge_method") != "S256":
        return refuse("invalid_request", "code_challenge_method must be S256")
    person = idp.queue.pop(0) if idp.queue else idp.default
    code = secrets.token_urlsafe(16)
    idp.codes[code] = _Code(
        query["client_id"], redirect_uri, person, query.get("nonce"), query["code_challenge"]
    )
    params = {"code": code}
    if state is not None:
        params["state"] = state
    return _redirect_with(redirect_uri, params)


def _client_credentials(request: Request, form: dict[str, str]) -> tuple[str, str]:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(header[6:], validate=True).decode()
        except ValueError:
            return "", ""
        client_id, _, secret = decoded.partition(":")
        return unquote_plus(client_id), unquote_plus(secret)
    return form.get("client_id", ""), form.get("client_secret", "")


async def token(request: Request) -> Response:
    idp = _idp(request)
    form = {key: str(value) for key, value in (await request.form()).items()}
    client_id, secret = _client_credentials(request, form)
    expected = idp.clients.get(client_id)
    if expected is None or not hmac.compare_digest(expected.encode(), secret.encode()):
        return JSONResponse({"error": "invalid_client"}, status_code=401)
    if idp.token_errors:
        return JSONResponse({"error": idp.token_errors.pop(0)}, status_code=400)
    if form.get("grant_type") != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
    issued = idp.codes.pop(form.get("code", ""), None)
    if (
        issued is None
        or issued.client_id != client_id
        or issued.redirect_uri != form.get("redirect_uri")
    ):
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    verifier = form.get("code_verifier", "")
    challenge = _b64(hashlib.sha256(verifier.encode()).digest())
    if not 43 <= len(verifier) <= 128 or not hmac.compare_digest(
        challenge, issued.challenge.encode()
    ):
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "PKCE verification failed"},
            status_code=400,
        )
    access_token = secrets.token_urlsafe(24)
    idp.access_tokens[access_token] = issued.person
    options = idp.token_options.pop(0) if idp.token_options else None
    id_token = idp.mint(issued.person, client_id=client_id, nonce=issued.nonce, options=options)
    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 300,
            "id_token": id_token,
        }
    )


async def userinfo(request: Request) -> Response:
    idp = _idp(request)
    header = request.headers.get("authorization", "")
    person = idp.access_tokens.get(header[7:]) if header.lower().startswith("bearer ") else None
    if person is None:
        return JSONResponse({"error": "invalid_token"}, status_code=401)
    body: dict[str, Any] = {"sub": person.sub}
    if person.email:
        body["email"] = person.email
    if person.name:
        body["name"] = person.name
    return JSONResponse(body)


def _unknown_fields(data: dict[str, Any], known: set[str]) -> Response | None:
    unknown = sorted(set(data) - known)
    if unknown:
        return JSONResponse({"error": f"unknown fields: {', '.join(unknown)}"}, status_code=400)
    return None


async def next_user(request: Request) -> Response:
    data = await request.json()
    bad = _unknown_fields(data, {f.name for f in fields(Person)})
    if bad:
        return bad
    _idp(request).next_user(Person(**data))
    return JSONResponse({"queued": True})


async def fail(request: Request) -> Response:
    """Make the next /authorize and/or /token fail: {"authorize": "access_denied", "token": ...}."""
    data = await request.json()
    bad = _unknown_fields(data, {"authorize", "token"})
    if bad:
        return bad
    idp = _idp(request)
    if data.get("authorize"):
        idp.fail_next_authorize(str(data["authorize"]))
    if data.get("token"):
        idp.fail_next_token(str(data["token"]))
    return JSONResponse({"queued": True})


async def next_token(request: Request) -> Response:
    """Mint the next ID token wrongly: the fields of IdTokenOptions."""
    data = await request.json()
    bad = _unknown_fields(data, {f.name for f in fields(IdTokenOptions)})
    if bad:
        return bad
    _idp(request).next_token(IdTokenOptions(**data))
    return JSONResponse({"queued": True})


async def reset(request: Request) -> Response:
    _idp(request).reset()
    return JSONResponse({"reset": True})


def build_app(idp: MockIdP) -> Starlette:
    """The provider as an ASGI app (mount it with httpx.ASGITransport, or serve it)."""
    app = Starlette(
        routes=[
            Route("/.well-known/openid-configuration", discovery, methods=["GET"]),
            Route("/jwks", jwks, methods=["GET"]),
            Route("/authorize", authorize, methods=["GET"]),
            Route("/token", token, methods=["POST"]),
            Route("/userinfo", userinfo, methods=["GET"]),
            Route("/_control/next-user", next_user, methods=["POST"]),
            Route("/_control/fail", fail, methods=["POST"]),
            Route("/_control/next-token", next_token, methods=["POST"]),
            Route("/_control/reset", reset, methods=["POST"]),
        ]
    )
    app.state.idp = idp
    return app


def main(argv: list[str] | None = None) -> None:
    """Serve the provider on 127.0.0.1 until stopped."""
    import uvicorn

    parser = argparse.ArgumentParser(prog="python -m tests.mocks.oidc_provider")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--client-secret", required=True)
    parser.add_argument(
        "--redirect-uri", action="append", required=True, help="registered URI (repeatable)"
    )
    args = parser.parse_args(argv)
    idp = MockIdP(
        f"http://127.0.0.1:{args.port}", {args.client_id: args.client_secret}, args.redirect_uri
    )
    uvicorn.run(build_app(idp), host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
