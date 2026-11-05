"""Take the client_id from HTTP Basic credentials at /token and /revoke.

RFC 6749 section 2.3.1 lets a client authenticate with `Authorization: Basic`
and leave client_id out of the form. The MCP SDK's authenticator reads
client_id only from the form, so such clients (GitHub Copilot among them) are
refused with "Missing client_id", and its revocation request also needs
client_secret in the form. This copies whichever of the two the form lacks
from the header before the SDK sees it. Authentication is still the SDK's: a
confidential client's secret is compared as before, and a public client's is
ignored.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any
from urllib.parse import parse_qsl, unquote, urlencode

PATHS = frozenset({"/token", "/revoke"})
_FORM = b"application/x-www-form-urlencoded"
# Larger bodies pass through untouched; the SDK refuses them itself.
_MAX_BODY = 64 * 1024


def basic_credentials(authorization: str) -> tuple[str, str] | None:
    """The URL-decoded (client_id, secret) in an `Authorization: Basic` header, else None."""
    scheme, _, encoded = authorization.partition(" ")
    if scheme.lower() != "basic":
        return None
    try:
        decoded = base64.b64decode(encoded.strip(), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None
    client_id, sep, secret = decoded.partition(":")
    return (unquote(client_id), unquote(secret)) if sep and client_id else None


def with_credentials(body: bytes, client_id: str, secret: str) -> bytes | None:
    """The form with the missing client_id and client_secret added, else None.

    A form naming a different client is left alone; the SDK refuses the mismatch.
    """
    fields = parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True)
    named = dict(fields)
    if named.get("client_id") not in (None, "", client_id):
        return None
    added = [("client_id", client_id)] if not named.get("client_id") else []
    if "client_secret" not in named:
        added.append(("client_secret", secret))
    if not added:
        return None
    kept = [(name, value) for name, value in fields if name != "client_id" or value]
    return urlencode([*kept, *added]).encode()


class BasicClientIdMiddleware:
    """Pure ASGI: complete a /token or /revoke form from its Basic credentials."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if (
            scope.get("type") != "http"
            or scope.get("method") != "POST"
            or scope.get("path") not in PATHS
        ):
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        credentials = basic_credentials(headers.get(b"authorization", b"").decode("latin-1"))
        length = headers.get(b"content-length", b"")
        if (
            credentials is None
            or not headers.get(b"content-type", b"").startswith(_FORM)
            or not length.isdigit()
            or int(length) > _MAX_BODY
        ):
            await self.app(scope, receive, send)
            return

        body = b""
        more = True
        while more:
            message = await receive()
            if message["type"] != "http.request":
                await self.app(scope, _replay([message]), send)
                return
            body += message.get("body", b"")
            more = message.get("more_body", False)

        rewritten = with_credentials(body, *credentials)
        if rewritten is not None:
            body = rewritten
            scope = dict(scope)
            scope["headers"] = [
                (name, value)
                for name, value in scope.get("headers") or []
                if name != b"content-length"
            ] + [(b"content-length", str(len(body)).encode())]
        await self.app(scope, _replay([{"type": "http.request", "body": body}], receive), send)


def _replay(messages: list[dict[str, Any]], then: Any = None) -> Any:
    """A receive callable that yields messages, then defers to the original."""
    pending = list(messages)

    async def receive() -> dict[str, Any]:
        if pending:
            return pending.pop(0)
        if then is not None:
            message: dict[str, Any] = await then()
            return message
        return {"type": "http.disconnect"}

    return receive
