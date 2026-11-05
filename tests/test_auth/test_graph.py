"""Entra group overage: groups come from Graph, or not at all. Never from the token's URL."""

from typing import Any

import httpx
import pytest

from u2_mcp.auth.graph import GraphGroups

TID = "11111111-2222-3333-4444-555555555555"
OID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _graph(answer: Any, seen: list[httpx.Request]) -> GraphGroups:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return answer(request)

    return GraphGroups(
        "client", "secret", http=lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )


def _ok(request: httpx.Request) -> httpx.Response:
    if request.url.host == "login.microsoftonline.com":
        return httpx.Response(200, json={"access_token": "graph-token"})
    return httpx.Response(200, json={"value": ["g-1", "g-2"]})


@pytest.mark.asyncio
async def test_groups_are_looked_up_for_the_tenant_and_user() -> None:
    seen: list[httpx.Request] = []
    groups = await _graph(_ok, seen)(
        {
            "tid": TID,
            "oid": OID,
            "_claim_sources": {"src1": {"endpoint": "https://evil.example/steal"}},
        }
    )
    assert groups == ["g-1", "g-2"]
    assert str(seen[0].url) == f"https://login.microsoftonline.com/{TID}/oauth2/v2.0/token"
    assert str(seen[1].url) == f"https://graph.microsoft.com/v1.0/users/{OID}/getMemberGroups"
    assert seen[1].headers["authorization"] == "Bearer graph-token"
    assert all(r.url.host != "evil.example" for r in seen)


@pytest.mark.asyncio
@pytest.mark.parametrize("claims", [{}, {"tid": "../x", "oid": OID}, {"tid": TID, "oid": "1/2"}])
async def test_missing_or_odd_ids_mean_no_lookup(claims: dict[str, str]) -> None:
    seen: list[httpx.Request] = []
    assert await _graph(_ok, seen)(claims) is None
    assert seen == []


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [400, 403, 500])
async def test_graph_failures_mean_no_groups(status: int) -> None:
    def failing(request: httpx.Request) -> httpx.Response:
        if request.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json={"access_token": "t"})
        return httpx.Response(status, json={"error": {"code": "Authorization_RequestDenied"}})

    assert await _graph(failing, [])({"tid": TID, "oid": OID}) is None


@pytest.mark.asyncio
async def test_a_network_error_means_no_groups() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    assert await _graph(refuse, [])({"tid": TID, "oid": OID}) is None


@pytest.mark.asyncio
async def test_no_access_token_means_no_lookup_and_no_bearer_none() -> None:
    seen: list[httpx.Request] = []

    def no_token(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token_type": "Bearer"})

    assert await _graph(no_token, seen)({"tid": TID, "oid": OID}) is None
    assert [r.url.host for r in seen] == ["login.microsoftonline.com"]
    assert all("authorization" not in r.headers for r in seen)


@pytest.mark.asyncio
@pytest.mark.parametrize("token_body", [["not", "a", "dict"], "text", None])
async def test_a_malformed_token_answer_means_no_groups(token_body: Any) -> None:
    def odd(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=token_body)

    assert await _graph(odd, [])({"tid": TID, "oid": OID}) is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "content", [b"<html>not json</html>", b'["a"]', b'{"value": "x"}', b'{"value": null}', b"{}"]
)
async def test_a_malformed_groups_answer_means_no_groups(content: bytes) -> None:
    def odd(request: httpx.Request) -> httpx.Response:
        if request.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json={"access_token": "t"})
        return httpx.Response(200, content=content)

    assert await _graph(odd, [])({"tid": TID, "oid": OID}) is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error", [httpx.ReadTimeout("slow"), httpx.InvalidURL("bad"), RuntimeError("boom")]
)
async def test_any_failure_of_the_http_client_means_no_groups(error: Exception) -> None:
    def explode(request: httpx.Request) -> httpx.Response:
        raise error

    assert await _graph(explode, [])({"tid": TID, "oid": OID}) is None


@pytest.mark.asyncio
async def test_a_client_factory_that_fails_means_no_groups() -> None:
    def broken() -> httpx.AsyncClient:
        raise RuntimeError("no client")

    assert await GraphGroups("c", "s", http=broken)({"tid": TID, "oid": OID}) is None
