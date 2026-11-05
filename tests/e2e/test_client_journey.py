"""From an empty server to a tool call from an MCP client, the way an admin would do it."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import anyio
import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from playwright.sync_api import Page, expect

from .conftest import Server
from .wizard import create_token, finish_wizard, grant_on

pytestmark = pytest.mark.e2e


async def _call(url: str, token: str, tool: str, arguments: dict[str, Any]) -> str:
    http_client = httpx.AsyncClient(headers={"Authorization": f"Bearer {token}"})
    try:
        async with (
            streamable_http_client(url, http_client=http_client) as (read, write, _),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            result = await session.call_tool(tool, arguments)
    finally:
        await http_client.aclose()
    return "\n".join(getattr(block, "text", "") for block in result.content)


def call_tool(url: str, token: str, tool: str, arguments: dict[str, Any]) -> str:
    """Call an MCP tool as an editor would, off Playwright's event loop."""
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(anyio.run, _call, url, token, tool, arguments).result(timeout=60)


def test_wizard_grant_token_and_a_tool_call(page: Page, server: Server) -> None:
    finish_wizard(page, server)
    mcp_url = server.url("/")

    # Being an admin gives no data access: before a grant the token sees nothing.
    early = create_token(page, server, name="before-grant")
    assert json.loads(call_tool(mcp_url, early, "list_connections", {}))["connections"] == []

    grant_on(page, server)
    expect(page.get_by_role("cell", name="admin", exact=True)).to_be_visible()

    token = create_token(page, server)
    page.reload()
    expect(page.locator("#new-token")).to_have_count(0)  # shown once only

    listed = json.loads(call_tool(mcp_url, token, "list_connections", {}))
    assert [c["name"] for c in listed["connections"]] == ["Prod"]

    # No connection argument: the only connection this person can see is used.
    assert "CUSTOMERS" in call_tool(mcp_url, token, "list_files", {})

    page.get_by_role("button", name="Revoke laptop").click()
    expect(page.locator(".notice")).to_have_text("Token revoked.")
    refused = httpx.post(
        mcp_url,
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream",
        },
        timeout=10,
    )
    assert refused.status_code == 401
