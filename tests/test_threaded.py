"""Synchronous tools run on worker threads, so a slow one never stalls the loop."""

from __future__ import annotations

import threading
import time
from typing import Any, cast

import anyio
import pytest
from mcp.server.fastmcp import FastMCP

from u2_mcp import server, threaded
from u2_mcp.identity import CallerIdentity, current_caller, use_caller
from u2_mcp.routing import Route, current_route, use_route
from u2_mcp.threaded import ThreadedFastMCP, set_tool_thread_limit, tool_thread_limit


@pytest.mark.asyncio
async def test_a_blocked_tool_does_not_stall_another_call() -> None:
    """While one call waits in its tool, another call on the same loop completes."""
    probe = ThreadedFastMCP("probe")
    entered = threading.Event()
    release = threading.Event()

    @probe.tool()
    def slow() -> dict[str, Any]:
        entered.set()
        # Bounded, so a regression fails the timing assertion instead of hanging.
        release.wait(timeout=5)
        return {"slow": True}

    @probe.tool()
    def quick() -> dict[str, Any]:
        return {"quick": True}

    results: dict[str, Any] = {}

    async def call_slow() -> None:
        results["slow"] = await probe.call_tool("slow", {})

    try:
        async with anyio.create_task_group() as group:
            group.start_soon(call_slow)
            while not entered.is_set():
                await anyio.sleep(0.01)
            started = time.monotonic()
            results["quick"] = await probe.call_tool("quick", {})
            elapsed = time.monotonic() - started
            # Run inline, the slow call would have hogged the loop until its wait
            # timed out, and finished before the quick one even started.
            assert "slow" not in results
            release.set()
    finally:
        release.set()

    assert elapsed < 1.0
    assert "quick" in str(results["quick"])
    assert "slow" in str(results["slow"])


@pytest.mark.asyncio
async def test_caller_and_route_are_visible_inside_the_worker() -> None:
    """The context the request set up reaches the tool on its worker thread."""
    probe = ThreadedFastMCP("probe")
    seen: dict[str, Any] = {}

    @probe.tool()
    def whoami() -> dict[str, Any]:
        seen["thread"] = threading.get_ident()
        seen["caller"] = current_caller()
        seen["route"] = current_route()
        return {}

    alice = CallerIdentity(subject="alice", name="Alice", user_id=7)
    route = cast(Route, object())
    with use_caller(alice), use_route(route):
        await probe.call_tool("whoami", {})

    assert seen["thread"] != threading.get_ident()
    assert seen["caller"] is alice
    assert seen["route"] is route


@pytest.mark.asyncio
async def test_async_tools_still_run_on_the_loop() -> None:
    """Async tools are left to FastMCP; only synchronous ones are moved."""
    probe = ThreadedFastMCP("probe")
    seen: dict[str, int] = {}

    @probe.tool()
    async def native() -> dict[str, Any]:
        seen["thread"] = threading.get_ident()
        return {}

    await probe.call_tool("native", {})
    assert seen["thread"] == threading.get_ident()


@pytest.mark.asyncio
async def test_tool_listing_is_unchanged() -> None:
    """Clients see the same schema whichever FastMCP class registered the tool."""

    def lookup(file_name: str, record_id: str, connection: str | None = None) -> dict[str, Any]:
        """Look a record up."""
        return {}

    plain, threaded = FastMCP("plain"), ThreadedFastMCP("threaded")
    plain.tool()(lookup)
    threaded.tool()(lookup)

    assert [t.model_dump() for t in await plain.list_tools()] == [
        t.model_dump() for t in await threaded.list_tools()
    ]


def test_server_instances_offload_tools() -> None:
    """The module-level instance, used by every transport, is the threaded one."""
    assert isinstance(server.mcp, ThreadedFastMCP)


def test_thread_limit_follows_the_connection_slots(monkeypatch: pytest.MonkeyPatch) -> None:
    """The tool pool is sized from U2_MAX_CONNECTIONS plus headroom."""
    monkeypatch.setattr(threaded, "_tool_threads", threaded.DEFAULT_TOOL_THREADS)
    assert tool_thread_limit() == threaded.DEFAULT_TOOL_THREADS

    set_tool_thread_limit(25)
    assert tool_thread_limit() == 25 + threaded.TOOL_THREAD_HEADROOM
