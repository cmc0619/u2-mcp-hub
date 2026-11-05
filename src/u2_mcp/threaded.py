"""Run synchronous tools on worker threads, never on the event loop.

FastMCP calls a plain `def` tool directly on the event loop. Every u2-mcp tool is
synchronous and talks to the database, so one slow query or a slow connect would
freeze every other caller in the process -- in team mode, other people's tool
calls, the admin site and the health check, which share the loop.

ThreadedFastMCP overrides call_tool, the one place every transport (stdio,
Streamable HTTP) dispatches a tool. For a synchronous tool it runs a per-call copy
of the registered Tool whose function hands the work to a worker thread. The
registered Tool is left untouched: its schema, its `fn` (the guard, which tests
also call directly) and its metadata stay as they are.

The worker runs in a copy of the caller's context (anyio copies it), so the
caller identity and the route the guard installs are visible inside the tool.
Per-session serialization is unchanged: ConnectionManager's own locks still keep
commands on one session from interleaving.

Tool calls get their own thread limiter rather than anyio's shared default, so a
crowd of callers queued behind slow sessions cannot take every thread from the
admin site and other Starlette work that uses the default pool.
"""

from __future__ import annotations

import functools
from collections.abc import Sequence
from typing import Any

import anyio.to_thread
from anyio import CapacityLimiter
from anyio.lowlevel import RunVar
from mcp.server.fastmcp import FastMCP
from mcp.types import ContentBlock

# Threads for tool calls when no configuration has set a size (stdio, tests):
# anyio's own default.
DEFAULT_TOOL_THREADS = 40

# Threads beyond the connection-slot limit, for tools that never touch a session
# (list_connections, knowledge) so they are not queued behind database calls.
TOOL_THREAD_HEADROOM = 8

_tool_threads = DEFAULT_TOOL_THREADS
# One limiter per event loop: a limiter is bound to the loop it was made on.
_limiter: RunVar[CapacityLimiter] = RunVar("u2_tool_limiter")


def set_tool_thread_limit(max_connections: int) -> None:
    """Size the tool thread pool from the connection-slot limit.

    Each connection slot runs one command at a time, so threads beyond the slot
    count would only wait on a session lock; a little headroom keeps tools that
    need no session responsive. Takes effect on event loops started afterwards.

    Args:
        max_connections: U2_MAX_CONNECTIONS, the most sessions held open at once
    """
    global _tool_threads
    _tool_threads = max(1, max_connections) + TOOL_THREAD_HEADROOM


def tool_thread_limit() -> int:
    """Return the number of threads tool calls may use at once."""
    return _tool_threads


def _tool_limiter() -> CapacityLimiter:
    """Return this event loop's limiter for tool threads, creating it on first use."""
    try:
        return _limiter.get()
    except LookupError:
        limiter = CapacityLimiter(_tool_threads)
        _limiter.set(limiter)
        return limiter


class ThreadedFastMCP(FastMCP):
    """FastMCP that runs synchronous tools on worker threads."""

    async def call_tool(
        self, name: str, arguments: dict[str, Any]
    ) -> Sequence[ContentBlock] | dict[str, Any]:
        """Call a tool by name, off the event loop when the tool is synchronous.

        Args:
            name: Tool name
            arguments: Tool arguments from the client

        Returns:
            The converted tool result, exactly as FastMCP.call_tool returns it
        """
        tool = self._tool_manager.get_tool(name)
        if tool is None or tool.is_async:
            return await super().call_tool(name, arguments)

        fn = tool.fn

        async def in_worker(*args: Any, **kwargs: Any) -> Any:
            return await anyio.to_thread.run_sync(
                functools.partial(fn, *args, **kwargs), limiter=_tool_limiter()
            )

        offloaded = tool.model_copy(update={"fn": in_worker, "is_async": True})
        result: Sequence[ContentBlock] | dict[str, Any] = await offloaded.run(
            arguments, context=self.get_context(), convert_result=True
        )
        return result
