"""Audit: filters and CSV export."""

from __future__ import annotations

import anyio
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from .security import admin_only
from .services import AuditFilters, audit_csv, audit_entries
from .templating import admin_context, render


@admin_only
async def audit(request: Request) -> Response:
    """The audit trail, filtered; the newest 200 rows."""
    ctx = admin_context(request)
    filters = AuditFilters.from_query(request.query_params)
    connections = ctx.store.list_connections()
    return render(
        request,
        "audit.html",
        entries=audit_entries(ctx, filters),
        filters=filters,
        query=request.url.query,
        users=ctx.store.list_users(),
        connections=connections,
        names={c.id: c.name for c in connections},
    )


@admin_only
async def audit_export(request: Request) -> Response:
    """Every matching audit row as a CSV download."""
    ctx = admin_context(request)
    filters = AuditFilters.from_query(request.query_params)
    body = await anyio.to_thread.run_sync(lambda: audit_csv(ctx, filters))
    return Response(
        body,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="u2-mcp-audit.csv"',
            "Cache-Control": "no-store",
        },
    )


routes = [
    Route("/audit", audit, methods=["GET"]),
    Route("/audit.csv", audit_export, methods=["GET"]),
]
