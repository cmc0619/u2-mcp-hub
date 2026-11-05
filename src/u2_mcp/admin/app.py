"""The admin site as a Starlette application, mounted by the server at /admin."""

from __future__ import annotations

import logging

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.routing import BaseRoute, Mount
from starlette.staticfiles import StaticFiles

from . import (
    routes_audit,
    routes_auth,
    routes_connections,
    routes_grants,
    routes_knowledge,
    routes_me,
    routes_roles,
    routes_setup,
    routes_sso,
    routes_users,
)
from .context import AdminContext
from .security import AdminGuard

logger = logging.getLogger(__name__)


def build_admin_app(ctx: AdminContext) -> Starlette:
    """Build the admin site.

    Args:
        ctx: The site's dependencies, kept on app.state.ctx

    Returns:
        A Starlette app whose paths are relative to its mount point
    """
    if ctx.config.admin_signin_limit == 0:
        logger.warning(
            "Admin sign-in rate limit is off (U2_ADMIN_SIGNIN_LIMIT=0). "
            "Use this only for development."
        )
    routes: list[BaseRoute] = [
        *routes_setup.routes,
        *routes_auth.routes,
        *routes_sso.routes,
        *routes_connections.routes,
        *routes_grants.routes,
        *routes_knowledge.routes,
        *routes_me.routes,
        *routes_users.routes,
        *routes_roles.routes,
        *routes_audit.routes,
        Mount("/static", app=StaticFiles(packages=[("u2_mcp.admin", "static")]), name="static"),
    ]
    app = Starlette(routes=routes, middleware=[Middleware(AdminGuard, ctx=ctx)])
    app.state.ctx = ctx
    return app
