"""Server-rendered pages: one Jinja2 environment, autoescaped."""

from __future__ import annotations

from datetime import UTC, datetime
from functools import lru_cache
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape
from starlette.requests import Request
from starlette.responses import HTMLResponse

from ..setup_code import is_setup_complete
from ..version import running_version
from .context import AdminContext
from .problems import PROBLEMS
from .sso_services import groups_visible

# Notices are chosen by a short code in the query string, never by free text, so
# a link cannot put words of its own on an admin page.
NOTICES: dict[str, str] = {
    "saved": "Saved.",
    "deleted": "Deleted.",
    "disconnected": "Sessions closed.",
    "signed_out": "You are signed out.",
    "password_changed": "Your password is changed.",
    "setup_done": "Setup is finished.",
    "revoked": "Token revoked.",
    "app_signed_out": "App signed out. It must sign in again to use the server.",
    "apps_signed_out": "Apps signed out. Each must sign in again to use the server.",
    "token_created": "Token created.",
    "u2_login_saved": "Your U2 login is saved.",
    "u2_login_removed": "Your U2 login is removed.",
    "u2_login_cleared": "U2 login cleared.",
    "password_reset": "Temporary password set. They must change it at their next sign-in.",
    "user_deleted": "Person deleted.",
}


def when(value: float | None) -> str:
    """Format a stored timestamp for a page: YYYY-MM-DD HH:MM UTC, or blank."""
    if value is None:
        return ""
    try:
        return datetime.fromtimestamp(value, tz=UTC).strftime("%Y-%m-%d %H:%M UTC")
    except (OverflowError, OSError, ValueError):
        return "far future"


@lru_cache(maxsize=1)
def _environment() -> Environment:
    env = Environment(
        loader=PackageLoader("u2_mcp.admin", "templates"),
        autoescape=select_autoescape(["html"], default_for_string=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["when"] = when
    env.globals["running_version"] = running_version
    return env


def admin_context(request: Request) -> AdminContext:
    """Return the admin site's dependencies for this request."""
    ctx: AdminContext = request.app.state.ctx
    return ctx


def render(
    request: Request, template: str, *, status_code: int = 200, **context: Any
) -> HTMLResponse:
    """Render a template with the values every page uses.

    Args:
        request: The current request
        template: Path under admin/templates
        status_code: HTTP status
        **context: Page values; these override the defaults below
    """
    ctx = admin_context(request)
    user = getattr(request.state, "user", None)
    values: dict[str, Any] = {
        "request": request,
        "user": user,
        "csrf_token": getattr(request.state, "csrf_token", ""),
        "setup_complete": is_setup_complete(ctx.store),
        "notice": NOTICES.get(request.query_params.get("notice", "")),
        "problem": PROBLEMS.get(request.query_params.get("problem", "")),
        # Only admins see the Groups tab and the grants editor, so only they pay for it.
        "groups_visible": bool(user and user.is_admin and groups_visible(ctx)),
    }
    values.update(context)
    page = _environment().get_template(template).render(**values)
    # Admin pages show settings and sessions; never let a browser or proxy keep them.
    return HTMLResponse(page, status_code=status_code, headers={"Cache-Control": "no-store"})
