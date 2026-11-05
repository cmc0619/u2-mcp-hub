"""The admin site, mounted at /admin in team mode."""

from . import ids as _ids  # noqa: F401  (registers the `{id:id}` path convertor first)
from .app import build_admin_app
from .context import AdminContext

__all__ = ["AdminContext", "build_admin_app"]
