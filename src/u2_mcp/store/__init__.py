"""The settings database: connections, people, roles, grants, tokens and audit.

The store exists only in team mode (U2_SECRET_KEY set on an HTTP transport). In
stdio mode, and in HTTP mode without that key, get_store() returns None and the
server behaves exactly as it did before team mode existed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .repo import Store

_store: Store | None = None
_global_read_only = False


def install_store(store: Store | None, *, global_read_only: bool = False) -> None:
    """Install (or, with None, remove) the process-wide settings store.

    Args:
        store: The store, or None to leave team mode
        global_read_only: The U2_READ_ONLY switch, which caps every connection
    """
    global _store, _global_read_only
    _store = store
    _global_read_only = global_read_only


def get_store() -> Store | None:
    """Return the settings store, or None outside team mode."""
    return _store


def is_global_read_only() -> bool:
    """Return the U2_READ_ONLY switch recorded when the store was installed."""
    return _global_read_only
