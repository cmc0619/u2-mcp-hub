"""One database session per connection and login.

In team mode the guard installs a route (a connection plus the login to present
there), and this registry hands out that route's session, opening it on first use
and evicting the least recently used one beyond U2_MAX_CONNECTIONS. In stdio mode
there is no route and the one U2_HOST login is used.
"""

from __future__ import annotations

import logging
import re
import threading
from collections import OrderedDict
from collections.abc import Callable

from .config import U2Config
from .connection import ConnectionManager
from .routing import Route, config_for, current_route
from .store import get_store

logger = logging.getLogger(__name__)


class ConnectionRegistry:
    """Holds one ConnectionManager per database login.

    Args:
        config: Server configuration
    """

    def __init__(self, config: U2Config) -> None:
        self._config = config
        # Ordered by least-recently-used, so the eviction victim is obvious.
        self._managers: OrderedDict[str, ConnectionManager] = OrderedDict()
        self._max_connections = max(1, int(getattr(config, "max_connections", 25)))
        self._lock = threading.RLock()

    @property
    def config(self) -> U2Config:
        """Return the server configuration, without opening a connection."""
        return self._config

    def for_route(self, route: Route) -> ConnectionManager:
        """Return the connection manager for a team-mode route.

        Args:
            route: The connection and login chosen for this call

        Returns:
            The manager holding that route's session, pointed at its server
        """
        return self._manager_for(
            route.key,
            lambda: ConnectionManager(
                config_for(self._config, route.connection), route.credentials
            ),
            route.connection.name,
        )

    def evict_connection(self, connection_id: int) -> int:
        """Close every slot for one team-mode connection, whatever the login.

        Called when an admin edits, switches off or deletes a connection: a slot
        keeps the host, port and password it was opened with, so it must not
        outlive the settings it was built from.

        Returns:
            How many slots were closed
        """
        prefix = f"{connection_id}:"
        with self._lock:
            keys = [key for key in self._managers if key.startswith(prefix)]
            evicted = [(key, self._managers.pop(key)) for key in keys]
        self._close_evicted(evicted)
        return len(evicted)

    def evict_owner(self, connection_id: int, user_id: int) -> int:
        """Close one person's slots on a per-user connection (see Route.owner_id).

        Called when that person changes or removes their own U2 login, so their
        next call reconnects with the new one; nobody else's session is touched.

        Returns:
            How many slots were closed
        """
        pattern = re.compile(rf"{connection_id}:v\d+:u{user_id}:")
        with self._lock:
            keys = [key for key in self._managers if pattern.match(key)]
            evicted = [(key, self._managers.pop(key)) for key in keys]
        self._close_evicted(evicted)
        return len(evicted)

    def sessions_for_connection(self, connection_id: int) -> list[str]:
        """Return the logins (user@account) holding a slot on one connection."""
        prefix = f"{connection_id}:"
        with self._lock:
            return [
                re.sub(r"^v\d+:(u\d+:)?", "", key[len(prefix) :])
                for key in self._managers
                if key.startswith(prefix)
            ]

    def _manager_for(
        self, key: str, create: Callable[[], ConnectionManager], label: str
    ) -> ConnectionManager:
        """Return the manager for a key, creating it (and evicting) if needed."""
        with self._lock:
            manager = self._managers.get(key)
            if manager is not None:
                self._managers.move_to_end(key)
                return manager

            evicted = self._take_evictable_managers()
            manager = create()
            self._managers[key] = manager
            logger.info(
                f"Opened connection slot '{key}' for {label} "
                f"({len(self._managers)}/{self._max_connections} in use)"
            )

        # Closing happens outside the lock. The connection being evicted may be
        # the one that stopped responding, and closing a wedged socket can block
        # for as long as the network timeout -- which would freeze every caller.
        self._close_evicted(evicted)
        return manager

    def _take_evictable_managers(self) -> list[tuple[str, ConnectionManager]]:
        """Remove least-recently-used slots to make room, without closing them.

        Without a ceiling, one connection per caller becomes one connection per
        caller *ever seen*, and a crowd of authenticated users could exhaust the
        database's own connection limit. Callers whose slot is evicted simply
        reconnect on their next request.

        Returns:
            The removed slots, for the caller to close outside the lock
        """
        evicted: list[tuple[str, ConnectionManager]] = []
        while len(self._managers) >= self._max_connections:
            evicted.append(self._managers.popitem(last=False))
        return evicted

    @staticmethod
    def _close_evicted(evicted: list[tuple[str, ConnectionManager]]) -> None:
        """Close connections already removed from the registry, on a daemon thread.

        uopy's close waits for any RPC in flight on the session, and the caller may
        be the HTTP event loop (an admin save, switch, delete or disconnect), so
        the caller never waits for the close.

        Args:
            evicted: Slots removed from the registry
        """
        if not evicted:
            return

        def close_all() -> None:
            for key, manager in evicted:
                logger.info(f"Evicting connection slot '{key}'")
                try:
                    manager.disconnect()
                except Exception as exc:  # noqa: BLE001 - nobody is waiting to hear it
                    logger.warning(f"Error closing evicted connection '{key}': {exc}")

        threading.Thread(target=close_all, name="u2-evict-close", daemon=True).start()

    def current(self) -> ConnectionManager:
        """Return the connection manager for the current call.

        In team mode the guard has installed a route naming the connection and
        login; in stdio mode the environment's login is used.
        """
        route = current_route()
        if route is not None:
            return self.for_route(route)
        if get_store() is not None:
            # Team mode never falls back to the environment's login.
            raise RuntimeError("no connection was chosen for this call")
        return self._manager_for(
            "local", lambda: ConnectionManager(self._config), self._config.user
        )

    def active_logins(self) -> list[str]:
        """Return the database logins that currently hold a connection slot."""
        with self._lock:
            return sorted(self._managers)

    def disconnect_all(self) -> int:
        """Close every connection this registry holds.

        Returns:
            Count of connections closed
        """
        with self._lock:
            closed = sum(manager.disconnect() for manager in self._managers.values())
            self._managers.clear()
            return closed
