"""Show a newly created token exactly once, across a POST-redirect-GET.

The token is held in memory only, for a few minutes, keyed by the session
that created it. The redirected page takes it out; a refresh finds nothing.
"""

from __future__ import annotations

import hmac
import secrets
import threading
import time
from collections.abc import Callable


class OneTimeReveal:
    """A short-lived, take-once store of values, each tied to one owner.

    Args:
        ttl_seconds: How long a value waits to be taken
        clock: Monotonic time source, replaceable in tests
    """

    def __init__(
        self, *, ttl_seconds: float = 300.0, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._ttl = ttl_seconds
        self._clock = clock
        self._items: dict[str, tuple[str, str, float]] = {}
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        for key in [k for k, (_o, _v, expires) in self._items.items() if expires <= now]:
            del self._items[key]

    def prune(self) -> None:
        """Drop every expired value. Pages call this on each read, reveal or not."""
        with self._lock:
            self._prune(self._clock())

    def put(self, owner: str, value: str) -> str:
        """Hold a value for its owner and return the id that takes it."""
        reveal_id = secrets.token_urlsafe(16)
        with self._lock:
            now = self._clock()
            self._prune(now)
            self._items[reveal_id] = (owner, value, now + self._ttl)
        return reveal_id

    def take(self, owner: str, reveal_id: str) -> str | None:
        """Return the value once, to its owner only; None otherwise."""
        with self._lock:
            self._prune(self._clock())
            item = self._items.get(reveal_id)
            if item is None or not hmac.compare_digest(item[0], owner):
                return None
            del self._items[reveal_id]
            return item[1]
