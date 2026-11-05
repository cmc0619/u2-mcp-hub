"""OAuth state in a throwaway in-memory settings database, for provider tests."""

import contextlib
import threading
from collections.abc import Iterator
from pathlib import Path
from sqlite3 import Connection

from u2_mcp.auth.storage import AuthStorage
from u2_mcp.store.db import open_database


def scratch_auth_storage() -> AuthStorage:
    conn = open_database(Path(":memory:"))
    lock = threading.RLock()

    @contextlib.contextmanager
    def locked() -> Iterator[Connection]:
        with lock:
            yield conn

    return AuthStorage(locked)
