"""Changing one record safely: the U2 record lock, and the guard that backs it up.

A U2 record lock belongs to the session, not to the caller. It keeps another
session out, but two tool calls on the same connection share one session and so
hold the same lock. Read-change-write tools therefore take a per-manager guard
as well, so those calls take turns too.
"""

from __future__ import annotations

import logging
import threading
import weakref
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

logger = logging.getLogger(__name__)

RECORD_NOT_FOUND = 30001  # uopy's status for a record that is not there
RECORD_LOCKED = 30002  # uopy's status for a record another user has locked
LOCK_EXCLUSIVE = 4  # uopy.LOCK_EXCLUSIVE without LOCK_WAIT: a READU that never waits

_write_guards: weakref.WeakKeyDictionary[Any, threading.Lock] = weakref.WeakKeyDictionary()
_write_guards_lock = threading.Lock()


def is_missing(error: Exception) -> bool:
    """Return whether a read failed only because the record is not there."""
    return getattr(error, "code", None) == RECORD_NOT_FOUND


def is_locked(error: Exception) -> bool:
    """Return whether a read failed because another user holds the record lock."""
    return getattr(error, "code", None) == RECORD_LOCKED


def write_guard(manager: Any) -> threading.Lock:
    """Return the lock that serializes read-change-write calls on one manager's session."""
    with _write_guards_lock:
        guard = _write_guards.get(manager)
        if guard is None:
            guard = _write_guards[manager] = threading.Lock()
        return guard


@contextmanager
def record_lock_released(handle: Any, record_id: str) -> Iterator[None]:
    """Release this session's lock on a record however the block ends."""
    try:
        yield
    finally:
        try:
            handle.unlock(record_id)
        except Exception as error:  # a dead session has already dropped its locks
            logger.warning(f"Could not release the lock on {record_id}: {error}")
