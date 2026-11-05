"""Checking that a connection's settings work: what the admin site's Test button runs."""

from __future__ import annotations

import contextlib
import math
import threading
import time
from dataclasses import dataclass

from .config import U2Config
from .connection import ConnectionManager
from .credentials import U2Credentials
from .routing import config_for
from .store.models import Connection

CHECK_COMMAND = "COUNT VOC"
CHECK_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True)
class CheckResult:
    """What a test of a connection found."""

    ok: bool
    message: str
    elapsed_ms: float


def _elapsed_ms(started: float) -> float:
    return (time.monotonic() - started) * 1000.0


def check_connection(
    base: U2Config,
    connection: Connection,
    credentials: U2Credentials,
    *,
    timeout: float = CHECK_TIMEOUT_SECONDS,
) -> CheckResult:
    """Open a session with these settings and run COUNT VOC, within a time limit.

    The session is the test's own: it never enters the connection registry, so a
    test can neither reuse nor disturb anyone's live session. This blocks the
    calling thread for up to `timeout` seconds, so call it from a worker thread,
    never on the event loop.

    Args:
        base: Server configuration; safety settings carry over
        connection: The settings to test (need not be saved yet)
        credentials: The login to test with
        timeout: Seconds to wait for the whole attempt

    Returns:
        The result, with the driver's own error text on failure
    """
    started = time.monotonic()
    outcome: list[CheckResult] = []
    abandoned = threading.Event()
    no_answer = f"No answer from {connection.host}:{connection.port} within {timeout:g} seconds."

    def attempt() -> None:
        # The driver's connect timeout is capped at the check's own, so an attempt
        # the caller gave up on does not linger connecting for the full U2_TIMEOUT.
        settings = config_for(base, connection)
        settings = settings.model_copy(
            update={"timeout": max(1, min(settings.timeout, math.ceil(timeout)))}
        )
        manager = ConnectionManager(settings, credentials)
        try:
            manager.connect()
            if abandoned.is_set():
                return  # the caller gave up while we connected; just close (finally)
            remaining = max(0.1, timeout - (time.monotonic() - started))
            response = manager.execute_command(CHECK_COMMAND, timeout=remaining)
            outcome.append(
                CheckResult(
                    True,
                    f"Connected to {connection.account} on {connection.host}. "
                    f"{CHECK_COMMAND}: {response.strip()}",
                    _elapsed_ms(started),
                )
            )
        except TimeoutError:
            outcome.append(CheckResult(False, no_answer, _elapsed_ms(started)))
        except Exception as exc:  # noqa: BLE001 - the driver's own words are the point
            outcome.append(CheckResult(False, str(exc) or type(exc).__name__, _elapsed_ms(started)))
        finally:
            # Closing a failed test session is best effort.
            with contextlib.suppress(Exception):
                manager.disconnect()

    # A daemon thread: if the host never answers, the attempt is abandoned rather
    # than holding the admin's request (or the process at shutdown) hostage.
    worker = threading.Thread(target=attempt, name=f"check-{connection.name}", daemon=True)
    worker.start()
    worker.join(timeout)
    if outcome:
        return outcome[0]
    abandoned.set()
    return CheckResult(False, no_answer, _elapsed_ms(started))
