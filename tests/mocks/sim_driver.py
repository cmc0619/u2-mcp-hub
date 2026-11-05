"""A scripted U2 driver for browser tests: U2_DRIVER=tests.mocks.sim_driver.

Rocket U2 cannot run in CI, so the browser tests drive the real server against
this module. It answers like a healthy server except for three scripted
failures, each with fixed text a test can assert on.
"""

from __future__ import annotations

import time
from typing import Any

from tests.mocks.mock_uopy import MockCommand as Command
from tests.mocks.mock_uopy import MockFile as File
from tests.mocks.mock_uopy import MockList as List
from tests.mocks.mock_uopy import MockSession, UOError
from tests.mocks.mock_uopy import MockSubroutine as Subroutine

UNREACHABLE_HOST = "unreachable.invalid"
SLOW_HOST = "slow.invalid"
SLOW_SECONDS = 30.0
WRONG_PASSWORD = "wrong-password"
COUNT_VOC_RESPONSE = "1234 records counted."
# What a selection returns, so list_files (SSELECT VOC) names the account's files.
ACCOUNT_FILES = ["CUSTOMERS", "ORDERS", "PRODUCTS"]

__all__ = ["Command", "File", "List", "Subroutine", "UOError", "connect"]


def connect(**kwargs: Any) -> MockSession:
    """Open a simulated session, or fail the way a real server would."""
    host = str(kwargs.get("host", ""))
    if host == UNREACHABLE_HOST:
        raise UOError(message=f"Cannot reach {host}:{kwargs.get('port')}: connection refused")
    if host == SLOW_HOST:
        time.sleep(SLOW_SECONDS)
    if kwargs.get("password") == WRONG_PASSWORD:
        raise UOError(message="Login refused: wrong user name or password")
    session = MockSession(**kwargs)
    session.command_responses["COUNT VOC"] = COUNT_VOC_RESPONSE
    session.set_select_list(ACCOUNT_FILES)
    return session
