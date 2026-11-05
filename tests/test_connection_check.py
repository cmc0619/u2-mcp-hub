"""The Test button: connect, run COUNT VOC, report the driver's own words."""

import time
from collections.abc import Iterator
from typing import Any

import pytest

from tests.mocks import sim_driver
from tests.mocks.mock_uopy import MockSession
from u2_mcp.config import U2Config
from u2_mcp.connection_check import check_connection
from u2_mcp.credentials import U2Credentials
from u2_mcp.driver import reset_driver
from u2_mcp.store.models import Connection


@pytest.fixture(autouse=True)
def scripted_driver(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("U2_DRIVER", "tests.mocks.sim_driver")
    reset_driver()
    yield
    reset_driver()


def _connection(host: str = "u2.example") -> Connection:
    return Connection(
        id=0,
        name="Prod",
        host=host,
        port=31438,
        service="uvcs",
        account="PROD",
        ssl=False,
        login_mode="shared",
        shared_user="svc",
        has_shared_password=True,
        read_only=True,
        enabled=True,
    )


def _login(password: str = "secret") -> U2Credentials:
    return U2Credentials(user="svc", password=password, account="PROD", is_shared=True)


def test_a_working_connection_reports_the_count(mock_config: U2Config) -> None:
    result = check_connection(mock_config, _connection(), _login())

    assert result.ok is True
    assert sim_driver.COUNT_VOC_RESPONSE in result.message


def test_a_wrong_password_shows_the_driver_text(mock_config: U2Config) -> None:
    result = check_connection(mock_config, _connection(), _login(sim_driver.WRONG_PASSWORD))

    assert result.ok is False
    assert "Login refused: wrong user name or password" in result.message


def test_an_unreachable_host_shows_the_driver_text(mock_config: U2Config) -> None:
    result = check_connection(mock_config, _connection(sim_driver.UNREACHABLE_HOST), _login())

    assert result.ok is False
    assert "Cannot reach unreachable.invalid:31438" in result.message


def test_a_silent_host_times_out(mock_config: U2Config) -> None:
    result = check_connection(mock_config, _connection(sim_driver.SLOW_HOST), _login(), timeout=0.5)

    assert result.ok is False
    assert result.message == "No answer from slow.invalid:31438 within 0.5 seconds."
    assert result.elapsed_ms < 5000


def test_a_late_connect_after_the_timeout_runs_no_command(
    mock_config: U2Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    sessions: list[MockSession] = []
    real_connect = sim_driver.connect

    def recording_connect(**kwargs: Any) -> MockSession:
        session = real_connect(**kwargs)
        sessions.append(session)
        return session

    monkeypatch.setattr(sim_driver, "SLOW_SECONDS", 1.0)
    monkeypatch.setattr(sim_driver, "connect", recording_connect)

    result = check_connection(mock_config, _connection(sim_driver.SLOW_HOST), _login(), timeout=0.3)
    assert result.message == "No answer from slow.invalid:31438 within 0.3 seconds."

    time.sleep(1.5)
    assert len(sessions) == 1  # the abandoned attempt did connect, late
    assert sessions[0].executed_commands == []


def test_a_hanging_command_reports_the_same_no_answer_text(
    mock_config: U2Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_connect = sim_driver.connect

    def hanging_connect(**kwargs: Any) -> MockSession:
        session = real_connect(**kwargs)
        session.command_delay_seconds = 5
        return session

    monkeypatch.setattr(sim_driver, "connect", hanging_connect)

    result = check_connection(mock_config, _connection(), _login(), timeout=0.5)

    assert result.ok is False
    assert result.message == "No answer from u2.example:31438 within 0.5 seconds."
    assert result.elapsed_ms < 3000


def test_the_connect_timeout_is_capped_at_the_check_timeout(
    mock_config: U2Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The driver never waits longer to connect than the check itself waits."""
    seen: dict[str, Any] = {}
    real_connect = sim_driver.connect

    def recording_connect(**kwargs: Any) -> MockSession:
        seen.update(kwargs)
        return real_connect(**kwargs)

    monkeypatch.setattr(sim_driver, "connect", recording_connect)
    result = check_connection(mock_config, _connection(), _login(), timeout=5)

    assert result.ok is True
    assert seen["timeout"] == min(mock_config.timeout, 5)
