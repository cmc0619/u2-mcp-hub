"""U2_ADMIN_SIGNIN_LIMIT: the sign-in attempts allowed a minute, and 0 for development."""

import dataclasses
import logging
from collections.abc import Callable

import pytest

from u2_mcp.admin.app import build_admin_app
from u2_mcp.admin.context import AdminContext
from u2_mcp.config import U2Config
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import finish_setup

from .helpers import PASSWORD, admin_client, sign_in

WARNING = (
    "Admin sign-in rate limit is off (U2_ADMIN_SIGNIN_LIMIT=0). Use this only for development."
)


@pytest.fixture
def with_limit(
    ctx: AdminContext, monkeypatch: pytest.MonkeyPatch
) -> Callable[[str | None], AdminContext]:
    """A context whose config reads U2_ADMIN_SIGNIN_LIMIT (None leaves it unset)."""

    def make(value: str | None) -> AdminContext:
        if value is None:
            monkeypatch.delenv("U2_ADMIN_SIGNIN_LIMIT", raising=False)
        else:
            monkeypatch.setenv("U2_ADMIN_SIGNIN_LIMIT", value)
        made = dataclasses.replace(ctx, config=U2Config())
        finish_setup(made.store)
        made.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
        return made

    return make


def _statuses(ctx: AdminContext, attempts: int) -> list[int]:
    with admin_client(ctx) as client:
        return [sign_in(client, password="wrong password!").status_code for _ in range(attempts)]  # type: ignore[attr-defined]


def test_the_default_is_five_a_minute(with_limit: Callable[[str | None], AdminContext]) -> None:
    ctx = with_limit(None)
    assert ctx.config.admin_signin_limit == 5
    assert _statuses(ctx, 6) == [401] * 5 + [429]


def test_three_allows_three_then_refuses(with_limit: Callable[[str | None], AdminContext]) -> None:
    assert _statuses(with_limit("3"), 5) == [401] * 3 + [429] * 2


def test_zero_never_refuses(with_limit: Callable[[str | None], AdminContext]) -> None:
    assert _statuses(with_limit("0"), 30) == [401] * 30


def test_zero_also_lets_the_right_password_in_after_many_failures(
    with_limit: Callable[[str | None], AdminContext],
) -> None:
    ctx = with_limit("0")
    with admin_client(ctx) as client:
        for _ in range(10):
            sign_in(client, password="wrong password!")
        assert sign_in(client).status_code == 303  # type: ignore[attr-defined]


def test_a_negative_limit_fails_config_validation(
    monkeypatch: pytest.MonkeyPatch, mock_env: dict[str, str]
) -> None:
    monkeypatch.setenv("U2_ADMIN_SIGNIN_LIMIT", "-1")
    with pytest.raises(ValueError, match="U2_ADMIN_SIGNIN_LIMIT"):
        U2Config()


def test_a_limit_of_zero_is_logged_once_at_startup(
    with_limit: Callable[[str | None], AdminContext], caplog: pytest.LogCaptureFixture
) -> None:
    ctx = with_limit("0")
    with caplog.at_level(logging.WARNING):
        build_admin_app(ctx)
    assert [r.getMessage() for r in caplog.records if "rate limit" in r.getMessage()] == [WARNING]


@pytest.mark.parametrize("value", [None, "3"])
def test_a_limit_above_zero_logs_no_warning(
    with_limit: Callable[[str | None], AdminContext],
    caplog: pytest.LogCaptureFixture,
    value: str | None,
) -> None:
    with caplog.at_level(logging.WARNING):
        build_admin_app(with_limit(value))
    assert "rate limit" not in caplog.text
