"""Setup state and the one-time setup code."""

import re

from u2_mcp.setup_code import (
    SETUP_CODE_SETTING,
    check_setup_code,
    completed_step,
    ensure_setup_code,
    finish_setup,
    is_setup_complete,
    mark_step_done,
    next_step,
)
from u2_mcp.store.repo import Store


def test_a_new_server_starts_at_the_admin_step(store: Store) -> None:
    assert completed_step(store) is None
    assert next_step(store) == "admin"
    assert is_setup_complete(store) is False


def test_steps_advance_and_never_go_back(store: Store) -> None:
    mark_step_done(store, "admin")
    mark_step_done(store, "connection")
    mark_step_done(store, "admin")  # pressing Save again on an earlier step

    assert completed_step(store) == "connection"
    assert next_step(store) == "server_address"


def test_the_code_is_stable_until_setup_finishes(store: Store) -> None:
    code = ensure_setup_code(store)

    assert code is not None
    assert re.fullmatch(r"[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}", code)
    assert ensure_setup_code(store) == code


def test_the_code_is_checked_forgivingly(store: Store) -> None:
    code = ensure_setup_code(store)
    assert code is not None

    assert check_setup_code(store, f"  {code.lower()} ") is True
    assert check_setup_code(store, code.replace("-", "")) is True
    assert check_setup_code(store, "AAAA-AAAA-AAAA") is False
    assert check_setup_code(store, "") is False


def test_finishing_removes_the_code(store: Store) -> None:
    ensure_setup_code(store)

    finish_setup(store)

    assert is_setup_complete(store) is True
    assert next_step(store) == "done"
    assert store.get_setting(SETUP_CODE_SETTING) is None
    assert ensure_setup_code(store) is None


def test_non_ascii_input_is_simply_wrong(store: Store) -> None:
    ensure_setup_code(store)

    assert check_setup_code(store, "é") is False
    assert check_setup_code(store, "ABCD-EFGH-JKLé") is False
