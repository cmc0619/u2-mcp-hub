"""Setup state and the one-time code that guards the setup wizard.

Until setup is finished, anyone who can reach /admin/setup could create the
first admin. The code proves they can also read the server's log or run a
command on it. It is stored encrypted, because `u2-mcp admin show-setup-code`
runs in a separate process and must be able to print it.
"""

from __future__ import annotations

import hmac
import secrets

from .store.repo import Store

SETUP_STEPS: tuple[str, ...] = ("admin", "connection", "server_address", "sso", "done")
SETUP_STATE_SETTING = "setup_state"
SETUP_COMPLETE_SETTING = "setup_complete"
SETUP_CODE_SETTING = "setup_code"

WRONG_SETUP_CODE_MESSAGE = (
    "That setup code is not right. Find the current code in the server log, "
    "or run: u2-mcp admin show-setup-code"
)

_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O or 1/I to misread


def is_setup_complete(store: Store) -> bool:
    """Return whether the wizard's Finish has been pressed."""
    return bool(store.get_setting(SETUP_COMPLETE_SETTING, False))


def completed_step(store: Store) -> str | None:
    """Return the furthest completed step, or None."""
    value = store.get_setting(SETUP_STATE_SETTING)
    return value if value in SETUP_STEPS else None


def next_step(store: Store) -> str:
    """Return the first step not yet completed ("done" once all others are)."""
    done = completed_step(store)
    if done is None:
        return SETUP_STEPS[0]
    index = SETUP_STEPS.index(done)
    return SETUP_STEPS[min(index + 1, len(SETUP_STEPS) - 1)]


def mark_step_done(store: Store, step: str) -> None:
    """Record a step as completed. Re-saving an earlier step never moves progress back."""
    done = completed_step(store)
    if done is None or SETUP_STEPS.index(step) > SETUP_STEPS.index(done):
        store.set_setting(SETUP_STATE_SETTING, step)


def _generate() -> str:
    raw = "".join(secrets.choice(_ALPHABET) for _ in range(12))
    return f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}"


def _normalise(code: str) -> str:
    return "".join(ch for ch in code.upper() if ch.isascii() and ch.isalnum())


def ensure_setup_code(store: Store) -> str | None:
    """Return the setup code, creating it if needed; None once setup is finished."""
    if is_setup_complete(store):
        return None
    existing = store.get_secret_setting(SETUP_CODE_SETTING)
    if existing:
        return existing
    code = _generate()
    store.set_secret_setting(SETUP_CODE_SETTING, code)
    return code


def check_setup_code(store: Store, presented: str) -> bool:
    """Return whether a typed code matches, ignoring case, spaces and dashes."""
    expected = store.get_secret_setting(SETUP_CODE_SETTING)
    if not expected or not presented:
        return False
    return hmac.compare_digest(_normalise(expected).encode(), _normalise(presented).encode())


def finish_setup(store: Store) -> None:
    """Mark setup finished and destroy the code."""
    store.set_setting(SETUP_STATE_SETTING, SETUP_STEPS[-1])
    store.set_setting(SETUP_COMPLETE_SETTING, True)
    store.set_secret_setting(SETUP_CODE_SETTING, None)
