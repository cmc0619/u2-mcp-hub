"""Secrets in the settings database must be useless without U2_SECRET_KEY."""

import pytest

from u2_mcp.store.crypto import SecretBox, SecretUnreadable

KEY = "k" * 40
OTHER_KEY = "o" * 40


def test_a_secret_round_trips() -> None:
    box = SecretBox(KEY)
    assert box.decrypt(box.encrypt("hunter2")) == "hunter2"


def test_ciphertext_does_not_contain_the_secret() -> None:
    assert "hunter2" not in SecretBox(KEY).encrypt("hunter2")


def test_a_different_key_cannot_read_the_secret() -> None:
    stored = SecretBox(KEY).encrypt("hunter2")
    with pytest.raises(SecretUnreadable, match="re-enter"):
        SecretBox(OTHER_KEY).decrypt(stored)


def test_a_short_key_is_refused() -> None:
    with pytest.raises(ValueError, match="at least 32"):
        SecretBox("short")


def test_unicode_secrets_survive() -> None:
    box = SecretBox(KEY)
    assert box.decrypt(box.encrypt("pässwörd€")) == "pässwörd€"


@pytest.mark.parametrize("corrupt", ["gAAAAABé-not-ascii", "\u00ff" * 60, "gAAAAAB\udcff"])
def test_a_corrupt_non_ascii_token_is_unreadable_not_a_crash(corrupt: str) -> None:
    """A mangled column must surface as SecretUnreadable, which callers handle."""
    with pytest.raises(SecretUnreadable):
        SecretBox(KEY).decrypt(corrupt)


def test_a_secret_that_is_not_utf8_is_unreadable_not_a_crash() -> None:
    box = SecretBox(KEY)
    stored = box._fernet.encrypt(b"\xff\xfe").decode("ascii")
    with pytest.raises(SecretUnreadable):
        box.decrypt(stored)
