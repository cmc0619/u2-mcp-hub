"""Local-account passwords."""

from u2_mcp.passwords import (
    MIN_PASSWORD_LENGTH,
    hash_password,
    one_time_password,
    password_problem,
    verify_password,
)


def test_a_hash_verifies_only_its_password() -> None:
    stored = hash_password("correct horse battery")

    assert stored.startswith("$argon2id$")
    assert verify_password(stored, "correct horse battery") is True
    assert verify_password(stored, "wrong horse battery") is False


def test_a_missing_hash_never_verifies() -> None:
    assert verify_password(None, "anything at all") is False


def test_a_garbage_hash_never_verifies() -> None:
    assert verify_password("not-a-hash", "anything at all") is False


def test_short_passwords_are_refused() -> None:
    assert password_problem("x" * (MIN_PASSWORD_LENGTH - 1), username="ann") == (
        "Use at least 12 characters."
    )


def test_the_username_is_refused() -> None:
    assert password_problem("annabelle-lee", username="Annabelle-Lee") == (
        "Don't use your username as your password."
    )


def test_a_good_password_passes() -> None:
    assert password_problem("long enough passphrase", username="ann") is None


def test_one_time_passwords_are_long_and_different() -> None:
    first, second = one_time_password(), one_time_password()

    assert len(first) >= MIN_PASSWORD_LENGTH
    assert first != second


def test_an_empty_hash_never_verifies() -> None:
    assert verify_password("", "there is no such user") is False
