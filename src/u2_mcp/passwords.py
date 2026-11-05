"""Local-account passwords: argon2id hashes and the rules a new password must meet."""

from __future__ import annotations

import secrets
from functools import lru_cache

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

MIN_PASSWORD_LENGTH = 12

_hasher = PasswordHasher()  # argon2id with the library's current defaults


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    """A hash to verify against when the user does not exist, so timing matches."""
    return _hasher.hash("there is no such user")


_dummy_hash()  # warm it now so the first unknown-user check is not slower


def hash_password(password: str) -> str:
    """Return an argon2id hash of a password."""
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    """Return whether a password matches a stored hash.

    Args:
        password_hash: The stored hash, or None when the user does not exist
        password: What was typed

    Returns:
        True only for a match. A missing or malformed hash is never a match.
    """
    try:
        _hasher.verify(password_hash or _dummy_hash(), password)
    except (VerificationError, InvalidHashError):
        return False
    return bool(password_hash)


def password_problem(password: str, *, username: str) -> str | None:
    """Return why a new password is unacceptable, or None if it is fine."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Use at least {MIN_PASSWORD_LENGTH} characters."
    if password.casefold() == username.casefold():
        return "Don't use your username as your password."
    return None


def one_time_password() -> str:
    """Return a random password for a reset; the user must change it at sign-in."""
    return secrets.token_urlsafe(15)
