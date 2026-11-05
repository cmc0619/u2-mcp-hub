"""Encryption for the secrets kept in the settings database.

The database holds U2 passwords and the SSO client secret. Anyone who can copy
the file -- a backup, a mis-mounted volume, a support bundle -- would otherwise
hold every database login the team uses. Encrypting those columns under a key
that lives only in the environment means the file alone is not enough.

The key is derived with HKDF so an operator can supply any long random string
rather than a correctly formatted Fernet key.
"""

from __future__ import annotations

import base64

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_SALT = b"u2-mcp settings database"
_INFO = b"fernet key v1"
_MIN_KEY_LENGTH = 32


class SecretUnreadable(Exception):
    """Raised when a stored secret cannot be decrypted with the current key."""

    pass


class SecretBox:
    """Encrypts and decrypts short secrets under U2_SECRET_KEY.

    Args:
        secret_key: The operator's secret, at least 32 characters

    Raises:
        ValueError: If the key is too short to be a credible secret
    """

    def __init__(self, secret_key: str) -> None:
        if len(secret_key) < _MIN_KEY_LENGTH:
            raise ValueError(f"U2_SECRET_KEY must be at least {_MIN_KEY_LENGTH} characters")
        derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=_SALT, info=_INFO).derive(
            secret_key.encode("utf-8")
        )
        self._fernet = Fernet(base64.urlsafe_b64encode(derived))

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a secret for storage.

        Args:
            plaintext: The secret

        Returns:
            An opaque ASCII token safe to store in a TEXT column
        """
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, token: str, ttl: int | None = None) -> str:
        """Decrypt a stored secret.

        Args:
            token: A value produced by encrypt()
            ttl: Refuse tokens older than this many seconds

        Returns:
            The original secret

        Raises:
            SecretUnreadable: If the token was made under a different key or is corrupt
        """
        try:
            return self._fernet.decrypt(token.encode("ascii"), ttl=ttl).decode("utf-8")
        except InvalidToken as exc:
            raise SecretUnreadable(
                "This secret was stored under a different U2_SECRET_KEY; re-enter it"
            ) from exc
        except ValueError as exc:  # includes UnicodeError: a mangled column
            raise SecretUnreadable("This stored secret is corrupt; re-enter it") from exc
