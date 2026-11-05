"""The database login a session connects with."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class U2Credentials:
    """A database login for one session.

    Attributes:
        user: Universe/UniData username
        password: Password for that account
        account: Universe account to connect to
        is_shared: True when this login is used by more than one person, which
            means the database cannot tell those people apart
    """

    user: str
    password: str = field(repr=False)
    account: str
    is_shared: bool

    @property
    def pool_key(self) -> str:
        """Return the key that keeps one login's session apart from another's."""
        return f"{self.user}@{self.account}"
