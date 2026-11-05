"""Fixed messages that travel across a redirect as a short code.

A code in the query string selects one of these texts, so a link can never put
words of its own on an admin page (the same rule as NOTICES in templating.py).
"""

from __future__ import annotations

from urllib.parse import urlencode

PROBLEMS: dict[str, str] = {
    "grant_duplicate": (
        "That person or group already has a grant on this connection. Change its role instead."
    ),
    "grant_u2_login": "Enter this person's U2 user and password for this connection.",
    "grant_u2_password": "Enter the password again: the U2 user changed.",
    "u2_login_user": "Enter your U2 user name.",
    "u2_login_password": "Enter your U2 password.",
    "u2_login_rate_limited": "Too many attempts. Wait a minute and try again.",
    "u2_login_password_again": "Enter the password again: the U2 user changed.",
    "gone": "That item no longer exists. Reload the page.",
    "token_name": "Give the token a name of up to 64 characters.",
    "token_days": "Choose a lifetime from 1 day up to the maximum shown.",
    "user_self": "You can't remove your own admin access or disable yourself.",
    "last_admin": (
        "Keep at least one enabled local admin. It is the way back in if company sign-in fails."
    ),
    "reset_self": "Use Change password for your own account.",
    "reset_sso": "Signs in with company sign-in; no password here.",
    "delete_self": "You can't delete your own account.",
    "not_admin": "Your own admin access was removed or disabled, so nothing was changed.",
    "role_builtin": "Built-in roles can't be changed. Clone one to make your own.",
    "role_in_use": "This role is used by a grant. Change those grants first.",
    "unknown_permission": "That permission does not exist.",
    "per_user_check": "Per-person connections are tested on the connection page, with a U2 login.",
}


class Refused(Exception):
    """A change was refused for a reason with a fixed message.

    Attributes:
        code: Key into PROBLEMS
    """

    def __init__(self, code: str) -> None:
        super().__init__(PROBLEMS[code])
        self.code = code


def with_query(url: str, **params: str) -> str:
    """Append query parameters to a server-chosen admin URL."""
    joiner = "&" if "?" in url else "?"
    return f"{url}{joiner}{urlencode(params)}"
