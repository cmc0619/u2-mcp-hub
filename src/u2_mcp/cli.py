"""`u2-mcp admin ...`: break-glass commands run on the server itself.

Typical use, in Docker: docker exec <container> u2-mcp admin show-setup-code
"""

from __future__ import annotations

import argparse
import sys

from .admin.services import (
    PUBLIC_URL_SETTING,
    RESTART_NOTE,
    ValidationFailed,
    clean_public_url,
)
from .config import U2Config
from .passwords import hash_password, one_time_password
from .setup_code import ensure_setup_code, is_setup_complete
from .store.bootstrap import TeamModeError, open_store_for_cli
from .store.repo import Store


def run_admin_cli(argv: list[str]) -> int:
    """Run an admin command.

    Args:
        argv: Arguments after `u2-mcp admin`

    Returns:
        Process exit code: 0 success, 1 refused, 2 cannot open the database
    """
    parser = argparse.ArgumentParser(prog="u2-mcp admin")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("show-setup-code", help="Print the code the setup wizard asks for")
    reset = commands.add_parser(
        "reset-password",
        help="Give a local user a one-time password and re-enable them",
    )
    reset.add_argument("username")
    reset.add_argument(
        "--admin",
        action="store_true",
        help="Also make them an admin (the way back in when no admin is left)",
    )
    address = commands.add_parser(
        "set-public-url", help="Set or clear the server address saved in the admin site"
    )
    address.add_argument("url", nargs="?", help="The address people use, such as https://...")
    address.add_argument(
        "--clear", action="store_true", help="Forget the saved address (U2_PUBLIC_URL applies)"
    )
    args = parser.parse_args(argv)

    if args.command == "set-public-url" and (args.url is None) == (not args.clear):
        print("Give either an address or --clear.")
        return 1

    try:
        store = open_store_for_cli(U2Config())
    except TeamModeError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if args.command == "show-setup-code":
        if is_setup_complete(store):
            print("Setup is finished, so there is no setup code. Sign in at /admin.")
            return 1
        print(ensure_setup_code(store))
        return 0

    if args.command == "set-public-url":
        return _set_public_url(store, None if args.clear else args.url)

    user = store.get_user_by_username(args.username)
    if user is None:
        print(f"No local user named '{args.username}'.")
        return 1
    password = one_time_password()
    store.set_password_hash(user.id, hash_password(password), must_change=True)
    # --admin is the break-glass path: a locked-out operator needs an enabled admin.
    store.set_user_flags(user.id, is_admin=True if args.admin else None, disabled=False)
    store.delete_admin_sessions_for(user.id)
    store.add_audit(
        kind="admin",
        action="user.reset_password",
        outcome="ok",
        actor_label="command line",
        params={"username": args.username, "re_enabled": True, "made_admin": args.admin},
    )
    print(f"One-time password for {args.username}: {password}")
    now = store.get_user(user.id)
    if now is not None and now.is_admin:
        print(f"{args.username} is enabled and is an admin, so they can sign in at /admin.")
    else:
        print(f"{args.username} is enabled and is not an admin (use --admin to make them one).")
    print("They must choose a new password when they next sign in.")
    return 0


def _set_public_url(store: Store, url: str | None) -> int:
    """Save (or, with None, forget) the server address, as the Settings page does."""
    if url is None:
        store.delete_setting(PUBLIC_URL_SETTING)
        cleaned = None
        print("The saved server address is cleared; U2_PUBLIC_URL (or host and port) applies.")
    else:
        try:
            cleaned = clean_public_url(url)
        except ValidationFailed as failed:
            print(failed.errors["public_url"])
            return 1
        store.set_setting(PUBLIC_URL_SETTING, cleaned)
        print(f"Server address set to {cleaned}.")
    store.add_audit(
        kind="admin",
        action="settings.public_url",
        outcome="ok",
        actor_label="command line",
        params={"public_url": cleaned},
    )
    print(f"Sign-in cookies use it at once. {RESTART_NOTE}")
    return 0
