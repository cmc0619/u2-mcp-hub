"""Every change the admin site makes, in one place.

The setup wizard and the everyday pages both call these functions, so the
wizard has no logic of its own (spec: setup wizard rule 1). Each change is
validated here, saved, and written to the audit table with kind "admin".
"""

from __future__ import annotations

import contextlib
import csv
import io
import json
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from .. import routing
from ..access import visible_connections
from ..config import U2Config
from ..connection_check import CheckResult
from ..credentials import U2Credentials
from ..passwords import hash_password, password_problem, verify_password
from ..store.crypto import SecretUnreadable
from ..store.models import Connection, Grant, Group, Role, TokenRecord, U2Login, User
from ..store.repo import LastAdmin, StaleEdit, Store, StoreError
from ..tokens import (
    DEFAULT_LIFETIME_DAYS,
    MAX_LIFETIME_DAYS,
    create_token,
    is_fresh,
    revoke,
)
from .context import AdminContext
from .problems import Refused

DEFAULT_PORT = 31438
PUBLIC_URL_SETTING = routing.PUBLIC_URL_SETTING
RESTART_NOTE = (
    "Restart the server after changing the address or company sign-in: VS Code sign-in "
    "and personal access tokens pick them up at startup."
)
SERVER_CHANGED = "Enter the password again: the server details changed."

_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}")
_USERNAME = re.compile(r"[A-Za-z0-9._@-]{1,64}")


class ValidationFailed(Exception):
    """A form had problems; `errors` maps each field to its message."""

    def __init__(self, errors: dict[str, str]) -> None:
        super().__init__("; ".join(errors.values()))
        self.errors = errors


def _int(value: str | None) -> int:
    try:
        return int(value or 0)
    except ValueError:
        return 0


@dataclass
class ConnectionForm:
    """The connection form's values, as typed. The password is never shown back."""

    name: str = ""
    host: str = ""
    port: str = str(DEFAULT_PORT)
    service: str = "uvcs"
    account: str = ""
    ssl: bool = False
    login_mode: str = "shared"
    login_user: str = ""
    login_password: str = ""
    read_only: bool = True
    enabled: bool = True
    version: int = 0  # 0 means a new connection

    @classmethod
    def from_form(cls, data: Mapping[str, str]) -> ConnectionForm:
        """Read a submitted form. Unchecked checkboxes are absent, so they read as False."""
        return cls(
            name=data.get("name", "").strip(),
            host=data.get("host", "").strip(),
            port=data.get("port", "").strip(),
            service=data.get("service", "uvcs").strip(),
            account=data.get("account", "").strip(),
            ssl=data.get("ssl") == "on",
            login_mode=data.get("login_mode", "shared").strip(),
            login_user=data.get("login_user", "").strip(),
            login_password=data.get("login_password", ""),
            read_only=data.get("read_only") == "on",
            enabled=data.get("enabled") == "on",
            version=_int(data.get("version")),
        )

    @classmethod
    def from_connection(cls, connection: Connection) -> ConnectionForm:
        """Fill the form from a saved connection, for editing."""
        return cls(
            name=connection.name,
            host=connection.host,
            port=str(connection.port),
            service=connection.service,
            account=connection.account,
            ssl=connection.ssl,
            login_mode=connection.login_mode,
            login_user=connection.shared_user or "",
            read_only=connection.read_only,
            enabled=connection.enabled,
            version=connection.version,
        )

    @property
    def port_number(self) -> int:
        """The port as a number (call errors() first)."""
        return int(self.port)

    def targets(self, *, host: str, port: int, service: str, ssl: bool, account: str) -> bool:
        """Whether this form names that server and account, so a saved password may go to it.

        The port is compared as text, so a malformed port never matches.
        """
        return (self.host, self.port, self.service, self.ssl, self.account) == (
            host,
            str(port),
            service,
            ssl,
            account,
        )

    def targets_connection(self, connection: Connection) -> bool:
        """Whether this form names the saved connection's server and account."""
        return self.targets(
            host=connection.host,
            port=connection.port,
            service=connection.service,
            ssl=connection.ssl,
            account=connection.account,
        )

    def errors(self, *, password_required: bool) -> dict[str, str]:
        """Return each field's problem; empty when the form is valid."""
        found: dict[str, str] = {}
        if not self.name:
            found["name"] = "Give the connection a name."
        elif not _NAME.fullmatch(self.name):
            found["name"] = (
                "Use letters, digits, spaces, dots, dashes or underscores (up to 64), "
                "starting with a letter or digit."
            )
        if not self.host:
            found["host"] = "Enter the U2 server's host name or address."
        if not (self.port.isascii() and self.port.isdecimal()) or not 1 <= int(self.port) <= 65535:
            found["port"] = "Enter a port between 1 and 65535."
        if self.service not in ("uvcs", "udcs"):
            found["service"] = "Choose UniVerse (uvcs) or UniData (udcs)."
        if not self.account:
            found["account"] = "Enter the U2 account name."
        if self.login_mode not in ("shared", "per_user"):
            found["login_mode"] = "Choose shared or per-user logins."
        elif self.login_mode == "shared":
            if not self.login_user:
                found["login_user"] = "Enter the U2 login the server uses."
            if password_required and not self.login_password:
                found["login_password"] = "Enter the password for that login."
        return found

    def described(self) -> dict[str, Any]:
        """The form's values for the audit trail, never the password."""
        return {
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "service": self.service,
            "account": self.account,
            "ssl": self.ssl,
            "login_mode": self.login_mode,
            "login_user": self.login_user,
            "read_only": self.read_only,
            "enabled": self.enabled,
        }


def _audit(
    ctx: AdminContext,
    actor: User | None,
    action: str,
    *,
    kind: str = "admin",
    connection_id: int | None = None,
    params: dict[str, Any] | None = None,
    outcome: str = "ok",
) -> None:
    ctx.store.add_audit(
        kind=kind,
        action=action,
        outcome=outcome,
        actor_user_id=actor.id if actor else None,
        actor_label=actor.label if actor else "setup wizard",
        connection_id=connection_id,
        params=params,
    )


def _existing(ctx: AdminContext, connection_id: int) -> Connection:
    connection = ctx.store.get_connection(connection_id)
    if connection is None:
        raise StoreError("That connection no longer exists.")
    return connection


def save_connection(
    ctx: AdminContext,
    form: ConnectionForm,
    *,
    actor: User,
    connection_id: int | None = None,
) -> Connection:
    """Create or update a connection.

    Args:
        form: What was submitted
        actor: Who is saving
        connection_id: The connection being edited, or None to create one

    A blank password box keeps the stored password only while host, port,
    service, ssl and account still name the same server. Otherwise the password
    must be typed again.

    Raises:
        ValidationFailed: With per-field messages
        StaleEdit: If someone saved the connection since this form was opened
        StoreError: If the name is taken or the connection is gone
    """
    existing = _existing(ctx, connection_id) if connection_id is not None else None
    shared = form.login_mode == "shared"
    has_stored = (
        existing is not None and existing.login_mode == "shared" and existing.has_shared_password
    )
    password = form.login_password or None
    server_changed = False
    # A blank box reuses a password only for the server it was given for, so
    # pointing the form at another host cannot send that password there.
    if shared and password is None and existing is not None and has_stored:
        server_changed = not form.targets_connection(existing)
    keeps_stored = has_stored and not server_changed
    errors = form.errors(password_required=shared and password is None and not keeps_stored)
    if server_changed:
        errors["login_password"] = SERVER_CHANGED
    if errors:
        raise ValidationFailed(errors)

    # Personal U2 passwords were given for the old server: never send them on.
    # Whatever the login mode now: logins kept through a detour via shared mode
    # must not reach a new server either.
    forget = existing is not None and not form.targets_connection(existing)
    cleared = (
        len(ctx.store.list_u2_logins_for_connection(existing.id))
        if forget and existing is not None
        else 0
    )

    try:
        if existing is None:
            saved = ctx.store.add_connection(
                name=form.name,
                host=form.host,
                port=form.port_number,
                service=form.service,
                account=form.account,
                ssl=form.ssl,
                login_mode=form.login_mode,
                shared_user=form.login_user if shared else None,
                shared_password=password if shared else None,
                read_only=form.read_only,
                enabled=form.enabled,
                actor=actor.label,
            )
            action = "connection.create"
        else:
            saved = ctx.store.update_connection(
                existing.id,
                expected_version=form.version,
                name=form.name,
                host=form.host,
                port=form.port_number,
                service=form.service,
                account=form.account,
                ssl=form.ssl,
                login_mode=form.login_mode,
                shared_user=form.login_user if shared else None,
                shared_password=password if shared else None,
                clear_shared_password=not shared,
                clear_u2_logins=forget,
                read_only=form.read_only,
                enabled=form.enabled,
                actor=actor.label,
            )
            ctx.registry().evict_connection(saved.id)
            action = "connection.update"
    except StoreError as exc:
        if "already exists" in str(exc):
            raise ValidationFailed({"name": str(exc)}) from exc
        raise
    params = form.described()
    if cleared:
        # Not "...password...": the audit redactor would blank a key with that word.
        params["cleared_u2_logins"] = cleared
    _audit(ctx, actor, action, connection_id=saved.id, params=params)
    return saved


def delete_connection(ctx: AdminContext, connection_id: int, *, actor: User) -> None:
    """Delete a connection, its grants and its live sessions, keeping database notes."""
    existing = _existing(ctx, connection_id)
    ctx.store.delete_connection(connection_id)
    ctx.registry().evict_connection(connection_id)
    _audit(
        ctx, actor, "connection.delete", connection_id=connection_id, params={"name": existing.name}
    )


def disconnect_connection(ctx: AdminContext, connection_id: int, *, actor: User) -> int:
    """Close every live session on a connection. Returns how many closed."""
    _existing(ctx, connection_id)
    closed = ctx.registry().evict_connection(connection_id)
    _audit(
        ctx, actor, "connection.disconnect", connection_id=connection_id, params={"closed": closed}
    )
    return closed


def check_connection_form(
    ctx: AdminContext,
    form: ConnectionForm,
    *,
    connection_id: int | None = None,
) -> CheckResult:
    """Test the settings on a form, saved or not.

    A blank password box means the stored password (when editing), but only
    for the server it belongs to, as in save_connection. Per-user connections
    are tested with the login typed on the form, which is not saved.

    Raises:
        ValidationFailed: If the settings are not complete enough to try
    """
    errors = form.errors(password_required=False)
    if form.login_mode == "per_user" and not form.login_user:
        errors["login_user"] = "Enter a U2 login to test with."
    if form.login_mode == "per_user" and not form.login_password:
        errors["login_password"] = "Enter the password for that U2 login to test with."
    if errors:
        raise ValidationFailed(errors)

    password = form.login_password
    shared = form.login_mode == "shared"
    if not password and shared and connection_id is not None:
        existing = ctx.store.get_connection(connection_id)
        if existing is not None and existing.has_shared_password:
            # Only to the server it was saved for: see save_connection.
            if not form.targets_connection(existing):
                raise ValidationFailed({"login_password": SERVER_CHANGED})
            try:
                password = ctx.store.shared_password(connection_id) or ""
            except SecretUnreadable:
                return CheckResult(
                    False,
                    "The stored password can't be read; U2_SECRET_KEY may have changed. "
                    "Type the password again.",
                    0.0,
                )
    if shared and not password:
        raise ValidationFailed({"login_password": "Enter the password for that login."})

    transient = Connection(
        id=connection_id or 0,
        name=form.name,
        host=form.host,
        port=form.port_number,
        service=form.service,
        account=form.account,
        ssl=form.ssl,
        login_mode=form.login_mode,
        shared_user=form.login_user,
        has_shared_password=bool(password),
        read_only=True,
        enabled=True,
    )
    login = U2Credentials(
        user=form.login_user, password=password, account=form.account, is_shared=shared
    )
    return ctx.check(ctx.config, transient, login)


def create_local_user(
    ctx: AdminContext,
    *,
    username: str,
    password: str,
    password_again: str,
    display_name: str = "",
    is_admin: bool,
    actor: User | None,
) -> User:
    """Create a local (password) account.

    Raises:
        ValidationFailed: With per-field messages
    """
    username = username.strip()
    errors: dict[str, str] = {}
    if not _USERNAME.fullmatch(username):
        errors["username"] = "Use 1 to 64 letters, digits, dots, dashes, underscores or @."
    problem = password_problem(password, username=username)
    if problem:
        errors["password"] = problem
    elif password != password_again:
        errors["password_again"] = "The two passwords don't match."
    if errors:
        raise ValidationFailed(errors)
    try:
        user = ctx.store.add_local_user(
            username,
            display_name=display_name.strip() or None,
            password_hash=hash_password(password),
            is_admin=is_admin,
        )
    except StoreError as exc:
        raise ValidationFailed({"username": str(exc)}) from exc
    _audit(ctx, actor, "user.create", params={"username": username, "is_admin": is_admin})
    return user


def change_password(
    ctx: AdminContext, user: User, *, current: str, new: str, new_again: str
) -> None:
    """Change a local user's own password and clear any forced change.

    Raises:
        ValidationFailed: With per-field messages
    """
    errors: dict[str, str] = {}
    if not verify_password(ctx.store.password_hash(user.id), current):
        errors["current_password"] = "That is not your current password."
    problem = password_problem(new, username=user.username or "")
    if problem:
        errors["new_password"] = problem
    elif new != new_again:
        errors["new_password_again"] = "The two passwords don't match."
    if errors:
        raise ValidationFailed(errors)
    ctx.store.set_password_hash(user.id, hash_password(new), must_change=False)
    _audit(ctx, user, "admin.password_change", kind="auth")


def public_url_for(store: Store, config: U2Config) -> str:
    """The address people use: saved in the UI, else U2_PUBLIC_URL, else host and port.

    Args:
        store: The settings database
        config: Server configuration
    """
    saved = store.get_setting(PUBLIC_URL_SETTING)
    if saved:
        return str(saved)
    if config.public_url:
        return config.public_url.rstrip("/")
    return f"http://{config.http_host}:{config.http_port}"


def effective_public_url(ctx: AdminContext) -> str:
    """The address people use, for the admin site (see public_url_for)."""
    return public_url_for(ctx.store, ctx.config)


def public_url_warning(url: str) -> str | None:
    """Return a warning when the address is not https."""
    if url.lower().startswith("https://"):
        return None
    return (
        "This address is not https. Sign-in cookies and tokens would cross the network unencrypted."
    )


def clean_public_url(url: str) -> str:
    """Trim a typed server address and check it is a plain http(s) URL.

    Used by the admin site and `u2-mcp admin set-public-url` alike.

    Raises:
        ValidationFailed: If it is not an http(s) URL
    """
    cleaned = url.strip().rstrip("/")
    parts = urlsplit(cleaned)
    if (
        parts.scheme not in ("http", "https")
        or not parts.netloc
        or parts.query
        or parts.fragment
        or parts.username
        or parts.password
    ):
        raise ValidationFailed(
            {"public_url": "Enter the full address people use, such as https://u2-mcp.example.com"}
        )
    return cleaned


def save_public_url(ctx: AdminContext, url: str, *, actor: User) -> str:
    """Save the server's public address.

    Raises:
        ValidationFailed: If it is not an http(s) URL
    """
    cleaned = clean_public_url(url)
    ctx.store.set_setting(PUBLIC_URL_SETTING, cleaned)
    _audit(ctx, actor, "settings.public_url", params={"public_url": cleaned})
    return cleaned


# Settings key: whether people who are not admins may sign in to this admin site.
# On unless an admin turns it off. Admins always may; MCP access is not affected.
NON_ADMIN_SIGN_IN_SETTING = "non_admin_sign_in"


def non_admin_sign_in_enabled(store: Store) -> bool:
    """Whether people who are not admins may sign in to this admin site."""
    return bool(store.get_setting(NON_ADMIN_SIGN_IN_SETTING, True))


def kept_off_this_site(store: Store, user: User) -> bool:
    """Whether this person may not use the admin site: not an admin, while it is off.

    Local and company sign-in alike. Their MCP access (personal tokens, app
    sign-in) is untouched.
    """
    return not user.is_admin and not non_admin_sign_in_enabled(store)


EVERYONE_WARNING = "Everyone who can sign in gets this role on this connection."
_SUBJECT_TYPES = ("user", "group", "everyone")


@dataclass(frozen=True)
class GrantRow:
    """A grant with the names a page shows beside it."""

    grant: Grant
    connection: Connection
    subject_label: str
    role: Role


def _subject_label(ctx: AdminContext, subject_type: str, subject_id: int | None) -> str | None:
    """A subject's name, or None when it does not exist."""
    if subject_type == "everyone":
        return "Everyone"
    if subject_type == "user" and subject_id is not None:
        user = ctx.store.get_user(subject_id)
        return user.label if user else None
    if subject_type == "group" and subject_id is not None:
        group = next((g for g in ctx.store.list_groups() if g.id == subject_id), None)
        if group is None:
            return None
        name = group.label or group.external_id
        return f"{name} ({group.issuer})" if group.issuer else name
    return None


def grant_rows(
    ctx: AdminContext,
    *,
    connection_id: int | None = None,
    subject_type: str | None = None,
    subject_id: int | None = None,
) -> list[GrantRow]:
    """The grants on one connection, or held by one subject, ready to show."""
    if connection_id is not None:
        grants = ctx.store.grants_on_connection(connection_id)
    elif subject_type is not None:
        grants = ctx.store.grants_for_subject(subject_type, subject_id)
    else:
        grants = []
    rows = []
    for grant in grants:
        connection = ctx.store.get_connection(grant.connection_id)
        role = ctx.store.get_role(grant.role_id)
        label = _subject_label(ctx, grant.subject_type, grant.subject_id)
        if connection is not None and role is not None and label is not None:
            rows.append(GrantRow(grant, connection, label, role))
    return sorted(rows, key=lambda r: (r.connection.name.casefold(), r.subject_label.casefold()))


def save_grant(
    ctx: AdminContext,
    *,
    connection_id: int,
    subject_type: str,
    subject_id: int | None,
    role_id: int,
    actor: User,
) -> Grant:
    """Give a user, a group or everyone a role on a connection.

    On a per-user connection each person sets their own U2 login on My access;
    a grant never carries one.

    Raises:
        Refused: grant_duplicate or gone
    """
    connection = ctx.store.get_connection(connection_id)
    role = ctx.store.get_role(role_id)
    if subject_type == "everyone":
        subject_id = None
    if (
        connection is None
        or role is None
        or subject_type not in _SUBJECT_TYPES
        or _subject_label(ctx, subject_type, subject_id) is None
    ):
        raise Refused("gone")
    try:
        grant = ctx.store.add_grant(
            connection_id=connection_id,
            subject_type=subject_type,
            subject_id=subject_id,
            role_id=role_id,
        )
    except StoreError as exc:
        raise Refused("grant_duplicate" if "already has" in str(exc) else "gone") from exc
    _audit(
        ctx,
        actor,
        "grant.create",
        connection_id=connection_id,
        params={"subject_type": subject_type, "subject_id": subject_id, "role": role.name},
    )
    return grant


def update_grant(ctx: AdminContext, grant_id: int, *, role_id: int, actor: User) -> Grant:
    """Change a grant's role.

    Raises:
        Refused: gone
    """
    grant = ctx.store.get_grant(grant_id)
    connection = ctx.store.get_connection(grant.connection_id) if grant else None
    role = ctx.store.get_role(role_id)
    if grant is None or connection is None or role is None:
        raise Refused("gone")
    try:
        updated = ctx.store.update_grant(grant_id, role_id=role_id)
    except StoreError as exc:
        raise Refused("gone") from exc
    _audit(
        ctx,
        actor,
        "grant.update",
        connection_id=connection.id,
        params={"grant_id": grant_id, "role": role.name},
    )
    return updated


def delete_grant(ctx: AdminContext, grant_id: int, *, actor: User) -> None:
    """Remove a grant. The person's own U2 login, if any, stays theirs.

    Raises:
        Refused: gone
    """
    grant = ctx.store.get_grant(grant_id)
    if grant is None or not ctx.store.delete_grant(grant_id):
        raise Refused("gone")
    _audit(
        ctx,
        actor,
        "grant.delete",
        connection_id=grant.connection_id,
        params={"subject_type": grant.subject_type, "subject_id": grant.subject_id},
    )


# ------------------------------------------------------------ personal U2 logins


@dataclass(frozen=True)
class U2LoginRow:
    """One person's own U2 login on one per-user connection, as a page shows it.

    login is None when the person has not set one. The password is never here.
    """

    connection: Connection
    person: User
    login: U2Login | None


def _my_per_user_connection(ctx: AdminContext, user: User, connection_id: int) -> Connection:
    """A per-user connection the person can use now, else Refused("gone").

    Hidden, disabled, shared and missing connections all get the same answer, so
    the self-service forms cannot be used to probe for connections or passwords.
    """
    for visible in visible_connections(ctx.store, user.id, global_read_only=ctx.config.read_only):
        if visible.connection.id == connection_id and visible.connection.login_mode == "per_user":
            return visible.connection
    raise Refused("gone")


def my_u2_logins(ctx: AdminContext, user: User) -> list[U2LoginRow]:
    """The signed-in person's own login on every per-user connection they can use."""
    mine = {login.connection_id: login for login in ctx.store.list_u2_logins_for_user(user.id)}
    return [
        U2LoginRow(visible.connection, user, mine.get(visible.connection.id))
        for visible in visible_connections(
            ctx.store, user.id, global_read_only=ctx.config.read_only
        )
        if visible.connection.login_mode == "per_user"
    ]


def _login_to_use(
    ctx: AdminContext, user: User, connection: Connection, u2_user: str, u2_password: str
) -> tuple[str, str | None]:
    """Check a typed login; return (user name, new password or None to keep).

    Raises:
        Refused: u2_login_user, u2_login_password or u2_login_password_again
    """
    name = u2_user.strip()
    if not name:
        raise Refused("u2_login_user")
    if u2_password:
        return name, u2_password
    stored = ctx.store.get_u2_login(user.id, connection.id)
    if stored is None:
        raise Refused("u2_login_password")
    if stored.u2_user != name:
        # The stored password belongs to the old U2 user: never pair it with another.
        raise Refused("u2_login_password_again")
    return name, None


def save_my_u2_login(
    ctx: AdminContext, user: User, connection_id: int, *, u2_user: str, u2_password: str
) -> U2Login:
    """Save the signed-in person's own U2 login. A blank password keeps the stored one.

    The person's live sessions on the connection close, so the next call uses
    the new login.

    Raises:
        Refused: gone, u2_login_user, u2_login_password or u2_login_password_again
    """
    connection = _my_per_user_connection(ctx, user, connection_id)
    name, password = _login_to_use(ctx, user, connection, u2_user, u2_password)
    try:
        saved = ctx.store.set_u2_login(user.id, connection.id, name, password)
    except StoreError as exc:
        raise Refused("gone") from exc
    ctx.registry().evict_owner(connection.id, user.id)
    _audit(
        ctx,
        user,
        "u2_login_set",
        connection_id=connection.id,
        params={"connection": connection.name, "u2_user": name},
    )
    return saved


def check_my_u2_login(
    ctx: AdminContext, user: User, connection_id: int, *, u2_user: str, u2_password: str
) -> CheckResult:
    """Test the signed-in person's login on a connection, without saving it.

    The server, port and account come from the saved connection; the login is the
    one typed, with the stored password when the box is blank.

    Raises:
        Refused: gone, u2_login_user, u2_login_password or u2_login_password_again
    """
    connection = _my_per_user_connection(ctx, user, connection_id)
    name, password = _login_to_use(ctx, user, connection, u2_user, u2_password)
    if password is None:
        try:
            password = ctx.store.get_u2_login_password(user.id, connection.id)
        except SecretUnreadable:
            return CheckResult(
                False,
                "Your stored password can't be read; U2_SECRET_KEY may have changed. "
                "Type the password again.",
                0.0,
            )
        if password is None:
            raise Refused("u2_login_password")
    login = U2Credentials(user=name, password=password, account=connection.account, is_shared=False)
    result = ctx.check(ctx.config, connection, login)
    _audit(
        ctx,
        user,
        "u2_login_test",
        connection_id=connection.id,
        params={"connection": connection.name, "u2_user": name},
        outcome="ok" if result.ok else "failed",
    )
    return result


def remove_my_u2_login(ctx: AdminContext, user: User, connection_id: int) -> None:
    """Forget the signed-in person's own U2 login on a connection.

    Raises:
        Refused: gone, when they have none there
    """
    _forget_u2_login(ctx, user.id, connection_id, actor=user, action="u2_login_removed")


def clear_u2_login(ctx: AdminContext, user_id: int, connection_id: int, *, actor: User) -> None:
    """Forget someone's U2 login (admin). Admins never see or set the password.

    Raises:
        Refused: gone, when there is none
    """
    _forget_u2_login(ctx, user_id, connection_id, actor=actor, action="u2_login_cleared")


def _forget_u2_login(
    ctx: AdminContext, user_id: int, connection_id: int, *, actor: User, action: str
) -> None:
    login = ctx.store.get_u2_login(user_id, connection_id)
    connection = ctx.store.get_connection(connection_id)
    if login is None or connection is None or not ctx.store.delete_u2_login(user_id, connection_id):
        raise Refused("gone")
    ctx.registry().evict_owner(connection_id, user_id)
    params: dict[str, Any] = {"connection": connection.name, "u2_user": login.u2_user}
    if action == "u2_login_cleared":
        params["user_id"] = user_id
    _audit(ctx, actor, action, connection_id=connection_id, params=params)


def u2_logins_on_connection(ctx: AdminContext, connection: Connection) -> list[U2LoginRow]:
    """Everyone who can use a per-user connection, with whether their login is set.

    Includes people who reach it through a group or everyone, and anyone who still
    has a login stored there. Empty for a shared connection.
    """
    if connection.login_mode != "per_user":
        return []
    logins = {
        login.user_id: login for login in ctx.store.list_u2_logins_for_connection(connection.id)
    }
    rows = []
    for person in ctx.store.list_users():
        can_use = any(
            visible.connection.id == connection.id
            for visible in visible_connections(
                ctx.store, person.id, global_read_only=ctx.config.read_only
            )
        )
        if can_use or person.id in logins:
            rows.append(U2LoginRow(connection, person, logins.get(person.id)))
    return sorted(rows, key=lambda row: row.person.label.casefold())


def u2_logins_of_person(ctx: AdminContext, person: User) -> list[U2LoginRow]:
    """A person's own login on every per-user connection they can use or have one on."""
    logins = {login.connection_id: login for login in ctx.store.list_u2_logins_for_user(person.id)}
    usable = {
        visible.connection.id
        for visible in visible_connections(
            ctx.store, person.id, global_read_only=ctx.config.read_only
        )
    }
    return [
        U2LoginRow(connection, person, logins.get(connection.id))
        for connection in ctx.store.list_connections()
        if connection.login_mode == "per_user"
        and (connection.id in usable or connection.id in logins)
    ]


TOKEN_MAX_LIFETIME_SETTING = "token_max_lifetime_days"


@dataclass(frozen=True)
class TokenView:
    """A token as a page lists it."""

    record: TokenRecord
    status: str  # "Active", "Paused", "Expired" or "Revoked"

    @property
    def revocable(self) -> bool:
        """Whether a Revoke button applies (it does to a paused token too)."""
        return self.status in ("Active", "Paused")


def token_max_lifetime(ctx: AdminContext) -> int | None:
    """The admin's cap on token lifetime in days, or None for no cap."""
    value = ctx.store.get_setting(TOKEN_MAX_LIFETIME_SETTING)
    return None if value is None else int(value)


TOKEN_POLICY_PROBLEM = (
    f"Enter a whole number of days from 1 to {MAX_LIFETIME_DAYS}, or leave it blank for no limit."
)


def save_token_policy(ctx: AdminContext, value: str, *, actor: User) -> int | None:
    """Set the longest lifetime a new token may have; blank removes the cap.

    Existing tokens keep their expiry. A cap of 0 is refused: only an absent
    setting means no cap.

    Raises:
        ValidationFailed: Unless blank or a whole number from 1 to MAX_LIFETIME_DAYS
    """
    text = value.strip()
    if not text:
        ctx.store.delete_setting(TOKEN_MAX_LIFETIME_SETTING)
        days = None
    elif text.isascii() and text.isdecimal() and 1 <= int(text) <= MAX_LIFETIME_DAYS:
        days = int(text)
        ctx.store.set_setting(TOKEN_MAX_LIFETIME_SETTING, days)
    else:
        raise ValidationFailed({"token_max_days": TOKEN_POLICY_PROBLEM})
    _audit(ctx, actor, "settings.token_policy", params={"max_days": days})
    return days


def set_non_admin_sign_in(ctx: AdminContext, enabled: bool, *, actor: User) -> None:
    """Allow or stop admin-site sign-in for people who are not admins."""
    ctx.store.set_setting(NON_ADMIN_SIGN_IN_SETTING, enabled)
    _audit(ctx, actor, "settings.non_admin_sign_in", params={"enabled": enabled})


def default_token_days(ctx: AdminContext) -> int:
    """The lifetime the create form suggests: 90 days, or the cap if lower."""
    cap = token_max_lifetime(ctx)
    return DEFAULT_LIFETIME_DAYS if cap is None else min(DEFAULT_LIFETIME_DAYS, cap)


def token_views(ctx: AdminContext, user_id: int) -> list[TokenView]:
    """A user's tokens, newest first, with their status now."""
    now = ctx.store.clock()
    owner = ctx.store.get_user(user_id)
    fresh = owner is None or is_fresh(
        owner, now=now, freshness_days=ctx.config.token_freshness_days
    )
    views = []
    for record in ctx.store.list_tokens(user_id):
        if record.revoked_at is not None:
            status = "Revoked"
        elif now >= record.expires_at:
            status = "Expired"
        else:
            status = "Active" if fresh else "Paused"
        views.append(TokenView(record, status))
    return views


def create_personal_token(
    ctx: AdminContext, user: User, *, name: str, days: str
) -> tuple[str, TokenRecord]:
    """Create a token for the signed-in user. The token itself is returned once.

    Raises:
        Refused: token_name or token_days
    """
    name = name.strip()
    if not name or len(name) > 64:
        raise Refused("token_name")
    if not (days.isascii() and days.isdecimal()):
        raise Refused("token_days")
    try:
        token, record = create_token(
            ctx.store,
            user.id,
            name,
            lifetime_days=int(days),
            max_lifetime_days=token_max_lifetime(ctx),
        )
    except (ValueError, OverflowError) as exc:
        raise Refused("token_days") from exc
    # Key names containing "token" are redacted by the audit table, so use plain ones.
    _audit(ctx, user, "token.create", params={"id": record.id, "label": name, "days": int(days)})
    return token, record


def revoke_personal_token(ctx: AdminContext, token_id: int, *, owner_id: int, actor: User) -> None:
    """Revoke one of owner_id's tokens.

    My access passes the signed-in user as owner, so nobody revokes another
    person's token there. The Users page passes the user being viewed.

    Raises:
        Refused: gone, when the token is missing or not owner_id's
    """
    record = ctx.store.get_token(token_id)
    if record is None or record.user_id != owner_id:
        raise Refused("gone")
    revoke(ctx.store, token_id)
    _audit(ctx, actor, "token.revoke", params={"id": token_id, "owner_id": owner_id})


@dataclass(frozen=True)
class SignedInApp:
    """An MCP client the person signed in to with their company account."""

    client_id: str
    name: str
    signed_in_at: float
    last_refreshed_at: float
    expires_at: float | None


def signed_in_apps(ctx: AdminContext, user: User) -> list[SignedInApp]:
    """The MCP apps holding live OAuth tokens for this person, most recent first.

    Tokens name their person as issuer plus subject, exactly as the identity
    resolver reads them, so only this person's apps are listed.
    """
    if ctx.oauth_storage is None or user.kind != "sso" or not user.sso_subject:
        return []
    by_client: dict[str, list[Any]] = {}
    for token in ctx.oauth_storage.tokens_for_person(user.sso_subject, user.sso_issuer):
        by_client.setdefault(token.client_id, []).append(token)
    apps = []
    for client_id, tokens in by_client.items():
        client = ctx.oauth_storage.get_client(client_id)
        expiries = [t.expires_at for t in tokens if t.expires_at]
        apps.append(
            SignedInApp(
                client_id=client_id,
                name=(client.client_name if client else None) or client_id,
                signed_in_at=min(t.signed_in_at or t.created_at for t in tokens),
                last_refreshed_at=max(t.created_at for t in tokens),
                expires_at=max(expiries) if expiries else None,
            )
        )
    return sorted(apps, key=lambda app: app.last_refreshed_at, reverse=True)


def users_with_apps(ctx: AdminContext, users: list[User]) -> set[int]:
    """Ids of the given company sign-in users who have an app signed in, in one read."""
    if ctx.oauth_storage is None:
        return set()
    holders = ctx.oauth_storage.people_with_tokens()
    return {
        u.id
        for u in users
        if u.kind == "sso" and u.sso_subject and (u.sso_issuer, u.sso_subject) in holders
    }


def sign_out_app(
    ctx: AdminContext, user: User, client_id: str, *, actor: User | None = None
) -> None:
    """Revoke this person's OAuth tokens for one MCP app; other people keep theirs.

    Args:
        ctx: The admin context
        user: Whose app to sign out
        client_id: The app
        actor: Who did it, when an admin signs out someone else's app; the
            person themself otherwise

    Raises:
        Refused: gone, when the person holds no tokens for that app
    """
    actor = actor or user
    if ctx.oauth_storage is None or user.kind != "sso" or not user.sso_subject:
        raise Refused("gone")
    client = ctx.oauth_storage.get_client(client_id)
    removed = ctx.oauth_storage.revoke_client_tokens_for_person(
        user.sso_subject, user.sso_issuer, client_id
    )
    if not removed:
        raise Refused("gone")
    _audit(
        ctx,
        actor,
        "oauth_app.sign_out",
        params={
            "user_id": user.id,
            "client_id": client_id,
            "client_name": client.client_name if client else None,
            "tokens": removed,
        },
    )


def sign_out_all_apps(ctx: AdminContext, user: User, *, actor: User) -> int:
    """Sign every MCP app out of one person's account, one audited sign-out per app.

    Returns:
        How many apps were signed out

    Raises:
        Refused: gone, when the person has no signed-in apps
    """
    apps = signed_in_apps(ctx, user)
    if not apps:
        raise Refused("gone")
    for app in apps:
        with contextlib.suppress(Refused):  # its tokens ran out meanwhile
            sign_out_app(ctx, user, app.client_id, actor=actor)
    return len(apps)


def set_user_flags(
    ctx: AdminContext,
    user_id: int,
    *,
    is_admin: bool | None = None,
    disabled: bool | None = None,
    actor: User,
) -> User:
    """Turn a user's admin flag or disabled flag on or off.

    Nobody demotes or disables themselves, and the last enabled local admin
    stays: it is the way back in when company sign-in fails. The store checks
    that inside the change's own transaction. With no flag given, nothing
    changes and nothing is audited.

    Raises:
        Refused: not_admin, user_self, last_admin or gone
    """
    target = ctx.store.get_user(user_id)
    if target is None:
        raise Refused("gone")
    if is_admin is None and disabled is None:
        return target
    current = ctx.store.get_user(actor.id)
    if current is None or not current.is_admin or current.disabled:
        raise Refused("not_admin")
    if user_id == actor.id and (is_admin is False or disabled is True):
        raise Refused("user_self")
    try:
        ctx.store.set_user_flags(user_id, is_admin=is_admin, disabled=disabled)
    except LastAdmin as exc:
        raise Refused("last_admin") from exc
    except StoreError as exc:
        raise Refused("gone") from exc
    params: dict[str, Any] = {"user_id": user_id}
    params.update(
        {k: v for k, v in (("is_admin", is_admin), ("disabled", disabled)) if v is not None}
    )
    _audit(ctx, actor, "user.flags", params=params)
    updated = ctx.store.get_user(user_id)
    if updated is None:
        raise Refused("gone")
    return updated


GENERATED_PASSWORD_LENGTH = 16
_EMAIL = re.compile(r"[^@\s]+@[^@\s]+")


def reset_password(
    ctx: AdminContext, user_id: int, *, password: str, generate: bool, actor: User
) -> str | None:
    """Give a local user a temporary password they must change at next sign-in.

    Ends all of the person's admin sessions. Tokens stay valid. The password is
    never audited.

    Args:
        ctx: Admin context
        user_id: The person
        password: The typed temporary password (ignored when generate is True)
        generate: Make a random password instead
        actor: The admin

    Returns:
        The generated password, to show once; None when the admin typed it

    Raises:
        Refused: gone, reset_self or reset_sso
        ValidationFailed: With the password field's message
    """
    target = ctx.store.get_user(user_id)
    if target is None:
        raise Refused("gone")
    if target.id == actor.id:
        raise Refused("reset_self")
    if target.kind != "local":
        raise Refused("reset_sso")
    if generate:
        password = secrets.token_urlsafe(12)[:GENERATED_PASSWORD_LENGTH]
    problem = password_problem(password, username=target.username or "")
    if problem:
        raise ValidationFailed({"password": problem})
    try:
        ctx.store.reset_password(target.id, hash_password(password))
    except StoreError as exc:
        raise Refused("gone") from exc
    _audit(
        ctx,
        actor,
        "password_reset",
        params={"user_id": target.id, "username": target.username, "generated": generate},
    )
    return password if generate else None


def edit_person(
    ctx: AdminContext,
    user_id: int,
    *,
    username: str,
    display_name: str,
    email: str,
    actor: User,
) -> None:
    """Change a person's display name and email, and a local user's username.

    Raises:
        Refused: gone
        ValidationFailed: With per-field messages
    """
    target = ctx.store.get_user(user_id)
    if target is None:
        raise Refused("gone")
    display_name, email, username = display_name.strip(), email.strip(), username.strip()
    errors: dict[str, str] = {}
    new_username: str | None = None
    if target.kind == "local":
        if not _USERNAME.fullmatch(username):
            errors["username"] = "Use 1 to 64 letters, digits, dots, dashes, underscores or @."
        else:
            new_username = username
    if len(display_name) > 100:
        errors["display_name"] = "Use up to 100 characters."
    if email and (len(email) > 254 or not _EMAIL.fullmatch(email)):
        errors["email"] = "Enter an email address, or leave it empty."
    if errors:
        raise ValidationFailed(errors)
    try:
        ctx.store.update_user_details(
            target.id,
            display_name=display_name or None,
            email=email or None,
            username=new_username,
        )
    except StoreError as exc:
        if "no longer exists" in str(exc):
            raise Refused("gone") from exc
        raise ValidationFailed({"username": str(exc)}) from exc
    if new_username is not None and new_username != target.username:
        _audit(
            ctx,
            actor,
            "user_renamed",
            params={"user_id": target.id, "from": target.username, "to": new_username},
        )
    else:
        _audit(ctx, actor, "user_edited", params={"user_id": target.id})


@dataclass(frozen=True)
class DeletionSummary:
    """What goes with a person when they are deleted."""

    tokens: int
    grants: int
    u2_logins: int
    sessions: int


def deletion_summary(ctx: AdminContext, person: User) -> DeletionSummary:
    """Count what deleting this person removes."""
    return DeletionSummary(
        tokens=len(ctx.store.list_tokens(person.id)),
        grants=len(ctx.store.grants_for_subject("user", person.id)),
        u2_logins=len(ctx.store.list_u2_logins_for_user(person.id)),
        sessions=ctx.store.count_admin_sessions_for(person.id),
    )


def delete_person(ctx: AdminContext, user_id: int, *, actor: User) -> None:
    """Delete a person, closing their live U2 sessions and admin sessions.

    The audit keeps their earlier rows, and the deletion row names them.

    Raises:
        Refused: gone, delete_self or last_admin
    """
    target = ctx.store.get_user(user_id)
    if target is None:
        raise Refused("gone")
    if target.id == actor.id:
        raise Refused("delete_self")
    logins = ctx.store.list_u2_logins_for_user(target.id)
    try:
        ctx.store.delete_user(target.id)
    except LastAdmin as exc:
        raise Refused("last_admin") from exc
    except StoreError as exc:
        raise Refused("gone") from exc
    for login in logins:
        ctx.registry().evict_owner(login.connection_id, target.id)
    if target.kind == "sso" and target.sso_subject and ctx.oauth_storage is not None:
        # Their MCP OAuth tokens die with them; only a fresh company sign-in brings
        # them back.
        ctx.oauth_storage.revoke_tokens_for_subject(target.sso_subject)
    _audit(
        ctx,
        actor,
        "user_deleted",
        params={
            "user_id": target.id,
            "username": target.username,
            "label": target.label,
            "kind": target.kind,
        },
    )


def user_groups(ctx: AdminContext, user_id: int) -> list[Group]:
    """The groups recorded at a user's last SSO sign-in."""
    mine = set(ctx.store.group_ids_for_user(user_id))
    return [group for group in ctx.store.list_groups() if group.id in mine]


MCP_PROTOCOL_VERSION = "2025-06-18"


def curl_example(public_url: str) -> str:
    """A curl command that initializes an MCP session with a token, for My access.

    The token stays a placeholder: the page never holds a real one.
    """
    url = public_url.rstrip("/") + "/"
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "curl", "version": "1"},
            },
        },
        separators=(",", ":"),
    )
    return (
        f"curl -X POST {url} \\\n"
        '  -H "Authorization: Bearer <token>" \\\n'
        '  -H "Content-Type: application/json" \\\n'
        '  -H "Accept: application/json, text/event-stream" \\\n'
        f"  -d '{body}'"
    )


_ROLE_NAME_PROBLEM = (
    "Use letters, digits, spaces, dots, dashes or underscores (up to 64), "
    "starting with a letter or digit."
)


def _custom_role(ctx: AdminContext, role_id: int) -> Role:
    role = ctx.store.get_role(role_id)
    if role is None:
        raise Refused("gone")
    if role.builtin:
        raise Refused("role_builtin")
    return role


def clone_role(ctx: AdminContext, role_id: int, *, actor: User) -> Role:
    """Copy a role, built-in or custom, into a new editable custom role.

    Raises:
        Refused: gone
    """
    source = ctx.store.get_role(role_id)
    if source is None:
        raise Refused("gone")
    base = f"Copy of {source.name}"[:64]
    name, number = base, 1
    while ctx.store.get_role_by_name(name) is not None:
        number += 1
        name = f"{base[:60]} {number}"
    role = ctx.store.add_role(name, sorted(source.permissions))
    _audit(ctx, actor, "role.create", params={"name": name, "from": source.name})
    return role


def save_role(
    ctx: AdminContext,
    role_id: int,
    *,
    name: str,
    permissions: list[str],
    version: int,
    actor: User,
) -> Role:
    """Save a custom role's name and permissions.

    Raises:
        ValidationFailed: For a bad or taken name
        Refused: role_builtin, unknown_permission or gone
        StaleEdit: If someone saved the role since this form was opened
    """
    _custom_role(ctx, role_id)
    name = name.strip()
    if not _NAME.fullmatch(name):
        raise ValidationFailed({"name": _ROLE_NAME_PROBLEM})
    try:
        role = ctx.store.update_role(
            role_id, expected_version=version, name=name, permissions=permissions
        )
    except StaleEdit:
        raise
    except StoreError as exc:
        if "already exists" in str(exc):
            raise ValidationFailed({"name": str(exc)}) from exc
        if "unknown permission" in str(exc):
            raise Refused("unknown_permission") from exc
        raise Refused("gone") from exc
    _audit(ctx, actor, "role.update", params={"name": name, "permissions": sorted(permissions)})
    return role


def remove_role(ctx: AdminContext, role_id: int, *, actor: User) -> None:
    """Delete a custom role that no grant uses.

    Raises:
        Refused: role_builtin, role_in_use or gone
    """
    role = _custom_role(ctx, role_id)
    if ctx.store.role_in_use(role_id):
        raise Refused("role_in_use")
    try:
        ctx.store.delete_role(role_id)
    except StoreError as exc:
        raise Refused("role_in_use" if "in use" in str(exc) else "gone") from exc
    _audit(ctx, actor, "role.delete", params={"name": role.name})


def set_group_label(ctx: AdminContext, group_id: int, label: str, *, actor: User) -> None:
    """Name a group for admins; blank shows the identity provider's value.

    Raises:
        ValidationFailed: For a label over 64 characters
        Refused: gone
    """
    label = label.strip()
    if len(label) > 64:
        raise ValidationFailed({"label": "Use up to 64 characters."})
    try:
        ctx.store.set_group_label(group_id, label or None)
    except StoreError as exc:
        raise Refused("gone") from exc
    _audit(ctx, actor, "group.label", params={"group_id": group_id, "label": label or None})


_CSV_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def _date(value: str) -> str:
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return ""
    return value


def _day_start(value: str) -> float:
    day = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=UTC)
    return day.timestamp()


@dataclass(frozen=True)
class AuditFilters:
    """The Audit page's filters, read safely from a query string. Dates are UTC days."""

    user_id: int | None = None
    connection_id: int | None = None
    kind: str | None = None
    action: str = ""
    date_from: str = ""
    date_to: str = ""

    @classmethod
    def from_query(cls, query: Mapping[str, str]) -> AuditFilters:
        """Read filters; anything malformed is ignored rather than refused."""

        def number(key: str) -> int | None:
            value = query.get(key, "")
            # 18 digits always fits SQLite's 64-bit integers; longer is ignored.
            ok = value.isascii() and value.isdecimal() and len(value) <= 18
            return int(value) if ok else None

        kind = query.get("kind", "")
        return cls(
            user_id=number("user"),
            connection_id=number("connection"),
            kind=kind if kind in ("tool", "admin", "auth") else None,
            action=query.get("action", "").strip()[:64],
            date_from=_date(query.get("from", "")),
            date_to=_date(query.get("to", "")),
        )

    @property
    def since(self) -> float | None:
        """Start of the first day, or None."""
        return _day_start(self.date_from) if self.date_from else None

    @property
    def until(self) -> float | None:
        """End of the last day (start of the next), or None."""
        if not self.date_to:
            return None
        return _day_start(self.date_to) + timedelta(days=1).total_seconds()


def audit_entries(
    ctx: AdminContext, filters: AuditFilters, *, limit: int | None = 200
) -> list[dict[str, Any]]:
    """Audit rows matching the filters, newest first."""
    return ctx.store.query_audit(
        actor_user_id=filters.user_id,
        connection_id=filters.connection_id,
        kind=filters.kind,
        action=filters.action,
        since=filters.since,
        until=filters.until,
        limit=limit,
    )


def _csv_cell(value: Any) -> str:
    """A CSV cell that a spreadsheet will not run as a formula."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_CSV_FORMULA_START) else text


def audit_csv(ctx: AdminContext, filters: AuditFilters) -> str:
    """Every audit row matching the filters, as CSV text."""
    names = {c.id: c.name for c in ctx.store.list_connections()}
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        ["at", "actor", "kind", "connection", "action", "outcome", "duration_ms", "params"]
    )
    for entry in audit_entries(ctx, filters, limit=None):
        at = datetime.fromtimestamp(entry["at"], tz=UTC).isoformat()
        connection = names.get(entry["connection_id"], entry["connection_id"])
        params = json.dumps(entry["params"]) if entry["params"] is not None else ""
        writer.writerow(
            [
                _csv_cell(value)
                for value in (
                    at,
                    entry["actor_label"],
                    entry["kind"],
                    connection,
                    entry["action"],
                    entry["outcome"],
                    entry["duration_ms"],
                    params,
                )
            ]
        )
    return out.getvalue()
