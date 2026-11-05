"""Every read and write of the settings database.

One connection is shared by the whole process and guarded by a lock. SQLite in
WAL mode handles this load easily -- the server makes a handful of small queries
per tool call -- and one lock means no caller ever sees half of another's write.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import Any

from ..permissions import BUILTIN_ROLES, PERMISSIONS
from .crypto import SecretBox
from .knowledge import KnowledgeNamespace, KnowledgeTopic, remember_database
from .models import AdminSession, Connection, Grant, Group, Role, TokenRecord, U2Login, User

_SECRET_PARAM_WORDS = ("password", "secret", "token")


class StoreError(Exception):
    """Raised when a write would break a rule of the settings database."""

    pass


class LastAdmin(StoreError):
    """Raised when a change would leave no enabled local admin."""


STALE_CONNECTION_MESSAGE = (
    "Someone else changed this connection since you opened it. Reload to see their changes."
)

STALE_ROLE_MESSAGE = (
    "Someone else changed this role since you opened it. Reload to see their changes."
)

CONNECTION_ID_SETTING = "last_connection_id"


class StaleEdit(StoreError):
    """An edit was based on a version of the record that has since been saved over."""


def _is_secret_name(key: str) -> bool:
    return any(word in key.lower() for word in _SECRET_PARAM_WORDS)


def _redact_value(value: Any) -> Any:
    """Redact secret-named keys inside nested dicts and lists."""
    if isinstance(value, dict):
        return {
            key: "[redacted]" if _is_secret_name(str(key)) else _redact_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    return value


def _redact(params: dict[str, Any] | None) -> dict[str, Any] | None:
    """Replace values whose parameter names suggest a secret, at any depth."""
    if params is None:
        return None
    return {
        key: "[redacted]" if _is_secret_name(key) else _redact_value(value)
        for key, value in params.items()
    }


class Store:
    """The settings database.

    Args:
        conn: Connection from open_database()
        box: Encrypts the secret columns
        data_dir: Directory holding the database and per-connection files
        clock: Source of the current time, replaceable in tests
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        box: SecretBox,
        data_dir: Path,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._conn = conn
        self._box = box
        self._lock = threading.RLock()
        self.data_dir = Path(data_dir)
        self.clock = clock

    # ------------------------------------------------------------------ helpers

    @contextlib.contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        """Run a block as one transaction under the store lock."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    @contextlib.contextmanager
    def locked(self) -> Iterator[sqlite3.Connection]:
        """The shared connection under the store lock, for single statements.

        The OAuth and knowledge stores use this, so their statements never land
        inside another thread's open transaction.
        """
        with self._lock:
            yield self._conn

    def _one(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Row | None:
        with self._lock:
            row: sqlite3.Row | None = self._conn.execute(sql, tuple(params)).fetchone()
            return row

    def _all(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(sql, tuple(params)).fetchall())

    def _encrypt(self, value: str | None) -> str | None:
        return None if value is None else self._box.encrypt(value)

    # -------------------------------------------------------------- connections

    @staticmethod
    def _connection(row: sqlite3.Row) -> Connection:
        return Connection(
            id=row["id"],
            name=row["name"],
            host=row["host"],
            port=row["port"],
            service=row["service"],
            account=row["account"],
            ssl=bool(row["ssl"]),
            login_mode=row["login_mode"],
            shared_user=row["shared_user"],
            has_shared_password=row["shared_password_enc"] is not None,
            read_only=bool(row["read_only"]),
            enabled=bool(row["enabled"]),
            version=row["version"],
        )

    def add_connection(
        self,
        *,
        name: str,
        host: str,
        port: int,
        service: str,
        account: str,
        ssl: bool = False,
        login_mode: str = "shared",
        shared_user: str | None = None,
        shared_password: str | None = None,
        read_only: bool = True,
        enabled: bool = True,
        actor: str | None = None,
    ) -> Connection:
        """Add a U2 connection. New connections are read-only unless stated otherwise.

        Raises:
            StoreError: If the name is taken or the values break a schema rule
        """
        now = self.clock()
        try:
            with self._tx() as conn:
                # Ids are never reused: audit rows and registry slots name a connection by
                # id, so a new connection must not inherit a deleted one's (review M-2).
                highest = conn.execute("SELECT COALESCE(MAX(id), 0) FROM connections").fetchone()
                mark = conn.execute(
                    "SELECT value FROM settings WHERE key = ?", (CONNECTION_ID_SETTING,)
                ).fetchone()
                new_id = max(int(highest[0]), int(json.loads(mark[0])) if mark else 0) + 1
                conn.execute(
                    "INSERT INTO connections (id, name, host, port, service, account, ssl, "
                    "login_mode, shared_user, shared_password_enc, read_only, enabled, "
                    "created_at, created_by, updated_at, updated_by) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        new_id,
                        name,
                        host,
                        port,
                        service,
                        account,
                        int(ssl),
                        login_mode,
                        shared_user,
                        self._encrypt(shared_password),
                        int(read_only),
                        int(enabled),
                        now,
                        actor,
                        now,
                        actor,
                    ),
                )
                conn.execute(
                    "INSERT INTO settings (key, value) VALUES (?, ?) "
                    "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                    (CONNECTION_ID_SETTING, json.dumps(new_id)),
                )
                remember_database(conn, host, account)
        except sqlite3.IntegrityError as exc:
            if "UNIQUE" in str(exc):
                raise StoreError(f"A connection named '{name}' already exists") from exc
            raise StoreError(f"Invalid connection settings: {exc}") from exc
        created = self.get_connection(new_id)
        assert created is not None
        return created

    def get_connection(self, connection_id: int) -> Connection | None:
        """Return a connection by id, or None."""
        row = self._one("SELECT * FROM connections WHERE id = ?", (connection_id,))
        return self._connection(row) if row else None

    def get_connection_by_name(self, name: str) -> Connection | None:
        """Return a connection by its exact name, or None."""
        row = self._one("SELECT * FROM connections WHERE name = ?", (name,))
        return self._connection(row) if row else None

    def list_connections(self) -> list[Connection]:
        """Return every connection, ordered by name."""
        rows = self._all("SELECT * FROM connections ORDER BY name")
        return [self._connection(row) for row in rows]

    def has_connections(self) -> bool:
        """Return whether any connection exists."""
        return self._one("SELECT 1 FROM connections LIMIT 1") is not None

    def set_connection_flags(
        self,
        connection_id: int,
        *,
        read_only: bool | None = None,
        enabled: bool | None = None,
        actor: str | None = None,
    ) -> None:
        """Change a connection's read-only or enabled switch."""
        with self._tx() as conn:
            if read_only is not None:
                conn.execute(
                    "UPDATE connections SET read_only = ? WHERE id = ?",
                    (int(read_only), connection_id),
                )
            if enabled is not None:
                conn.execute(
                    "UPDATE connections SET enabled = ? WHERE id = ?",
                    (int(enabled), connection_id),
                )
            conn.execute(
                "UPDATE connections SET version = version + 1, updated_at = ?, updated_by = ? "
                "WHERE id = ?",
                (self.clock(), actor, connection_id),
            )

    def update_connection(
        self,
        connection_id: int,
        *,
        expected_version: int,
        name: str,
        host: str,
        port: int,
        service: str,
        account: str,
        ssl: bool,
        login_mode: str,
        shared_user: str | None,
        shared_password: str | None = None,
        clear_shared_password: bool = False,
        clear_u2_logins: bool = False,
        read_only: bool,
        enabled: bool,
        actor: str | None,
    ) -> Connection:
        """Save an edited connection, unless someone else saved it first.

        Args:
            connection_id: The connection being edited
            expected_version: The version the editor started from
            shared_password: A new password, or None to keep the stored one
            clear_shared_password: Remove the stored password (per-user connections)
            clear_u2_logins: Forget every personal U2 login on this connection, in
                the same transaction (the server changed)

        Raises:
            StaleEdit: If the connection was saved since expected_version
            StoreError: If it no longer exists, the name is taken, or a value is invalid
        """
        if clear_shared_password and shared_password is not None:
            raise StoreError("Give a new password or clear it, not both.")
        try:
            with self._tx() as conn:
                row = conn.execute(
                    "SELECT version FROM connections WHERE id = ?", (connection_id,)
                ).fetchone()
                if row is None:
                    raise StoreError("That connection no longer exists.")
                if row[0] != expected_version:
                    raise StaleEdit(STALE_CONNECTION_MESSAGE)
                remember_database(conn, host, account)
                conn.execute(
                    "UPDATE connections SET name = ?, host = ?, port = ?, service = ?, "
                    "account = ?, ssl = ?, login_mode = ?, shared_user = ?, read_only = ?, "
                    "enabled = ?, version = version + 1, updated_at = ?, updated_by = ? "
                    "WHERE id = ?",
                    (
                        name,
                        host,
                        port,
                        service,
                        account,
                        int(ssl),
                        login_mode,
                        shared_user,
                        int(read_only),
                        int(enabled),
                        self.clock(),
                        actor,
                        connection_id,
                    ),
                )
                if clear_shared_password:
                    conn.execute(
                        "UPDATE connections SET shared_password_enc = NULL WHERE id = ?",
                        (connection_id,),
                    )
                elif shared_password is not None:
                    conn.execute(
                        "UPDATE connections SET shared_password_enc = ? WHERE id = ?",
                        (self._encrypt(shared_password), connection_id),
                    )
                if clear_u2_logins:
                    # Same transaction as the host change: no call can pair the new
                    # server with a password that was given for the old one.
                    conn.execute(
                        "DELETE FROM user_u2_logins WHERE connection_id = ?", (connection_id,)
                    )
        except sqlite3.IntegrityError as exc:
            if "UNIQUE" in str(exc):
                raise StoreError(f"A connection named '{name}' already exists") from exc
            raise StoreError(f"Invalid connection settings: {exc}") from exc
        saved = self.get_connection(connection_id)
        assert saved is not None
        return saved

    def delete_connection(self, connection_id: int) -> bool:
        """Delete a connection and (through foreign keys) its grants, keeping DB notes.

        Returns:
            Whether a connection was deleted
        """
        with self._tx() as conn:
            cursor = conn.execute("DELETE FROM connections WHERE id = ?", (connection_id,))
            return cursor.rowcount > 0

    def shared_password(self, connection_id: int) -> str | None:
        """Decrypt a connection's shared U2 password.

        Raises:
            SecretUnreadable: If it was stored under a different U2_SECRET_KEY
        """
        row = self._one(
            "SELECT shared_password_enc FROM connections WHERE id = ?", (connection_id,)
        )
        if row is None or row[0] is None:
            return None
        return self._box.decrypt(row[0])

    # --------------------------------------------------------------- knowledge

    def list_knowledge_namespaces(self) -> list[KnowledgeNamespace]:
        """The databases that have notes, by server and account."""
        rows = self._all(
            "SELECT k.scope, n.server, n.account, COUNT(*) AS count FROM knowledge k "
            "JOIN knowledge_namespaces n ON k.scope = n.scope GROUP BY k.scope "
            "ORDER BY n.server, n.account"
        )
        return [
            KnowledgeNamespace(row["scope"], row["server"], row["account"], row["count"])
            for row in rows
        ]

    @staticmethod
    def _knowledge_topic(row: sqlite3.Row) -> KnowledgeTopic:
        return KnowledgeTopic(
            row["scope"], row["topic"], row["topic_key"], row["content"], row["updated_at"]
        )

    def list_knowledge_topics(self, scope: str) -> list[KnowledgeTopic]:
        return [
            self._knowledge_topic(row)
            for row in self._all(
                "SELECT * FROM knowledge WHERE scope = ? ORDER BY topic_key", (scope,)
            )
        ]

    def get_knowledge_topic(self, scope: str, key: str) -> KnowledgeTopic | None:
        row = self._one("SELECT * FROM knowledge WHERE scope = ? AND topic_key = ?", (scope, key))
        return self._knowledge_topic(row) if row else None

    def change_knowledge_topic(
        self, scope: str, key: str, *, revision: str, content: str | None
    ) -> bool:
        """Replace full text (including blank text), or delete with None, atomically."""
        with self._tx() as conn:
            row = conn.execute(
                "SELECT * FROM knowledge WHERE scope = ? AND topic_key = ?", (scope, key)
            ).fetchone()
            if row is None:
                return False
            if self._knowledge_topic(row).revision != revision:
                raise StaleEdit(
                    "Someone else changed this topic since you opened it. Reload to see "
                    "their changes before trying again."
                )
            if content is None:
                conn.execute(
                    "DELETE FROM knowledge WHERE scope = ? AND topic_key = ?", (scope, key)
                )
            else:
                conn.execute(
                    "UPDATE knowledge SET content = ?, updated_at = ? "
                    "WHERE scope = ? AND topic_key = ?",
                    (content, self.clock(), scope, key),
                )
        return True

    # -------------------------------------------------------------------- users

    @staticmethod
    def _user(row: sqlite3.Row) -> User:
        return User(
            id=row["id"],
            kind=row["kind"],
            username=row["username"],
            sso_subject=row["sso_subject"],
            email=row["email"],
            display_name=row["display_name"],
            is_admin=bool(row["is_admin"]),
            disabled=bool(row["disabled"]),
            last_sso_login_at=row["last_sso_login_at"],
            groups_unavailable=bool(row["groups_unavailable"]),
            created_at=row["created_at"],
            must_change_password=bool(row["must_change_password"]),
            sso_issuer=row["sso_issuer"],
        )

    def add_local_user(
        self,
        username: str,
        *,
        display_name: str | None = None,
        email: str | None = None,
        password_hash: str | None = None,
        is_admin: bool = False,
    ) -> User:
        """Create a local (password) user.

        Raises:
            StoreError: If the username is taken
        """
        try:
            with self._tx() as conn:
                cursor = conn.execute(
                    "INSERT INTO users (kind, username, display_name, email, password_hash, "
                    "is_admin, created_at) VALUES ('local', ?, ?, ?, ?, ?, ?)",
                    (username, display_name, email, password_hash, int(is_admin), self.clock()),
                )
                new_id = int(cursor.lastrowid or 0)
        except sqlite3.IntegrityError as exc:
            if "UNIQUE" in str(exc):
                raise StoreError(f"A user named '{username}' already exists") from exc
            raise StoreError(f"Invalid user: {exc}") from exc
        created = self.get_user(new_id)
        assert created is not None
        return created

    def get_or_create_sso_user(
        self,
        subject: str,
        *,
        issuer: str | None = None,
        email: str | None = None,
        display_name: str | None = None,
    ) -> User:
        """Return the SSO user with this issuer and subject, creating them with no access if new.

        Email and display name are refreshed from the identity provider when given.
        """
        with self._tx() as conn:
            row = conn.execute(
                "SELECT id FROM users WHERE sso_subject = ? AND sso_issuer IS ?",
                (subject, issuer),
            ).fetchone()
            if row is None:
                cursor = conn.execute(
                    "INSERT INTO users (kind, sso_issuer, sso_subject, email, display_name, "
                    "created_at) VALUES ('sso', ?, ?, ?, ?, ?)",
                    (issuer, subject, email, display_name, self.clock()),
                )
                user_id = int(cursor.lastrowid or 0)
            else:
                user_id = int(row["id"])
                conn.execute(
                    "UPDATE users SET email = COALESCE(?, email), "
                    "display_name = COALESCE(?, display_name) WHERE id = ?",
                    (email, display_name, user_id),
                )
        user = self.get_user(user_id)
        assert user is not None
        return user

    def get_sso_user(self, issuer: str | None, subject: str) -> User | None:
        """Return the SSO user with exactly this issuer and subject."""
        row = self._one(
            "SELECT * FROM users WHERE sso_subject = ? AND sso_issuer IS ?", (subject, issuer)
        )
        return self._user(row) if row else None

    def get_user(self, user_id: int) -> User | None:
        """Return a user by id, or None."""
        row = self._one("SELECT * FROM users WHERE id = ?", (user_id,))
        return self._user(row) if row else None

    def get_user_by_subject(self, subject: str) -> User | None:
        """Return an SSO user with this subject, whatever their issuer, or None.

        For display and tests only: two providers may share a subject, so sign-in
        and token checks use get_sso_user. An issuer-less row comes first.
        """
        row = self._one(
            "SELECT * FROM users WHERE sso_subject = ? ORDER BY sso_issuer IS NOT NULL, id LIMIT 1",
            (subject,),
        )
        return self._user(row) if row else None

    def get_user_by_username(self, username: str) -> User | None:
        """Return the local user with this exact username, or None."""
        row = self._one("SELECT * FROM users WHERE kind = 'local' AND username = ?", (username,))
        return self._user(row) if row else None

    def list_users(
        self, *, search: str = "", is_admin: bool | None = None, disabled: bool | None = None
    ) -> list[User]:
        """Return users matching a text search and flags, ordered by label.

        Args:
            search: Matched, case-insensitively, against username, email, display
                name and SSO subject. LIKE wildcards in it are taken literally.
            is_admin: Only admins (True) or only non-admins (False)
            disabled: Only disabled (True) or only enabled (False) users
        """
        sql = "SELECT * FROM users WHERE 1 = 1"
        params: list[Any] = []
        if search:
            escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            pattern = f"%{escaped}%"
            sql += (
                " AND (username LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\' "
                "OR display_name LIKE ? ESCAPE '\\' OR sso_subject LIKE ? ESCAPE '\\')"
            )
            params += [pattern] * 4
        if is_admin is not None:
            sql += " AND is_admin = ?"
            params.append(int(is_admin))
        if disabled is not None:
            sql += " AND disabled = ?"
            params.append(int(disabled))
        users = [self._user(row) for row in self._all(sql, params)]
        return sorted(users, key=lambda user: (user.label.casefold(), user.id))

    def password_hash(self, user_id: int) -> str | None:
        """Return a local user's stored password hash, or None."""
        row = self._one("SELECT password_hash FROM users WHERE id = ?", (user_id,))
        return None if row is None else row[0]

    def set_password_hash(self, user_id: int, password_hash: str, *, must_change: bool) -> None:
        """Replace a user's password hash and set whether they must change it.

        Raises:
            StoreError: If the user does not exist
        """
        with self._tx() as conn:
            cursor = conn.execute(
                "UPDATE users SET password_hash = ?, must_change_password = ? WHERE id = ?",
                (password_hash, int(must_change), user_id),
            )
            if cursor.rowcount == 0:
                raise StoreError("That user no longer exists.")

    def set_user_admin(self, user_id: int, is_admin: bool) -> None:
        """Grant or remove admin-site access. This never grants data access.

        Raises:
            StoreError: If the user does not exist
        """
        with self._tx() as conn:
            cursor = conn.execute(
                "UPDATE users SET is_admin = ? WHERE id = ?", (int(is_admin), user_id)
            )
            if cursor.rowcount == 0:
                raise StoreError("That user no longer exists.")

    def has_local_admin(self) -> bool:
        """Return whether an enabled local admin exists (break-glass access)."""
        row = self._one(
            "SELECT 1 FROM users WHERE kind = 'local' AND is_admin = 1 AND disabled = 0 LIMIT 1"
        )
        return row is not None

    def set_user_disabled(self, user_id: int, disabled: bool) -> None:
        """Disable or re-enable a user. Disabling ends their admin-site sessions.

        Raises:
            StoreError: If the user does not exist
        """
        with self._tx() as conn:
            cursor = conn.execute(
                "UPDATE users SET disabled = ? WHERE id = ?", (int(disabled), user_id)
            )
            if cursor.rowcount == 0:
                raise StoreError("That user no longer exists.")
            if disabled:
                conn.execute("DELETE FROM admin_sessions WHERE user_id = ?", (user_id,))

    def set_user_flags(
        self, user_id: int, *, is_admin: bool | None = None, disabled: bool | None = None
    ) -> None:
        """Change a user's admin and disabled flags in one transaction.

        The last enabled local admin stays: it is the way back in when company
        sign-in fails. The check runs inside the same transaction as the change,
        so two admins removing each other at once cannot both succeed.
        Disabling ends the user's admin-site sessions.

        Raises:
            LastAdmin: If the change would leave no enabled local admin
            StoreError: If the user does not exist
        """
        enabled_local_admins = (
            "SELECT COUNT(*) FROM users WHERE kind = 'local' AND is_admin = 1 AND disabled = 0"
        )
        with self._tx() as conn:
            if conn.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone() is None:
                raise StoreError("That user no longer exists.")
            had_admins = conn.execute(enabled_local_admins).fetchone()[0]
            if is_admin is not None:
                conn.execute("UPDATE users SET is_admin = ? WHERE id = ?", (int(is_admin), user_id))
            if disabled is not None:
                conn.execute("UPDATE users SET disabled = ? WHERE id = ?", (int(disabled), user_id))
                if disabled:
                    conn.execute("DELETE FROM admin_sessions WHERE user_id = ?", (user_id,))
            if had_admins and not conn.execute(enabled_local_admins).fetchone()[0]:
                raise LastAdmin("Keep at least one enabled local admin.")

    def reset_password(self, user_id: int, password_hash: str) -> int:
        """Replace a local user's password, force a change at next sign-in, end sessions.

        Returns:
            How many admin-site sessions ended

        Raises:
            StoreError: If the user does not exist or signs in with company sign-in
        """
        with self._tx() as conn:
            cursor = conn.execute(
                "UPDATE users SET password_hash = ?, must_change_password = 1 "
                "WHERE id = ? AND kind = 'local'",
                (password_hash, user_id),
            )
            if cursor.rowcount == 0:
                raise StoreError("That user no longer exists or has no password.")
            return conn.execute("DELETE FROM admin_sessions WHERE user_id = ?", (user_id,)).rowcount

    def update_user_details(
        self,
        user_id: int,
        *,
        display_name: str | None,
        email: str | None,
        username: str | None = None,
    ) -> None:
        """Change a user's display name and email, and a local user's username.

        Raises:
            StoreError: If the user does not exist, the username is taken, or a
                username is given for a user who signs in with company sign-in
        """
        try:
            with self._tx() as conn:
                row = conn.execute("SELECT kind FROM users WHERE id = ?", (user_id,)).fetchone()
                if row is None:
                    raise StoreError("That user no longer exists.")
                if username is not None and row["kind"] != "local":
                    raise StoreError("Only local users have a username.")
                conn.execute(
                    "UPDATE users SET display_name = ?, email = ?, "
                    "username = COALESCE(?, username) "
                    "WHERE id = ?",
                    (display_name, email, username, user_id),
                )
        except sqlite3.IntegrityError as exc:
            raise StoreError(f"A user named '{username}' already exists") from exc

    def delete_user(self, user_id: int) -> None:
        """Delete a person with their tokens, sessions, group membership and U2 logins.

        Grants given to them go too (a grant's subject has no foreign key). Audit
        rows stay. The last enabled local admin cannot be deleted: the check runs
        in the same transaction, so two admins deleting each other cannot both win.

        Raises:
            LastAdmin: If no enabled local admin would be left
            StoreError: If the user does not exist
        """
        enabled_local_admins = (
            "SELECT COUNT(*) FROM users WHERE kind = 'local' AND is_admin = 1 AND disabled = 0"
        )
        with self._tx() as conn:
            if conn.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone() is None:
                raise StoreError("That user no longer exists.")
            had_admins = conn.execute(enabled_local_admins).fetchone()[0]
            conn.execute(
                "DELETE FROM grants WHERE subject_type = 'user' AND subject_id = ?", (user_id,)
            )
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            if had_admins and not conn.execute(enabled_local_admins).fetchone()[0]:
                raise LastAdmin("Keep at least one enabled local admin.")

    def record_sso_login(self, user_id: int, group_external_ids: list[str] | None) -> None:
        """Record a completed SSO sign-in and replace the user's group membership.

        Groups are the user's own provider's: a group id another issuer also uses
        is a different group, so it never inherits that group's grants.

        Args:
            user_id: The user who signed in
            group_external_ids: Groups from the identity provider's claim, or None
                when the provider did not supply them (for example an Entra group
                overage). None clears membership and flags the user, so stale groups
                never keep granting access.
        """
        now = self.clock()
        with self._tx() as conn:
            conn.execute(
                "UPDATE users SET last_sso_login_at = ?, groups_unavailable = ? WHERE id = ?",
                (now, int(group_external_ids is None), user_id),
            )
            conn.execute("DELETE FROM user_groups WHERE user_id = ?", (user_id,))
            issuer = conn.execute(
                "SELECT sso_issuer FROM users WHERE id = ?", (user_id,)
            ).fetchone()[0]
            for external_id in sorted(set(group_external_ids or [])):
                row = conn.execute(
                    "SELECT id FROM groups WHERE issuer IS ? AND external_id = ?",
                    (issuer, external_id),
                ).fetchone()
                if row is None:
                    cursor = conn.execute(
                        "INSERT INTO groups (issuer, external_id, first_seen_at, last_seen_at) "
                        "VALUES (?, ?, ?, ?)",
                        (issuer, external_id, now, now),
                    )
                    group_id = int(cursor.lastrowid or 0)
                else:
                    group_id = int(row[0])
                    conn.execute("UPDATE groups SET last_seen_at = ? WHERE id = ?", (now, group_id))
                conn.execute(
                    "INSERT INTO user_groups (user_id, group_id, recorded_at) VALUES (?, ?, ?)",
                    (user_id, group_id, now),
                )

    # ------------------------------------------------------------------- groups

    def group_ids_for_user(self, user_id: int) -> list[int]:
        """Return the ids of the groups recorded at the user's last SSO sign-in."""
        rows = self._all(
            "SELECT group_id FROM user_groups WHERE user_id = ? ORDER BY group_id", (user_id,)
        )
        return [int(row[0]) for row in rows]

    def list_groups(self) -> list[Group]:
        """Return every group ever seen at sign-in."""
        rows = self._all("SELECT * FROM groups ORDER BY external_id, issuer")
        return [self._group(row) for row in rows]

    def has_groups(self) -> bool:
        """Whether any group was ever seen at sign-in or is named in a grant."""
        row = self._one(
            "SELECT EXISTS (SELECT 1 FROM groups) "
            "OR EXISTS (SELECT 1 FROM grants WHERE subject_type = 'group')"
        )
        return bool(row and row[0])

    def get_group(self, group_id: int) -> Group | None:
        """Return a group by id, or None."""
        row = self._one("SELECT * FROM groups WHERE id = ?", (group_id,))
        return self._group(row) if row else None

    @staticmethod
    def _group(row: sqlite3.Row) -> Group:
        return Group(
            id=row["id"],
            issuer=row["issuer"],
            external_id=row["external_id"],
            label=row["label"],
            last_seen_at=row["last_seen_at"],
        )

    def delete_group(self, group_id: int) -> int:
        """Delete a group, its grants and who was in it.

        Returns:
            How many grants went with it

        Raises:
            StoreError: If the group does not exist
        """
        with self._tx() as conn:
            grants = conn.execute(
                "DELETE FROM grants WHERE subject_type = 'group' AND subject_id = ?", (group_id,)
            ).rowcount
            if conn.execute("DELETE FROM groups WHERE id = ?", (group_id,)).rowcount == 0:
                raise StoreError("That group no longer exists.")
        return grants

    def set_group_label(self, group_id: int, label: str | None) -> None:
        """Set the name admins see for a group; None shows its claim value.

        Raises:
            StoreError: If the group does not exist
        """
        with self._tx() as conn:
            cursor = conn.execute("UPDATE groups SET label = ? WHERE id = ?", (label, group_id))
            if cursor.rowcount == 0:
                raise StoreError("That group no longer exists.")

    # -------------------------------------------------------------------- roles

    @staticmethod
    def _role(row: sqlite3.Row) -> Role:
        return Role(
            id=row["id"],
            name=row["name"],
            builtin=bool(row["builtin"]),
            permissions=frozenset(json.loads(row["permissions"])),
            version=row["version"],
        )

    def seed_builtin_roles(self) -> None:
        """Create the built-in roles, or bring their permissions up to date."""
        with self._tx() as conn:
            for name, permissions in BUILTIN_ROLES.items():
                conn.execute(
                    "INSERT INTO roles (name, builtin, permissions) VALUES (?, 1, ?) "
                    "ON CONFLICT (name) DO UPDATE SET permissions = excluded.permissions, "
                    "builtin = 1",
                    (name, json.dumps(list(permissions))),
                )

    def get_role(self, role_id: int) -> Role | None:
        """Return a role by id, or None."""
        row = self._one("SELECT * FROM roles WHERE id = ?", (role_id,))
        return self._role(row) if row else None

    def get_role_by_name(self, name: str) -> Role | None:
        """Return a role by name, or None."""
        row = self._one("SELECT * FROM roles WHERE name = ?", (name,))
        return self._role(row) if row else None

    def list_roles(self) -> list[Role]:
        """Return every role: built-in roles first, then custom roles, each by name."""
        rows = self._all("SELECT * FROM roles ORDER BY builtin DESC, name")
        return [self._role(row) for row in rows]

    def add_role(self, name: str, permissions: Iterable[str]) -> Role:
        """Create a custom role.

        Raises:
            StoreError: If a permission is unknown or the name is taken
        """
        wanted = list(dict.fromkeys(permissions))
        unknown = [p for p in wanted if p not in PERMISSIONS]
        if unknown:
            raise StoreError(f"unknown permission(s): {', '.join(unknown)}")
        try:
            with self._tx() as conn:
                cursor = conn.execute(
                    "INSERT INTO roles (name, builtin, permissions) VALUES (?, 0, ?)",
                    (name, json.dumps(wanted)),
                )
                new_id = int(cursor.lastrowid or 0)
        except sqlite3.IntegrityError as exc:
            raise StoreError(f"A role named '{name}' already exists") from exc
        role = self.get_role(new_id)
        assert role is not None
        return role

    def role_in_use(self, role_id: int) -> int:
        """Return how many grants use a role."""
        row = self._one("SELECT COUNT(*) FROM grants WHERE role_id = ?", (role_id,))
        return int(row[0]) if row else 0

    def update_role(
        self, role_id: int, *, expected_version: int, name: str, permissions: Iterable[str]
    ) -> Role:
        """Save an edited custom role, unless someone else saved it first.

        Raises:
            StaleEdit: If the role was saved since expected_version
            StoreError: If it is built-in, gone, the name is taken or a permission unknown
        """
        wanted = list(dict.fromkeys(permissions))
        unknown = [p for p in wanted if p not in PERMISSIONS]
        if unknown:
            raise StoreError(f"unknown permission(s): {', '.join(unknown)}")
        try:
            with self._tx() as conn:
                row = conn.execute(
                    "SELECT builtin, version FROM roles WHERE id = ?", (role_id,)
                ).fetchone()
                if row is None:
                    raise StoreError("That role no longer exists.")
                if row["builtin"]:
                    raise StoreError("Built-in roles can't be changed.")
                if row["version"] != expected_version:
                    raise StaleEdit(STALE_ROLE_MESSAGE)
                conn.execute(
                    "UPDATE roles SET name = ?, permissions = ?, version = version + 1 "
                    "WHERE id = ?",
                    (name, json.dumps(wanted), role_id),
                )
        except sqlite3.IntegrityError as exc:
            raise StoreError(f"A role named '{name}' already exists") from exc
        role = self.get_role(role_id)
        if role is None:
            raise StoreError("That role no longer exists.")
        return role

    def delete_role(self, role_id: int) -> None:
        """Delete a custom role that no grant uses.

        Raises:
            StoreError: If it is built-in, in use or gone
        """
        with self._tx() as conn:
            row = conn.execute("SELECT builtin FROM roles WHERE id = ?", (role_id,)).fetchone()
            if row is None:
                raise StoreError("That role no longer exists.")
            if row["builtin"]:
                raise StoreError("Built-in roles can't be changed.")
            used = conn.execute(
                "SELECT COUNT(*) FROM grants WHERE role_id = ?", (role_id,)
            ).fetchone()[0]
            if used:
                raise StoreError("That role is in use.")
            conn.execute("DELETE FROM roles WHERE id = ?", (role_id,))

    # ------------------------------------------------------------------- grants

    @staticmethod
    def _grant(row: sqlite3.Row) -> Grant:
        return Grant(
            id=row["id"],
            connection_id=row["connection_id"],
            subject_type=row["subject_type"],
            subject_id=row["subject_id"],
            role_id=row["role_id"],
        )

    def add_grant(
        self,
        *,
        connection_id: int,
        subject_type: str,
        role_id: int,
        subject_id: int | None = None,
    ) -> Grant:
        """Give a user, a group or everyone a role on a connection.

        A per-user connection's U2 login is not part of a grant: see set_u2_login.

        Raises:
            StoreError: If that subject already has a grant on the connection, or the
                combination breaks a schema rule
        """
        try:
            with self._tx() as conn:
                cursor = conn.execute(
                    "INSERT INTO grants (connection_id, subject_type, subject_id, role_id, "
                    "created_at) VALUES (?, ?, ?, ?, ?)",
                    (connection_id, subject_type, subject_id, role_id, self.clock()),
                )
                new_id = int(cursor.lastrowid or 0)
        except sqlite3.IntegrityError as exc:
            if "UNIQUE" in str(exc):
                raise StoreError("That subject already has a grant on this connection") from exc
            raise StoreError(f"Invalid grant: {exc}") from exc
        row = self._one("SELECT * FROM grants WHERE id = ?", (new_id,))
        assert row is not None
        return self._grant(row)

    def grants_on_connection(self, connection_id: int) -> list[Grant]:
        """Return every grant on one connection."""
        rows = self._all(
            "SELECT * FROM grants WHERE connection_id = ? ORDER BY id", (connection_id,)
        )
        return [self._grant(row) for row in rows]

    def get_grant(self, grant_id: int) -> Grant | None:
        """Return a grant by id, or None."""
        row = self._one("SELECT * FROM grants WHERE id = ?", (grant_id,))
        return self._grant(row) if row else None

    def grants_for_subject(self, subject_type: str, subject_id: int | None) -> list[Grant]:
        """Return one user's, one group's, or everyone's own grants (not inherited ones)."""
        if subject_type == "everyone":
            return self.everyone_grants()
        rows = self._all(
            "SELECT * FROM grants WHERE subject_type = ? AND subject_id = ? ORDER BY id",
            (subject_type, subject_id),
        )
        return [self._grant(row) for row in rows]

    def everyone_grants(self) -> list[Grant]:
        """Return every grant whose subject is everyone."""
        rows = self._all("SELECT * FROM grants WHERE subject_type = 'everyone' ORDER BY id")
        return [self._grant(row) for row in rows]

    def update_grant(self, grant_id: int, *, role_id: int) -> Grant:
        """Change a grant's role.

        Raises:
            StoreError: If the grant no longer exists or the role is invalid
        """
        try:
            with self._tx() as conn:
                cursor = conn.execute(
                    "UPDATE grants SET role_id = ? WHERE id = ?", (role_id, grant_id)
                )
                if cursor.rowcount == 0:
                    raise StoreError("That grant no longer exists.")
        except sqlite3.IntegrityError as exc:
            raise StoreError(f"Invalid grant: {exc}") from exc
        updated = self.get_grant(grant_id)
        if updated is None:
            raise StoreError("That grant no longer exists.")
        return updated

    def delete_grant(self, grant_id: int) -> bool:
        """Delete a grant. Returns whether one was deleted."""
        with self._tx() as conn:
            return conn.execute("DELETE FROM grants WHERE id = ?", (grant_id,)).rowcount > 0

    def grants_for(
        self, user_id: int, group_ids: Iterable[int], connection_id: int | None = None
    ) -> list[Grant]:
        """Return the grants that apply to a user: theirs, their groups', and everyone's.

        Args:
            user_id: The user
            group_ids: Ids of the user's groups
            connection_id: Limit to one connection when given
        """
        groups = list(group_ids)
        placeholders = ",".join("?" for _ in groups) or "NULL"
        sql = (
            "SELECT * FROM grants WHERE ("
            "(subject_type = 'user' AND subject_id = ?) "
            f"OR (subject_type = 'group' AND subject_id IN ({placeholders})) "
            "OR subject_type = 'everyone')"
        )
        params: list[Any] = [user_id, *groups]
        if connection_id is not None:
            sql += " AND connection_id = ?"
            params.append(connection_id)
        return [self._grant(row) for row in self._all(sql + " ORDER BY id", params)]

    # ---------------------------------------------------------- personal logins

    @staticmethod
    def _u2_login(row: sqlite3.Row) -> U2Login:
        return U2Login(
            user_id=row["user_id"],
            connection_id=row["connection_id"],
            u2_user=row["u2_user"],
            updated_at=row["updated_at"],
        )

    def get_u2_login(self, user_id: int, connection_id: int) -> U2Login | None:
        """Return a person's own U2 login on a connection, without its password."""
        row = self._one(
            "SELECT user_id, connection_id, u2_user, updated_at FROM user_u2_logins "
            "WHERE user_id = ? AND connection_id = ?",
            (user_id, connection_id),
        )
        return self._u2_login(row) if row else None

    def get_u2_login_password(self, user_id: int, connection_id: int) -> str | None:
        """Decrypt a person's own U2 password on a connection.

        Raises:
            SecretUnreadable: If it was stored under a different U2_SECRET_KEY
        """
        row = self._one(
            "SELECT u2_password_enc FROM user_u2_logins WHERE user_id = ? AND connection_id = ?",
            (user_id, connection_id),
        )
        return None if row is None else self._box.decrypt(row[0])

    def set_u2_login(
        self, user_id: int, connection_id: int, u2_user: str, u2_password: str | None
    ) -> U2Login:
        """Save a person's own U2 login on a connection.

        Args:
            user_id: The person
            connection_id: The per-user connection
            u2_user: Their U2 user name
            u2_password: A new password, or None to keep the stored one

        Raises:
            StoreError: If the password is to be kept but none is stored, or the
                person or connection does not exist
        """
        try:
            with self._tx() as conn:
                if u2_password is None:
                    cursor = conn.execute(
                        "UPDATE user_u2_logins SET u2_user = ?, updated_at = ? "
                        "WHERE user_id = ? AND connection_id = ?",
                        (u2_user, self.clock(), user_id, connection_id),
                    )
                    if cursor.rowcount == 0:
                        raise StoreError("No U2 password is stored to keep.")
                else:
                    conn.execute(
                        "INSERT INTO user_u2_logins (user_id, connection_id, u2_user, "
                        "u2_password_enc, updated_at) VALUES (?, ?, ?, ?, ?) "
                        "ON CONFLICT (user_id, connection_id) DO UPDATE SET "
                        "u2_user = excluded.u2_user, "
                        "u2_password_enc = excluded.u2_password_enc, "
                        "updated_at = excluded.updated_at",
                        (
                            user_id,
                            connection_id,
                            u2_user,
                            self._box.encrypt(u2_password),
                            self.clock(),
                        ),
                    )
        except sqlite3.IntegrityError as exc:
            raise StoreError(f"Invalid U2 login: {exc}") from exc
        saved = self.get_u2_login(user_id, connection_id)
        assert saved is not None
        return saved

    def delete_u2_login(self, user_id: int, connection_id: int) -> bool:
        """Forget a person's own U2 login on a connection. Returns whether one existed."""
        with self._tx() as conn:
            cursor = conn.execute(
                "DELETE FROM user_u2_logins WHERE user_id = ? AND connection_id = ?",
                (user_id, connection_id),
            )
            return cursor.rowcount > 0

    def list_u2_logins_for_user(self, user_id: int) -> list[U2Login]:
        """Return every U2 login one person has set, by connection id."""
        rows = self._all(
            "SELECT user_id, connection_id, u2_user, updated_at FROM user_u2_logins "
            "WHERE user_id = ? ORDER BY connection_id",
            (user_id,),
        )
        return [self._u2_login(row) for row in rows]

    def list_u2_logins_for_connection(self, connection_id: int) -> list[U2Login]:
        """Return every person's U2 login on one connection, by user id."""
        rows = self._all(
            "SELECT user_id, connection_id, u2_user, updated_at FROM user_u2_logins "
            "WHERE connection_id = ? ORDER BY user_id",
            (connection_id,),
        )
        return [self._u2_login(row) for row in rows]

    # ------------------------------------------------------------------- tokens

    @staticmethod
    def _token(row: sqlite3.Row) -> TokenRecord:
        return TokenRecord(
            id=row["id"],
            user_id=row["user_id"],
            name=row["name"],
            token_hash=row["token_hash"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            last_used_at=row["last_used_at"],
            last_used_ip=row["last_used_ip"],
            revoked_at=row["revoked_at"],
        )

    def add_token(
        self, *, user_id: int, name: str, token_hash: str, expires_at: float
    ) -> TokenRecord:
        """Store a new personal access token's hash."""
        with self._tx() as conn:
            cursor = conn.execute(
                "INSERT INTO tokens (user_id, name, token_hash, created_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (user_id, name, token_hash, self.clock(), expires_at),
            )
            new_id = int(cursor.lastrowid or 0)
        row = self._one("SELECT * FROM tokens WHERE id = ?", (new_id,))
        assert row is not None
        return self._token(row)

    def get_token_by_hash(self, token_hash: str) -> TokenRecord | None:
        """Return the token with this hash, or None."""
        row = self._one("SELECT * FROM tokens WHERE token_hash = ?", (token_hash,))
        return self._token(row) if row else None

    def get_token(self, token_id: int) -> TokenRecord | None:
        """Return a token record by id, or None."""
        row = self._one("SELECT * FROM tokens WHERE id = ?", (token_id,))
        return self._token(row) if row else None

    def touch_token(self, token_id: int, *, at: float, ip: str | None) -> None:
        """Record that a token was just used."""
        with self._tx() as conn:
            conn.execute(
                "UPDATE tokens SET last_used_at = ?, last_used_ip = ? WHERE id = ?",
                (at, ip, token_id),
            )

    def revoke_token(self, token_id: int, *, at: float) -> None:
        """Revoke a token. Revoking twice keeps the first time."""
        with self._tx() as conn:
            conn.execute(
                "UPDATE tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?",
                (at, token_id),
            )

    def list_tokens(self, user_id: int) -> list[TokenRecord]:
        """Return a user's tokens, newest first."""
        rows = self._all(
            "SELECT * FROM tokens WHERE user_id = ? ORDER BY created_at DESC, id DESC",
            (user_id,),
        )
        return [self._token(row) for row in rows]

    # ----------------------------------------------------------- admin sessions

    @staticmethod
    def _admin_session(row: sqlite3.Row) -> AdminSession:
        return AdminSession(
            id_hash=row["id_hash"],
            user_id=row["user_id"],
            csrf_token=row["csrf_token"],
            created_at=row["created_at"],
            last_seen_at=row["last_seen_at"],
            ip=row["ip"],
        )

    def add_admin_session(
        self, *, id_hash: str, user_id: int, csrf_token: str, ip: str | None
    ) -> AdminSession:
        """Record a new admin-site session."""
        now = self.clock()
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO admin_sessions (id_hash, user_id, csrf_token, created_at, "
                "last_seen_at, ip) VALUES (?, ?, ?, ?, ?, ?)",
                (id_hash, user_id, csrf_token, now, now, ip),
            )
        return AdminSession(id_hash, user_id, csrf_token, now, now, ip)

    def get_admin_session(self, id_hash: str) -> AdminSession | None:
        """Return a session by the hash of its id, or None."""
        row = self._one("SELECT * FROM admin_sessions WHERE id_hash = ?", (id_hash,))
        return self._admin_session(row) if row else None

    def touch_admin_session(self, id_hash: str, *, at: float) -> None:
        """Record activity on a session, for the idle timeout."""
        with self._tx() as conn:
            conn.execute(
                "UPDATE admin_sessions SET last_seen_at = ? WHERE id_hash = ?", (at, id_hash)
            )

    def delete_admin_session(self, id_hash: str) -> None:
        """End one session."""
        with self._tx() as conn:
            conn.execute("DELETE FROM admin_sessions WHERE id_hash = ?", (id_hash,))

    def count_admin_sessions_for(self, user_id: int) -> int:
        """Return how many admin-site sessions a user has."""
        row = self._one("SELECT COUNT(*) FROM admin_sessions WHERE user_id = ?", (user_id,))
        return int(row[0]) if row else 0

    def delete_admin_sessions_for(self, user_id: int) -> int:
        """End every session a user has. Returns how many ended."""
        with self._tx() as conn:
            cursor = conn.execute("DELETE FROM admin_sessions WHERE user_id = ?", (user_id,))
            return cursor.rowcount

    def purge_admin_sessions(self, *, created_before: float, idle_before: float) -> int:
        """Delete sessions past their absolute lifetime or idle timeout."""
        with self._tx() as conn:
            cursor = conn.execute(
                "DELETE FROM admin_sessions WHERE created_at < ? OR last_seen_at < ?",
                (created_before, idle_before),
            )
            return cursor.rowcount

    def count_admin_sessions(self, *, seen_since: float) -> int:
        """Return how many admin-site sessions were active since a time."""
        row = self._one(
            "SELECT COUNT(*) FROM admin_sessions WHERE last_seen_at >= ?", (seen_since,)
        )
        return int(row[0]) if row else 0

    # -------------------------------------------------------------------- audit

    def add_audit(
        self,
        *,
        kind: str,
        action: str,
        outcome: str,
        actor_user_id: int | None = None,
        actor_label: str | None = None,
        connection_id: int | None = None,
        params: dict[str, Any] | None = None,
        duration_ms: float | None = None,
    ) -> None:
        """Append an audit row. Parameters whose names suggest a secret are redacted."""
        redacted = _redact(params)
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO audit (at, actor_user_id, actor_label, kind, connection_id, "
                "action, params, outcome, duration_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    self.clock(),
                    actor_user_id,
                    actor_label,
                    kind,
                    connection_id,
                    action,
                    None if redacted is None else json.dumps(redacted, default=str),
                    outcome,
                    duration_ms,
                ),
            )

    @staticmethod
    def _audit_entries(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
        entries = []
        for row in rows:
            entry = dict(row)
            entry["params"] = json.loads(entry["params"]) if entry["params"] else None
            entries.append(entry)
        return entries

    def recent_audit(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return the newest audit rows, newest first, with params decoded."""
        rows = self._all("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))
        return self._audit_entries(rows)

    def query_audit(
        self,
        *,
        actor_user_id: int | None = None,
        connection_id: int | None = None,
        kind: str | None = None,
        action: str = "",
        since: float | None = None,
        until: float | None = None,
        limit: int | None = 200,
    ) -> list[dict[str, Any]]:
        """Return matching audit rows, newest first, with params decoded.

        Args:
            actor_user_id: Only rows by this user
            connection_id: Only rows about this connection
            kind: Only rows of this kind (tool, admin or auth)
            action: A prefix: "grant." matches every grant action. LIKE
                wildcards in it are taken literally.
            since: Only rows at or after this time
            until: Only rows before this time
            limit: At most this many rows; None for all
        """
        sql = "SELECT * FROM audit WHERE 1 = 1"
        params: list[Any] = []
        if actor_user_id is not None:
            sql += " AND actor_user_id = ?"
            params.append(actor_user_id)
        if connection_id is not None:
            sql += " AND connection_id = ?"
            params.append(connection_id)
        if kind is not None:
            sql += " AND kind = ?"
            params.append(kind)
        if action:
            escaped = action.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            sql += " AND action LIKE ? ESCAPE '\\'"
            params.append(escaped + "%")
        if since is not None:
            sql += " AND at >= ?"
            params.append(since)
        if until is not None:
            sql += " AND at < ?"
            params.append(until)
        sql += " ORDER BY id DESC"
        if limit is not None:
            sql += " LIMIT ?"
            params.append(limit)
        return self._audit_entries(self._all(sql, params))

    # ----------------------------------------------------------------- settings

    def get_setting(self, key: str, default: Any = None) -> Any:
        """Return a setting's JSON value, or the default."""
        row = self._one("SELECT value FROM settings WHERE key = ?", (key,))
        return json.loads(row[0]) if row else default

    def set_setting(self, key: str, value: Any) -> None:
        """Store a setting as JSON."""
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) "
                "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                (key, json.dumps(value)),
            )

    def delete_setting(self, key: str) -> None:
        """Remove a setting."""
        with self._tx() as conn:
            conn.execute("DELETE FROM settings WHERE key = ?", (key,))

    def seal(self, plaintext: str) -> str:
        """Encrypt a short value for a cookie: confidential and tamper-evident."""
        return self._box.encrypt(plaintext)

    def unseal(self, sealed: str, *, max_age_seconds: int) -> str:
        """Open a value made by seal().

        Raises:
            SecretUnreadable: If it was changed, made under another key, or is too old
        """
        return self._box.decrypt(sealed, ttl=max_age_seconds)

    def get_secret_setting(self, key: str) -> str | None:
        """Return a decrypted secret setting, or None.

        Raises:
            SecretUnreadable: If it was stored under a different U2_SECRET_KEY
        """
        stored = self.get_setting(key)
        return None if stored is None else self._box.decrypt(stored)

    def set_secret_setting(self, key: str, value: str | None) -> None:
        """Store a secret setting encrypted; None removes it."""
        if value is None:
            self.delete_setting(key)
        else:
            self.set_setting(key, self._box.encrypt(value))
