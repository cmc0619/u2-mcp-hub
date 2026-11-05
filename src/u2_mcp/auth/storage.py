"""The MCP OAuth bridge's state, kept in the settings database.

Registered clients, authorization codes, access and refresh tokens and in-flight
sign-ins live in the oauth_* tables, so a restart signs nobody out. Bearer
secrets are stored only as SHA-256 hashes: a copy of the database yields no
usable credentials.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from ..store.db import Locked

logger = logging.getLogger(__name__)


@dataclass
class StoredClient:
    """Registered OAuth client (from DCR)."""

    client_id: str
    client_secret: str | None
    client_name: str | None
    redirect_uris: list[str]
    grant_types: list[str]
    response_types: list[str]
    scope: str | None
    token_endpoint_auth_method: str = "client_secret_post"  # Default auth method
    created_at: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class StoredAuthCode:
    """Authorization code pending exchange."""

    code: str
    client_id: str
    redirect_uri: str
    scope: str
    state: str
    code_challenge: str | None
    code_challenge_method: str | None
    user_subject: str  # User identifier from IdP
    user_claims: dict[str, Any]  # Claims from IdP
    resource: str | None = None  # RFC 8707 resource indicator
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 600)  # 10 min


@dataclass
class StoredToken:
    """Issued access or refresh token."""

    token: str
    token_type: str  # "access" or "refresh"
    client_id: str
    user_subject: str
    scope: str
    created_at: float = field(default_factory=time.time)
    expires_at: float | None = None
    user_claims: dict[str, Any] = field(default_factory=dict)
    resource: str | None = None  # RFC 8707 resource indicator
    # When the person signed in through the app; carried across refreshes.
    # None on tokens issued before it was recorded.
    signed_in_at: float | None = None


def token_issuer(claims: dict[str, Any] | None) -> str | None:
    """The issuer a token's person belongs to: the "iss" its claims carry, else None.

    A person is issuer plus subject. The identity resolver and My access both
    match tokens to people through this, so they always agree.
    """
    named = (claims or {}).get("iss")
    return named if isinstance(named, str) and named else None


@dataclass
class PendingAuthorization:
    """State for in-progress authorization flow."""

    state: str  # Internal state for IdP redirect
    client_id: str
    redirect_uri: str
    scope: str
    code_challenge: str | None
    code_challenge_method: str | None
    claude_redirect_uri: str  # Where to redirect after IdP auth
    claude_state: str | None  # Claude's original state to return
    resource: str | None = None  # RFC 8707 resource indicator
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 600)
    idp_code_verifier: str | None = None  # PKCE verifier for our own leg to the IdP


# Claim statements for single-use secrets. Written out in full rather than
# composed at runtime, so no table or column name is ever interpolated.
_CLAIM_AUTH_CODE = "DELETE FROM oauth_codes WHERE code_hash = ? RETURNING payload"
_CLAIM_PENDING_AUTH = "DELETE FROM oauth_pending WHERE state_hash = ? RETURNING payload"


def hash_secret(value: str) -> str:
    """Return the SHA-256 hex digest used as a lookup key for a secret.

    Args:
        value: The bearer token, authorization code or state parameter

    Returns:
        Hex digest safe to store and to index on
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class AuthStorage:
    """OAuth state in the settings database, with secrets stored as hashes.

    Args:
        locked: Store.locked, which yields the shared connection under its lock
        cleanup_interval: Seconds between automatic purges of expired rows
    """

    def __init__(self, locked: Locked, cleanup_interval: int = 300) -> None:
        self._locked = locked
        self._cleanup_interval = cleanup_interval
        self._last_cleanup = time.time()

    # -- plumbing -----------------------------------------------------------

    def _write(self, sql: str, parameters: tuple[Any, ...] = ()) -> int:
        """Run a statement that changes rows and return how many it changed."""
        with self._locked() as conn:
            return conn.execute(sql, parameters).rowcount

    def _read_one(self, sql: str, parameters: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        """Run a query expected to match at most one row."""
        with self._locked() as conn:
            row: sqlite3.Row | None = conn.execute(sql, parameters).fetchone()
            return row

    def _claim_one(self, statement: str, key_hash: str) -> sqlite3.Row | None:
        """Read a single-use row and delete it in one step (DELETE ... RETURNING).

        A read then a delete would let two threads both read it, and one
        authorization code be exchanged twice. The statement is one of this
        module's constants, so no table name is built at runtime.
        """
        with self._locked() as conn:
            # fetchall steps the statement to its end, so its implicit transaction commits.
            rows = conn.execute(statement, (key_hash,)).fetchall()
            return rows[0] if rows else None

    def _maybe_cleanup(self) -> None:
        """Purge expired rows if enough time has passed since the last purge."""
        if time.time() - self._last_cleanup < self._cleanup_interval:
            return
        self.cleanup()

    # -- clients ------------------------------------------------------------

    def store_client(self, client: StoredClient) -> None:
        """Store a registered client."""
        self._write(
            "INSERT OR REPLACE INTO oauth_clients (client_id, redirect_key, payload) "
            "VALUES (?, ?, ?)",
            (client.client_id, _redirect_key(client.redirect_uris), json.dumps(asdict(client))),
        )
        logger.info(f"Stored client: {client.client_id} ({client.client_name})")

    def get_client(self, client_id: str) -> StoredClient | None:
        """Retrieve a client by ID."""
        row = self._read_one("SELECT payload FROM oauth_clients WHERE client_id = ?", (client_id,))
        return StoredClient(**json.loads(row["payload"])) if row else None

    def find_client_by_redirect_uris(self, redirect_uris: list[str]) -> StoredClient | None:
        """Find an existing client with exactly these redirect URIs."""
        row = self._read_one(
            "SELECT payload FROM oauth_clients WHERE redirect_key = ?",
            (_redirect_key(redirect_uris),),
        )
        return StoredClient(**json.loads(row["payload"])) if row else None

    def delete_client(self, client_id: str) -> bool:
        """Delete a client and revoke everything issued to it."""
        deleted = self._write("DELETE FROM oauth_clients WHERE client_id = ?", (client_id,))
        if deleted:
            self._write("DELETE FROM oauth_tokens WHERE client_id = ?", (client_id,))
            logger.info(f"Deleted client: {client_id}")
        return bool(deleted)

    def validate_client_credentials(
        self, client_id: str, client_secret: str | None
    ) -> StoredClient | None:
        """Validate client credentials, comparing secrets in constant time."""
        client = self.get_client(client_id)
        if client is None:
            return None
        if client.client_secret is None:
            return client
        if secrets.compare_digest(client.client_secret or "", client_secret or ""):
            return client
        return None

    # -- authorization codes ------------------------------------------------

    def store_auth_code(self, auth_code: StoredAuthCode) -> None:
        """Store an authorization code, keyed by its hash."""
        self._maybe_cleanup()
        payload = json.dumps({**asdict(auth_code), "code": ""})  # stored only as its hash
        self._write(
            "INSERT OR REPLACE INTO oauth_codes (code_hash, expires_at, payload) VALUES (?, ?, ?)",
            (hash_secret(auth_code.code), auth_code.expires_at, payload),
        )

    def get_auth_code(self, code: str) -> StoredAuthCode | None:
        """Retrieve and consume an authorization code (one-time use)."""
        row = self._claim_one(_CLAIM_AUTH_CODE, hash_secret(code))
        if row is None:
            return None
        stored = StoredAuthCode(**{**json.loads(row["payload"]), "code": code})
        if time.time() > stored.expires_at:
            logger.debug("Auth code expired")
            return None
        return stored

    # -- tokens -------------------------------------------------------------

    def _store_token(self, token: StoredToken, token_type: str) -> None:
        """Store a token under its hash, so the raw value never reaches disk."""
        self._maybe_cleanup()
        payload = asdict(token)
        payload["token"] = ""  # the caller already holds it; disk must not
        self._write(
            "INSERT OR REPLACE INTO oauth_tokens "
            "(token_hash, token_type, client_id, expires_at, payload) VALUES (?, ?, ?, ?, ?)",
            (
                hash_secret(token.token),
                token_type,
                token.client_id,
                token.expires_at,
                json.dumps(payload),
            ),
        )

    def _get_token(self, token: str, token_type: str) -> StoredToken | None:
        """Retrieve a token by hash, dropping it if it has expired."""
        token_hash = hash_secret(token)
        row = self._read_one(
            "SELECT payload FROM oauth_tokens WHERE token_hash = ? AND token_type = ?",
            (token_hash, token_type),
        )
        if row is None:
            return None
        stored = StoredToken(**json.loads(row["payload"]))
        if stored.expires_at and time.time() > stored.expires_at:
            self._revoke_token(token, token_type)
            logger.debug(f"{token_type.capitalize()} token expired")
            return None
        # The raw value is not on disk, so put it back for the caller.
        stored.token = token
        return stored

    def _revoke_token(self, token: str, token_type: str) -> bool:
        """Delete a token row."""
        return bool(
            self._write(
                "DELETE FROM oauth_tokens WHERE token_hash = ? AND token_type = ?",
                (hash_secret(token), token_type),
            )
        )

    def store_access_token(self, token: StoredToken) -> None:
        """Store an access token."""
        self._store_token(token, "access")
        logger.debug(f"Stored access token for user {token.user_subject}")

    def get_access_token(self, token: str) -> StoredToken | None:
        """Retrieve an access token."""
        return self._get_token(token, "access")

    def revoke_access_token(self, token: str) -> bool:
        """Revoke an access token."""
        return self._revoke_token(token, "access")

    def store_refresh_token(self, token: StoredToken) -> None:
        """Store a refresh token."""
        self._store_token(token, "refresh")

    def get_refresh_token(self, token: str) -> StoredToken | None:
        """Retrieve a refresh token."""
        return self._get_token(token, "refresh")

    def revoke_refresh_token(self, token: str) -> bool:
        """Revoke a refresh token."""
        return self._revoke_token(token, "refresh")

    def revoke_tokens_for_subject(self, subject: str) -> int:
        """Revoke every access and refresh token, and unexchanged code, issued to a person.

        The subject lives only in each row's payload, so rows are matched in Python
        under the lock rather than through SQLite's optional JSON functions.

        Returns:
            How many rows were removed
        """
        removed = 0
        with self._locked() as conn:
            for select, delete in (
                (
                    "SELECT rowid, payload FROM oauth_tokens",
                    "DELETE FROM oauth_tokens WHERE rowid = ?",
                ),
                (
                    "SELECT rowid, payload FROM oauth_codes",
                    "DELETE FROM oauth_codes WHERE rowid = ?",
                ),
            ):
                doomed = [
                    (row[0],)
                    for row in conn.execute(select).fetchall()
                    if json.loads(row["payload"]).get("user_subject") == subject
                ]
                conn.executemany(delete, doomed)
                removed += len(doomed)
        return removed

    def _person_token_rows(
        self, conn: sqlite3.Connection, subject: str, issuer: str | None
    ) -> list[tuple[int, StoredToken]]:
        """Unexpired access and refresh token rows issued to one person."""
        now = time.time()
        found = []
        for row in conn.execute("SELECT rowid, payload FROM oauth_tokens").fetchall():
            stored = StoredToken(**json.loads(row["payload"]))
            if (
                stored.user_subject == subject
                and token_issuer(stored.user_claims) == issuer
                and not (stored.expires_at and stored.expires_at < now)
            ):
                found.append((row[0], stored))
        return found

    def tokens_for_person(self, subject: str, issuer: str | None) -> list[StoredToken]:
        """Every unexpired access and refresh token issued to one person.

        The raw token values are not on disk, so each returned token is blank.
        """
        with self._locked() as conn:
            return [stored for _, stored in self._person_token_rows(conn, subject, issuer)]

    def people_with_tokens(self) -> set[tuple[str | None, str]]:
        """(issuer, subject) of everyone holding an unexpired token: one table read."""
        now = time.time()
        people: set[tuple[str | None, str]] = set()
        with self._locked() as conn:
            for row in conn.execute("SELECT payload FROM oauth_tokens").fetchall():
                stored = StoredToken(**json.loads(row["payload"]))
                if stored.user_subject and not (stored.expires_at and stored.expires_at < now):
                    people.add((token_issuer(stored.user_claims), stored.user_subject))
        return people

    def revoke_client_tokens_for_person(
        self, subject: str, issuer: str | None, client_id: str
    ) -> int:
        """Revoke one person's access and refresh tokens for one client.

        Returns:
            How many rows were removed
        """
        with self._locked() as conn:
            doomed = [
                (rowid,)
                for rowid, stored in self._person_token_rows(conn, subject, issuer)
                if stored.client_id == client_id
            ]
            conn.executemany("DELETE FROM oauth_tokens WHERE rowid = ?", doomed)
        return len(doomed)

    # -- pending authorization ----------------------------------------------

    def store_pending_auth(self, pending: PendingAuthorization) -> None:
        """Store in-flight authorization state for the identity provider round trip."""
        self._maybe_cleanup()
        payload = json.dumps({**asdict(pending), "state": ""})  # stored only as its hash
        self._write(
            "INSERT OR REPLACE INTO oauth_pending (state_hash, expires_at, payload) "
            "VALUES (?, ?, ?)",
            (hash_secret(pending.state), pending.expires_at, payload),
        )

    def get_pending_auth(self, state: str) -> PendingAuthorization | None:
        """Retrieve and consume pending authorization state (one-time use)."""
        row = self._claim_one(_CLAIM_PENDING_AUTH, hash_secret(state))
        if row is None:
            return None
        stored = PendingAuthorization(**{**json.loads(row["payload"]), "state": state})
        if time.time() > stored.expires_at:
            logger.debug("Pending auth expired")
            return None
        return stored

    # -- housekeeping -------------------------------------------------------

    def cleanup(self) -> None:
        """Remove every expired row."""
        now = time.time()
        removed = self._write("DELETE FROM oauth_codes WHERE expires_at < ?", (now,))
        removed += self._write(
            "DELETE FROM oauth_tokens WHERE expires_at IS NOT NULL AND expires_at < ?", (now,)
        )
        removed += self._write("DELETE FROM oauth_pending WHERE expires_at < ?", (now,))
        self._last_cleanup = now
        if removed:
            logger.debug(f"Cleaned up {removed} expired auth entries")


def _redirect_key(redirect_uris: list[str]) -> str:
    """Return an order-independent key for a client's redirect URIs."""
    return "\n".join(sorted(redirect_uris))
