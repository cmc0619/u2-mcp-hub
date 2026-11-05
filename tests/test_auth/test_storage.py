"""The MCP OAuth bridge's state, kept in the settings database."""

import time
from pathlib import Path
from typing import Any

import pytest

from u2_mcp.auth.storage import (
    AuthStorage,
    PendingAuthorization,
    StoredAuthCode,
    StoredClient,
    StoredToken,
)
from u2_mcp.store.crypto import SecretBox
from u2_mcp.store.db import DATABASE_FILENAME, open_database
from u2_mcp.store.repo import Store


def make_client(client_id: str = "client-1") -> StoredClient:
    """Build a registered client for testing."""
    return StoredClient(
        client_id=client_id,
        client_secret="s3cret",
        client_name="Claude",
        redirect_uris=["https://claude.ai/api/mcp/auth_callback"],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope="u2:read",
    )


def make_token(token: str = "tok-1", token_type: str = "access", **overrides: Any) -> StoredToken:
    """Build an issued token for testing."""
    values: dict[str, Any] = {
        "token": token,
        "token_type": token_type,
        "client_id": "client-1",
        "user_subject": "mike@example.com",
        "scope": "u2:read",
        "expires_at": time.time() + 3600,
        "user_claims": {"email": "mike@example.com", "name": "Mike"},
    }
    values.update(overrides)
    return StoredToken(**values)


def make_auth_code(code: str = "code-1") -> StoredAuthCode:
    """Build a pending authorization code for testing."""
    return StoredAuthCode(
        code=code,
        client_id="client-1",
        redirect_uri="https://claude.ai/api/mcp/auth_callback",
        scope="u2:read",
        state="abc",
        code_challenge="challenge",
        code_challenge_method="S256",
        user_subject="mike@example.com",
        user_claims={"email": "mike@example.com"},
    )


def make_pending(state: str = "state-1") -> PendingAuthorization:
    """Build in-flight authorization state for testing."""
    return PendingAuthorization(
        state=state,
        client_id="client-1",
        redirect_uri="https://claude.ai/api/mcp/auth_callback",
        scope="u2:read",
        code_challenge=None,
        code_challenge_method=None,
        claude_redirect_uri="https://claude.ai/api/mcp/auth_callback",
        claude_state="claude-state",
    )


@pytest.fixture
def storage(oauth_storage: AuthStorage) -> AuthStorage:
    return oauth_storage


class TestClientRegistration:
    """Storing and retrieving DCR clients."""

    def test_stored_client_can_be_read_back(self, storage: Any) -> None:
        """A registered client is returned intact."""
        storage.store_client(make_client())

        found = storage.get_client("client-1")

        assert found is not None
        assert found.client_name == "Claude"
        assert found.redirect_uris == ["https://claude.ai/api/mcp/auth_callback"]

    def test_unknown_client_is_none(self, storage: Any) -> None:
        """An unregistered client id returns nothing."""
        assert storage.get_client("nope") is None

    def test_client_is_findable_by_redirect_uris(self, storage: Any) -> None:
        """Re-registration finds the existing client by its redirect URIs."""
        storage.store_client(make_client())

        found = storage.find_client_by_redirect_uris(["https://claude.ai/api/mcp/auth_callback"])

        assert found is not None
        assert found.client_id == "client-1"

    def test_deleting_a_client_removes_its_tokens(self, storage: Any) -> None:
        """Deleting a client revokes what was issued to it."""
        storage.store_client(make_client())
        storage.store_access_token(make_token("tok-1"))

        assert storage.delete_client("client-1") is True
        assert storage.get_client("client-1") is None
        assert storage.get_access_token("tok-1") is None

    def test_correct_secret_validates(self, storage: Any) -> None:
        """A matching client secret authenticates the client."""
        storage.store_client(make_client())

        assert storage.validate_client_credentials("client-1", "s3cret") is not None

    def test_wrong_secret_is_rejected(self, storage: Any) -> None:
        """A mismatched client secret does not authenticate."""
        storage.store_client(make_client())

        assert storage.validate_client_credentials("client-1", "wrong") is None


class TestTokens:
    """Access and refresh token lifecycle."""

    def test_access_token_round_trips_with_its_claims(self, storage: Any) -> None:
        """A stored token returns with the identity it was issued for."""
        storage.store_access_token(make_token("tok-1"))

        found = storage.get_access_token("tok-1")

        assert found is not None
        assert found.user_subject == "mike@example.com"
        assert found.user_claims["name"] == "Mike"

    def test_expired_access_token_is_not_returned(self, storage: Any) -> None:
        """A token past its expiry is treated as absent."""
        storage.store_access_token(make_token("old", expires_at=time.time() - 1))

        assert storage.get_access_token("old") is None

    def test_revoked_access_token_is_gone(self, storage: Any) -> None:
        """Revoking a token removes it."""
        storage.store_access_token(make_token("tok-1"))

        assert storage.revoke_access_token("tok-1") is True
        assert storage.get_access_token("tok-1") is None

    def test_refresh_token_round_trips(self, storage: Any) -> None:
        """A refresh token is stored and retrieved independently of access tokens."""
        storage.store_refresh_token(make_token("ref-1", token_type="refresh"))

        found = storage.get_refresh_token("ref-1")

        assert found is not None
        assert found.token_type == "refresh"

    def test_revoked_refresh_token_is_gone(self, storage: Any) -> None:
        """Revoking a refresh token removes it."""
        storage.store_refresh_token(make_token("ref-1", token_type="refresh"))

        assert storage.revoke_refresh_token("ref-1") is True
        assert storage.get_refresh_token("ref-1") is None


class TestOneTimeUse:
    """Authorization codes and pending state may each be consumed once."""

    def test_auth_code_can_be_consumed_once(self, storage: Any) -> None:
        """The second exchange of the same code gets nothing."""
        storage.store_auth_code(make_auth_code())

        assert storage.get_auth_code("code-1") is not None
        assert storage.get_auth_code("code-1") is None

    def test_expired_auth_code_is_refused(self, storage: Any) -> None:
        """A code past its expiry cannot be exchanged."""
        code = make_auth_code("stale")
        code.expires_at = time.time() - 1
        storage.store_auth_code(code)

        assert storage.get_auth_code("stale") is None

    def test_pending_auth_can_be_consumed_once(self, storage: Any) -> None:
        """Returning from the identity provider twice with one state fails the second time."""
        storage.store_pending_auth(make_pending())

        assert storage.get_pending_auth("state-1") is not None
        assert storage.get_pending_auth("state-1") is None

    def test_pending_auth_preserves_the_callers_state(self, storage: Any) -> None:
        """The client's own state parameter survives the round trip."""
        storage.store_pending_auth(make_pending())

        pending = storage.get_pending_auth("state-1")

        assert pending is not None
        assert pending.claude_state == "claude-state"


class TestDurability:
    """OAuth state lives in the settings database, as hashes."""

    def test_tokens_survive_a_restart(self, tmp_path: Path) -> None:
        """Reopening the database still recognises an issued token."""
        path = tmp_path / "db" / DATABASE_FILENAME
        conn = open_database(path)
        first = AuthStorage(Store(conn, SecretBox("t" * 40), path.parent).locked)
        first.store_client(make_client())
        first.store_access_token(make_token("tok-1"))
        conn.close()

        conn = open_database(path)
        second = AuthStorage(Store(conn, SecretBox("t" * 40), path.parent).locked)
        found = second.get_access_token("tok-1")
        conn.close()
        assert found is not None
        assert found.user_subject == "mike@example.com"

    def test_raw_secrets_are_never_written_to_the_database(self, store: Store) -> None:
        storage = AuthStorage(store.locked)
        storage.store_access_token(make_token("super-secret-token"))
        storage.store_refresh_token(make_token("super-secret-refresh", token_type="refresh"))
        storage.store_auth_code(make_auth_code("super-secret-code"))
        storage.store_pending_auth(make_pending("super-secret-state"))

        with store.locked() as conn:
            dump = " ".join(conn.iterdump())
        assert "super-secret" not in dump

    def test_expired_entries_are_purged(self, store: Store) -> None:
        storage = AuthStorage(store.locked)
        storage.store_access_token(make_token("old", expires_at=time.time() - 1))
        storage.store_access_token(make_token("current"))

        storage.cleanup()

        with store.locked() as conn:
            assert conn.execute("SELECT COUNT(*) FROM oauth_tokens").fetchone()[0] == 1


class TestRevokingAPersonsTokens:
    """Deleting a person ends every OAuth grant issued to them."""

    def test_access_refresh_and_unexchanged_codes_go(self, storage: Any) -> None:
        storage.store_access_token(make_token("a-mike"))
        storage.store_refresh_token(make_token("r-mike", token_type="refresh"))
        storage.store_auth_code(make_auth_code("c-mike"))
        storage.store_access_token(make_token("a-ann", user_subject="ann"))
        storage.store_refresh_token(make_token("r-ann", token_type="refresh", user_subject="ann"))

        removed = storage.revoke_tokens_for_subject("mike@example.com")

        assert removed == 3
        assert storage.get_access_token("a-mike") is None
        assert storage.get_refresh_token("r-mike") is None
        assert storage.get_auth_code("c-mike") is None
        assert storage.get_access_token("a-ann") is not None
        assert storage.get_refresh_token("r-ann") is not None
