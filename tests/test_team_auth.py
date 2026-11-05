"""Turning a request into a person: tokens, OAuth callers and SSO sign-ins."""

import contextlib
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.server.lowlevel.server import request_ctx
from mcp.shared.context import RequestContext
from starlette.requests import Request

from tests.mocks.oauth import scratch_auth_storage
from u2_mcp.access import decide
from u2_mcp.auth.idp.base import TokenInfo
from u2_mcp.auth.provider import U2OAuthProvider
from u2_mcp.auth.storage import PendingAuthorization, StoredToken
from u2_mcp.store.repo import Store
from u2_mcp.team_auth import (
    PatVerifier,
    SignInRefused,
    _client_ip,
    groups_for_sign_in,
    groups_from_claims,
    make_identity_resolver,
    make_sign_in_handler,
    record_sign_in,
)
from u2_mcp.tokens import create_token

ISS = "https://idp.example"


@contextlib.contextmanager
def _message_from(access: AccessToken | None) -> Iterator[None]:
    """Run the block as the SDK runs a tool: inside one message's request context.

    The request carries the bearer token that was verified for *this* message,
    the way the SDK's authentication middleware leaves it in the ASGI scope.
    """
    scope: dict[str, Any] = {"type": "http", "headers": []}
    if access is not None:
        scope["user"] = AuthenticatedUser(access)
    ctx: RequestContext[Any, Any, Any] = RequestContext(
        request_id=1, meta=None, session=MagicMock(), lifespan_context=None, request=Request(scope)
    )
    token = request_ctx.set(ctx)
    try:
        yield
    finally:
        request_ctx.reset(token)


@pytest.mark.parametrize(
    ("claims", "name", "expected"),
    [
        ({"groups": ["a", "b"]}, "groups", ["a", "b"]),
        ({"groups": "solo"}, "groups", ["solo"]),
        ({}, "groups", []),  # provider sends no groups at all
        ({"_claim_names": {"groups": "src1"}}, "groups", None),  # Entra overage
        ({"hasgroups": True}, "groups", None),  # Entra overage, implicit flow
        ({"roles": ["x"]}, "roles", ["x"]),
        ({"groups": 42}, "groups", []),
    ],
)
def test_groups_from_claims(claims: dict[str, Any], name: str, expected: list[str] | None) -> None:
    assert groups_from_claims(claims, name) == expected


class TestSignIn:
    @pytest.mark.asyncio
    async def test_a_first_sign_in_creates_the_user_with_groups(self, store: Store) -> None:
        handler = make_sign_in_handler(store, "groups", issuer=ISS)
        await handler(
            TokenInfo(subject="s1", email="a@x.com", name="Alice", raw_claims={"groups": ["g-dev"]})
        )
        user = store.get_user_by_subject("s1")
        assert user is not None and user.display_name == "Alice"
        assert user.last_sso_login_at is not None
        assert len(store.group_ids_for_user(user.id)) == 1
        entry = store.recent_audit(1)[0]
        assert entry["action"] == "sso_sign_in"
        assert "mcp" in str(entry)

    @pytest.mark.asyncio
    async def test_groups_from_the_adapter_are_used_when_claims_lack_them(
        self, store: Store
    ) -> None:
        await make_sign_in_handler(store, "groups", issuer=ISS)(
            TokenInfo(subject="s2", groups=["g-ops"])
        )
        user = store.get_user_by_subject("s2")
        assert user is not None and len(store.group_ids_for_user(user.id)) == 1

    @pytest.mark.asyncio
    async def test_overage_groups_come_from_the_resolver(self, store: Store) -> None:
        async def resolver(claims: dict[str, Any]) -> list[str] | None:
            return ["g-from-graph"]

        handler = make_sign_in_handler(store, "groups", resolver, issuer=ISS)
        await handler(TokenInfo(subject="s3", raw_claims={"_claim_names": {"groups": "src1"}}))
        user = store.get_user_by_subject("s3")
        assert user is not None and not user.groups_unavailable
        assert [g.external_id for g in store.list_groups()] == ["g-from-graph"]

    @pytest.mark.asyncio
    async def test_a_failing_resolver_leaves_groups_unavailable(self, store: Store) -> None:
        async def resolver(claims: dict[str, Any]) -> list[str] | None:
            raise RuntimeError("graph down")

        await make_sign_in_handler(store, "groups", resolver, issuer=ISS)(
            TokenInfo(subject="s4", raw_claims={"_claim_names": {"groups": "src1"}})
        )
        user = store.get_user_by_subject("s4")
        assert user is not None and user.groups_unavailable


@pytest.mark.asyncio
async def test_the_resolver_is_not_asked_when_the_token_lists_groups() -> None:
    asked: list[dict[str, Any]] = []

    async def resolver(claims: dict[str, Any]) -> list[str] | None:
        asked.append(claims)
        return []

    assert await groups_for_sign_in({"groups": ["a"]}, "groups", resolver) == ["a"]
    assert asked == []


def test_record_sign_in_says_where_the_sign_in_came_from(store: Store) -> None:
    user = record_sign_in(
        store, TokenInfo(subject="s5", name="Sue"), ["g"], via="admin", issuer=ISS
    )
    assert user.last_sso_login_at is not None
    assert "admin" in str(store.recent_audit(1)[0])


def test_a_disabled_person_is_refused_without_refreshing_anything(store: Store) -> None:
    sam = store.get_or_create_sso_user("sam", issuer=ISS, email="old@x.com")
    store.set_user_disabled(sam.id, True)
    with pytest.raises(SignInRefused):
        record_sign_in(
            store, TokenInfo(subject="sam", email="new@x.com"), ["eng"], via="admin", issuer=ISS
        )
    after = store.get_user_by_subject("sam")
    assert after is not None and after.last_sso_login_at is None and after.email == "old@x.com"
    assert store.list_groups() == []
    entry = store.recent_audit(1)[0]
    assert (entry["action"], entry["outcome"]) == ("sso_sign_in", "refused")
    assert "admin" in str(entry)


def test_an_overlong_subject_is_refused_not_cut(store: Store) -> None:
    with pytest.raises(SignInRefused):
        record_sign_in(store, TokenInfo(subject="s" * 256), ["g"], via="mcp", issuer=ISS)
    assert store.list_users() == []
    entry = store.recent_audit(1)[0]
    assert (entry["action"], entry["outcome"]) == ("sso_sign_in", "refused")
    assert store.get_user_by_subject("s" * 255) is None
    record_sign_in(store, TokenInfo(subject="s" * 255), ["g"], via="mcp", issuer=ISS)
    assert store.get_user_by_subject("s" * 255) is not None


@pytest.mark.asyncio
async def test_a_disabled_person_is_refused_on_the_mcp_path_too(store: Store) -> None:
    sam = store.get_or_create_sso_user("sam", issuer=ISS)
    store.set_user_disabled(sam.id, True)
    with pytest.raises(SignInRefused):
        await make_sign_in_handler(store, "groups", issuer=ISS)(
            TokenInfo(subject="sam", raw_claims={"groups": ["eng"]})
        )
    after = store.get_user_by_subject("sam")
    assert after is not None and after.last_sso_login_at is None
    assert store.recent_audit(1)[0]["outcome"] == "refused"
    assert "mcp" in str(store.recent_audit(1)[0])


def test_more_than_500_groups_count_as_unavailable(store: Store) -> None:
    groups = [f"g{i}" for i in range(501)]
    user = record_sign_in(store, TokenInfo(subject="many"), groups, via="mcp", issuer=ISS)
    assert user.groups_unavailable and store.list_groups() == []
    user = record_sign_in(store, TokenInfo(subject="many"), groups[:500], via="mcp", issuer=ISS)
    assert not user.groups_unavailable and len(store.list_groups()) == 500


def test_overlong_claims_are_dropped_or_cut(store: Store) -> None:
    long = "x" * 257
    user = record_sign_in(
        store,
        TokenInfo(subject="s6", email=long + "@x.com", name=long),
        ["ok", long, "y" * 256],
        via="admin",
        issuer=ISS,
    )
    assert user.email is None
    assert user.display_name == "x" * 256
    assert sorted(g.external_id for g in store.list_groups()) == ["ok", "y" * 256]


class TestPatVerifier:
    @pytest.mark.asyncio
    async def test_a_valid_token_is_accepted_with_read_scope(self, store: Store) -> None:
        user = store.add_local_user("ops")
        token, record = create_token(store, user.id, "script")
        verifier = PatVerifier(store, freshness_days=30, resource="https://u2.example")
        ip_token = _client_ip.set("10.9.8.7")
        try:
            access = await verifier.verify_token(token)
        finally:
            _client_ip.reset(ip_token)
        assert access is not None
        assert "u2:read" in access.scopes
        assert access.client_id == f"pat-{record.id}"
        # The SDK only lets the principal that opened an MCP session use it again;
        # the subject is what makes that principal a person rather than a token.
        assert access.subject == f"user:{user.id}"
        stored = store.get_token_by_hash(record.token_hash)
        assert stored is not None and stored.last_used_ip == "10.9.8.7"

    @pytest.mark.asyncio
    async def test_bad_or_foreign_tokens_are_refused(self, store: Store) -> None:
        verifier = PatVerifier(store, freshness_days=30, resource=None)
        assert await verifier.verify_token("u2pat_" + "x" * 43) is None
        assert await verifier.verify_token("an-oauth-token") is None


class TestIdentityResolver:
    def test_a_token_names_its_owner(self, store: Store) -> None:
        user = store.add_local_user("ops")
        token, record = create_token(store, user.id, "script")
        access = AccessToken(token=token, client_id=f"pat-{record.id}", scopes=["u2:read"])
        resolve = make_identity_resolver(store, None)
        with patch("mcp.server.auth.middleware.auth_context.get_access_token", return_value=access):
            caller = resolve()
        assert caller is not None
        assert (caller.user_id, caller.auth_method) == (user.id, "token")

    def test_an_oauth_token_names_the_signed_in_person(self, store: Store) -> None:
        sso = store.get_or_create_sso_user("s1", display_name="Alice")
        oauth_storage = MagicMock()
        oauth_storage.get_access_token.return_value = StoredToken(
            token="at", token_type="access", client_id="vscode", user_subject="s1", scope="u2:read"
        )
        access = AccessToken(token="at", client_id="vscode", scopes=["u2:read"])
        resolve = make_identity_resolver(store, oauth_storage)
        with patch("mcp.server.auth.middleware.auth_context.get_access_token", return_value=access):
            caller = resolve()
        assert caller is not None
        assert (caller.user_id, caller.auth_method, caller.client_id) == (sso.id, "oauth", "vscode")

    def test_a_deleted_persons_oauth_token_is_refused_and_recreates_nobody(
        self, store: Store
    ) -> None:
        """Only a fresh company sign-in may create a person, never a leftover token."""
        store.delete_user(store.get_or_create_sso_user("s1", display_name="Alice").id)
        oauth_storage = MagicMock()
        oauth_storage.get_access_token.return_value = StoredToken(
            token="at",
            token_type="access",
            client_id="vscode",
            user_subject="s1",
            scope="u2:read",
            user_claims={"name": "Alice"},
        )
        access = AccessToken(token="at", client_id="vscode", scopes=["u2:read"])
        resolve = make_identity_resolver(store, oauth_storage)
        with patch("mcp.server.auth.middleware.auth_context.get_access_token", return_value=access):
            caller = resolve()
        assert caller is None
        assert store.get_user_by_subject("s1") is None
        assert not [r for r in store.recent_audit(50) if r["action"] == "sso_sign_in"]

    def test_no_token_means_no_caller(self, store: Store) -> None:
        with patch("mcp.server.auth.middleware.auth_context.get_access_token", return_value=None):
            assert make_identity_resolver(store, None)() is None

    def test_the_current_messages_token_wins_over_the_sessions_opening_one(
        self, store: Store
    ) -> None:
        """The SDK keeps the opening request's token in context for a whole session."""
        alice = store.add_local_user("alice")
        bob = store.add_local_user("bob")
        alice_token, alice_record = create_token(store, alice.id, "laptop")
        bob_token, bob_record = create_token(store, bob.id, "laptop")
        opening = AccessToken(token=alice_token, client_id="c", scopes=["u2:read"])
        current = AccessToken(token=bob_token, client_id="c", scopes=["u2:read"])
        resolve = make_identity_resolver(store, None)
        with (
            patch("mcp.server.auth.middleware.auth_context.get_access_token", return_value=opening),
            _message_from(current),
        ):
            caller = resolve()
        assert caller is not None and caller.user_id == bob.id

    def test_a_message_without_an_authenticated_user_names_nobody(self, store: Store) -> None:
        """Falling back to the opening request's token would revive the stale caller."""
        alice = store.add_local_user("alice")
        alice_token, _ = create_token(store, alice.id, "laptop")
        opening = AccessToken(token=alice_token, client_id="c", scopes=["u2:read"])
        with (
            patch("mcp.server.auth.middleware.auth_context.get_access_token", return_value=opening),
            _message_from(None),
        ):
            assert make_identity_resolver(store, None)() is None

    def test_a_revoked_token_names_nobody(self, store: Store) -> None:
        user = store.add_local_user("ops")
        token, record = create_token(store, user.id, "script")
        store.revoke_token(record.id, at=1.0)
        access = AccessToken(token=token, client_id=f"pat-{record.id}", scopes=["u2:read"])
        with patch("mcp.server.auth.middleware.auth_context.get_access_token", return_value=access):
            assert make_identity_resolver(store, None)() is None


class TestProviderHooks:
    @pytest.mark.asyncio
    async def test_personal_tokens_bypass_the_oauth_store(self) -> None:
        expected = AccessToken(token="u2pat_x", client_id="pat-1", scopes=["u2:read"])
        pat_verifier = AsyncMock(return_value=expected)
        provider = U2OAuthProvider(
            idp_adapter=MagicMock(),
            issuer_url="https://u2.example",
            storage=scratch_auth_storage(),
            pat_verifier=pat_verifier,
        )
        assert await provider.load_access_token("u2pat_x") is expected
        assert await provider.load_access_token("not-a-pat") is None
        pat_verifier.assert_awaited_once_with("u2pat_x")

    @pytest.mark.asyncio
    async def test_an_oauth_token_carries_its_person_as_the_subject(self) -> None:
        """Without a subject the SDK's session-owner check compares client ids only,
        and everyone signing in through one registered client looks the same."""
        storage = MagicMock()
        storage.get_access_token.return_value = StoredToken(
            token="at",
            token_type="access",
            client_id="claude",
            user_subject="s-alice",
            scope="u2:read",
        )
        provider = U2OAuthProvider(
            idp_adapter=MagicMock(), issuer_url="https://u2.example", storage=storage
        )
        access = await provider.load_access_token("at")
        assert access is not None and access.subject == "s-alice"

    @pytest.mark.asyncio
    async def test_a_completed_idp_sign_in_is_reported_once(self) -> None:
        info = TokenInfo(subject="s1", email="a@x.com", raw_claims={"groups": []})
        adapter = MagicMock()
        adapter.exchange_code = AsyncMock(return_value=MagicMock(access_token="idp-at"))
        adapter.validate_token = AsyncMock(return_value=info)
        seen: list[TokenInfo] = []
        provider = U2OAuthProvider(
            idp_adapter=adapter,
            issuer_url="https://u2.example",
            storage=scratch_auth_storage(),
            on_sign_in=seen.append,
        )
        provider.storage.store_pending_auth(
            PendingAuthorization(
                state="st",
                client_id="c",
                redirect_uri="https://client/cb",
                scope="u2:read",
                code_challenge=None,
                code_challenge_method=None,
                claude_redirect_uri="https://client/cb",
                claude_state="cs",
            )
        )
        await provider.handle_idp_callback("code", "st")
        assert seen == [info]


ISS_A = "https://idp-a.example"
ISS_B = "https://idp-b.example"


class TestIdentityIsIssuerAndSubject:
    """Two providers (or a provider change) may issue one sub to different people."""

    def test_a_provider_change_does_not_inherit_the_old_persons_rights(self, store: Store) -> None:
        old = store.get_or_create_sso_user("sub-x", issuer=ISS_A, display_name="Old")
        store.set_user_admin(old.id, True)

        newcomer = record_sign_in(store, TokenInfo(subject="sub-x"), [], via="mcp", issuer=ISS_B)
        assert newcomer.id != old.id
        assert not newcomer.is_admin and newcomer.sso_issuer == ISS_B

        again = record_sign_in(store, TokenInfo(subject="sub-x"), [], via="admin", issuer=ISS_A)
        assert again.id == old.id

    def test_a_disabled_person_from_another_provider_does_not_block_a_newcomer(
        self, store: Store
    ) -> None:
        old = store.get_or_create_sso_user("sub-x", issuer=ISS_A)
        store.set_user_disabled(old.id, True)
        newcomer = record_sign_in(store, TokenInfo(subject="sub-x"), [], via="mcp", issuer=ISS_B)
        assert newcomer.id != old.id

    def test_a_provider_change_does_not_inherit_the_old_groups_grants(self, store: Store) -> None:
        connection = store.add_connection(
            name="Prod",
            host="h",
            port=1,
            service="uvcs",
            account="A",
            shared_user="svc",
            shared_password="pw",
            read_only=False,
        )
        developer = store.get_role_by_name("Developer")
        assert developer is not None
        old = record_sign_in(
            store, TokenInfo(subject="old-sub"), ["Developers"], via="admin", issuer=ISS_A
        )
        [old_group] = store.group_ids_for_user(old.id)
        store.add_grant(
            connection_id=connection.id,
            subject_type="group",
            subject_id=old_group,
            role_id=developer.id,
        )

        new = record_sign_in(
            store, TokenInfo(subject="new-sub"), ["Developers"], via="admin", issuer=ISS_B
        )

        assert store.group_ids_for_user(new.id) != [old_group]
        assert sorted((g.issuer, g.external_id) for g in store.list_groups()) == [
            (ISS_A, "Developers"),
            (ISS_B, "Developers"),
        ]
        assert not decide(store, new.id, "Prod", "records.write", global_read_only=False).allowed
        assert decide(store, old.id, "Prod", "records.write", global_read_only=False).allowed

    @pytest.mark.asyncio
    async def test_the_mcp_hook_takes_the_issuer_from_the_id_token(self, store: Store) -> None:
        handler = make_sign_in_handler(store, "groups", issuer=ISS_B)
        await handler(TokenInfo(subject="sub-y", raw_claims={"iss": ISS_A}))
        user = store.get_sso_user(ISS_A, "sub-y")
        assert user is not None

    @pytest.mark.asyncio
    async def test_the_mcp_hook_falls_back_to_the_providers_issuer(self, store: Store) -> None:
        async def discovered() -> str:
            return ISS_B

        await make_sign_in_handler(store, "groups", issuer=discovered)(TokenInfo(subject="sub-z"))
        assert store.get_sso_user(ISS_B, "sub-z") is not None

    def test_an_oauth_token_names_the_person_of_its_own_issuer(self, store: Store) -> None:
        a = store.get_or_create_sso_user("sub-x", issuer=ISS_A)
        b = store.get_or_create_sso_user("sub-x", issuer=ISS_B)
        oauth_storage = MagicMock()
        oauth_storage.get_access_token.return_value = StoredToken(
            token="at",
            token_type="access",
            client_id="vscode",
            user_subject="sub-x",
            scope="u2:read",
            user_claims={"iss": ISS_B},
        )
        access = AccessToken(token="at", client_id="vscode", scopes=["u2:read"])
        with patch("mcp.server.auth.middleware.auth_context.get_access_token", return_value=access):
            caller = make_identity_resolver(store, oauth_storage)()
        assert caller is not None and caller.user_id == b.id != a.id
