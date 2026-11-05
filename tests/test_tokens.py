"""Personal access tokens: how MCP clients without browser sign-in prove who is calling."""

import pytest

from u2_mcp.store.repo import Store
from u2_mcp.tokens import (
    MAX_LIFETIME_DAYS,
    TOKEN_PREFIX,
    TokenRejected,
    create_token,
    generate_token,
    hash_token,
    looks_like_token,
    revoke,
    verify_token,
)

DAY = 86400.0


class Clock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock(store: Store) -> Clock:
    fake = Clock()
    store.clock = fake
    return fake


@pytest.fixture
def sso_user(store: Store, clock: Clock) -> int:
    user = store.get_or_create_sso_user("sub-1")
    store.record_sso_login(user.id, [])
    return user.id


def test_tokens_have_the_prefix_and_enough_randomness() -> None:
    first, second = generate_token(), generate_token()
    assert first.startswith(TOKEN_PREFIX) and len(first) == len(TOKEN_PREFIX) + 43
    assert first != second
    assert looks_like_token(first) and not looks_like_token("eyJhbGciOi...")


def test_only_the_hash_is_stored(store: Store, sso_user: int) -> None:
    token, record = create_token(store, sso_user, "laptop")
    assert record.token_hash == hash_token(token)
    assert token not in record.token_hash
    dump = "\n".join(store._conn.iterdump())
    assert token not in dump


def test_a_valid_token_names_its_owner_and_records_use(
    store: Store, sso_user: int, clock: Clock
) -> None:
    token, _ = create_token(store, sso_user, "laptop")
    user, record = verify_token(store, token, ip="10.1.2.3")
    assert user.id == sso_user
    stored = store.get_token_by_hash(hash_token(token))
    assert stored is not None
    assert stored.last_used_at == clock.now and stored.last_used_ip == "10.1.2.3"


def test_use_is_recorded_at_most_once_a_minute(store: Store, sso_user: int, clock: Clock) -> None:
    token, _ = create_token(store, sso_user, "laptop")

    def last_used() -> float | None:
        record = store.get_token_by_hash(hash_token(token))
        assert record is not None
        return record.last_used_at

    verify_token(store, token)
    first_use = clock.now
    clock.now += 30
    verify_token(store, token)
    assert last_used() == first_use
    clock.now += 31
    verify_token(store, token)
    assert last_used() == clock.now


@pytest.mark.parametrize(
    ("setup", "message"),
    [
        ("unknown", "unknown token"),
        ("revoked", "token revoked"),
        ("expired", "token expired"),
        ("disabled", "account disabled"),
        ("not_a_pat", "not a personal access token"),
    ],
)
def test_refusals(store: Store, sso_user: int, clock: Clock, setup: str, message: str) -> None:
    token, record = create_token(store, sso_user, "laptop", lifetime_days=10)
    if setup == "unknown":
        token = generate_token()
    elif setup == "revoked":
        revoke(store, record.id)
    elif setup == "expired":
        clock.now += 10 * DAY
        store.record_sso_login(sso_user, [])  # stay fresh so expiry is what refuses
    elif setup == "disabled":
        store.set_user_disabled(sso_user, True)
    elif setup == "not_a_pat":
        token = "some-oauth-token"
    with pytest.raises(TokenRejected, match=message):
        verify_token(store, token)


def test_sso_users_must_have_signed_in_recently(store: Store, sso_user: int, clock: Clock) -> None:
    token, _ = create_token(store, sso_user, "laptop")
    clock.now += 29 * DAY
    verify_token(store, token)
    clock.now += 2 * DAY
    with pytest.raises(TokenRejected, match="sign in to the admin site to reactivate"):
        verify_token(store, token)
    store.record_sso_login(sso_user, [])
    verify_token(store, token)


def test_sso_users_who_never_signed_in_cannot_use_tokens(store: Store, clock: Clock) -> None:
    user = store.get_or_create_sso_user("imported")
    token, _ = create_token(store, user.id, "laptop")
    with pytest.raises(TokenRejected, match="reactivate"):
        verify_token(store, token)


def test_local_users_are_exempt_from_the_sign_in_rule(store: Store, clock: Clock) -> None:
    user = store.add_local_user("breakglass")
    token, _ = create_token(store, user.id, "script")
    clock.now += 60 * DAY
    assert verify_token(store, token)[0].id == user.id


def test_lifetime_must_be_positive_and_within_the_cap(store: Store, sso_user: int) -> None:
    with pytest.raises(ValueError, match="at least 1 day"):
        create_token(store, sso_user, "x", lifetime_days=0)
    with pytest.raises(ValueError, match="at most 30 days"):
        create_token(store, sso_user, "x", lifetime_days=90, max_lifetime_days=30)


def test_lifetime_has_a_hard_ceiling_even_without_a_cap(store: Store, sso_user: int) -> None:
    assert MAX_LIFETIME_DAYS == 3650
    create_token(store, sso_user, "x", lifetime_days=MAX_LIFETIME_DAYS)
    with pytest.raises(ValueError, match="at most 3650 days"):
        create_token(store, sso_user, "x", lifetime_days=MAX_LIFETIME_DAYS + 1)
    with pytest.raises(ValueError, match="at most 3650 days"):
        create_token(store, sso_user, "x", lifetime_days=400000, max_lifetime_days=500000)
