"""Sessions, the rate limiter and safe redirects."""

import pytest

from u2_mcp.admin.security import (
    SESSION_ABSOLUTE_SECONDS,
    SESSION_IDLE_SECONDS,
    RateLimiter,
    load_session,
    safe_next,
    start_session,
)
from u2_mcp.store.repo import Store


class Clock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class TestRateLimiter:
    def test_five_per_minute_then_refused(self) -> None:
        clock = Clock()
        limiter = RateLimiter(clock=clock)

        assert all(limiter.allow("ip:1") for _ in range(5))
        assert limiter.allow("ip:1") is False

    def test_the_window_slides(self) -> None:
        clock = Clock()
        limiter = RateLimiter(clock=clock)
        for _ in range(5):
            limiter.allow("ip:1")

        clock.now += 61

        assert limiter.allow("ip:1") is True

    def test_any_exhausted_key_refuses(self) -> None:
        limiter = RateLimiter(clock=Clock())
        for _ in range(5):
            limiter.allow("user:ann")

        assert limiter.allow("ip:2", "user:ann") is False
        assert limiter.allow("ip:2") is True

    def test_keys_with_no_recent_attempts_are_dropped(self) -> None:
        limiter = RateLimiter(clock=Clock())
        for _ in range(5):
            limiter.allow("user:ann")

        assert limiter.allow("ip:2", "user:ann") is False
        assert "ip:2" not in limiter._hits

    def test_a_full_table_is_swept(self) -> None:
        clock = Clock()
        limiter = RateLimiter(clock=clock, max_keys=2)
        limiter.allow("ip:1")
        limiter.allow("ip:2")

        clock.now += 61
        limiter.allow("ip:3")

        assert list(limiter._hits) == ["ip:3"]

    def test_the_default_cap_is_ten_thousand(self) -> None:
        assert RateLimiter()._max_keys == 10_000


class TestSessions:
    def _store(self, store: Store, clock: Clock) -> Store:
        store.clock = clock
        return store

    def test_a_session_loads_its_user(self, store: Store) -> None:
        clock = Clock()
        self._store(store, clock)
        user = store.add_local_user("ann", password_hash="h", is_admin=True)

        raw, session = start_session(store, user, "10.0.0.1")
        loaded = load_session(store, raw)

        assert loaded is not None
        assert loaded[1].id == user.id
        assert session.id_hash != raw  # only the hash is stored

    def test_idle_sessions_end(self, store: Store) -> None:
        clock = Clock()
        self._store(store, clock)
        user = store.add_local_user("ann", password_hash="h", is_admin=True)
        raw, _ = start_session(store, user, None)

        clock.now += SESSION_IDLE_SECONDS + 1

        assert load_session(store, raw) is None

    def test_activity_keeps_a_session_alive_until_the_absolute_limit(self, store: Store) -> None:
        clock = Clock()
        self._store(store, clock)
        user = store.add_local_user("ann", password_hash="h", is_admin=True)
        raw, _ = start_session(store, user, None)

        for _ in range(SESSION_ABSOLUTE_SECONDS // (SESSION_IDLE_SECONDS - 60) + 2):
            clock.now += SESSION_IDLE_SECONDS - 60
            if load_session(store, raw) is None:
                break
        else:
            pytest.fail("the session outlived its absolute lifetime")

        assert clock.now - 1_000_000.0 >= SESSION_ABSOLUTE_SECONDS - SESSION_IDLE_SECONDS

    def test_a_disabled_user_has_no_session(self, store: Store) -> None:
        self._store(store, Clock())
        user = store.add_local_user("ann", password_hash="h", is_admin=True)
        raw, _ = start_session(store, user, None)

        store.set_user_disabled(user.id, True)

        assert load_session(store, raw) is None

    def test_an_unknown_id(self, store: Store) -> None:
        assert load_session(store, "nonsense") is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("/admin/connections", "/admin/connections"),
        ("/admin/connections?x=1", "/admin/connections?x=1"),
        ("https://evil.example/admin/", "/admin/"),
        ("//evil.example/admin/", "/admin/"),
        ("/elsewhere", "/admin/"),
        ("/admin/\\evil", "/admin/"),
        (None, "/admin/"),
    ],
)
def test_safe_next(value: str | None, expected: str) -> None:
    assert safe_next(value) == expected
