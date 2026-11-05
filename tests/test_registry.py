"""The connection registry: one session per route (or the stdio login), bounded."""

import asyncio
import threading
import time
from typing import Any

import pytest

from tests.mocks.mock_uopy import MockSession
from tests.mocks.routes import make_route
from u2_mcp.config import U2Config
from u2_mcp.credentials import U2Credentials
from u2_mcp.registry import ConnectionRegistry
from u2_mcp.routing import Route, use_route

CALLERS = 50


class TestStdio:
    """Without a route, the one U2_HOST login is used."""

    def test_every_call_shares_the_environment_login(
        self, mock_config: U2Config, mock_uopy: MockSession
    ) -> None:
        registry = ConnectionRegistry(mock_config)

        first = registry.current()
        assert first is registry.current()
        assert first.credentials.user == mock_config.user
        assert first.credentials.is_shared is True

    def test_team_mode_never_uses_the_environment_login(
        self, mock_config: U2Config, mock_uopy: MockSession
    ) -> None:
        import pytest

        from u2_mcp.store import install_store

        install_store(object())  # type: ignore[arg-type]
        try:
            with pytest.raises(RuntimeError, match="no connection"):
                ConnectionRegistry(mock_config).current()
        finally:
            install_store(None)


class TestRoutes:
    def test_the_database_receives_the_routes_login(
        self, mock_config: U2Config, mock_uopy: MockSession
    ) -> None:
        registry = ConnectionRegistry(mock_config)
        with use_route(make_route(1, "ann")):
            registry.current().connect()

        assert mock_uopy.connect_kwargs["user"] == "ann"
        assert mock_uopy.connect_kwargs["account"] == "A"

    def test_each_login_gets_its_own_session_and_reuses_it(
        self, mock_config: U2Config, mock_uopy: MockSession
    ) -> None:
        registry = ConnectionRegistry(mock_config)

        ann = registry.for_route(make_route(1, "ann"))
        assert ann is registry.for_route(make_route(1, "ann"))
        assert ann is not registry.for_route(make_route(1, "bob"))
        assert len(registry.active_logins()) == 2

    def test_disconnect_all_clears_every_slot(
        self, mock_config: U2Config, mock_uopy: MockSession
    ) -> None:
        registry = ConnectionRegistry(mock_config)
        registry.for_route(make_route(1, "ann")).connect()
        registry.for_route(make_route(1, "bob")).connect()

        assert registry.disconnect_all() == 2
        assert registry.active_logins() == []


class TestLimits:
    """One session per login must not become unbounded sessions."""

    def test_sessions_do_not_grow_without_limit_and_the_newest_stays(
        self, mock_config: U2Config, mock_uopy: MockSession
    ) -> None:
        mock_config.max_connections = 5
        registry = ConnectionRegistry(mock_config)
        for n in range(20):
            registry.for_route(make_route(1, f"U{n}"))

        assert len(registry.active_logins()) <= 5
        assert any(key.endswith("U19@A") for key in registry.active_logins())

    def test_concurrent_callers_stay_within_the_limit(
        self, mock_config: U2Config, mock_uopy: MockSession
    ) -> None:
        mock_config.max_connections = 10
        registry = ConnectionRegistry(mock_config)
        barrier = threading.Barrier(CALLERS)
        errors: list[Exception] = []

        def request(index: int) -> None:
            barrier.wait()
            try:
                registry.for_route(make_route(1, f"U{index}"))
            except Exception as exc:  # noqa: BLE001 - collected and asserted below
                errors.append(exc)

        threads = [threading.Thread(target=request, args=(n,)) for n in range(CALLERS)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert errors == []
        assert len(registry.active_logins()) <= 10

    def test_one_login_arriving_many_times_gets_one_session(
        self, mock_config: U2Config, mock_uopy: MockSession
    ) -> None:
        registry = ConnectionRegistry(mock_config)
        barrier = threading.Barrier(CALLERS)
        managers: list[Any] = []
        lock = threading.Lock()

        def request() -> None:
            barrier.wait()
            manager = registry.for_route(make_route(1, "U1"))
            with lock:
                managers.append(manager)

        threads = [threading.Thread(target=request) for _ in range(CALLERS)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len({id(manager) for manager in managers}) == 1

    def test_an_evicted_login_reconnects_and_its_session_is_closed(
        self, mock_config: U2Config, mock_uopy: MockSession
    ) -> None:
        mock_config.max_connections = 2
        registry = ConnectionRegistry(mock_config)
        evicted = registry.for_route(make_route(1, "U0"))
        evicted.connect()

        for n in range(1, 6):
            registry.for_route(make_route(1, f"U{n}"))

        # The close runs on a background thread.
        deadline = time.monotonic() + 5
        while evicted.connection_info is not None and time.monotonic() < deadline:
            time.sleep(0.01)
        assert evicted.connection_info is None
        assert "test-user" in registry.for_route(make_route(1, "U0")).execute_command("WHO")

    def test_a_slow_eviction_does_not_stall_the_registry(
        self, mock_config: U2Config, mock_uopy: MockSession
    ) -> None:
        """Closing a wedged session happens outside the registry lock."""
        mock_config.max_connections = 2
        registry = ConnectionRegistry(mock_config)
        victim = registry.for_route(make_route(1, "U0"))
        victim.connect()

        closing = threading.Event()
        release = threading.Event()
        original_disconnect = victim.disconnect

        def slow_disconnect() -> bool:
            closing.set()
            release.wait(timeout=5)
            return original_disconnect()

        victim.disconnect = slow_disconnect  # type: ignore[method-assign]

        def fill_the_registry() -> None:
            for n in range(1, 5):
                registry.for_route(make_route(1, f"U{n}"))

        filler = threading.Thread(target=fill_the_registry)
        filler.start()
        assert closing.wait(timeout=5), "eviction never started"

        answered = threading.Event()

        def ask_registry() -> None:
            registry.active_logins()
            answered.set()

        asker = threading.Thread(target=ask_registry)
        asker.start()
        try:
            assert answered.wait(timeout=2), "the registry was blocked by a slow eviction"
        finally:
            release.set()
            asker.join(timeout=5)
            filler.join(timeout=5)


class TestForgettingAConnection:
    """After an admin edits or deletes a connection, no old session may survive."""

    def test_evict_closes_every_login_on_that_connection_only(
        self, mock_config: U2Config, mock_uopy: MockSession
    ) -> None:
        registry = ConnectionRegistry(mock_config)
        registry.for_route(make_route(1, "ann"))
        registry.for_route(make_route(1, "bob"))
        registry.for_route(make_route(2, "ann"))

        assert sorted(registry.sessions_for_connection(1)) == ["ann@A", "bob@A"]
        assert registry.evict_connection(1) == 2
        assert registry.sessions_for_connection(1) == []
        assert registry.sessions_for_connection(2) == ["ann@A"]

    def test_id_prefixes_do_not_collide(
        self, mock_config: U2Config, mock_uopy: MockSession
    ) -> None:
        registry = ConnectionRegistry(mock_config)
        registry.for_route(make_route(12, "ann"))

        assert registry.evict_connection(1) == 0
        assert registry.sessions_for_connection(12) == ["ann@A"]

    def test_versions_get_separate_slots_and_evict_closes_both(
        self, mock_config: U2Config, mock_uopy: MockSession
    ) -> None:
        registry = ConnectionRegistry(mock_config)
        old = registry.for_route(make_route(1, "ann", version=1))
        new = registry.for_route(make_route(1, "ann", version=2))

        assert old is not new
        assert registry.sessions_for_connection(1) == ["ann@A", "ann@A"]
        assert registry.evict_connection(1) == 2

    def test_evict_owner_closes_only_that_persons_slots(
        self, mock_config: U2Config, mock_uopy: MockSession
    ) -> None:
        registry = ConnectionRegistry(mock_config)
        mine = make_route(1, "sam")
        registry.for_route(Route(mine.connection, mine.credentials, owner_id=7))
        registry.for_route(Route(mine.connection, mine.credentials, owner_id=17))
        registry.for_route(Route(make_route(2, "sam").connection, mine.credentials, owner_id=7))

        assert registry.sessions_for_connection(1) == ["sam@A", "sam@A"]
        assert registry.evict_owner(1, 7) == 1
        assert registry.sessions_for_connection(1) == ["sam@A"]
        assert registry.sessions_for_connection(2) == ["sam@A"]

    @pytest.mark.asyncio
    async def test_an_admin_eviction_does_not_block_the_event_loop(
        self, mock_config: U2Config, mock_uopy: MockSession
    ) -> None:
        """uopy's close waits for the session lock an in-flight RPC holds."""
        registry = ConnectionRegistry(mock_config)
        registry.for_route(make_route(1, "ann")).connect()
        rpc_in_flight = threading.Lock()
        rpc_in_flight.acquire()
        closed = threading.Event()

        def close() -> None:
            # Bounded, so a regression fails the timing check instead of hanging.
            if rpc_in_flight.acquire(timeout=1):
                rpc_in_flight.release()
            closed.set()

        mock_uopy.close = close  # type: ignore[method-assign]

        async def probe() -> float:
            started = time.monotonic()
            await asyncio.sleep(0.01)
            return time.monotonic() - started

        try:
            task = asyncio.create_task(probe())
            await asyncio.sleep(0)
            assert registry.evict_connection(1) == 1
            assert await asyncio.wait_for(task, timeout=5) < 0.2
            assert registry.sessions_for_connection(1) == []
        finally:
            rpc_in_flight.release()
        assert closed.wait(timeout=5), "the evicted session was never closed"


@pytest.mark.parametrize("opener", ["connect", "get_session"])
def test_a_login_still_running_when_evicted_is_closed(
    mock_config: U2Config, mock_uopy: MockSession, opener: str
) -> None:
    """A session that finishes logging in after its slot is evicted is not left open."""
    from unittest.mock import patch

    registry = ConnectionRegistry(mock_config)
    manager = registry.for_route(make_route(1, "ann"))
    entered, resume, cleanup_started = threading.Event(), threading.Event(), threading.Event()
    session = MockSession()
    real_disconnect = manager.disconnect

    def disconnect() -> bool:
        cleanup_started.set()
        return real_disconnect()

    manager.disconnect = disconnect  # type: ignore[method-assign]

    def slow_login(**_kwargs: Any) -> MockSession:
        entered.set()
        resume.wait(timeout=5)
        return session

    with patch("uopy.connect", side_effect=slow_login):
        login = threading.Thread(target=getattr(manager, opener))
        login.start()
        assert entered.wait(timeout=5)
        assert registry.evict_connection(1) == 1
        assert cleanup_started.wait(timeout=5)
        time.sleep(0.05)  # an unlocked disconnect has returned by now
        resume.set()
        login.join(timeout=5)

    deadline = time.monotonic() + 5
    while session.is_active and time.monotonic() < deadline:
        time.sleep(0.01)
    assert registry.active_logins() == []
    assert session.is_active is False


def test_credentials_repr_hides_the_password() -> None:
    login = U2Credentials(user="u", password="hunter2-secret", account="A", is_shared=True)

    assert "hunter2-secret" not in repr(login)
