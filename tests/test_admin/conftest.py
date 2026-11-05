"""Shared fixtures for admin-site tests."""

from collections.abc import Callable
from dataclasses import dataclass, field

import pytest

from u2_mcp.admin.context import AdminContext
from u2_mcp.config import U2Config
from u2_mcp.connection_check import CheckResult
from u2_mcp.credentials import U2Credentials
from u2_mcp.store.models import Connection, User
from u2_mcp.store.repo import Store


@dataclass
class FakeRegistry:
    """Records which connections were evicted or disconnected."""

    evicted: list[int] = field(default_factory=list)
    live: dict[int, list[str]] = field(default_factory=dict)
    store: Store | None = None
    hosts_at_evict: list[str | None] = field(default_factory=list)
    owners_evicted: list[tuple[int, int]] = field(default_factory=list)

    def evict_connection(self, connection_id: int) -> int:
        self.evicted.append(connection_id)
        if self.store is not None:
            saved = self.store.get_connection(connection_id)
            self.hosts_at_evict.append(saved.host if saved else None)
        return len(self.live.pop(connection_id, []))

    def evict_owner(self, connection_id: int, user_id: int) -> int:
        self.owners_evicted.append((connection_id, user_id))
        return 0

    def sessions_for_connection(self, connection_id: int) -> list[str]:
        return list(self.live.get(connection_id, []))


@dataclass
class FakeCheck:
    """Records what was tested and answers with a fixed result."""

    result: CheckResult = field(default_factory=lambda: CheckResult(True, "fine", 1.0))
    calls: list[tuple[Connection, U2Credentials]] = field(default_factory=list)

    def __call__(
        self, base: U2Config, connection: Connection, credentials: U2Credentials
    ) -> CheckResult:
        self.calls.append((connection, credentials))
        return self.result


@pytest.fixture
def registry(store: Store) -> FakeRegistry:
    return FakeRegistry(store=store)


@pytest.fixture
def check() -> FakeCheck:
    return FakeCheck()


@pytest.fixture
def ctx(
    store: Store, mock_config: U2Config, registry: FakeRegistry, check: FakeCheck
) -> AdminContext:
    registry_getter: Callable[[], FakeRegistry] = lambda: registry  # noqa: E731
    return AdminContext(
        store=store,
        config=mock_config,
        registry=registry_getter,  # type: ignore[arg-type]
        check=check,
    )


@pytest.fixture
def admin(store: Store) -> User:
    return store.add_local_user("root", password_hash="unused", is_admin=True)
