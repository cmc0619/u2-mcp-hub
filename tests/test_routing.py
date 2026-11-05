"""A tool call reaches the right U2 server, as the right U2 user."""

import pytest

from tests.mocks.mock_uopy import MockSession
from u2_mcp.access import decide
from u2_mcp.config import U2Config
from u2_mcp.connection import ConnectionManager
from u2_mcp.credentials import U2Credentials
from u2_mcp.identity import LOCAL_CALLER, caller_for_user, use_caller
from u2_mcp.registry import ConnectionRegistry
from u2_mcp.routing import (
    Route,
    RouteError,
    config_for,
    current_route,
    resolve_route,
    use_route,
)
from u2_mcp.store.crypto import SecretBox
from u2_mcp.store.repo import Store


def _role(store: Store, name: str) -> int:
    role = store.get_role_by_name(name)
    assert role is not None
    return role.id


@pytest.fixture
def setup(store: Store) -> dict[str, int]:
    prod = store.add_connection(
        name="Prod",
        host="prod.example",
        port=31438,
        service="uvcs",
        account="LIVE",
        shared_user="svc",
        shared_password="prod-pw",
        read_only=False,
    ).id
    test = store.add_connection(
        name="Test",
        host="test.example",
        port=31439,
        service="udcs",
        account="TRAIN",
        login_mode="per_user",
        read_only=True,
    ).id
    alice = store.get_or_create_sso_user("alice").id
    bob = store.get_or_create_sso_user("bob").id
    store.record_sso_login(alice, ["g-dev"])
    group = store.group_ids_for_user(alice)[0]
    viewer = _role(store, "Viewer")
    store.add_grant(connection_id=prod, subject_type="everyone", role_id=viewer)
    store.add_grant(connection_id=test, subject_type="user", subject_id=bob, role_id=viewer)
    store.set_u2_login(bob, test, "bob_u2", "bob-pw")
    store.add_grant(connection_id=test, subject_type="group", subject_id=group, role_id=viewer)
    return {"prod": prod, "test": test, "alice": alice, "bob": bob}


def _route(store: Store, user_id: int, connection: str) -> Route:
    decision = decide(store, user_id, connection, "records.read", global_read_only=False)
    assert decision.allowed, decision.reason
    return resolve_route(store, decision)


def test_shared_connections_use_the_connection_login(store: Store, setup: dict[str, int]) -> None:
    route = _route(store, setup["alice"], "Prod")
    assert route.credentials.user == "svc"
    assert route.credentials.password == "prod-pw"
    assert route.credentials.account == "LIVE"
    assert route.credentials.is_shared


def test_per_user_connections_use_the_callers_own_login(
    store: Store, setup: dict[str, int]
) -> None:
    route = _route(store, setup["bob"], "Test")
    assert route.credentials.user == "bob_u2" and route.credentials.password == "bob-pw"
    assert not route.credentials.is_shared


def test_group_access_to_a_per_user_connection_needs_a_personal_login(
    store: Store, setup: dict[str, int]
) -> None:
    with pytest.raises(RouteError) as caught:
        _route(store, setup["alice"], "Test")
    assert str(caught.value) == "no U2 login set for you on Test; set it on My access"


def test_the_refusal_links_to_my_access_when_a_public_url_is_saved(
    store: Store, setup: dict[str, int]
) -> None:
    store.set_setting("public_url", "https://u2.example.com")
    with pytest.raises(RouteError) as caught:
        _route(store, setup["alice"], "Test")
    assert str(caught.value) == (
        "no U2 login set for you on Test; set it on My access (https://u2.example.com/admin/me)"
    )


def test_group_access_uses_the_persons_own_login(store: Store, setup: dict[str, int]) -> None:
    store.set_u2_login(setup["alice"], setup["test"], "alice_u2", "alice-pw")

    route = _route(store, setup["alice"], "Test")

    assert (route.credentials.user, route.credentials.password) == ("alice_u2", "alice-pw")
    assert route.owner_id == setup["alice"]


def test_two_people_with_the_same_u2_user_never_share_a_session(
    store: Store, setup: dict[str, int]
) -> None:
    store.set_u2_login(setup["alice"], setup["test"], "bob_u2", "a-guess")

    alice = _route(store, setup["alice"], "Test")
    bob = _route(store, setup["bob"], "Test")

    assert alice.credentials.pool_key == bob.credentials.pool_key
    assert alice.key != bob.key


def test_an_unreadable_personal_password_says_to_set_it_again(
    store: Store, setup: dict[str, int]
) -> None:
    store._box = SecretBox("w" * 40)
    with pytest.raises(RouteError, match="set it again on My access"):
        _route(store, setup["bob"], "Test")


def test_a_shared_connection_without_a_password_is_refused(store: Store) -> None:
    store.add_connection(name="Bare", host="h", port=1, service="uvcs", account="A")
    user = store.get_or_create_sso_user("u").id
    store.add_grant(
        connection_id=store.get_connection_by_name("Bare").id,  # type: ignore[union-attr]
        subject_type="everyone",
        role_id=_role(store, "Viewer"),
    )
    with pytest.raises(RouteError, match="has no U2 login configured"):
        _route(store, user, "Bare")


def test_an_unreadable_password_is_reported_not_crashed(
    store: Store, setup: dict[str, int]
) -> None:
    store._box = SecretBox("w" * 40)  # as if U2_SECRET_KEY changed
    with pytest.raises(RouteError, match="cannot be read"):
        _route(store, setup["alice"], "Prod")


def test_config_for_points_at_the_connection(store: Store, mock_config: U2Config) -> None:
    connection = store.add_connection(
        name="X",
        host="x.example",
        port=4000,
        service="udcs",
        account="ACC",
        ssl=True,
        read_only=True,
    )
    config = config_for(mock_config, connection)
    assert (config.host, config.port, config.service, config.ssl, config.account) == (
        "x.example",
        4000,
        "udcs",
        True,
        "ACC",
    )
    assert config.read_only
    assert mock_config.host == "test-host.example.com"  # the base is untouched


def test_the_route_is_scoped_to_a_block(store: Store, setup: dict[str, int]) -> None:
    route = _route(store, setup["alice"], "Prod")
    assert current_route() is None
    with use_route(route):
        assert current_route() is route
    assert current_route() is None


class TestRegistry:
    def test_each_connection_and_login_gets_its_own_session(
        self, store: Store, setup: dict[str, int], mock_config: U2Config
    ) -> None:
        registry = ConnectionRegistry(mock_config)
        prod_alice = registry.for_route(_route(store, setup["alice"], "Prod"))
        prod_bob = registry.for_route(_route(store, setup["bob"], "Prod"))
        test_bob = registry.for_route(_route(store, setup["bob"], "Test"))

        assert prod_alice is prod_bob  # same connection, same shared login
        assert test_bob is not prod_bob
        assert prod_bob.config.host == "prod.example"
        assert test_bob.config.host == "test.example"
        assert test_bob.credentials.user == "bob_u2"

    def test_current_prefers_the_installed_route(
        self, store: Store, setup: dict[str, int], mock_config: U2Config
    ) -> None:
        registry = ConnectionRegistry(mock_config)
        route = _route(store, setup["bob"], "Test")
        with use_route(route):
            assert registry.current().config.host == "test.example"
        with use_caller(LOCAL_CALLER):
            assert registry.current().config.host == "test-host.example.com"


def test_each_connection_dials_its_own_port_and_ssl(
    store: Store, mock_config: U2Config, mock_uopy: MockSession
) -> None:
    """A connection marked SSL must not quietly connect in the clear."""
    connection = store.add_connection(
        name="Secure",
        host="s.example",
        port=40001,
        service="udcs",
        account="ACC",
        ssl=True,
        shared_user="u",
        shared_password="p",
    )
    credentials = U2Credentials(user="u", password="p", account="ACC", is_shared=True)
    ConnectionManager(config_for(mock_config, connection), credentials).connect()
    kwargs = mock_uopy.connect_kwargs
    assert (kwargs["host"], kwargs["port"], kwargs["ssl"], kwargs["service"]) == (
        "s.example",
        40001,
        True,
        "udcs",
    )


def test_callers_built_from_users_carry_their_id(store: Store) -> None:
    sso = store.get_or_create_sso_user("sub-9", email="e@x.com", display_name="Eve")
    local = store.add_local_user("ops")
    sso_caller = caller_for_user(sso, auth_method="token")
    local_caller = caller_for_user(local, auth_method="local")
    assert (sso_caller.user_id, sso_caller.subject, sso_caller.auth_method) == (
        sso.id,
        "sub-9",
        "token",
    )
    assert local_caller.subject == "local:ops"
    assert LOCAL_CALLER.auth_method == "stdio" and LOCAL_CALLER.user_id is None
