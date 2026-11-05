"""Who may do what on which connection.

This is the code that decides who sees what, so it is tested as a table: every
row is one person, one connection, one permission, and the exact answer.
"""

from dataclasses import dataclass

import pytest

from u2_mcp.access import decide, effective_access, visible_connections
from u2_mcp.store.repo import Store


@dataclass
class World:
    store: Store
    alice: int
    bob: int


@pytest.fixture
def world(store: Store) -> World:
    """Six connections and two people, wired to exercise every rule.

    - Prod:     alice=Viewer (user), g-dev=Reporter (group, a custom read-only role)
    - Test:     g-dev=Developer
    - Archive:  g-dev=Developer, connection read-only
    - Training: everyone=Viewer
    - Hidden:   bob=Viewer only
    - Off:      everyone=Owner, connection disabled
    """

    world_reporter = store.add_role("Reporter", ["schema.read", "records.read", "query.run"]).id

    def role(name: str) -> int:
        found = store.get_role_by_name(name)
        assert found is not None
        return found.id

    def conn(name: str, read_only: bool = False, enabled: bool = True) -> int:
        return store.add_connection(
            name=name,
            host="h",
            port=1,
            service="uvcs",
            account="A",
            shared_user="svc",
            shared_password="pw",
            read_only=read_only,
            enabled=enabled,
        ).id

    alice = store.get_or_create_sso_user("alice").id
    bob = store.get_or_create_sso_user("bob").id
    store.record_sso_login(alice, ["g-dev"])
    store.record_sso_login(bob, [])
    dev_group = store.group_ids_for_user(alice)[0]

    prod, test, archive = conn("Prod"), conn("Test"), conn("Archive", read_only=True)
    training, hidden, off = conn("Training"), conn("Hidden"), conn("Off", enabled=False)

    store.add_grant(
        connection_id=prod, subject_type="user", subject_id=alice, role_id=role("Viewer")
    )
    store.add_grant(
        connection_id=prod, subject_type="group", subject_id=dev_group, role_id=world_reporter
    )
    store.add_grant(
        connection_id=test, subject_type="group", subject_id=dev_group, role_id=role("Developer")
    )
    store.add_grant(
        connection_id=archive, subject_type="group", subject_id=dev_group, role_id=role("Developer")
    )
    store.add_grant(connection_id=training, subject_type="everyone", role_id=role("Viewer"))
    store.add_grant(
        connection_id=hidden, subject_type="user", subject_id=bob, role_id=role("Viewer")
    )
    store.add_grant(connection_id=off, subject_type="everyone", role_id=role("Owner"))
    return World(store=store, alice=alice, bob=bob)


ALLOW = ""

CASES = [
    # who,    connection, permission,        global_ro, expected reason ("" = allowed)
    ("alice", "Prod", "records.read", False, ALLOW),
    ("alice", "Prod", "connection.use", False, ALLOW),
    ("alice", "Prod", "records.write", False, "you need records.write on Prod; ask an admin"),
    ("alice", "Test", "records.write", False, ALLOW),
    ("alice", "Test", "records.write", True, "Test is read-only"),
    ("alice", "Test", "records.read", True, ALLOW),
    ("alice", "Archive", "records.write", False, "Archive is read-only"),
    ("alice", "Archive", "records.read", False, ALLOW),
    # Read-only is about the ERP database; knowledge lives in this server's own store.
    ("alice", "Prod", "connection.use", True, ALLOW),
    ("alice", "Training", "records.read", False, ALLOW),
    (
        "alice",
        "Training",
        "records.write",
        False,
        "you need records.write on Training; ask an admin",
    ),
    ("alice", "Hidden", "records.read", False, "unknown connection 'Hidden'"),
    ("alice", "Off", "records.read", False, "unknown connection 'Off'"),
    ("alice", "Nope", "records.read", False, "unknown connection 'Nope'"),
    ("bob", "Hidden", "records.read", False, ALLOW),
    ("bob", "Test", "records.read", False, "unknown connection 'Test'"),
    ("alice", "Prod", "connection.use", False, ALLOW),
    ("bob", "Prod", "connection.use", False, "unknown connection 'Prod'"),
    ("alice", "Test", "connection.use", True, ALLOW),  # housekeeping is not a write
]


@pytest.mark.parametrize(("who", "connection", "permission", "global_ro", "expected"), CASES)
def test_decision_table(
    world: World, who: str, connection: str, permission: str, global_ro: bool, expected: str
) -> None:
    user_id = world.alice if who == "alice" else world.bob
    decision = decide(world.store, user_id, connection, permission, global_read_only=global_ro)
    assert decision.allowed == (expected == ALLOW)
    assert decision.reason == expected


def test_hidden_and_missing_connections_are_indistinguishable(world: World) -> None:
    hidden = decide(world.store, world.alice, "Hidden", "records.read", global_read_only=False)
    world.store.set_connection_flags(
        world.store.get_connection_by_name("Hidden").id,  # type: ignore[union-attr]
        enabled=False,
    )
    disabled = decide(world.store, world.alice, "Hidden", "records.read", global_read_only=False)
    assert hidden == disabled
    assert hidden.connection is None


def test_a_disabled_account_is_refused_everywhere(world: World) -> None:
    world.store.set_user_disabled(world.alice, True)
    decision = decide(world.store, world.alice, "Training", "records.read", global_read_only=False)
    assert not decision.allowed
    assert decision.reason == "account disabled"


def test_an_allowed_decision_names_the_caller_for_login_lookup(world: World) -> None:
    on_test = decide(world.store, world.alice, "Test", "records.read", global_read_only=False)
    refused = decide(world.store, world.alice, "Nope", "records.read", global_read_only=False)
    assert on_test.allowed and on_test.user_id == world.alice
    assert refused.user_id is None


def test_grant_changes_apply_to_the_next_decision(world: World) -> None:
    assert not decide(
        world.store, world.bob, "Test", "records.read", global_read_only=False
    ).allowed
    test_id = world.store.get_connection_by_name("Test").id  # type: ignore[union-attr]
    viewer = world.store.get_role_by_name("Viewer")
    assert viewer is not None
    world.store.add_grant(
        connection_id=test_id, subject_type="user", subject_id=world.bob, role_id=viewer.id
    )
    assert decide(world.store, world.bob, "Test", "records.read", global_read_only=False).allowed


def test_losing_groups_at_sign_in_removes_group_access(world: World) -> None:
    world.store.record_sso_login(world.alice, None)  # e.g. Entra group overage
    decision = decide(world.store, world.alice, "Test", "records.read", global_read_only=False)
    assert decision.reason == "unknown connection 'Test'"


def test_visible_connections_lists_only_granted_enabled_ones(world: World) -> None:
    visible = visible_connections(world.store, world.alice, global_read_only=False)
    assert [v.connection.name for v in visible] == ["Archive", "Prod", "Test", "Training"]
    archive = visible[0]
    assert "records.read" in archive.permissions
    assert "records.write" not in archive.permissions  # capped by read-only
    prod = visible[1]
    assert prod.roles == ("Reporter", "Viewer")


def test_visible_connections_honour_the_global_switch(world: World) -> None:
    visible = visible_connections(world.store, world.alice, global_read_only=True)
    test = next(v for v in visible if v.connection.name == "Test")
    assert "records.write" not in test.permissions


def test_effective_access_explains_where_each_permission_came_from(world: World) -> None:
    report = effective_access(world.store, world.alice, global_read_only=False)
    prod = next(r for r in report if r.connection.name == "Prod")
    assert prod.sources["records.read"] == ("group g-dev (Reporter)", "user grant (Viewer)")
    assert not any(p.startswith("knowledge.") for p in prod.sources)
    archive = next(r for r in report if r.connection.name == "Archive")
    assert "records.write" in archive.blocked_by_read_only
