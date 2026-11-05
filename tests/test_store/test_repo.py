"""The settings store: connections, users, roles, grants, sessions and audit."""

import sqlite3
import threading

import pytest

from u2_mcp.store import get_store, install_store
from u2_mcp.store.repo import (
    STALE_CONNECTION_MESSAGE,
    STALE_ROLE_MESSAGE,
    LastAdmin,
    StaleEdit,
    Store,
    StoreError,
)


def _prod(store: Store, **overrides: object) -> int:
    fields: dict[str, object] = {
        "name": "Prod",
        "host": "u2.example.com",
        "port": 31438,
        "service": "uvcs",
        "account": "DEMO",
        "shared_user": "svc",
        "shared_password": "s3cret",
    }
    fields.update(overrides)
    return store.add_connection(**fields).id  # type: ignore[arg-type]


class TestConnections:
    def test_a_connection_round_trips_without_exposing_its_password(self, store: Store) -> None:
        conn_id = _prod(store)
        connection = store.get_connection(conn_id)
        assert connection is not None
        assert connection.name == "Prod"
        assert connection.has_shared_password
        assert not hasattr(connection, "shared_password")
        assert store.shared_password(conn_id) == "s3cret"

    def test_the_password_is_encrypted_at_rest(self, store: Store) -> None:
        _prod(store)
        raw = store._conn.execute("SELECT shared_password_enc FROM connections").fetchone()[0]
        assert "s3cret" not in raw

    def test_connections_default_to_read_only(self, store: Store) -> None:
        connection = store.get_connection(_prod(store))
        assert connection is not None and connection.read_only

    def test_names_are_unique(self, store: Store) -> None:
        _prod(store)
        with pytest.raises(StoreError, match="already exists"):
            _prod(store)

    def test_lookup_by_name_and_listing(self, store: Store) -> None:
        _prod(store)
        _prod(store, name="Test")
        assert store.get_connection_by_name("Test") is not None
        assert store.get_connection_by_name("Nope") is None
        assert [c.name for c in store.list_connections()] == ["Prod", "Test"]
        assert store.has_connections()

    def test_flags_can_be_changed(self, store: Store) -> None:
        conn_id = _prod(store)
        store.set_connection_flags(conn_id, read_only=False, enabled=False)
        connection = store.get_connection(conn_id)
        assert connection is not None
        assert not connection.read_only and not connection.enabled


class TestUsersAndGroups:
    def test_sso_users_are_created_once_and_kept_up_to_date(self, store: Store) -> None:
        first = store.get_or_create_sso_user("sub-1", email="a@x.com", display_name="A")
        again = store.get_or_create_sso_user("sub-1", email="new@x.com", display_name="A")
        assert first.id == again.id
        assert again.email == "new@x.com"
        assert again.kind == "sso" and not again.is_admin and not again.disabled

    def test_local_users_need_a_unique_username(self, store: Store) -> None:
        store.add_local_user("admin", is_admin=True)
        with pytest.raises(StoreError, match="already exists"):
            store.add_local_user("admin")

    def test_sign_in_replaces_group_membership(self, store: Store) -> None:
        user = store.get_or_create_sso_user("sub-1")
        store.record_sso_login(user.id, ["g-dev", "g-ops"])
        store.record_sso_login(user.id, ["g-dev"])
        groups = {g.id: g.external_id for g in store.list_groups()}
        assert sorted(groups[i] for i in store.group_ids_for_user(user.id)) == ["g-dev"]
        assert set(groups.values()) == {"g-dev", "g-ops"}  # groups seen once are remembered

    def test_sign_in_records_the_time(self, store: Store) -> None:
        user = store.get_or_create_sso_user("sub-1")
        store.record_sso_login(user.id, [])
        refreshed = store.get_user(user.id)
        assert refreshed is not None and refreshed.last_sso_login_at is not None

    def test_missing_groups_flag_the_user_and_clear_membership(self, store: Store) -> None:
        user = store.get_or_create_sso_user("sub-1")
        store.record_sso_login(user.id, ["g-dev"])
        store.record_sso_login(user.id, None)
        refreshed = store.get_user(user.id)
        assert refreshed is not None and refreshed.groups_unavailable
        assert store.group_ids_for_user(user.id) == []

    def test_users_can_be_disabled(self, store: Store) -> None:
        user = store.get_or_create_sso_user("sub-1")
        store.set_user_disabled(user.id, True)
        refreshed = store.get_user(user.id)
        assert refreshed is not None and refreshed.disabled


class TestRolesAndGrants:
    def test_builtin_roles_are_seeded_once(self, store: Store) -> None:
        store.seed_builtin_roles()
        viewer = store.get_role_by_name("Viewer")
        assert viewer is not None and viewer.builtin
        assert "records.read" in viewer.permissions

    def test_custom_roles_reject_unknown_permissions(self, store: Store) -> None:
        with pytest.raises(StoreError, match="unknown permission"):
            store.add_role("Weird", ["records.read", "make.coffee"])

    def test_grants_for_combines_user_group_and_everyone(self, store: Store) -> None:
        prod = _prod(store)
        test = _prod(store, name="Test")
        viewer = store.get_role_by_name("Viewer")
        developer = store.get_role_by_name("Developer")
        assert viewer is not None and developer is not None
        user = store.get_or_create_sso_user("sub-1")
        other = store.get_or_create_sso_user("sub-2")
        store.record_sso_login(user.id, ["g-dev"])
        group_id = store.group_ids_for_user(user.id)[0]

        store.add_grant(
            connection_id=prod, subject_type="user", subject_id=user.id, role_id=viewer.id
        )
        store.add_grant(
            connection_id=prod, subject_type="group", subject_id=group_id, role_id=developer.id
        )
        store.add_grant(connection_id=test, subject_type="everyone", role_id=viewer.id)
        store.add_grant(
            connection_id=prod, subject_type="user", subject_id=other.id, role_id=developer.id
        )

        mine = store.grants_for(user.id, [group_id])
        assert sorted((g.connection_id, g.subject_type) for g in mine) == [
            (prod, "group"),
            (prod, "user"),
            (test, "everyone"),
        ]
        assert len(store.grants_for(user.id, [group_id], connection_id=test)) == 1

    def test_one_grant_per_subject_per_connection(self, store: Store) -> None:
        prod = _prod(store)
        viewer = store.get_role_by_name("Viewer")
        assert viewer is not None
        store.add_grant(connection_id=prod, subject_type="everyone", role_id=viewer.id)
        with pytest.raises(StoreError, match="already has a grant"):
            store.add_grant(connection_id=prod, subject_type="everyone", role_id=viewer.id)

    def test_a_grant_never_carries_a_u2_login(self, store: Store) -> None:
        prod = _prod(store, login_mode="per_user", shared_user=None, shared_password=None)
        viewer = store.get_role_by_name("Viewer")
        assert viewer is not None
        user = store.get_or_create_sso_user("sub-1")
        grant = store.add_grant(
            connection_id=prod, subject_type="user", subject_id=user.id, role_id=viewer.id
        )
        # Personal logins live in user_u2_logins (set_u2_login), never on a grant.
        assert not hasattr(grant, "per_user_u2_user")
        assert store.get_u2_login(user.id, prod) is None


class TestTokensAuditSettings:
    def test_tokens_are_found_by_hash_touched_and_revoked(self, store: Store) -> None:
        user = store.get_or_create_sso_user("sub-1")
        token = store.add_token(user_id=user.id, name="laptop", token_hash="h1", expires_at=9e9)
        assert store.get_token_by_hash("h1") == token
        store.touch_token(token.id, at=100.0, ip="10.0.0.5")
        store.revoke_token(token.id, at=200.0)
        found = store.get_token_by_hash("h1")
        assert found is not None
        assert found.last_used_at == 100.0 and found.revoked_at == 200.0
        assert [t.name for t in store.list_tokens(user.id)] == ["laptop"]

    def test_audit_rows_redact_secrets(self, store: Store) -> None:
        store.add_audit(
            kind="tool",
            action="read_record",
            outcome="ok",
            params={"file_name": "X", "password": "pw"},
        )
        row = store.recent_audit(1)[0]
        assert row["action"] == "read_record"
        assert row["params"]["password"] == "[redacted]"

    def test_audit_rows_redact_nested_secrets(self, store: Store) -> None:
        store.add_audit(
            kind="tool",
            action="x",
            outcome="ok",
            params={
                "conn": {"password": "pw", "host": "h"},
                "args": [{"token": "t"}],
                "file_name": "F",
            },
        )
        params = store.recent_audit(1)[0]["params"]
        assert params["conn"]["password"] == "[redacted]"
        assert params["conn"]["host"] == "h"
        assert params["args"][0]["token"] == "[redacted]"
        assert params["file_name"] == "F"

    def test_settings_hold_json_values(self, store: Store) -> None:
        assert store.get_setting("missing", 5) == 5
        store.set_setting("token_policy", {"max_days": 90})
        assert store.get_setting("token_policy") == {"max_days": 90}


def test_the_store_singleton(store: Store) -> None:
    assert get_store() is None
    install_store(store)
    try:
        assert get_store() is store
    finally:
        install_store(None)


def test_the_store_survives_concurrent_threads(store: Store) -> None:
    _prod(store)
    errors: list[BaseException] = []

    def work() -> None:
        try:
            for _ in range(50):
                store.list_connections()
                store.add_audit(kind="tool", action="x", outcome="ok")
        except (sqlite3.Error, StoreError) as exc:
            errors.append(exc)

    threads = [threading.Thread(target=work) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(store.recent_audit(500)) == 200


def _per_user(store: Store, name: str = "Dev") -> int:
    return store.add_connection(
        name=name,
        host="u2.example",
        port=31438,
        service="uvcs",
        account="DEV",
        login_mode="per_user",
    ).id


def _viewer(store: Store) -> int:
    role = store.get_role_by_name("Viewer")
    assert role is not None
    return role.id


class TestGrants:
    def test_update_changes_the_role(self, store: Store) -> None:
        connection_id = _per_user(store)
        ann = store.add_local_user("ann")
        grant = store.add_grant(
            connection_id=connection_id,
            subject_type="user",
            subject_id=ann.id,
            role_id=_viewer(store),
        )
        developer = store.get_role_by_name("Developer")
        assert developer is not None

        updated = store.update_grant(grant.id, role_id=developer.id)

        assert updated.role_id == developer.id

    def test_update_of_a_missing_grant_is_refused(self, store: Store) -> None:
        with pytest.raises(StoreError):
            store.update_grant(999, role_id=_viewer(store))

    def test_delete_and_lookups(self, store: Store) -> None:
        connection_id = _per_user(store)
        everyone = store.add_grant(
            connection_id=connection_id, subject_type="everyone", role_id=_viewer(store)
        )

        assert store.get_grant(everyone.id) == everyone
        assert store.everyone_grants() == [everyone]
        assert store.grants_for_subject("everyone", None) == [everyone]
        assert store.delete_grant(everyone.id) is True
        assert store.delete_grant(everyone.id) is False
        assert store.get_grant(everyone.id) is None


class TestListing:
    def test_roles_list_builtins_first(self, store: Store) -> None:
        store.add_role("Auditor", ["schema.read"])

        names = [role.name for role in store.list_roles()]

        assert names[:3] == ["Developer", "Owner", "Viewer"]
        assert names[-1] == "Auditor"

    def test_users_filter_by_text_and_flags(self, store: Store) -> None:
        store.add_local_user("ann", display_name="Ann Admin", is_admin=True)
        bob = store.add_local_user("bob", email="bob@example.com")
        store.set_user_disabled(bob.id, True)

        assert [u.username for u in store.list_users()] == ["ann", "bob"]
        assert [u.username for u in store.list_users(search="EXAMPLE")] == ["bob"]
        assert [u.username for u in store.list_users(is_admin=True)] == ["ann"]
        assert [u.username for u in store.list_users(disabled=True)] == ["bob"]
        assert store.list_users(search="%") == []


class TestUserFlags:
    def test_flags_on_an_unknown_user_are_refused(self, store: Store) -> None:
        with pytest.raises(StoreError):
            store.set_user_admin(999, True)
        with pytest.raises(StoreError):
            store.set_user_disabled(999, True)

    def test_re_enabling_keeps_the_user_signed_out(self, store: Store) -> None:
        ann = store.add_local_user("ann")
        store.add_admin_session(id_hash="h", user_id=ann.id, csrf_token="c", ip=None)
        store.set_user_disabled(ann.id, True)
        store.set_user_disabled(ann.id, False)

        assert store.get_admin_session("h") is None


class TestRolesAndGroups:
    def test_editing_a_custom_role_bumps_its_version(self, store: Store) -> None:
        role = store.add_role("Auditor", ["schema.read"])

        edited = store.update_role(
            role.id,
            expected_version=role.version,
            name="Auditors",
            permissions=["schema.read", "records.read"],
        )

        assert edited.version == role.version + 1
        assert edited.permissions == {"schema.read", "records.read"}
        with pytest.raises(StaleEdit, match=STALE_ROLE_MESSAGE):
            store.update_role(role.id, expected_version=role.version, name="X", permissions=[])

    def test_builtin_roles_cannot_be_edited_or_deleted(self, store: Store) -> None:
        viewer = store.get_role_by_name("Viewer")
        assert viewer is not None
        with pytest.raises(StoreError):
            store.update_role(
                viewer.id, expected_version=viewer.version, name="Viewer", permissions=[]
            )
        with pytest.raises(StoreError):
            store.delete_role(viewer.id)

    def test_a_role_in_use_cannot_be_deleted(self, store: Store) -> None:
        role = store.add_role("Auditor", ["schema.read"])
        store.add_grant(connection_id=_per_user(store), subject_type="everyone", role_id=role.id)

        assert store.role_in_use(role.id) == 1
        with pytest.raises(StoreError):
            store.delete_role(role.id)

    def test_group_labels(self, store: Store) -> None:
        user = store.get_or_create_sso_user("s")
        store.record_sso_login(user.id, ["eng"])
        group = store.list_groups()[0]

        store.set_group_label(group.id, "Engineering")

        assert store.get_group(group.id).label == "Engineering"  # type: ignore[union-attr]
        with pytest.raises(StoreError):
            store.set_group_label(999, "x")


class TestSetUserFlags:
    def test_the_only_enabled_local_admin_stays(self, store: Store) -> None:
        ann = store.add_local_user("ann", is_admin=True)
        changes: list[dict[str, bool]] = [
            {"is_admin": False},
            {"disabled": True},
            {"is_admin": False, "disabled": True},
        ]
        for change in changes:
            with pytest.raises(LastAdmin):
                store.set_user_flags(ann.id, **change)
            kept = store.get_user(ann.id)
            assert kept is not None and kept.is_admin and not kept.disabled

    def test_both_flags_change_in_one_go(self, store: Store) -> None:
        store.add_local_user("ann", is_admin=True)
        bob = store.add_local_user("bob", is_admin=True)
        store.add_admin_session(id_hash="b", user_id=bob.id, csrf_token="c", ip=None)

        store.set_user_flags(bob.id, is_admin=False, disabled=True)

        changed = store.get_user(bob.id)
        assert changed is not None and not changed.is_admin and changed.disabled
        assert store.get_admin_session("b") is None

    def test_an_unknown_user_is_refused(self, store: Store) -> None:
        with pytest.raises(StoreError):
            store.set_user_flags(999, disabled=True)

    def test_without_a_local_admin_other_changes_still_work(self, store: Store) -> None:
        sue = store.get_or_create_sso_user("sub-1")
        store.set_user_admin(sue.id, True)

        store.set_user_flags(sue.id, is_admin=False)

        changed = store.get_user(sue.id)
        assert changed is not None and not changed.is_admin


class TestAuditAndIds:
    def test_a_deleted_connections_id_is_never_given_out_again(self, store: Store) -> None:
        first = _per_user(store, "A")
        second = _per_user(store, "B")
        store.delete_connection(second)

        third = _per_user(store, "C")

        assert third > second > first

    def test_audit_filters(self, store: Store) -> None:
        store.add_audit(
            kind="admin", action="grant.create", outcome="ok", actor_user_id=1, connection_id=7
        )
        store.add_audit(kind="tool", action="read_record", outcome="ok", actor_user_id=2)
        store.add_audit(kind="admin", action="grant_x", outcome="ok")

        assert [e["action"] for e in store.query_audit(kind="admin")] == ["grant_x", "grant.create"]
        assert [e["action"] for e in store.query_audit(action="grant.")] == ["grant.create"]
        assert [e["action"] for e in store.query_audit(actor_user_id=2)] == ["read_record"]
        assert [e["action"] for e in store.query_audit(connection_id=7)] == ["grant.create"]
        assert store.query_audit(since=store.clock() + 60) == []
        assert len(store.query_audit(limit=None)) == 3

    def test_counting_active_admin_sessions(self, store: Store) -> None:
        ann = store.add_local_user("ann")
        store.add_admin_session(id_hash="a", user_id=ann.id, csrf_token="c", ip=None)

        assert store.count_admin_sessions(seen_since=store.clock() - 60) == 1
        assert store.count_admin_sessions(seen_since=store.clock() + 60) == 0


class TestFollowUps:
    def test_a_new_password_and_clearing_it_are_not_both_allowed(self, store: Store) -> None:
        connection = store.add_connection(
            name="P",
            host="h",
            port=1,
            service="uvcs",
            account="A",
            shared_user="s",
            shared_password="p",
        )
        with pytest.raises(StoreError):
            store.update_connection(
                connection.id,
                expected_version=connection.version,
                name="P",
                host="h",
                port=1,
                service="uvcs",
                account="A",
                ssl=False,
                login_mode="shared",
                shared_user="s",
                shared_password="new",
                clear_shared_password=True,
                read_only=True,
                enabled=True,
                actor=None,
            )

    def test_setting_a_password_for_nobody_is_refused(self, store: Store) -> None:
        with pytest.raises(StoreError):
            store.set_password_hash(999, "h", must_change=False)


def _prod_connection(store: Store) -> int:
    return store.add_connection(
        name="Prod",
        host="u2.example",
        port=31438,
        service="uvcs",
        account="PROD",
        shared_user="svc",
        shared_password="first",
    ).id


def _edit(store: Store, connection_id: int, version: int, **changes: object) -> object:
    values: dict[str, object] = {
        "name": "Prod",
        "host": "u2.example",
        "port": 31438,
        "service": "uvcs",
        "account": "PROD",
        "ssl": False,
        "login_mode": "shared",
        "shared_user": "svc",
        "read_only": True,
        "enabled": True,
        "actor": "ann",
    }
    values.update(changes)
    return store.update_connection(connection_id, expected_version=version, **values)  # type: ignore[arg-type]


class TestEditingConnections:
    def test_an_edit_saves_and_bumps_the_version(self, store: Store) -> None:
        connection_id = _prod_connection(store)

        _edit(store, connection_id, 1, host="u2-new.example")

        saved = store.get_connection(connection_id)
        assert saved is not None
        assert saved.host == "u2-new.example"
        assert saved.version == 2

    def test_an_edit_from_an_old_version_is_refused(self, store: Store) -> None:
        connection_id = _prod_connection(store)
        _edit(store, connection_id, 1, host="first-save.example")

        with pytest.raises(StaleEdit, match="Someone else changed this connection"):
            _edit(store, connection_id, 1, host="second-save.example")

        saved = store.get_connection(connection_id)
        assert saved is not None and saved.host == "first-save.example"
        assert str(StaleEdit(STALE_CONNECTION_MESSAGE)) == STALE_CONNECTION_MESSAGE

    def test_leaving_the_password_out_keeps_it(self, store: Store) -> None:
        connection_id = _prod_connection(store)

        _edit(store, connection_id, 1)

        assert store.shared_password(connection_id) == "first"

    def test_a_new_password_replaces_it(self, store: Store) -> None:
        connection_id = _prod_connection(store)

        _edit(store, connection_id, 1, shared_password="second")

        assert store.shared_password(connection_id) == "second"

    def test_clearing_the_password(self, store: Store) -> None:
        connection_id = _prod_connection(store)

        _edit(
            store,
            connection_id,
            1,
            login_mode="per_user",
            shared_user=None,
            clear_shared_password=True,
        )

        assert store.shared_password(connection_id) is None

    def test_a_taken_name_is_refused(self, store: Store) -> None:
        connection_id = _prod_connection(store)
        store.add_connection(name="Test", host="h", port=1, service="uvcs", account="T")

        with pytest.raises(StoreError, match="already exists"):
            _edit(store, connection_id, 1, name="Test")

    def test_editing_a_deleted_connection_is_refused(self, store: Store) -> None:
        connection_id = _prod_connection(store)
        assert store.delete_connection(connection_id) is True

        with pytest.raises(StoreError, match="no longer exists"):
            _edit(store, connection_id, 1)

    def test_switches_bump_the_version(self, store: Store) -> None:
        connection_id = _prod_connection(store)

        store.set_connection_flags(connection_id, read_only=False, actor="ann")

        saved = store.get_connection(connection_id)
        assert saved is not None and saved.version == 2

    def test_deleting_removes_its_grants(self, store: Store) -> None:
        connection_id = _prod_connection(store)
        viewer = store.get_role_by_name("Viewer")
        assert viewer is not None
        store.add_grant(
            connection_id=connection_id, subject_type="everyone", subject_id=None, role_id=viewer.id
        )

        store.delete_connection(connection_id)

        assert store.grants_on_connection(connection_id) == []


class TestLocalPasswords:
    def test_lookup_by_username(self, store: Store) -> None:
        created = store.add_local_user("ann", password_hash="h1", is_admin=True)

        found = store.get_user_by_username("ann")

        assert found is not None and found.id == created.id
        assert store.get_user_by_username("nobody") is None

    def test_password_hash_round_trip_and_forced_change(self, store: Store) -> None:
        user = store.add_local_user("ann", password_hash="h1")

        store.set_password_hash(user.id, "h2", must_change=True)

        assert store.password_hash(user.id) == "h2"
        refreshed = store.get_user(user.id)
        assert refreshed is not None and refreshed.must_change_password is True

    def test_has_local_admin(self, store: Store) -> None:
        assert store.has_local_admin() is False
        user = store.add_local_user("ann", password_hash="h", is_admin=True)
        assert store.has_local_admin() is True
        store.set_user_disabled(user.id, True)
        assert store.has_local_admin() is False

    def test_admin_flag(self, store: Store) -> None:
        user = store.add_local_user("ann", password_hash="h")

        store.set_user_admin(user.id, True)

        refreshed = store.get_user(user.id)
        assert refreshed is not None and refreshed.is_admin is True

    def test_duplicate_username_is_named(self, store: Store) -> None:
        store.add_local_user("ann", password_hash="h")

        with pytest.raises(StoreError, match="already exists"):
            store.add_local_user("ann", password_hash="h")


class TestSecretSettings:
    def test_round_trip_is_encrypted_at_rest(self, store: Store) -> None:
        store.set_secret_setting("setup_code", "ABCD-EFGH-JKLM")

        assert store.get_secret_setting("setup_code") == "ABCD-EFGH-JKLM"
        assert "ABCD" not in str(store.get_setting("setup_code"))

    def test_none_deletes(self, store: Store) -> None:
        store.set_secret_setting("setup_code", "x")

        store.set_secret_setting("setup_code", None)

        assert store.get_secret_setting("setup_code") is None

    def test_delete_setting(self, store: Store) -> None:
        store.set_setting("k", 1)

        store.delete_setting("k")

        assert store.get_setting("k") is None


class TestAdminSessions:
    def test_add_get_touch_delete(self, store: Store) -> None:
        user = store.add_local_user("ann", password_hash="h", is_admin=True)

        created = store.add_admin_session(
            id_hash="abc", user_id=user.id, csrf_token="c", ip="10.0.0.1"
        )
        store.touch_admin_session("abc", at=created.created_at + 60)

        loaded = store.get_admin_session("abc")
        assert loaded is not None
        assert loaded.last_seen_at == created.created_at + 60
        store.delete_admin_session("abc")
        assert store.get_admin_session("abc") is None

    def test_disabling_a_user_ends_their_sessions(self, store: Store) -> None:
        user = store.add_local_user("ann", password_hash="h", is_admin=True)
        store.add_admin_session(id_hash="abc", user_id=user.id, csrf_token="c", ip=None)

        store.set_user_disabled(user.id, True)

        assert store.get_admin_session("abc") is None

    def test_delete_for_user(self, store: Store) -> None:
        user = store.add_local_user("ann", password_hash="h", is_admin=True)
        store.add_admin_session(id_hash="a", user_id=user.id, csrf_token="c", ip=None)
        store.add_admin_session(id_hash="b", user_id=user.id, csrf_token="c", ip=None)

        assert store.delete_admin_sessions_for(user.id) == 2

    def test_purge_old_and_idle(self, store: Store) -> None:
        user = store.add_local_user("ann", password_hash="h", is_admin=True)
        session = store.add_admin_session(id_hash="a", user_id=user.id, csrf_token="c", ip=None)

        removed = store.purge_admin_sessions(
            created_before=session.created_at - 1, idle_before=session.last_seen_at + 1
        )

        assert removed == 1


def _connection(store: Store, *, mode: str = "per_user") -> int:
    return store.add_connection(
        name=f"c-{mode}",
        host="h",
        port=1,
        service="uvcs",
        account="A",
        shared_user="s" if mode == "shared" else None,
        shared_password="p" if mode == "shared" else None,
        login_mode=mode,
    ).id


class TestResetPassword:
    def test_sets_the_hash_forces_a_change_and_ends_sessions(self, store: Store) -> None:
        bob = store.add_local_user("bob", password_hash="old")
        store.add_admin_session(id_hash="s1", user_id=bob.id, csrf_token="c", ip=None)

        ended = store.reset_password(bob.id, "new-hash")

        assert ended == 1 and store.get_admin_session("s1") is None
        assert store.password_hash(bob.id) == "new-hash"
        after = store.get_user(bob.id)
        assert after is not None and after.must_change_password

    def test_only_local_users_have_a_password(self, store: Store) -> None:
        sso = store.get_or_create_sso_user("sub-1")
        with pytest.raises(StoreError):
            store.reset_password(sso.id, "h")
        with pytest.raises(StoreError):
            store.reset_password(999, "h")


class TestUpdateDetails:
    def test_changes_name_email_and_username(self, store: Store) -> None:
        bob = store.add_local_user("bob")

        store.update_user_details(bob.id, display_name="Bob B", email="b@x.io", username="rob")

        after = store.get_user(bob.id)
        assert after is not None
        assert (after.username, after.display_name, after.email) == ("rob", "Bob B", "b@x.io")

    def test_a_taken_username_is_refused(self, store: Store) -> None:
        store.add_local_user("ann")
        bob = store.add_local_user("bob")
        with pytest.raises(StoreError, match="already exists"):
            store.update_user_details(bob.id, display_name=None, email=None, username="ann")

    def test_an_sso_user_keeps_no_username(self, store: Store) -> None:
        sso = store.get_or_create_sso_user("sub-1")
        with pytest.raises(StoreError):
            store.update_user_details(sso.id, display_name=None, email=None, username="x")
        store.update_user_details(sso.id, display_name="Sue", email=None)
        after = store.get_user(sso.id)
        assert after is not None and after.display_name == "Sue" and after.username is None


class TestDeleteUser:
    def test_everything_of_theirs_goes_and_the_rest_stays(self, store: Store) -> None:
        store.add_local_user("root", is_admin=True)
        bob = store.add_local_user("bob")
        cy = store.add_local_user("cy")
        per_user = _connection(store)
        shared = _connection(store, mode="shared")
        viewer = store.get_role_by_name("Viewer")
        assert viewer is not None
        store.add_grant(
            connection_id=per_user, subject_type="user", subject_id=bob.id, role_id=viewer.id
        )
        keep = store.add_grant(
            connection_id=shared, subject_type="user", subject_id=cy.id, role_id=viewer.id
        )
        store.add_grant(connection_id=per_user, subject_type="everyone", role_id=viewer.id)
        store.set_u2_login(bob.id, per_user, "bob_u2", "pw")
        store.set_u2_login(cy.id, per_user, "cy_u2", "pw")
        store.add_token(user_id=bob.id, name="t", token_hash="h" * 64, expires_at=9e9)
        store.add_admin_session(id_hash="s1", user_id=bob.id, csrf_token="c", ip=None)
        store.add_audit(
            kind="admin", action="x", outcome="ok", actor_user_id=bob.id, actor_label="bob"
        )

        store.delete_user(bob.id)

        assert store.get_user(bob.id) is None
        assert store.grants_for_subject("user", bob.id) == []
        assert store.list_u2_logins_for_user(bob.id) == []
        assert store.list_tokens(bob.id) == [] and store.get_admin_session("s1") is None
        assert store.get_grant(keep.id) is not None
        assert len(store.list_u2_logins_for_user(cy.id)) == 1
        assert len(store.everyone_grants()) == 1
        assert store.recent_audit(5)[0]["actor_label"] == "bob"

    def test_the_last_enabled_local_admin_stays(self, store: Store) -> None:
        ann = store.add_local_user("ann", is_admin=True)
        with pytest.raises(LastAdmin):
            store.delete_user(ann.id)
        assert store.get_user(ann.id) is not None

    def test_a_disabled_or_sso_admin_does_not_count(self, store: Store) -> None:
        ann = store.add_local_user("ann", is_admin=True)
        sso = store.get_or_create_sso_user("sub-1")
        store.set_user_admin(sso.id, True)
        with pytest.raises(LastAdmin):
            store.delete_user(ann.id)
        store.delete_user(sso.id)  # not a local admin: free to go

    def test_a_missing_user_is_an_error(self, store: Store) -> None:
        with pytest.raises(StoreError):
            store.delete_user(999)

    def test_two_admins_deleting_each_other_cannot_both_succeed(self, store: Store) -> None:
        first = store.add_local_user("a", is_admin=True)
        second = store.add_local_user("b", is_admin=True)
        barrier = threading.Barrier(2)
        outcomes: list[str] = []

        def delete(user_id: int) -> None:
            barrier.wait()
            try:
                store.delete_user(user_id)
                outcomes.append("deleted")
            except LastAdmin:
                outcomes.append("kept")

        threads = [threading.Thread(target=delete, args=(u.id,)) for u in (first, second)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert sorted(outcomes) == ["deleted", "kept"]
        assert store.has_local_admin()
