"""Personal U2 logins: one per person per connection, encrypted."""

import pytest

from u2_mcp.store.repo import Store, StoreError

KEY = "t" * 40


def _per_user(store: Store, name: str = "Dev") -> int:
    return store.add_connection(
        name=name, host="h", port=1, service="uvcs", account="A", login_mode="per_user"
    ).id


class TestStore:
    def test_set_get_and_delete(self, store: Store) -> None:
        dev = _per_user(store)
        ann = store.add_local_user("ann", password_hash="x")

        saved = store.set_u2_login(ann.id, dev, "ann_u2", "pw1")

        assert saved.u2_user == "ann_u2" and saved.updated_at > 0
        assert store.get_u2_login(ann.id, dev) == saved
        assert store.get_u2_login_password(ann.id, dev) == "pw1"
        assert store.list_u2_logins_for_user(ann.id) == [saved]
        assert store.list_u2_logins_for_connection(dev) == [saved]
        assert store.delete_u2_login(ann.id, dev)
        assert store.get_u2_login(ann.id, dev) is None
        assert store.get_u2_login_password(ann.id, dev) is None
        assert not store.delete_u2_login(ann.id, dev)

    def test_a_blank_password_keeps_the_stored_one(self, store: Store) -> None:
        dev = _per_user(store)
        ann = store.add_local_user("ann", password_hash="x")
        store.set_u2_login(ann.id, dev, "ann_u2", "pw1")

        store.set_u2_login(ann.id, dev, "ann_u2", None)

        assert store.get_u2_login_password(ann.id, dev) == "pw1"

    def test_keeping_a_password_that_was_never_stored_is_refused(self, store: Store) -> None:
        dev = _per_user(store)
        ann = store.add_local_user("ann", password_hash="x")

        with pytest.raises(StoreError):
            store.set_u2_login(ann.id, dev, "ann_u2", None)
        assert store.get_u2_login(ann.id, dev) is None

    def test_the_password_is_encrypted_and_never_in_a_repr(self, store: Store) -> None:
        dev = _per_user(store)
        ann = store.add_local_user("ann", password_hash="x")

        login = store.set_u2_login(ann.id, dev, "ann_u2", "hunter2-secret")

        assert "hunter2-secret" not in repr(login)
        raw = store._conn.execute("SELECT u2_password_enc FROM user_u2_logins").fetchone()[0]
        assert "hunter2-secret" not in raw

    def test_deleting_the_connection_or_the_person_removes_the_login(self, store: Store) -> None:
        dev = _per_user(store)
        ann = store.add_local_user("ann", password_hash="x")
        store.set_u2_login(ann.id, dev, "ann_u2", "pw")

        store.delete_connection(dev)

        assert store.list_u2_logins_for_user(ann.id) == []

    def test_a_server_change_forgets_every_login_on_that_connection(self, store: Store) -> None:
        dev = _per_user(store)
        other = _per_user(store, "Other")
        ann = store.add_local_user("ann", password_hash="x")
        store.set_u2_login(ann.id, dev, "ann_u2", "pw")
        store.set_u2_login(ann.id, other, "ann_u2", "pw")
        connection = store.get_connection(dev)
        assert connection is not None

        store.update_connection(
            dev,
            expected_version=connection.version,
            name="Dev",
            host="elsewhere",
            port=1,
            service="uvcs",
            account="A",
            ssl=False,
            login_mode="per_user",
            shared_user=None,
            read_only=True,
            enabled=True,
            actor="t",
            clear_u2_logins=True,
        )

        assert store.get_u2_login(ann.id, dev) is None
        assert store.get_u2_login(ann.id, other) is not None
