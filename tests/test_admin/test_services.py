"""Admin services: validation, saving, eviction and audit in one place."""

import pytest

from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.services import (
    SERVER_CHANGED,
    ConnectionForm,
    ValidationFailed,
    change_password,
    check_connection_form,
    create_local_user,
    delete_connection,
    disconnect_connection,
    effective_public_url,
    public_url_warning,
    save_connection,
    save_public_url,
)
from u2_mcp.passwords import hash_password, verify_password
from u2_mcp.store.models import User
from u2_mcp.store.repo import StaleEdit

from .conftest import FakeCheck, FakeRegistry


def _form(**changes: object) -> ConnectionForm:
    values: dict[str, str] = {
        "name": "Prod",
        "host": "u2.example",
        "port": "31438",
        "service": "uvcs",
        "account": "PROD",
        "login_mode": "shared",
        "login_user": "svc",
        "login_password": "secret",
        "read_only": "on",
        "enabled": "on",
    }
    values.update({key: str(value) for key, value in changes.items()})
    return ConnectionForm.from_form(values)


class TestConnectionForm:
    def test_unchecked_boxes_are_false(self) -> None:
        form = ConnectionForm.from_form({"name": "x"})

        assert form.read_only is False and form.enabled is False and form.ssl is False

    @pytest.mark.parametrize(
        ("field", "value", "message"),
        [
            ("name", "", "Give the connection a name."),
            ("name", "bad/name", "Use letters, digits, spaces, dots, dashes or underscores"),
            ("host", "", "Enter the U2 server's host name or address."),
            ("port", "0", "Enter a port between 1 and 65535."),
            ("port", "abc", "Enter a port between 1 and 65535."),
            ("service", "xyz", "Choose UniVerse (uvcs) or UniData (udcs)."),
            ("account", "", "Enter the U2 account name."),
            ("login_mode", "magic", "Choose shared or per-user logins."),
            ("login_user", "", "Enter the U2 login the server uses."),
        ],
    )
    def test_each_field_is_checked(self, field: str, value: str, message: str) -> None:
        errors = _form(**{field: value}).errors(password_required=False)

        assert message in errors[field]

    def test_a_password_can_be_required(self) -> None:
        errors = _form(login_password="").errors(password_required=True)

        assert errors == {"login_password": "Enter the password for that login."}

    def test_per_user_connections_need_no_login(self) -> None:
        assert _form(login_mode="per_user", login_user="").errors(password_required=False) == {}


class TestSavingConnections:
    def test_create_audits_without_the_password(self, ctx: AdminContext, admin: User) -> None:
        saved = save_connection(ctx, _form(), actor=admin)

        assert ctx.store.shared_password(saved.id) == "secret"
        entry = ctx.store.recent_audit(1)[0]
        assert entry["action"] == "connection.create" and entry["kind"] == "admin"
        assert entry["actor_label"] == admin.label
        assert "secret" not in str(entry["params"])

    def test_create_requires_a_password(self, ctx: AdminContext, admin: User) -> None:
        with pytest.raises(ValidationFailed) as failed:
            save_connection(ctx, _form(login_password=""), actor=admin)

        assert "login_password" in failed.value.errors

    def test_edit_keeps_the_password_and_evicts_sessions(
        self, ctx: AdminContext, admin: User, registry: FakeRegistry
    ) -> None:
        saved = save_connection(ctx, _form(), actor=admin)

        edited = save_connection(
            ctx,
            _form(name="Production", login_password="", version=saved.version),
            actor=admin,
            connection_id=saved.id,
        )

        assert edited.name == "Production"
        assert ctx.store.shared_password(saved.id) == "secret"
        assert registry.evicted == [saved.id]
        assert ctx.store.recent_audit(1)[0]["action"] == "connection.update"

    def test_a_stale_edit_is_refused(self, ctx: AdminContext, admin: User) -> None:
        saved = save_connection(ctx, _form(), actor=admin)
        save_connection(
            ctx, _form(host="a.example", version=saved.version), actor=admin, connection_id=saved.id
        )

        with pytest.raises(StaleEdit):
            save_connection(
                ctx,
                _form(host="b.example", version=saved.version),
                actor=admin,
                connection_id=saved.id,
            )

    def test_switching_to_per_user_drops_the_shared_login(
        self, ctx: AdminContext, admin: User
    ) -> None:
        saved = save_connection(ctx, _form(), actor=admin)

        edited = save_connection(
            ctx,
            _form(login_mode="per_user", version=saved.version),
            actor=admin,
            connection_id=saved.id,
        )

        assert edited.shared_user is None
        assert ctx.store.shared_password(saved.id) is None


class TestReviewFixes:
    def test_shared_check_without_any_password_is_refused(self, ctx: AdminContext) -> None:
        with pytest.raises(ValidationFailed) as failed:
            check_connection_form(ctx, _form(login_password=""))

        assert "login_password" in failed.value.errors

    def test_per_user_check_is_not_shared_and_ignores_stored_password(
        self, ctx: AdminContext, admin: User, check: FakeCheck
    ) -> None:
        saved = save_connection(ctx, _form(), actor=admin)

        check_connection_form(
            ctx, _form(login_mode="per_user", login_password="typed"), connection_id=saved.id
        )

        assert check.calls[0][1].is_shared is False

    def test_superscript_digits_are_not_a_port(self) -> None:
        assert "port" in _form(port="\u00b2").errors(password_required=False)

    def test_eviction_happens_after_the_save_is_committed(
        self, ctx: AdminContext, admin: User, registry: FakeRegistry
    ) -> None:
        saved = save_connection(ctx, _form(), actor=admin)

        save_connection(
            ctx,
            _form(host="new.example", version=saved.version),
            actor=admin,
            connection_id=saved.id,
        )

        assert registry.hosts_at_evict == ["new.example"]

    def test_a_taken_name_is_a_name_error(self, ctx: AdminContext, admin: User) -> None:
        save_connection(ctx, _form(), actor=admin)

        with pytest.raises(ValidationFailed) as failed:
            save_connection(ctx, _form(host="other.example"), actor=admin)

        assert "name" in failed.value.errors

    def test_disconnect_audits_and_counts(
        self, ctx: AdminContext, admin: User, registry: FakeRegistry
    ) -> None:
        saved = save_connection(ctx, _form(), actor=admin)
        registry.live[saved.id] = ["a@A", "b@A"]

        assert disconnect_connection(ctx, saved.id, actor=admin) == 2

        entry = ctx.store.recent_audit(1)[0]
        assert entry["action"] == "connection.disconnect" and entry["params"] == {"closed": 2}


class TestDelete:
    def test_delete_removes_and_audits(
        self, ctx: AdminContext, admin: User, registry: FakeRegistry
    ) -> None:
        saved = save_connection(ctx, _form(), actor=admin)

        delete_connection(ctx, saved.id, actor=admin)

        assert ctx.store.get_connection(saved.id) is None
        assert registry.evicted == [saved.id]
        entry = ctx.store.recent_audit(1)[0]
        assert entry["action"] == "connection.delete"
        assert entry["params"] == {"name": "Prod"}


class TestCheckingAForm:
    def test_the_typed_password_is_used(self, ctx: AdminContext, check: FakeCheck) -> None:
        check_connection_form(ctx, _form(login_password="typed"))

        tested, login = check.calls[0]
        assert tested.host == "u2.example" and login.password == "typed"

    def test_a_blank_password_falls_back_to_the_stored_one(
        self, ctx: AdminContext, admin: User, check: FakeCheck
    ) -> None:
        saved = save_connection(ctx, _form(), actor=admin)

        check_connection_form(ctx, _form(login_password=""), connection_id=saved.id)

        assert check.calls[0][1].password == "secret"

    def test_invalid_settings_are_not_tested(self, ctx: AdminContext, check: FakeCheck) -> None:
        with pytest.raises(ValidationFailed):
            check_connection_form(ctx, _form(host=""))

        assert check.calls == []

    def test_per_user_needs_a_test_login(self, ctx: AdminContext) -> None:
        with pytest.raises(ValidationFailed) as failed:
            check_connection_form(ctx, _form(login_mode="per_user", login_user=""))

        assert failed.value.errors == {"login_user": "Enter a U2 login to test with."}


class TestLocalUsers:
    def test_create_hashes_and_audits(self, ctx: AdminContext) -> None:
        user = create_local_user(
            ctx,
            username="ann",
            password="long enough pass",
            password_again="long enough pass",
            is_admin=True,
            actor=None,
        )

        assert verify_password(ctx.store.password_hash(user.id), "long enough pass")
        entry = ctx.store.recent_audit(1)[0]
        assert entry["action"] == "user.create" and entry["actor_label"] == "setup wizard"

    @pytest.mark.parametrize(
        ("username", "password", "again", "field", "message"),
        [
            ("bad name!", "long enough pass", "long enough pass", "username", "Use 1 to 64"),
            ("ann", "short", "short", "password", "Use at least 12 characters."),
            (
                "ann",
                "long enough pass",
                "different pass!",
                "password_again",
                "The two passwords don't match.",
            ),
        ],
    )
    def test_problems_are_reported_per_field(
        self, ctx: AdminContext, username: str, password: str, again: str, field: str, message: str
    ) -> None:
        with pytest.raises(ValidationFailed) as failed:
            create_local_user(
                ctx,
                username=username,
                password=password,
                password_again=again,
                is_admin=True,
                actor=None,
            )

        assert message in failed.value.errors[field]

    def test_a_taken_username(self, ctx: AdminContext) -> None:
        create_local_user(
            ctx,
            username="ann",
            password="long enough pass",
            password_again="long enough pass",
            is_admin=True,
            actor=None,
        )

        with pytest.raises(ValidationFailed) as failed:
            create_local_user(
                ctx,
                username="ann",
                password="long enough pass",
                password_again="long enough pass",
                is_admin=True,
                actor=None,
            )

        assert "already exists" in failed.value.errors["username"]

    def test_change_password(self, ctx: AdminContext) -> None:
        user = ctx.store.add_local_user("ann", password_hash=hash_password("old password 1"))
        ctx.store.set_password_hash(user.id, hash_password("old password 1"), must_change=True)

        change_password(
            ctx, user, current="old password 1", new="new password 22", new_again="new password 22"
        )

        assert verify_password(ctx.store.password_hash(user.id), "new password 22")
        refreshed = ctx.store.get_user(user.id)
        assert refreshed is not None and refreshed.must_change_password is False
        assert ctx.store.recent_audit(1)[0]["action"] == "admin.password_change"

    def test_change_password_checks_the_current_one(self, ctx: AdminContext) -> None:
        user = ctx.store.add_local_user("ann", password_hash=hash_password("old password 1"))

        with pytest.raises(ValidationFailed) as failed:
            change_password(
                ctx, user, current="wrong", new="new password 22", new_again="new password 22"
            )

        assert failed.value.errors == {"current_password": "That is not your current password."}


class TestPublicUrl:
    def test_save_trims_and_audits(self, ctx: AdminContext, admin: User) -> None:
        saved = save_public_url(ctx, " https://u2.example.com/ ", actor=admin)

        assert saved == "https://u2.example.com"
        assert effective_public_url(ctx) == "https://u2.example.com"
        assert ctx.store.recent_audit(1)[0]["action"] == "settings.public_url"

    def test_bad_addresses_are_refused(self, ctx: AdminContext, admin: User) -> None:
        with pytest.raises(ValidationFailed):
            save_public_url(ctx, "u2.example.com", actor=admin)

    def test_http_gets_a_warning(self) -> None:
        assert public_url_warning("http://u2.example.com") == (
            "This address is not https. Sign-in cookies and tokens would cross the "
            "network unencrypted."
        )
        assert public_url_warning("https://u2.example.com") is None

    def test_default_comes_from_the_environment(self, ctx: AdminContext) -> None:
        expected = ctx.config.public_url or f"http://{ctx.config.http_host}:{ctx.config.http_port}"

        assert effective_public_url(ctx) == expected


class TestPasswordFollowsTheServer:
    """A blank password box reuses a password only for the server it belongs to."""

    @pytest.mark.parametrize(
        "change",
        [
            {"host": "attacker.example"},
            {"port": "31439"},
            {"service": "udcs"},
            {"ssl": "on"},
            {"account": "OTHER"},
        ],
    )
    def test_saving_a_changed_server_needs_the_password_again(
        self, ctx: AdminContext, admin: User, change: dict[str, str]
    ) -> None:
        saved = save_connection(ctx, _form(), actor=admin)

        with pytest.raises(ValidationFailed) as failed:
            save_connection(
                ctx,
                _form(login_password="", version=saved.version, **change),
                actor=admin,
                connection_id=saved.id,
            )

        assert failed.value.errors["login_password"] == SERVER_CHANGED
        unchanged = ctx.store.get_connection(saved.id)
        assert unchanged is not None and unchanged.host == "u2.example"

    def test_testing_a_changed_server_needs_the_password_again(
        self, ctx: AdminContext, admin: User, check: FakeCheck
    ) -> None:
        saved = save_connection(ctx, _form(), actor=admin)

        with pytest.raises(ValidationFailed) as failed:
            check_connection_form(
                ctx, _form(host="attacker.example", login_password=""), connection_id=saved.id
            )

        assert failed.value.errors == {"login_password": SERVER_CHANGED}
        assert check.calls == []

    def test_a_typed_password_may_go_to_a_new_server(
        self, ctx: AdminContext, admin: User, check: FakeCheck
    ) -> None:
        saved = save_connection(ctx, _form(), actor=admin)

        check_connection_form(
            ctx, _form(host="u2-new.example", login_password="typed"), connection_id=saved.id
        )
        edited = save_connection(
            ctx,
            _form(host="u2-new.example", login_password="typed", version=saved.version),
            actor=admin,
            connection_id=saved.id,
        )

        assert check.calls[0][1].password == "typed"
        assert edited.host == "u2-new.example"
        assert ctx.store.shared_password(saved.id) == "typed"
