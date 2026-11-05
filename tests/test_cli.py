"""`u2-mcp admin ...` commands, run against a real settings database."""

from pathlib import Path

import pytest

from u2_mcp.cli import run_admin_cli
from u2_mcp.passwords import hash_password, verify_password
from u2_mcp.setup_code import ensure_setup_code, finish_setup
from u2_mcp.store.crypto import SecretBox
from u2_mcp.store.db import DATABASE_FILENAME, open_database
from u2_mcp.store.repo import Store

KEY = "c" * 40


@pytest.fixture
def team_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for name in ("U2_HOST", "U2_USER", "U2_PASSWORD", "U2_ACCOUNT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("U2_SECRET_KEY", KEY)
    monkeypatch.setenv("U2_DATA_DIR", str(tmp_path))
    return tmp_path


def _open(path: Path) -> Store:
    store = Store(open_database(path / DATABASE_FILENAME), SecretBox(KEY), path)
    store.seed_builtin_roles()
    return store


def test_show_setup_code_prints_the_current_code(
    team_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = ensure_setup_code(_open(team_dir))

    assert run_admin_cli(["show-setup-code"]) == 0
    assert capsys.readouterr().out.strip() == code


def test_show_setup_code_after_setup(team_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    finish_setup(_open(team_dir))

    assert run_admin_cli(["show-setup-code"]) == 1
    assert "Setup is finished" in capsys.readouterr().out


def test_without_a_database(team_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run_admin_cli(["show-setup-code"]) == 2
    assert "No settings database" in capsys.readouterr().err


def test_reset_password(team_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    store = _open(team_dir)
    user = store.add_local_user("ann", password_hash=hash_password("old password here"))
    store.set_user_disabled(user.id, True)
    store.add_admin_session(id_hash="s", user_id=user.id, csrf_token="c", ip=None)

    assert run_admin_cli(["reset-password", "ann"]) == 0

    printed = capsys.readouterr().out
    one_time = printed.split("One-time password for ann: ")[1].split()[0]
    reopened = _open(team_dir)
    assert verify_password(reopened.password_hash(user.id), one_time) is True
    refreshed = reopened.get_user(user.id)
    assert refreshed is not None and refreshed.must_change_password is True
    # An ordinary user is re-enabled but is not promoted.
    assert refreshed.is_admin is False and refreshed.disabled is False
    assert "ann is enabled" in printed and "not an admin" in printed
    assert reopened.get_admin_session("s") is None
    audit = reopened.recent_audit(1)[0]
    assert audit["action"] == "user.reset_password"
    assert audit["params"] == {"username": "ann", "re_enabled": True, "made_admin": False}


def test_reset_password_with_admin_restores_admin(
    team_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = _open(team_dir)
    user = store.add_local_user("ann", password_hash=hash_password("old password here"))
    store.set_user_disabled(user.id, True)

    assert run_admin_cli(["reset-password", "ann", "--admin"]) == 0

    printed = capsys.readouterr().out
    refreshed = _open(team_dir).get_user(user.id)
    assert refreshed is not None and refreshed.is_admin is True and refreshed.disabled is False
    assert "ann is enabled and is an admin" in printed
    params = _open(team_dir).recent_audit(1)[0]["params"]
    assert params == {"username": "ann", "re_enabled": True, "made_admin": True}


def test_reset_password_for_an_unknown_user(
    team_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _open(team_dir)

    assert run_admin_cli(["reset-password", "nobody"]) == 1
    assert "No local user named 'nobody'" in capsys.readouterr().out


class TestSetPublicUrl:
    """The way back in after saving an https address the browser cannot use yet."""

    def test_sets_the_address_and_audits(
        self, team_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _open(team_dir)

        assert run_admin_cli(["set-public-url", " http://10.0.0.5:8080/ "]) == 0

        reopened = _open(team_dir)
        assert reopened.get_setting("public_url") == "http://10.0.0.5:8080"
        entry = reopened.recent_audit(1)[0]
        assert entry["kind"] == "admin"
        assert entry["action"] == "settings.public_url"
        assert entry["actor_label"] == "command line"
        assert entry["params"] == {"public_url": "http://10.0.0.5:8080"}
        assert "http://10.0.0.5:8080" in capsys.readouterr().out

    def test_clear_removes_the_saved_address(
        self, team_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _open(team_dir).set_setting("public_url", "https://u2.example.com")

        assert run_admin_cli(["set-public-url", "--clear"]) == 0

        reopened = _open(team_dir)
        assert reopened.get_setting("public_url") is None
        entry = reopened.recent_audit(1)[0]
        assert entry["action"] == "settings.public_url"
        assert entry["actor_label"] == "command line"
        assert entry["params"] == {"public_url": None}

    def test_a_bad_address_is_refused(
        self, team_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _open(team_dir)

        assert run_admin_cli(["set-public-url", "u2.example.com"]) == 1

        assert "Enter the full address people use" in capsys.readouterr().out
        assert _open(team_dir).get_setting("public_url") is None

    @pytest.mark.parametrize(
        "argv", [["set-public-url"], ["set-public-url", "http://a", "--clear"]]
    )
    def test_needs_exactly_one_of_an_address_or_clear(
        self, team_dir: Path, argv: list[str], capsys: pytest.CaptureFixture[str]
    ) -> None:
        _open(team_dir)

        assert run_admin_cli(argv) == 1
        assert "--clear" in capsys.readouterr().out

    def test_without_a_database(self, team_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
        assert run_admin_cli(["set-public-url", "--clear"]) == 2
        assert "No settings database" in capsys.readouterr().err
