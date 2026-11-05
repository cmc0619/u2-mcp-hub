"""Testing and saving your own U2 login is rate limited: it must not guess passwords for free."""

import pytest

from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.security import RateLimiter
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import finish_setup
from u2_mcp.store.models import User

from .conftest import FakeCheck
from .helpers import PASSWORD, admin_client, csrf_from, sign_in

LIMITED = "Too many attempts. Wait a minute and try again."


@pytest.fixture
def bob(ctx: AdminContext) -> User:
    return ctx.store.add_local_user("bob", password_hash=hash_password(PASSWORD))


@pytest.fixture
def dev(ctx: AdminContext) -> int:
    connection = ctx.store.add_connection(
        name="Dev",
        host="dev.example",
        port=31438,
        service="uvcs",
        account="DEVACC",
        login_mode="per_user",
    )
    role = ctx.store.get_role_by_name("Viewer")
    assert role is not None
    ctx.store.add_grant(connection_id=connection.id, subject_type="everyone", role_id=role.id)
    return connection.id


def _start(ctx: AdminContext, *, limit: int = 5):  # type: ignore[no-untyped-def]
    ctx.limiter = RateLimiter(limit=limit)
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    finish_setup(ctx.store)
    return admin_client(ctx)


def _audit(ctx: AdminContext, action: str) -> list[dict]:
    return [row for row in ctx.store.recent_audit(200) if row["action"] == action]


def _test(client, dev: int, token: str, user: str = "u"):  # type: ignore[no-untyped-def]
    return client.post(
        f"/admin/me/u2-logins/{dev}/test",
        data={"csrf_token": token, "u2_user": user, "u2_password": "guess"},
        headers={"HX-Request": "true"},
    )


def _save(client, dev: int, token: str):  # type: ignore[no-untyped-def]
    return client.post(
        f"/admin/me/u2-logins/{dev}",
        data={"csrf_token": token, "u2_user": "u", "u2_password": "guess"},
        follow_redirects=False,
    )


def test_the_sixth_test_in_a_minute_is_refused_and_not_run(
    ctx: AdminContext, bob: User, dev: int, check: FakeCheck
) -> None:
    with _start(ctx) as client:
        sign_in(client, "bob")
        token = csrf_from(client.get("/admin/me").text)
        for _ in range(5):
            assert "Test passed" in _test(client, dev, token).text  # successes count too
        sixth = _test(client, dev, token)
    assert LIMITED in sixth.text and "<html" not in sixth.text
    assert len(check.calls) == 5
    [row] = _audit(ctx, "u2_login_test")[:1]
    assert row["outcome"] == "refused" and "guess" not in str(row)


def test_the_sixth_save_in_a_minute_is_refused_and_not_saved(
    ctx: AdminContext, bob: User, dev: int
) -> None:
    with _start(ctx) as client:
        sign_in(client, "bob")
        token = csrf_from(client.get("/admin/me").text)
        for _ in range(5):
            assert _save(client, dev, token).headers["location"].find("notice=") > 0
        ctx.store.delete_u2_login(bob.id, dev)
        sixth = _save(client, dev, token)
        page = client.get(sixth.headers["location"]).text
    assert "problem=u2_login_rate_limited" in sixth.headers["location"]
    assert LIMITED in page
    assert ctx.store.get_u2_login(bob.id, dev) is None
    assert _audit(ctx, "u2_login_set")[0]["outcome"] == "refused"


def test_tests_and_saves_share_the_budget(
    ctx: AdminContext, bob: User, dev: int, check: FakeCheck
) -> None:
    with _start(ctx, limit=2) as client:
        sign_in(client, "bob")
        token = csrf_from(client.get("/admin/me").text)
        _save(client, dev, token)
        _test(client, dev, token)
        assert LIMITED in _test(client, dev, token).text
    assert len(check.calls) == 1


def test_limit_zero_never_refuses(ctx: AdminContext, bob: User, dev: int, check: FakeCheck) -> None:
    with _start(ctx, limit=0) as client:
        sign_in(client, "bob")
        token = csrf_from(client.get("/admin/me").text)
        for _ in range(12):
            assert LIMITED not in _test(client, dev, token).text
    assert len(check.calls) == 12


def test_another_person_on_another_address_is_not_affected(
    ctx: AdminContext, bob: User, dev: int, check: FakeCheck
) -> None:
    ctx.store.add_local_user("carol", password_hash=hash_password(PASSWORD))
    with _start(ctx, limit=2) as client:
        sign_in(client, "bob")
        token = csrf_from(client.get("/admin/me").text)
        _test(client, dev, token)
        _test(client, dev, token)
        assert LIMITED in _test(client, dev, token).text
        with admin_client(ctx, client=("10.0.0.2", 5000)) as other:
            sign_in(other, "carol")
            carol_token = csrf_from(other.get("/admin/me").text)
            assert "Test passed" in _test(other, dev, carol_token).text


def test_people_behind_one_address_have_their_own_budgets(
    ctx: AdminContext, bob: User, dev: int, check: FakeCheck
) -> None:
    """An office behind one NAT address: only signed-in people get here, each counted alone."""
    ctx.store.add_local_user("carol", password_hash=hash_password(PASSWORD))
    with _start(ctx, limit=2) as client:
        sign_in(client, "bob")
        token = csrf_from(client.get("/admin/me").text)
        _test(client, dev, token)
        _test(client, dev, token)
        with admin_client(ctx) as same_ip:
            sign_in(same_ip, "carol")
            carol_token = csrf_from(same_ip.get("/admin/me").text)
            assert "Test passed" in _test(same_ip, dev, carol_token).text
