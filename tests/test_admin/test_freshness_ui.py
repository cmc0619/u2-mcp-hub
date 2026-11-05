"""Paused tokens and missing personal U2 logins are shown, not discovered by failure."""

from u2_mcp.access import effective_access, visible_connections
from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.security import SESSION_COOKIE, start_session
from u2_mcp.admin.services import token_views
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import finish_setup
from u2_mcp.store.repo import Store
from u2_mcp.tokens import create_token, fresh_until, is_fresh

from .helpers import PASSWORD, admin_client, sign_in

DAY = 86400.0


def _sso_user(store: Store, *, days_ago: float) -> int:
    user = store.get_or_create_sso_user("sam", display_name="Sam")
    store.record_sso_login(user.id, [])
    with store._tx() as conn:  # test-only: move the sign-in into the past
        conn.execute(
            "UPDATE users SET last_sso_login_at = ? WHERE id = ?",
            (store.clock() - days_ago * DAY, user.id),
        )
    return user.id


def test_is_fresh_counts_days_since_the_last_company_sign_in(store: Store) -> None:
    user_id = _sso_user(store, days_ago=29)
    user = store.get_user(user_id)
    assert user is not None
    now = store.clock()
    assert is_fresh(user, now=now, freshness_days=30)
    assert not is_fresh(user, now=now + 2 * DAY, freshness_days=30)
    until = fresh_until(user, freshness_days=30)
    assert until is not None and abs(until - (now + DAY)) < 5
    local = store.add_local_user("ann")
    assert is_fresh(local, now=now + 1000 * DAY, freshness_days=30)
    assert fresh_until(local, freshness_days=30) is None


def test_stale_owners_tokens_show_as_paused_and_stay_revocable(ctx: AdminContext) -> None:
    user_id = _sso_user(ctx.store, days_ago=31)
    create_token(ctx.store, user_id, "laptop")
    [view] = token_views(ctx, user_id)
    assert view.status == "Paused" and view.revocable


def test_the_users_page_explains_paused_tokens(ctx: AdminContext) -> None:
    user_id = _sso_user(ctx.store, days_ago=31)
    create_token(ctx.store, user_id, "laptop")
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    finish_setup(ctx.store)
    with admin_client(ctx) as client:
        sign_in(client)
        page = client.get(f"/admin/users/{user_id}").text
    assert "Paused" in page and "reactivate when the person signs in" in page
    assert "Revoke laptop" in page


def test_my_access_says_when_tokens_would_pause(ctx: AdminContext) -> None:
    user_id = _sso_user(ctx.store, days_ago=1)
    create_token(ctx.store, user_id, "laptop")
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    finish_setup(ctx.store)  # without an admin and finished setup every page is the wizard
    with admin_client(ctx) as client:
        # A session made directly: the company sign-in round trip has its own tests.
        user = ctx.store.get_user(user_id)
        assert user is not None
        raw_id, _ = start_session(ctx.store, user, "10.0.0.1")
        client.cookies.set(SESSION_COOKIE, raw_id, path="/admin")
        page = client.get("/admin/me").text
    assert "at least once every 30 days" in page


def test_group_access_on_a_per_person_connection_says_a_login_is_needed(store: Store) -> None:
    connection = store.add_connection(
        name="Prod",
        host="u2.example",
        port=31438,
        service="uvcs",
        account="PROD",
        login_mode="per_user",
    )
    viewer = store.get_role_by_name("Viewer")
    assert viewer is not None
    store.add_grant(connection_id=connection.id, subject_type="everyone", role_id=viewer.id)
    sam = store.get_or_create_sso_user("sam")
    [visible] = visible_connections(store, sam.id, global_read_only=False)
    assert visible.needs_personal_login
    [report] = effective_access(store, sam.id, global_read_only=False)
    assert report.needs_personal_login
    # Their own login, set on My access, counts whatever grant gives them access.
    store.set_u2_login(sam.id, connection.id, "sam", "pw")
    [visible] = visible_connections(store, sam.id, global_read_only=False)
    assert not visible.needs_personal_login


def test_exactly_the_freshness_days_is_still_fresh(store: Store) -> None:
    user_id = _sso_user(store, days_ago=0)
    user = store.get_user(user_id)
    assert user is not None and user.last_sso_login_at is not None
    last = user.last_sso_login_at
    assert is_fresh(user, now=last + 30 * DAY, freshness_days=30)
    assert not is_fresh(user, now=last + 30 * DAY + 1, freshness_days=30)


def test_an_sso_user_who_never_signed_in_is_not_fresh(store: Store) -> None:
    user = store.get_or_create_sso_user("never")
    assert user.last_sso_login_at is None
    assert not is_fresh(user, now=store.clock(), freshness_days=30)
    assert fresh_until(user, freshness_days=30) is None


def _users_page(ctx: AdminContext, user_id: int) -> str:
    create_token(ctx.store, user_id, "laptop")
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    finish_setup(ctx.store)
    with admin_client(ctx) as client:
        sign_in(client)
        return client.get(f"/admin/users/{user_id}").text


def test_paused_tokens_of_a_stale_sso_user_say_how_long(ctx: AdminContext) -> None:
    page = _users_page(ctx, _sso_user(ctx.store, days_ago=31))
    assert "no company sign-in for over 30 days" in page
    assert "Has not signed in with company sign-in yet" not in page


def test_paused_tokens_of_an_sso_user_who_never_signed_in_say_so(ctx: AdminContext) -> None:
    page = _users_page(ctx, ctx.store.get_or_create_sso_user("never", display_name="Nev").id)
    assert "Has not signed in with company sign-in yet" in page
    assert "no company sign-in for over" not in page
