"""Company sign-in on the admin site, against the mock provider (no network)."""

import dataclasses
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from starlette.testclient import TestClient

from tests.mocks.oidc_provider import MockIdP, Person, build_app
from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.routes_sso import (
    SSO_DISABLED,
    SSO_EXPIRED,
    SSO_NOT_SET_UP,
    SSO_REFUSED,
    SSO_UNAVAILABLE,
)
from u2_mcp.admin.security import RateLimiter
from u2_mcp.admin.services import effective_public_url
from u2_mcp.auth.oidc_client import OidcClient
from u2_mcp.config import U2Config
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import finish_setup
from u2_mcp.sso_config import ADMIN_CALLBACK_PATH, SsoSettings, clear_sso, store_sso
from u2_mcp.store.crypto import SecretUnreadable
from u2_mcp.store.repo import Store

from .helpers import PASSWORD, admin_client, csrf_from, sign_in

ISSUER = "http://localhost"
GROUPS_TAB = 'href="/admin/groups"'


@pytest.fixture
def idp(ctx: AdminContext) -> MockIdP:
    provider = MockIdP(
        ISSUER, {"u2-mcp": "s3cret"}, [effective_public_url(ctx) + ADMIN_CALLBACK_PATH]
    )
    app = build_app(provider)
    ctx.http = lambda: httpx.AsyncClient(transport=httpx.ASGITransport(app=app))
    store_sso(
        ctx.store,
        SsoSettings(
            "oidc", f"{ISSUER}/.well-known/openid-configuration", "u2-mcp", "groups", False
        ),
        "s3cret",
    )
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    finish_setup(ctx.store)
    return provider


def _follow_idp(idp: MockIdP, location: str) -> str:
    """The browser's visit to the provider, which approves at once; returns the callback path."""
    parts = urlsplit(location)
    with TestClient(build_app(idp)) as browser:
        approved = browser.get(f"{parts.path}?{parts.query}", follow_redirects=False)
    callback = urlsplit(approved.headers["location"])
    return f"{callback.path}?{callback.query}"


def _start(client: TestClient, next_url: str = "") -> httpx.Response:
    page = client.get("/admin/sign-in")
    return client.post(
        "/admin/sign-in/sso",
        data={"csrf_token": csrf_from(page.text), "next": next_url},
        follow_redirects=False,
    )


def _sso_sign_in(client: TestClient, idp: MockIdP, next_url: str = "") -> httpx.Response:
    start = _start(client, next_url)
    assert start.status_code == 303, start.text
    return client.get(_follow_idp(idp, start.headers["location"]), follow_redirects=False)


def test_a_first_company_sign_in_creates_the_user_and_a_session(
    ctx: AdminContext, idp: MockIdP
) -> None:
    idp.next_user(Person(sub="sam", email="sam@x.com", name="Sam", groups=["eng"]))
    with admin_client(ctx) as client:
        response = _sso_sign_in(client, idp)
        assert response.status_code == 303 and response.headers["location"] == "/admin/"
        me = client.get("/admin/me")
    assert me.status_code == 200 and "Sam" in me.text
    user = ctx.store.get_user_by_subject("sam")
    assert user is not None and user.last_sso_login_at is not None and not user.is_admin
    assert [g.external_id for g in ctx.store.list_groups()] == ["eng"]
    assert [e["action"] for e in ctx.store.recent_audit(2)] == ["admin.sign_in", "sso_sign_in"]


def test_the_page_asked_for_is_where_sign_in_lands(ctx: AdminContext, idp: MockIdP) -> None:
    with admin_client(ctx) as client:
        response = _sso_sign_in(client, idp, next_url="/admin/me")
    assert response.headers["location"] == "/admin/me"


def test_each_sign_in_replaces_the_groups(ctx: AdminContext, idp: MockIdP) -> None:
    idp.next_user(Person(sub="sam", groups=["eng", "ops"]))
    idp.next_user(Person(sub="sam", groups=["ops"]))
    with admin_client(ctx) as client:
        _sso_sign_in(client, idp)
        _sso_sign_in(client, idp)
    sam = ctx.store.get_user_by_subject("sam")
    assert sam is not None
    names = {g.id: g.external_id for g in ctx.store.list_groups()}
    assert [names[i] for i in ctx.store.group_ids_for_user(sam.id)] == ["ops"]


def test_overage_people_are_flagged_on_users(ctx: AdminContext, idp: MockIdP) -> None:
    idp.next_user(Person(sub="olga", name="Olga", overage=True))
    with admin_client(ctx) as client:
        _sso_sign_in(client, idp)
    olga = ctx.store.get_user_by_subject("olga")
    assert olga is not None and olga.groups_unavailable
    with admin_client(ctx) as admin:
        sign_in(admin)
        users = admin.get("/admin/users").text
    assert "Olga" in users and "(groups unavailable)" in users


def test_a_callback_from_another_browser_is_refused(ctx: AdminContext, idp: MockIdP) -> None:
    with admin_client(ctx) as starter:
        callback = _follow_idp(idp, _start(starter).headers["location"])
    with admin_client(ctx) as other:
        response = other.get(callback, follow_redirects=False)
    assert response.status_code == 400 and SSO_EXPIRED in response.text
    assert ctx.store.get_user_by_subject("user-1") is None


def test_a_changed_state_or_a_replay_is_refused(ctx: AdminContext, idp: MockIdP) -> None:
    with admin_client(ctx) as client:
        callback = _follow_idp(idp, _start(client).headers["location"])
        forged = client.get(callback.replace("state=", "state=x"), follow_redirects=False)
        assert forged.status_code == 400
        callback = _follow_idp(idp, _start(client).headers["location"])
        assert client.get(callback, follow_redirects=False).status_code == 303
        replay = client.get(callback, follow_redirects=False)
    assert replay.status_code == 400 and SSO_EXPIRED in replay.text


def test_a_non_ascii_state_is_refused_not_a_crash(ctx: AdminContext, idp: MockIdP) -> None:
    with admin_client(ctx) as client:
        _start(client)
        response = client.get(
            "/admin/sign-in/sso/callback?code=x&state=%C3%A9", follow_redirects=False
        )
    assert response.status_code == 400 and SSO_EXPIRED in response.text


def test_a_refusal_by_the_provider_is_shown(ctx: AdminContext, idp: MockIdP) -> None:
    with admin_client(ctx) as client:
        state = parse_qs(urlsplit(_start(client).headers["location"]).query)["state"][0]
        response = client.get(
            f"/admin/sign-in/sso/callback?error=access_denied&state={state}", follow_redirects=False
        )
    assert response.status_code == 400
    assert "Company sign-in failed:" in response.text and "access_denied" in response.text
    assert ctx.store.recent_audit(1)[0]["outcome"] == "failed"


def test_a_disabled_person_gets_no_session(ctx: AdminContext, idp: MockIdP) -> None:
    sam = ctx.store.get_or_create_sso_user("sam", issuer=idp.issuer)
    ctx.store.set_user_disabled(sam.id, True)
    idp.next_user(Person(sub="sam", groups=["eng"]))
    with admin_client(ctx) as client:
        response = _sso_sign_in(client, idp)
        after = client.get("/admin/me", follow_redirects=False)
    assert response.status_code == 403 and SSO_DISABLED in response.text
    assert after.status_code == 303  # still signed out
    refreshed = ctx.store.get_user_by_subject("sam")
    assert refreshed is not None and refreshed.last_sso_login_at is None
    assert ctx.store.list_groups() == []
    latest = ctx.store.recent_audit(2)
    assert [(e["action"], e["outcome"]) for e in latest] == [
        ("admin.sign_in", "refused"),
        ("sso_sign_in", "refused"),
    ]


def test_an_over_long_subject_is_refused_without_calling_it_disabled(
    ctx: AdminContext, idp: MockIdP
) -> None:
    idp.next_user(Person(sub="s" * 300))
    with admin_client(ctx) as client:
        response = _sso_sign_in(client, idp)
    assert response.status_code == 403
    assert SSO_REFUSED in response.text and "disabled" not in response.text
    latest = ctx.store.recent_audit(2)
    assert [(e["action"], e["params"]["reason"]) for e in latest] == [
        ("admin.sign_in", "subject_too_long"),
        ("sso_sign_in", "subject_too_long"),
    ]


def test_the_settings_test_signs_nobody_in(ctx: AdminContext, idp: MockIdP) -> None:
    idp.next_user(Person(sub="tess", name="Tess", groups=["eng"]))
    users_before = len(ctx.store.list_users())
    with admin_client(ctx) as client:
        sign_in(client)
        token = csrf_from(client.get("/admin/settings").text)
        start = client.post(
            "/admin/settings/sso/test", data={"csrf_token": token}, follow_redirects=False
        )
        result = client.get(_follow_idp(idp, start.headers["location"]))
        still_admin = client.get("/admin/connections", follow_redirects=False)
    assert "Company sign-in works" in result.text and "eng" in result.text and "Tess" in result.text
    assert len(ctx.store.list_users()) == users_before
    assert still_admin.status_code == 200
    assert ctx.store.recent_audit(1)[0]["action"] == "settings.sso_test"


def test_settings_offer_the_test_button_once_saved(ctx: AdminContext, idp: MockIdP) -> None:
    with admin_client(ctx) as client:
        sign_in(client)
        assert "Test sign-in" in client.get("/admin/settings").text
        clear_sso(ctx.store)
        assert "Test sign-in" not in client.get("/admin/settings").text


def test_the_sign_in_page_offers_company_sign_in_only_when_set_up(
    ctx: AdminContext, idp: MockIdP
) -> None:
    with admin_client(ctx) as client:
        assert "Sign in with your company account" in client.get("/admin/sign-in").text
        clear_sso(ctx.store)
        assert "Sign in with your company account" not in client.get("/admin/sign-in").text
        assert _start(client).status_code == 400
        assert SSO_NOT_SET_UP in _start(client).text


def test_a_bad_discovery_url_is_reported_when_starting(ctx: AdminContext, idp: MockIdP) -> None:
    store_sso(
        ctx.store,
        SsoSettings(
            "oidc", f"{ISSUER}/nowhere/.well-known/openid-configuration", "u2-mcp", "groups", False
        ),
        None,
    )
    with admin_client(ctx) as client:
        response = _start(client)
    assert response.status_code == 400
    assert SSO_UNAVAILABLE in response.text
    assert "404" not in response.text and ISSUER not in response.text
    entry = ctx.store.recent_audit(1)[0]
    assert (entry["action"], entry["outcome"]) == ("admin.sign_in", "failed")
    assert "404" in str(entry)


def test_a_failed_test_start_shows_the_admin_the_detail_and_is_audited(
    ctx: AdminContext, idp: MockIdP
) -> None:
    store_sso(
        ctx.store,
        SsoSettings(
            "oidc", f"{ISSUER}/nowhere/.well-known/openid-configuration", "u2-mcp", "groups", False
        ),
        None,
    )
    with admin_client(ctx) as client:
        sign_in(client)
        token = csrf_from(client.get("/admin/settings").text)
        response = client.post(
            "/admin/settings/sso/test", data={"csrf_token": token}, follow_redirects=False
        )
    assert response.status_code == 400 and "answered 404" in response.text
    entry = ctx.store.recent_audit(1)[0]
    assert (entry["action"], entry["outcome"]) == ("settings.sso_test", "failed")


def _with_signin_limit(
    ctx: AdminContext, monkeypatch: pytest.MonkeyPatch, value: str
) -> AdminContext:
    monkeypatch.setenv("U2_ADMIN_SIGNIN_LIMIT", value)
    return dataclasses.replace(ctx, config=U2Config())


def test_starting_company_sign_in_allows_twenty_times_the_limit_per_address(
    ctx: AdminContext, idp: MockIdP, monkeypatch: pytest.MonkeyPatch, mock_env: dict[str, str]
) -> None:
    ctx = _with_signin_limit(ctx, monkeypatch, "1")
    with admin_client(ctx) as client:
        statuses = [_start(client).status_code for _ in range(21)]
    assert statuses == [303] * 20 + [429]


def test_an_office_behind_one_address_can_start_more_than_the_password_limit(
    ctx: AdminContext, idp: MockIdP
) -> None:
    ctx.limiter = RateLimiter(limit=5)
    with admin_client(ctx) as client:
        statuses = [_start(client).status_code for _ in range(6)]
    assert statuses == [303] * 6


def test_a_signin_limit_of_zero_also_turns_the_start_limit_off(
    ctx: AdminContext, idp: MockIdP, monkeypatch: pytest.MonkeyPatch, mock_env: dict[str, str]
) -> None:
    ctx = _with_signin_limit(ctx, monkeypatch, "0")
    with admin_client(ctx) as client:
        statuses = {_start(client).status_code for _ in range(30)}
    assert statuses == {303}


def test_an_unexpected_error_in_the_callback_is_a_400_and_clears_the_cookie(
    ctx: AdminContext, idp: MockIdP, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def boom(*args: object, **kwargs: object) -> dict[str, object]:
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(OidcClient, "sign_in", boom)
    with admin_client(ctx) as client:
        start = _start(client)
        response = client.get(_follow_idp(idp, start.headers["location"]), follow_redirects=False)
        assert response.status_code == 400
        assert "secret internal detail" not in response.text
        assert "u2_admin_sso=" in response.headers.get("set-cookie", "")
        assert "Max-Age=0" in response.headers.get("set-cookie", "")
    entry = ctx.store.recent_audit(1)[0]
    assert (entry["action"], entry["outcome"]) == ("admin.sign_in", "failed")


def test_the_test_button_opens_with_noopener(ctx: AdminContext, idp: MockIdP) -> None:
    with admin_client(ctx) as client:
        sign_in(client)
        page = client.get("/admin/settings").text
    assert 'target="_blank" rel="noopener noreferrer"' in page


def test_sealed_values_expire_and_resist_tampering(
    store: Store, monkeypatch: pytest.MonkeyPatch
) -> None:
    sealed = store.seal("hello")
    assert store.unseal(sealed, max_age_seconds=60) == "hello"
    with pytest.raises(SecretUnreadable):
        store.unseal(sealed[:-6] + "AAAAAA", max_age_seconds=60)
    later = time.time() + 3600
    monkeypatch.setattr(time, "time", lambda: later)
    with pytest.raises(SecretUnreadable):
        store.unseal(sealed, max_age_seconds=600)


# --- Groups stay out of sight on a local-sign-in-only server (controller amendment 1) ---


def _local_only(ctx: AdminContext) -> int:
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    finish_setup(ctx.store)
    connection = ctx.store.add_connection(
        name="Prod",
        host="u2.example",
        port=31438,
        service="uvcs",
        account="DEV",
        shared_user="svc",
        shared_password="pw",
    )
    return connection.id


def _pages(ctx: AdminContext, connection_id: int) -> tuple[str, str]:
    with admin_client(ctx) as client:
        sign_in(client)
        listing = client.get("/admin/connections").text
        connection = client.get(f"/admin/connections/{connection_id}").text
    return listing, connection


def test_a_local_only_server_hides_groups(ctx: AdminContext) -> None:
    connection_id = _local_only(ctx)
    listing, connection = _pages(ctx, connection_id)
    assert GROUPS_TAB not in listing
    assert 'value="group"' not in connection and 'value="user"' in connection
    with admin_client(ctx) as client:
        sign_in(client)
        assert client.get("/admin/groups").status_code == 200  # still reachable by link


def test_saving_company_sign_in_shows_groups(ctx: AdminContext) -> None:
    connection_id = _local_only(ctx)
    store_sso(
        ctx.store,
        SsoSettings("oidc", f"{ISSUER}/.well-known/openid-configuration", "c", "groups", False),
        "s",
    )
    listing, connection = _pages(ctx, connection_id)
    assert GROUPS_TAB in listing and 'value="group"' in connection


def test_a_known_group_keeps_groups_visible_without_sso(ctx: AdminContext) -> None:
    connection_id = _local_only(ctx)
    sam = ctx.store.get_or_create_sso_user("sam")
    ctx.store.record_sso_login(sam.id, ["eng"])
    listing, connection = _pages(ctx, connection_id)
    assert GROUPS_TAB in listing and 'value="group"' in connection


def test_the_user_page_shows_groups_only_when_visible(ctx: AdminContext) -> None:
    _local_only(ctx)
    bob = ctx.store.add_local_user("bob", password_hash=hash_password(PASSWORD))
    with admin_client(ctx) as client:
        sign_in(client)
        assert "<th>Groups</th>" not in client.get(f"/admin/users/{bob.id}").text
        sam = ctx.store.get_or_create_sso_user("sam")
        ctx.store.record_sso_login(sam.id, ["eng"])
        assert "<th>Groups</th>" in client.get(f"/admin/users/{bob.id}").text


def test_non_admin_sign_in_off_refuses_company_sign_in_and_records_nothing(
    ctx: AdminContext, idp: MockIdP
) -> None:
    """Refused at the site: no session, no new person, and no fresher tokens."""
    from u2_mcp.admin.services import NON_ADMIN_SIGN_IN_SETTING

    known = ctx.store.get_or_create_sso_user("sam", issuer=ISSUER, display_name="Sam")
    ctx.store.set_setting(NON_ADMIN_SIGN_IN_SETTING, False)
    idp.next_user(Person(sub="sam", email="sam@x.com", name="Sam", groups=["eng"]))
    idp.next_user(Person(sub="newbie", name="New"))
    with admin_client(ctx) as client:
        response = _sso_sign_in(client, idp)
        assert response.status_code == 403
        assert "turned off for people who are not admins" in response.text
        assert client.get("/admin/me", follow_redirects=False).status_code == 303
        assert _sso_sign_in(client, idp).status_code == 403
    sam = ctx.store.get_user(known.id)
    assert sam is not None and sam.last_sso_login_at is None  # tokens not refreshed
    assert ctx.store.get_user_by_subject("newbie") is None  # nobody created
    assert ctx.store.recent_audit(1)[0]["outcome"] == "refused"


def test_an_admin_signs_in_with_company_sign_in_while_it_is_off(
    ctx: AdminContext, idp: MockIdP
) -> None:
    from u2_mcp.admin.services import NON_ADMIN_SIGN_IN_SETTING

    boss = ctx.store.get_or_create_sso_user("boss", issuer=ISSUER, display_name="Boss")
    ctx.store.set_user_admin(boss.id, True)
    ctx.store.set_setting(NON_ADMIN_SIGN_IN_SETTING, False)
    idp.next_user(Person(sub="boss", name="Boss"))
    with admin_client(ctx) as client:
        assert _sso_sign_in(client, idp).status_code == 303
