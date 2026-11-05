"""Company sign-in settings: one validated save for the wizard and Settings."""

from pathlib import Path
from typing import Any

import pytest

from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.services import ValidationFailed
from u2_mcp.admin.sso_services import (
    CLAIM_PROBLEM,
    CLIENT_ID_PROBLEM,
    DISCOVERY_HTTPS,
    DISCOVERY_PROBLEM,
    ENTRA_TENANT,
    PROVIDER_PROBLEM,
    SECRET_AGAIN,
    SECRET_NEEDED,
    TENANT_PROBLEM,
    SsoForm,
    remove_sso,
    save_sso,
)
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import completed_step, finish_setup, mark_step_done
from u2_mcp.sso_config import (
    SSO_SECRET_SETTING,
    SsoSettings,
    load_sso,
    sso_client_secret,
    store_sso,
)
from u2_mcp.store.models import User

from .helpers import PASSWORD, admin_client, csrf_from, sign_in

TENANT = "11111111-2222-3333-4444-555555555555"
ENTRA_URL = f"https://login.microsoftonline.com/{TENANT}/v2.0/.well-known/openid-configuration"
GOOD: dict[str, Any] = {
    "provider": "entra",
    "tenant_id": TENANT,
    "client_id": "app-1",
    "client_secret": "s3cret",
    "groups_claim": "groups",
}
OIDC: dict[str, Any] = {
    **GOOD,
    "provider": "oidc",
    "tenant_id": "",
    "discovery_url": "https://idp.example/.well-known/openid-configuration",
}


@pytest.mark.parametrize(
    ("changes", "field", "message"),
    [
        ({"provider": "saml"}, "provider", PROVIDER_PROBLEM),
        ({"tenant_id": ""}, "tenant_id", TENANT_PROBLEM),
        ({"tenant_id": "not a tenant"}, "tenant_id", TENANT_PROBLEM),
        ({"tenant_id": "{tenantid}"}, "tenant_id", TENANT_PROBLEM),
        ({"tenant_id": "common"}, "tenant_id", ENTRA_TENANT),
        ({"tenant_id": "Organizations"}, "tenant_id", ENTRA_TENANT),
        ({"tenant_id": "consumers"}, "tenant_id", ENTRA_TENANT),
        ({"client_id": ""}, "client_id", CLIENT_ID_PROBLEM),
        ({"client_secret": ""}, "client_secret", SECRET_NEEDED),
        ({"groups_claim": "has space"}, "groups_claim", CLAIM_PROBLEM),
    ],
)
def test_the_entra_form_names_each_problem(
    changes: dict[str, str], field: str, message: str
) -> None:
    form = SsoForm.from_form({**GOOD, **changes})
    assert form.errors(stored=None, has_secret=False)[field] == message


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"discovery_url": "https://idp.example/"}, DISCOVERY_PROBLEM),
        ({"discovery_url": "http://idp.example/.well-known/openid-configuration"}, DISCOVERY_HTTPS),
    ],
)
def test_other_providers_still_use_a_discovery_url(changes: dict[str, str], message: str) -> None:
    form = SsoForm.from_form({**OIDC, **changes})
    assert form.errors(stored=None, has_secret=False) == {"discovery_url": message}


def test_entra_ignores_the_discovery_url_and_oidc_ignores_the_tenant() -> None:
    entra = SsoForm.from_form({**GOOD, "discovery_url": "junk"})
    oidc = SsoForm.from_form({**OIDC, "tenant_id": "junk"})
    assert entra.errors(stored=None, has_secret=False) == {}
    assert oidc.errors(stored=None, has_secret=False) == {}


@pytest.mark.parametrize("tenant", [TENANT, "contoso.com", "contoso.onmicrosoft.com"])
def test_a_tenant_guid_or_domain_is_accepted(tenant: str) -> None:
    form = SsoForm.from_form({**GOOD, "tenant_id": tenant})
    assert form.errors(stored=None, has_secret=False) == {}


def test_loopback_http_discovery_is_allowed_for_local_test_providers() -> None:
    form = SsoForm.from_form(
        {**OIDC, "discovery_url": "http://127.0.0.1:8901/.well-known/openid-configuration"}
    )
    assert form.errors(stored=None, has_secret=False) == {}


def test_entra_builds_the_tenant_discovery_url(ctx: AdminContext, admin: User) -> None:
    settings = save_sso(ctx, SsoForm.from_form({**GOOD, "tenant_id": f" {TENANT} "}), actor=admin)
    assert settings.discovery_url == ENTRA_URL
    assert ctx.store.get_setting("sso") == {
        "provider": "entra",
        "discovery_url": ENTRA_URL,
        "client_id": "app-1",
        "groups_claim": "groups",
        "graph_overage": False,
    }


def test_oidc_saves_its_discovery_url(ctx: AdminContext, admin: User) -> None:
    settings = save_sso(ctx, SsoForm.from_form(OIDC), actor=admin)
    assert settings.discovery_url == OIDC["discovery_url"]


def test_the_form_prefills_the_tenant_from_the_saved_url(ctx: AdminContext) -> None:
    store_sso(ctx.store, SsoSettings("entra", ENTRA_URL, "app-1", "groups", False), "s")
    form = SsoForm.from_settings(load_sso(ctx.store))
    assert form.tenant_id == TENANT and form.provider == "entra"


def test_saving_encrypts_the_secret_and_audits_without_it(ctx: AdminContext, admin: User) -> None:
    settings = save_sso(ctx, SsoForm.from_form(GOOD), actor=admin)
    assert load_sso(ctx.store) == settings
    assert sso_client_secret(ctx.store) == "s3cret"
    assert "s3cret" not in str(ctx.store.get_setting(SSO_SECRET_SETTING))
    entry = ctx.store.recent_audit(1)[0]
    assert entry["action"] == "settings.sso" and "s3cret" not in str(entry)


def test_the_audit_records_whether_the_credential_changed(ctx: AdminContext, admin: User) -> None:
    save_sso(ctx, SsoForm.from_form(GOOD), actor=admin)
    typed = ctx.store.recent_audit(1)[0]["params"]
    assert typed["credential_changed"] is True
    save_sso(ctx, SsoForm.from_form({**GOOD, "client_secret": ""}), actor=admin)
    blank = ctx.store.recent_audit(1)[0]["params"]
    assert blank["credential_changed"] is False


def test_the_entra_secret_hint_is_in_the_form_for_css_to_toggle() -> None:
    root = Path("src/u2_mcp/admin")
    css = (root / "static/styles.css").read_text(encoding="utf8")
    html = (root / "templates/partials/sso_form.html").read_text(encoding="utf8")
    assert "Use the secret's Value, not its Secret ID." in html
    assert "sso-secret-entra" in html and "sso-secret-entra" in css


def test_a_blank_secret_keeps_the_saved_one_until_the_client_id_changes(
    ctx: AdminContext, admin: User
) -> None:
    save_sso(ctx, SsoForm.from_form(GOOD), actor=admin)
    save_sso(
        ctx, SsoForm.from_form({**GOOD, "client_secret": "", "groups_claim": "roles"}), actor=admin
    )
    saved = load_sso(ctx.store)
    assert sso_client_secret(ctx.store) == "s3cret"
    assert saved is not None and saved.groups_claim == "roles"
    with pytest.raises(ValidationFailed) as failed:
        save_sso(
            ctx, SsoForm.from_form({**GOOD, "client_secret": "", "client_id": "app-2"}), actor=admin
        )
    assert failed.value.errors == {"client_secret": SECRET_AGAIN}


def test_the_graph_lookup_is_for_entra_only(ctx: AdminContext, admin: User) -> None:
    form = SsoForm.from_form({**OIDC, "graph_overage": "on"})
    assert save_sso(ctx, form, actor=admin).graph_overage is False
    form = SsoForm.from_form({**GOOD, "graph_overage": "on"})
    assert save_sso(ctx, form, actor=admin).graph_overage is True


def test_turning_it_off_forgets_the_secret(ctx: AdminContext, admin: User) -> None:
    save_sso(ctx, SsoForm.from_form(GOOD), actor=admin)
    remove_sso(ctx, actor=admin)
    assert load_sso(ctx.store) is None and sso_client_secret(ctx.store) is None
    assert ctx.store.recent_audit(1)[0]["action"] == "settings.sso_clear"


def _wizard_at_sso(ctx: AdminContext) -> None:
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    mark_step_done(ctx.store, "server_address")


def test_the_server_address_step_leads_to_company_sign_in(ctx: AdminContext) -> None:
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    mark_step_done(ctx.store, "connection")
    with admin_client(ctx) as client:
        sign_in(client)
        page = client.get("/admin/setup/server_address")
        response = client.post(
            "/admin/setup/server_address",
            data={"csrf_token": csrf_from(page.text), "public_url": "http://10.0.0.5:8080"},
            follow_redirects=False,
        )
    assert response.headers["location"] == "/admin/setup/sso"


def test_the_sso_step_can_be_skipped(ctx: AdminContext) -> None:
    _wizard_at_sso(ctx)
    with admin_client(ctx) as client:
        sign_in(client)
        page = client.get("/admin/setup/sso")
        assert "Skip this step" in page.text and "Company sign-in" in page.text
        assert "Directory (tenant) ID" in page.text and "Application (client) ID" in page.text
        assert "Web redirect URI" in page.text
        response = client.post(
            "/admin/setup/sso/next",
            data={"csrf_token": csrf_from(page.text)},
            follow_redirects=False,
        )
    assert response.headers["location"] == "/admin/setup/done"
    assert completed_step(ctx.store) == "sso"


def test_the_sso_step_saves_and_waits_for_continue(ctx: AdminContext) -> None:
    _wizard_at_sso(ctx)
    with admin_client(ctx) as client:
        sign_in(client)
        token = csrf_from(client.get("/admin/setup/sso").text)
        saved = client.post(
            "/admin/setup/sso", data={**GOOD, "csrf_token": token}, follow_redirects=False
        )
        assert saved.headers["location"] == "/admin/setup/sso?notice=saved"
        page = client.get("/admin/setup/sso")
        assert "Continue" in page.text and "A secret is saved" in page.text
        assert f'value="{TENANT}"' in page.text
        bad = client.post(
            "/admin/setup/sso",
            data={**GOOD, "client_id": "", "csrf_token": token},
            follow_redirects=False,
        )
    assert bad.status_code == 400 and CLIENT_ID_PROBLEM in bad.text
    assert completed_step(ctx.store) == "server_address"


def test_settings_saves_and_turns_off_company_sign_in(ctx: AdminContext) -> None:
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    finish_setup(ctx.store)
    with admin_client(ctx) as client:
        sign_in(client)
        token = csrf_from(client.get("/admin/settings").text)
        saved = client.post(
            "/admin/settings/sso", data={**OIDC, "csrf_token": token}, follow_redirects=False
        )
        assert saved.status_code == 303
        page = client.get("/admin/settings")
        assert "Turn off company sign-in" in page.text
        assert "/admin/sign-in/sso/callback" in page.text and "/oauth/callback" in page.text
        assert "Discovery URL" in page.text
        client.post("/admin/settings/sso/clear", data={"csrf_token": token}, follow_redirects=False)
    assert load_sso(ctx.store) is None
