"""Company sign-in (OIDC) settings, kept in the settings database.

The admin site edits them, and the admin site's sign-in reads them on every
sign-in. The MCP OAuth bridge reads them at startup. The client secret is
encrypted with U2_SECRET_KEY.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING

from .auth.graph import GraphGroups
from .auth.oidc_client import HttpFactory, OidcClient
from .store.crypto import SecretUnreadable

if TYPE_CHECKING:
    from .store.repo import Store

SSO_SETTING = "sso"
SSO_SECRET_SETTING = "sso_client_secret"
ADMIN_CALLBACK_PATH = "/admin/sign-in/sso/callback"
MCP_CALLBACK_PATH = "/oauth/callback"
PROVIDERS: dict[str, str] = {
    "entra": "Microsoft Entra ID",
    "oidc": "Other OpenID Connect provider (Okta, Google, Auth0, Duo, Keycloak)",
}
_ENTRA_DISCOVERY = re.compile(
    r"https://login\.microsoftonline\.com/([^/]+)/v2\.0/\.well-known/openid-configuration"
)


def entra_discovery_url(tenant_id: str) -> str:
    """The Entra discovery URL for a tenant (a GUID or a verified domain)."""
    return f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"


def tenant_from_discovery(url: str) -> str | None:
    """The tenant in an Entra discovery URL, or None when it is not one."""
    match = _ENTRA_DISCOVERY.fullmatch(url)
    return match.group(1) if match else None


@dataclass(frozen=True)
class SsoSettings:
    """Company sign-in as configured (the secret is kept separately, encrypted)."""

    provider: str
    discovery_url: str
    client_id: str
    groups_claim: str
    graph_overage: bool

    @property
    def provider_label(self) -> str:
        """The provider's name as the pages show it."""
        return PROVIDERS.get(self.provider, self.provider)


def load_sso(store: Store) -> SsoSettings | None:
    """Return the saved company sign-in settings, or None when it is not set up."""
    value = store.get_setting(SSO_SETTING)
    if not isinstance(value, dict):
        return None
    try:
        return SsoSettings(
            provider=str(value["provider"]),
            discovery_url=str(value["discovery_url"]),
            client_id=str(value["client_id"]),
            groups_claim=str(value.get("groups_claim") or "groups"),
            graph_overage=bool(value.get("graph_overage", False)),
        )
    except KeyError:
        return None


def sso_client_secret(store: Store) -> str | None:
    """Return the decrypted client secret, or None.

    Raises:
        SecretUnreadable: If it was saved under a different U2_SECRET_KEY
    """
    return store.get_secret_setting(SSO_SECRET_SETTING)


def store_sso(store: Store, settings: SsoSettings, client_secret: str | None) -> None:
    """Save the settings; a None secret keeps the saved one."""
    store.set_setting(SSO_SETTING, asdict(settings))
    if client_secret is not None:
        store.set_secret_setting(SSO_SECRET_SETTING, client_secret)


def clear_sso(store: Store) -> None:
    """Turn company sign-in off and forget its secret."""
    store.delete_setting(SSO_SETTING)
    store.set_secret_setting(SSO_SECRET_SETTING, None)


def oidc_client(store: Store, http: HttpFactory) -> OidcClient | None:
    """The OIDC client for the saved settings, or None when company sign-in is off.

    An unreadable secret yields a client with no secret: starting a sign-in still
    works, and the exchange then says that no client secret is saved.
    """
    settings = load_sso(store)
    if settings is None:
        return None
    try:
        secret = sso_client_secret(store)
    except SecretUnreadable:
        secret = None
    return OidcClient(settings.discovery_url, settings.client_id, secret, http=http)


def overage_resolver(store: Store, settings: SsoSettings, http: HttpFactory) -> GraphGroups | None:
    """The Microsoft Graph lookup when the admin turned it on, else None."""
    if not settings.graph_overage:
        return None
    try:
        secret = sso_client_secret(store)
    except SecretUnreadable:
        return None
    return GraphGroups(settings.client_id, secret, http=http) if secret else None
