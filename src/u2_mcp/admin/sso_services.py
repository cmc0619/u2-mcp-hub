"""Saving company sign-in settings: one function for the wizard and Settings (spec rule 1).

Microsoft Entra ID is set up from the app registration's own values (Directory
(tenant) ID, Application (client) ID, client secret); the discovery URL is built
from the tenant. Other OpenID Connect providers give their discovery URL.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from ..sso_config import (
    ADMIN_CALLBACK_PATH,
    MCP_CALLBACK_PATH,
    PROVIDERS,
    SsoSettings,
    clear_sso,
    entra_discovery_url,
    load_sso,
    sso_client_secret,
    store_sso,
    tenant_from_discovery,
)
from ..store.crypto import SecretUnreadable
from ..store.models import User
from .context import AdminContext
from .services import RESTART_NOTE, ValidationFailed, effective_public_url

DISCOVERY_SUFFIX = "/.well-known/openid-configuration"
PROVIDER_PROBLEM = "Choose a provider."
DISCOVERY_PROBLEM = "Enter the discovery URL, ending in /.well-known/openid-configuration."
DISCOVERY_HTTPS = "The discovery URL must be https."
ENTRA_TENANT = (
    "Use your own tenant ID (Overview page of the app registration), "
    "not common, organizations or consumers."
)
TENANT_PROBLEM = "Enter the Directory (tenant) ID: a GUID, or a domain such as contoso.com."
CLIENT_ID_PROBLEM = "Enter the client (application) ID."
SECRET_NEEDED = "Enter the client secret."
SECRET_AGAIN = "Enter the client secret again: the client ID changed."
CLAIM_PROBLEM = "Use up to 64 letters, digits, dots, dashes, underscores, colons or slashes."

_CLAIM = re.compile(r"[A-Za-z0-9_.:/-]{1,64}")
_LOOPBACK = ("localhost", "127.0.0.1", "::1")
_TENANT_GUID = re.compile(r"[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}")
_TENANT_DOMAIN = re.compile(
    r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}"
)
_ENTRA_SHARED = ("common", "organizations", "consumers")


@dataclass
class SsoForm:
    """The company sign-in form as submitted (the secret only when typed).

    `tenant_id` is a form field only: Entra's discovery URL is built from it.
    """

    provider: str = "entra"
    tenant_id: str = ""
    discovery_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    groups_claim: str = "groups"
    graph_overage: bool = False

    @classmethod
    def from_form(cls, data: Mapping[str, Any]) -> SsoForm:
        """Read a submitted form."""
        return cls(
            provider=str(data.get("provider", "")).strip(),
            tenant_id=str(data.get("tenant_id", "")).strip(),
            discovery_url=str(data.get("discovery_url", "")).strip(),
            client_id=str(data.get("client_id", "")).strip(),
            client_secret=str(data.get("client_secret", "")),
            groups_claim=str(data.get("groups_claim", "")).strip() or "groups",
            graph_overage=data.get("graph_overage") == "on",
        )

    @classmethod
    def from_settings(cls, settings: SsoSettings | None) -> SsoForm:
        """The form pre-filled from saved settings (never the secret)."""
        if settings is None:
            return cls()
        return cls(
            provider=settings.provider,
            tenant_id=tenant_from_discovery(settings.discovery_url) or "",
            discovery_url=settings.discovery_url,
            client_id=settings.client_id,
            groups_claim=settings.groups_claim,
            graph_overage=settings.graph_overage,
        )

    @property
    def effective_discovery_url(self) -> str:
        """The discovery URL to save: built from the tenant for Entra."""
        if self.provider == "entra":
            return entra_discovery_url(self.tenant_id)
        return self.discovery_url

    def errors(self, *, stored: SsoSettings | None, has_secret: bool) -> dict[str, str]:
        """Each field's problem; empty when the form can be saved."""
        errors: dict[str, str] = {}
        if self.provider not in PROVIDERS:
            errors["provider"] = PROVIDER_PROBLEM
        elif self.provider == "entra":
            problem = _tenant_problem(self.tenant_id)
            if problem:
                errors["tenant_id"] = problem
        else:
            problem = _discovery_problem(self.discovery_url)
            if problem:
                errors["discovery_url"] = problem
        if (
            not self.client_id
            or len(self.client_id) > 255
            or any(c.isspace() for c in self.client_id)
        ):
            errors["client_id"] = CLIENT_ID_PROBLEM
        if not self.client_secret:
            if not has_secret:
                errors["client_secret"] = SECRET_NEEDED
            elif stored is not None and stored.client_id != self.client_id:
                errors["client_secret"] = SECRET_AGAIN
        if not _CLAIM.fullmatch(self.groups_claim):
            errors["groups_claim"] = CLAIM_PROBLEM
        return errors


def _tenant_problem(tenant: str) -> str | None:
    """A tenant goes into a URL, so only a GUID or a plain domain name is accepted."""
    if tenant.lower() in _ENTRA_SHARED:
        return ENTRA_TENANT
    if _TENANT_GUID.fullmatch(tenant) or _TENANT_DOMAIN.fullmatch(tenant):
        return None
    return TENANT_PROBLEM


def _discovery_problem(url: str) -> str | None:
    parts = urlsplit(url)
    if (
        parts.scheme not in ("http", "https")
        or not parts.netloc
        or not parts.path.endswith(DISCOVERY_SUFFIX)
        or parts.query
        or parts.fragment
        or parts.username
        or parts.password
        or any(c.isspace() for c in url)
    ):
        return DISCOVERY_PROBLEM
    if parts.scheme == "http" and parts.hostname not in _LOOPBACK:
        return DISCOVERY_HTTPS
    return None


def _has_secret(ctx: AdminContext) -> tuple[bool, bool]:
    """(a secret is saved and readable, a secret is saved but unreadable)."""
    try:
        return sso_client_secret(ctx.store) is not None, False
    except SecretUnreadable:
        return False, True


def save_sso(ctx: AdminContext, form: SsoForm, *, actor: User) -> SsoSettings:
    """Validate and save company sign-in settings.

    Raises:
        ValidationFailed: With each field's problem
    """
    stored = load_sso(ctx.store)
    has_secret, _unreadable = _has_secret(ctx)
    errors = form.errors(stored=stored, has_secret=has_secret)
    if errors:
        raise ValidationFailed(errors)
    settings = SsoSettings(
        provider=form.provider,
        discovery_url=form.effective_discovery_url,
        client_id=form.client_id,
        groups_claim=form.groups_claim,
        graph_overage=form.graph_overage and form.provider == "entra",
    )
    store_sso(ctx.store, settings, form.client_secret or None)
    ctx.store.add_audit(
        kind="admin",
        action="settings.sso",
        outcome="ok",
        actor_user_id=actor.id,
        actor_label=actor.label,
        params={
            "provider": settings.provider,
            "discovery_url": settings.discovery_url,
            "client_id": settings.client_id,
            "groups_claim": settings.groups_claim,
            "graph_overage": settings.graph_overage,
            "credential_changed": bool(form.client_secret),
        },
    )
    return settings


def remove_sso(ctx: AdminContext, *, actor: User) -> None:
    """Turn company sign-in off (local admins can always still sign in)."""
    clear_sso(ctx.store)
    ctx.store.add_audit(
        kind="admin",
        action="settings.sso_clear",
        outcome="ok",
        actor_user_id=actor.id,
        actor_label=actor.label,
    )


def sso_context(
    ctx: AdminContext,
    *,
    action_url: str,
    form: SsoForm | None = None,
    errors: dict[str, str] | None = None,
) -> dict[str, Any]:
    """What partials/sso_form.html needs, for the wizard and Settings alike."""
    settings = load_sso(ctx.store)
    has_secret, unreadable = _has_secret(ctx)
    if unreadable:
        hint = "The saved secret can't be read with this U2_SECRET_KEY. Enter it again."
    elif has_secret:
        hint = "A secret is saved. Leave this blank to keep it."
    else:
        hint = "From your identity provider's app registration."
    public = effective_public_url(ctx)
    return {
        "sso": settings,
        "sso_form": form or SsoForm.from_settings(settings),
        "sso_errors": errors or {},
        "sso_providers": list(PROVIDERS.items()),
        "sso_secret_hint": hint,
        "sso_admin_callback": public + ADMIN_CALLBACK_PATH,
        "sso_mcp_callback": public + MCP_CALLBACK_PATH,
        "sso_action": action_url,
        "sso_submit_label": "Save company sign-in",
        "sso_restart_note": RESTART_NOTE,
    }


def groups_visible(ctx: AdminContext) -> bool:
    """Whether pages show groups: company sign-in is set up, or groups already exist.

    Groups only come from company sign-ins, so a local-sign-in-only server hides
    them. Existing groups or group grants keep them visible, so nothing becomes
    unreachable when company sign-in is turned off later.
    """
    return load_sso(ctx.store) is not None or ctx.store.has_groups()
