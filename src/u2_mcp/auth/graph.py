"""Microsoft Graph lookup for Entra ID's group overage.

When a person is in more groups than fit in a token, Entra leaves the groups out
and says so with `_claim_names`. Their groups can then be read from Graph with
the application's own credentials (client-credentials grant; the app needs the
GroupMember.Read.All application permission). Only fixed Microsoft hosts are
called, with the tenant and user ids checked as GUIDs: the `_claim_sources`
endpoint inside the token is never fetched. Any failure means "groups unknown",
never an exception: the person still signs in, flagged as groups-unavailable.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from .oidc_client import HttpFactory, default_http

logger = logging.getLogger(__name__)

LOGIN_BASE = "https://login.microsoftonline.com"
GRAPH_BASE = "https://graph.microsoft.com"
_GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


class GraphGroups:
    """Resolve an overage person's group ids through Microsoft Graph.

    Args:
        client_id: The Entra application (client) id
        client_secret: Its secret
        http: Makes the HTTP client (replaced in tests)
        login_base: Entra's token host
        graph_base: Graph's host
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *,
        http: HttpFactory = default_http,
        login_base: str = LOGIN_BASE,
        graph_base: str = GRAPH_BASE,
    ) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self._http = http
        self.login_base = login_base
        self.graph_base = graph_base

    async def __call__(self, claims: dict[str, Any]) -> list[str] | None:
        """Return the person's group ids, or None when they cannot be read."""
        tenant, object_id = str(claims.get("tid") or ""), str(claims.get("oid") or "")
        if not _GUID.fullmatch(tenant) or not _GUID.fullmatch(object_id):
            logger.warning("Group overage: the token has no usable tid/oid, so groups are unknown")
            return None
        try:
            async with self._http() as client:
                token = await client.post(
                    f"{self.login_base}/{tenant}/oauth2/v2.0/token",
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "scope": f"{self.graph_base}/.default",
                    },
                )
                if token.status_code != 200:
                    logger.warning(f"Group overage: Graph token refused ({token.status_code})")
                    return None
                access = token.json().get("access_token")
                if not isinstance(access, str) or not access:
                    logger.warning("Group overage: Graph sent no access token")
                    return None
                answer = await client.post(
                    f"{self.graph_base}/v1.0/users/{object_id}/getMemberGroups",
                    json={"securityEnabledOnly": False},
                    headers={"Authorization": f"Bearer {access}"},
                )
                if answer.status_code != 200:
                    logger.warning(
                        f"Group overage: Graph refused the lookup ({answer.status_code})"
                    )
                    return None
                values = answer.json().get("value")
        except Exception as exc:  # the contract is "never raises": any failure means unknown
            logger.warning(f"Group overage: Graph lookup failed ({type(exc).__name__}): {exc}")
            return None
        if not isinstance(values, list):
            return None
        return [str(value) for value in values]
