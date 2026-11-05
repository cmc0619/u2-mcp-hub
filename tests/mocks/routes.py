"""Build team-mode routes for registry tests without a settings database."""

from u2_mcp.credentials import U2Credentials
from u2_mcp.routing import Route
from u2_mcp.store.models import Connection


def make_route(
    connection_id: int, user: str, *, version: int = 1, owner_id: int | None = None
) -> Route:
    """A route to connection `connection_id` (account A) as `user`."""
    connection = Connection(
        id=connection_id,
        name=f"c{connection_id}",
        host="h",
        port=1,
        service="uvcs",
        account="A",
        ssl=False,
        login_mode="shared",
        shared_user=user,
        has_shared_password=True,
        read_only=True,
        enabled=True,
        version=version,
    )
    credentials = U2Credentials(user=user, password="p", account="A", is_shared=True)
    return Route(connection, credentials, owner_id=owner_id)
