"""Main MCP server entry point for u2-mcp.

Two ways to run it: `u2-mcp` (stdio) serves one local operator with the U2_HOST
login; `u2-mcp --streamable-http` is team mode, which needs U2_SECRET_KEY and
takes its connections, people and access rules from the admin site.
"""

import argparse
import logging
import sys
import threading
from pathlib import Path
from typing import Any

from pydantic import AnyHttpUrl

from .access import visible_connections
from .config import U2Config
from .connection import ConnectionError, ConnectionManager
from .guard import LOCAL_CONNECTION_NAME, check_tool_coverage, guarded
from .identity import IdentityError, current_caller, set_identity_resolver
from .registry import ConnectionRegistry
from .store import get_store, install_store, is_global_read_only
from .store.bootstrap import open_team_store
from .team_auth import (
    ClientAddressMiddleware,
    PatVerifier,
    make_identity_resolver,
    make_sign_in_handler,
)
from .threaded import ThreadedFastMCP, set_tool_thread_limit

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Create FastMCP server instance. Synchronous tools run on worker threads, so a
# slow query never stalls the event loop (see threaded.py).
mcp = ThreadedFastMCP("U2 MCP Server")

# One session per connection and login (team mode), or the one stdio login.
_connection_registry: ConnectionRegistry | None = None

# Set directly by tests that want a single manager; takes precedence when present.
_connection_manager: ConnectionManager | None = None

_connection_registry_lock = threading.Lock()


def get_connection_registry() -> ConnectionRegistry:
    """Get or create the registry holding one connection per database login."""
    global _connection_registry
    # Tools run on worker threads, so two first calls can arrive together.
    with _connection_registry_lock:
        if _connection_registry is None:
            _connection_registry = ConnectionRegistry(U2Config())
        return _connection_registry


def get_connection_manager() -> ConnectionManager:
    """Get the connection manager for the current call.

    In team mode it is the session for the route the guard chose; in stdio mode,
    the one session for the U2_HOST login.
    """
    if _connection_manager is not None:
        return _connection_manager
    return get_connection_registry().current()


def reset_connection_manager() -> None:
    """Reset the global connection state (useful for testing)."""
    global _connection_manager, _connection_registry
    if _connection_manager is not None:
        _connection_manager.disconnect()
    _connection_manager = None
    if _connection_registry is not None:
        _connection_registry.disconnect_all()
    _connection_registry = None


# =============================================================================
# Connection Management Tools
# =============================================================================


@mcp.tool()
@guarded()
def connect(connection: str | None = None) -> dict[str, Any]:
    """Establish connection to the Universe/UniData server.

    Args:
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        Connection status and details including host, account, service, and timestamp.
    """
    from .utils.knowledge import get_knowledge_store

    try:
        manager = get_connection_manager()
        info = manager.connect()

        # Check for available knowledge
        store = get_knowledge_store()
        topics = store.list_topics()
        knowledge_hint = None
        if topics:
            topic_names = [t["topic"] for t in topics]
            knowledge_hint = (
                f"Previous knowledge available ({len(topics)} topics): {', '.join(topic_names)}. "
                "Call get_all_knowledge() to retrieve learned information about this database."
            )

        result: dict[str, Any] = {
            "status": "connected",
            "host": info.host,
            "account": info.account,
            "service": info.service,
            "connected_at": info.connected_at.isoformat(),
        }

        if knowledge_hint:
            result["knowledge_available"] = knowledge_hint

        return result
    except ConnectionError as e:
        return {"status": "error", "message": str(e)}
    except Exception as e:
        logger.error(f"Unexpected error during connect: {e}")
        return {"status": "error", "message": f"Unexpected error: {e}"}


@mcp.tool()
@guarded()
def disconnect(connection: str | None = None) -> dict[str, Any]:
    """Close your session to the Universe/UniData server.

    Args:
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        Disconnection status and count of closed connections.
    """
    try:
        manager = get_connection_manager()
        closed = manager.disconnect()
        return {
            "status": "disconnected",
            "connections_closed": int(closed),
        }
    except Exception as e:
        logger.error(f"Error during disconnect: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
@guarded()
def list_sessions(connection: str | None = None) -> dict[str, Any]:
    """List the database sessions this server holds open for you.

    Args:
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        List of active connections with their details (name, host, account, service,
        connection time, and active status).
    """
    try:
        manager = get_connection_manager()
        info = manager.connection_info
        sessions = []
        if info is not None:
            sessions.append(
                {
                    "host": info.host,
                    "account": info.account,
                    "service": info.service,
                    "connected_at": info.connected_at.isoformat(),
                }
            )
        return {"connections": sessions}
    except Exception as e:
        logger.error(f"Error listing connections: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
@guarded()
def list_connections() -> dict[str, Any]:
    """List the U2 connections you can use, with your roles and permissions on each.

    Pass one of these names as the `connection` argument of any other tool. When
    only one connection is listed, `connection` can be left out.

    Returns:
        Dictionary with a `connections` list
    """
    store = get_store()
    if store is None:
        # Read the configuration only: listing is not using, so open no session.
        config = (
            _connection_manager.config
            if _connection_manager is not None
            else get_connection_registry().config
        )
        return {
            "connections": [
                {
                    "name": LOCAL_CONNECTION_NAME,
                    "account": config.account,
                    "read_only": config.read_only,
                    "roles": [],
                    "permissions": "all",
                }
            ]
        }

    try:
        caller = current_caller()
    except IdentityError as exc:
        return {"error": str(exc)}
    if caller.user_id is None:
        return {"error": "this request is not signed in"}

    global_read_only = is_global_read_only()
    return {
        "connections": [
            {
                "name": visible.connection.name,
                "account": visible.connection.account,
                "read_only": visible.connection.read_only or global_read_only,
                "roles": list(visible.roles),
                "permissions": sorted(visible.permissions),
            }
            for visible in visible_connections(
                store, caller.user_id, global_read_only=global_read_only
            )
        ]
    }


# =============================================================================
# Import and register tools from submodules
# =============================================================================

# These imports register the tools and resources with the mcp instance
from .resources import examples, knowledge, syntax_help  # noqa: E402, F401
from .tools import (  # noqa: E402, F401
    basic,
    dictionary,
    files,
    query,
    subroutine,
    transaction,
)


async def _health(_request: Any) -> Any:
    """Answer container health checks; needs no authentication."""
    from starlette.responses import JSONResponse

    return JSONResponse({"status": "ok"})


def _health_route() -> Any:
    """The `/health` route every HTTP mode serves."""
    from starlette.routing import Route as StarletteRoute

    return StarletteRoute("/health", _health, methods=["GET"])


class CorsOutsideAdmin:
    """CORS for the MCP endpoints, never for the admin site.

    With allow_credentials, a listed origin could read admin pages with the
    signed-in admin's cookie. The admin site needs no cross-origin access at all.
    """

    def __init__(self, app: Any, /, **cors: Any) -> None:
        from starlette.middleware.cors import CORSMiddleware

        self.app = app
        self.cors = CORSMiddleware(app, **cors)

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        path = scope.get("path", "")
        if scope.get("type") == "http" and (path == "/admin" or path.startswith("/admin/")):
            await self.app(scope, receive, send)
            return
        await self.cors(scope, receive, send)


def _issuer_allowed(url: str) -> bool:
    """OAuth issuers must be https; the MCP SDK allows http only for localhost."""
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    return parts.scheme == "https" or parts.hostname in ("localhost", "127.0.0.1")


def _stored_sso_adapter(store: Any, public_url: str, http: Any = None) -> Any | None:
    """The OAuth bridge's IdP adapter, built from the admin site's company sign-in.

    It exchanges codes through the admin site's OidcClient, so a provider that
    takes only client_secret_basic works for both.

    Args:
        store: The settings database
        public_url: This server's address (the bridge's issuer)
        http: Makes the HTTP client for the provider; replaced in tests

    Returns None, with a warning naming the fix, when it cannot be used yet.
    """
    from .auth.idp.stored import StoredSsoAdapter
    from .auth.oidc_client import OidcClient, default_http
    from .sso_config import load_sso, sso_client_secret
    from .store.crypto import SecretUnreadable

    settings = load_sso(store)
    if settings is None:
        return None
    for label, value in (
        ("discovery URL", settings.discovery_url),
        ("client ID", settings.client_id),
    ):
        if not value:
            logger.warning(
                "Company sign-in is saved without a %s, so VS Code sign-in stays off. "
                "Enter it again under Settings and restart.",
                label,
            )
            return None
    try:
        secret = sso_client_secret(store)
    except SecretUnreadable:
        secret = None
    if not secret:
        logger.warning(
            "Company sign-in is set up but its client secret is missing or unreadable, so "
            "VS Code sign-in stays off. Enter the secret again under Settings and restart."
        )
        return None
    if not _issuer_allowed(public_url):
        logger.warning(
            "Company sign-in for VS Code needs an https server address (%s is not), so it "
            "stays off. Personal access tokens still work.",
            public_url,
        )
        return None
    return StoredSsoAdapter(
        OidcClient(settings.discovery_url, settings.client_id, secret, http=http or default_http)
    )


def _team_sign_in(store: Any, adapter: Any) -> Any:
    """The OAuth bridge's on_sign_in, with the saved provider's groups settings.

    People are bound to the provider's issuer: the validated ID token's iss, else
    the issuer in the provider's discovery document.
    """
    from .auth.oidc_client import default_http
    from .sso_config import load_sso, overage_resolver

    settings = load_sso(store)
    claim = settings.groups_claim if settings is not None else "groups"
    resolver = overage_resolver(store, settings, default_http) if settings is not None else None

    async def discovered_issuer() -> str:
        return str((await adapter.get_oidc_config())["issuer"])

    return make_sign_in_handler(store, claim, resolver, issuer=discovered_issuer)


def build_streamable_http_app(config: U2Config) -> Any:
    """Build the team-mode Streamable HTTP application.

    Split from run_streamable_http_server so tests can serve the real application.

    Args:
        config: Server configuration

    Returns:
        The Starlette application to serve

    Raises:
        SystemExit: Without U2_SECRET_KEY, or with U2_HTTP_CORS_ORIGINS='*'
    """
    from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
    from starlette.routing import Mount, Route

    from .admin import AdminContext, build_admin_app
    from .admin.services import public_url_for
    from .auth.callback import handle_oauth_callback
    from .auth.provider import U2OAuthProvider
    from .auth.storage import AuthStorage
    from .setup_code import ensure_setup_code

    if config.secret_key is None:
        raise SystemExit(
            "--streamable-http runs team mode, which needs U2_SECRET_KEY (at least 32 "
            "characters). Set it, then add connections in the admin site at /admin. "
            "For a single local user, run u2-mcp without --streamable-http (stdio)."
        )
    # The server sends credentials, so any web page a signed-in user visits could
    # drive it with their session.
    if "*" in config.http_cors_origins:
        raise SystemExit(
            "U2_HTTP_CORS_ORIGINS='*' is refused because this server accepts credentials. "
            "Name the origins that may connect, for example https://claude.ai."
        )
    check_tool_coverage(mcp)

    store = open_team_store(config)
    install_store(store, global_read_only=config.read_only)
    logger.info(f"Team mode: settings database in {store.data_dir}")
    set_tool_thread_limit(config.max_connections)

    # The address saved in the admin site wins, then U2_PUBLIC_URL, then host and
    # port: the same rule the admin site applies to cookies and snippets.
    public_url = public_url_for(store, config)
    # Company sign-in saved in the admin site also drives VS Code's OAuth sign-in.
    # It is read here, at startup: RESTART_NOTE tells admins to restart after changes.
    adapter = _stored_sso_adapter(store, public_url)
    pat_verifier = PatVerifier(
        store, freshness_days=config.token_freshness_days, resource=public_url
    )

    auth_provider = None
    token_verifier = None
    if adapter is not None:
        # It also accepts personal access tokens, validates the ID token (Entra
        # puts groups only there), and records each completed sign-in.
        auth_provider = U2OAuthProvider(
            idp_adapter=adapter,
            issuer_url=public_url,
            token_expiry=config.token_expiry_seconds,
            refresh_token_expiry=config.refresh_token_expiry_seconds,
            storage=AuthStorage(store.locked),
            on_sign_in=_team_sign_in(store, adapter),
            id_token_claims=adapter.client.validate_id_token,
            pat_verifier=pat_verifier.verify_token,
        )
        # Validated here so a malformed address fails at startup, not at sign-in.
        issuer_url = AnyHttpUrl(public_url)
        auth_settings = AuthSettings(
            issuer_url=issuer_url,
            resource_server_url=issuer_url,
            # Keeps today's behaviour (no resource check by the SDK) explicitly.
            validate_token_resource=False,
            client_registration_options=ClientRegistrationOptions(
                enabled=True,  # Required for Claude.ai DCR
                valid_scopes=["u2:read", "u2:write"],
                default_scopes=["u2:read"],
            ),
            revocation_options=RevocationOptions(enabled=True),
            required_scopes=["u2:read"],
        )
        set_identity_resolver(make_identity_resolver(store, auth_provider.storage))
        logger.info("MCP OAuth sign-in uses the admin site's company sign-in")
    else:
        # Without company sign-in, personal access tokens are the only way in.
        token_verifier = pat_verifier
        auth_settings = AuthSettings(
            issuer_url=AnyHttpUrl(public_url),
            resource_server_url=None,
            required_scopes=["u2:read"],
        )
        set_identity_resolver(make_identity_resolver(store, None))
        logger.info("No company sign-in: personal access tokens required")

    # A second instance, because the module-level one was created without auth.
    mcp_streamable = ThreadedFastMCP(
        name="U2 MCP Server",
        auth_server_provider=auth_provider,
        token_verifier=token_verifier,
        auth=auth_settings,
        host=config.http_host,
        port=config.http_port,
        streamable_http_path="/",  # Root path for Claude.ai compatibility
    )

    # Tools, resources and prompts are registered on the module-level instance.
    mcp_streamable._tool_manager._tools.update(mcp._tool_manager._tools)
    mcp_streamable._resource_manager._resources.update(mcp._resource_manager._resources)
    mcp_streamable._prompt_manager._prompts.update(mcp._prompt_manager._prompts)

    # Get the Streamable HTTP app
    app = mcp_streamable.streamable_http_app()

    # Request logging: method, path and outcome. Never a body, never a header: the
    # OAuth responses carry tokens, and a bearer token's prefix is still a secret.
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request as StarletteRequest
    from starlette.responses import Response as StarletteResponse

    class RequestLoggingMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: StarletteRequest, call_next: Any) -> StarletteResponse:
            has_authorization = "authorization" in request.headers

            logger.info(
                "REQUEST: %s %s auth=%s origin=%s",
                request.method,
                request.url.path,
                "present" if has_authorization else "none",
                request.headers.get("origin", "none"),
            )

            response: StarletteResponse = await call_next(request)

            logger.info(
                "RESPONSE: %s %s -> %s",
                request.method,
                request.url.path,
                response.status_code,
            )

            return response

    app.add_middleware(RequestLoggingMiddleware)

    # Add CORS middleware
    app.add_middleware(
        CorsOutsideAdmin,
        allow_origins=config.http_cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Outermost, so every layer (and the admin site) sees the client behind a trusted proxy.
    app.add_middleware(ClientAddressMiddleware, trusted_proxies=config.trusted_proxy_networks)

    # Add custom OAuth callback route for external IdP
    if auth_provider:
        from .auth.basic_client_id import BasicClientIdMiddleware

        # Clients that authenticate with HTTP Basic at /token and /revoke send no
        # client_id in the form; the SDK needs one there.
        app.add_middleware(BasicClientIdMiddleware)

        from starlette.requests import Request
        from starlette.responses import Response

        async def oauth_callback_handler(request: Request) -> Response:
            return await handle_oauth_callback(request, auth_provider)

        # Add route to the app's router
        app.routes.append(Route("/oauth/callback", oauth_callback_handler, methods=["GET"]))

    app.routes.append(_health_route())

    admin_ctx = AdminContext(
        store=store,
        config=config,
        registry=get_connection_registry,
        mcp_oauth=auth_provider is not None,
        oauth_storage=auth_provider.storage if auth_provider is not None else None,
    )
    app.routes.append(Mount("/admin", app=build_admin_app(admin_ctx)))
    setup_code = ensure_setup_code(store)
    if setup_code:
        logger.warning(
            "Admin setup is not finished. Open %s/admin/setup and enter the setup "
            "code %s (also shown by: u2-mcp admin show-setup-code)",
            public_url,
            setup_code,
        )

    return app


def _check_tls_files(config: U2Config) -> None:
    """Stop with a plain message when U2_TLS_CERT or U2_TLS_KEY cannot be read."""
    for setting, value in (("U2_TLS_CERT", config.tls_cert), ("U2_TLS_KEY", config.tls_key)):
        if not value:
            continue
        try:
            with Path(value).open("rb") as handle:
                handle.read(1)
        except OSError as exc:
            raise SystemExit(
                f"{setting} is {value}, which cannot be read ({exc.strerror or exc}). "
                "Mount the file into the container or fix the path."
            ) from exc


def run_streamable_http_server() -> None:
    """Run the team-mode Streamable HTTP server (admin site, PATs, OAuth bridge)."""
    import uvicorn

    config = U2Config()
    _check_tls_files(config)
    app = build_streamable_http_app(config)

    logger.info(
        f"Starting U2 MCP Server (Streamable HTTP) on {config.http_host}:{config.http_port}"
    )
    logger.info(f"MCP endpoint: http://{config.http_host}:{config.http_port}/")
    logger.info(f"CORS origins: {config.http_cors_origins}")

    # Uvicorn would otherwise believe X-Forwarded-* from 127.0.0.1 by itself;
    # U2_TRUSTED_PROXIES (ClientAddressMiddleware) is the only source of that trust.
    uvicorn.run(
        app,
        host=config.http_host,
        port=config.http_port,
        log_level="info",
        proxy_headers=False,
        # U2_TLS_CERT and U2_TLS_KEY (both or neither; U2Config checks) serve https
        # directly, without a reverse proxy. None for both means plain http.
        ssl_certfile=config.tls_cert,
        ssl_keyfile=config.tls_key,
    )


def main() -> None:
    """Entry point for the MCP server."""
    # `u2-mcp admin ...` is a separate command, not a transport flag. Checked
    # first so bare `u2-mcp` (Claude Desktop's stdio launch) is unaffected.
    if len(sys.argv) > 1 and sys.argv[1] == "admin":
        from .cli import run_admin_cli

        sys.exit(run_admin_cli(sys.argv[2:]))

    # A tool without an access check must stop the server, not ship open.
    check_tool_coverage(mcp)

    parser = argparse.ArgumentParser(
        description="U2 MCP Server - Connect AI assistants to Universe/UniData databases"
    )
    parser.add_argument(
        "--streamable-http",
        action="store_true",
        help="Run as Streamable HTTP server for Claude.ai Integrations",
    )
    parser.add_argument(
        "--host",
        type=str,
        default=None,
        help="HTTP server host (overrides U2_HTTP_HOST env var)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="HTTP server port (overrides U2_HTTP_PORT env var)",
    )

    args = parser.parse_args()

    # Override config with CLI args if provided
    if args.host:
        import os

        os.environ["U2_HTTP_HOST"] = args.host
    if args.port:
        import os

        os.environ["U2_HTTP_PORT"] = str(args.port)

    if args.streamable_http:
        run_streamable_http_server()
        return

    config = U2Config()
    missing = [
        name
        for name, value in (
            ("U2_HOST", config.host),
            ("U2_USER", config.user),
            ("U2_PASSWORD", config.password),
            ("U2_ACCOUNT", config.account),
        )
        if not value
    ]
    if missing:
        raise SystemExit(
            f"{', '.join(missing)} must be set for the stdio server. Team mode "
            "(U2_SECRET_KEY, the admin site) runs only with --streamable-http."
        )
    logger.info("Starting U2 MCP Server (stdio mode)")
    mcp.run()


if __name__ == "__main__":
    main()
