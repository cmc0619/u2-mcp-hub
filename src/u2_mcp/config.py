"""Configuration management for u2-mcp using pydantic-settings."""

import ipaddress

from pydantic import (
    Field,
    SecretStr,
    ValidationInfo,
    computed_field,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
_LIST_ALIASES = {
    "admin_allowed_ips": "U2_ADMIN_ALLOWED_IPS",
    "trusted_proxies": "U2_TRUSTED_PROXIES",
}


def _networks(value: str | None) -> list[Network]:
    """Parse a comma-separated list of addresses or CIDR networks; blank entries are skipped."""
    if not value:
        return []
    return [
        ipaddress.ip_network(part.strip(), strict=False)
        for part in value.split(",")
        if part.strip()
    ]


class U2Config(BaseSettings):
    """Configuration for U2 MCP Server, loaded from environment variables.

    Required for stdio (in team mode, --streamable-http with U2_SECRET_KEY, connections
    live in the settings database instead):
        U2_HOST: Universe/UniData server hostname
        U2_USER: Username for authentication
        U2_PASSWORD: Password for authentication
        U2_ACCOUNT: Account name to connect to

    Optional environment variables:
        U2_SERVICE: Service type (uvcs for Universe, udcs for UniData)
        U2_PORT: Server port
        U2_SSL: Enable SSL/TLS
        U2_TIMEOUT: Connection timeout in seconds
        U2_READ_ONLY: Disable write operations
        U2_MAX_RECORDS: Maximum SELECT results
        U2_BLOCKED_COMMANDS: Comma-separated list of blocked TCL commands
        U2_BASIC_FILES: Comma-separated glob patterns naming BASIC program files
    """

    # The stdio login. Team mode ignores these: connections live in the settings database.
    host: str = Field(
        default="",
        alias="U2_HOST",
        description="Universe/UniData server hostname",
    )
    user: str = Field(
        default="",
        alias="U2_USER",
        description="Username for authentication",
    )
    password: str = Field(
        default="",
        alias="U2_PASSWORD",
        description="Password for authentication",
    )
    account: str = Field(
        default="",
        alias="U2_ACCOUNT",
        description="Account name to connect to",
    )

    # Optional connection settings
    service: str = Field(
        default="uvcs",
        alias="U2_SERVICE",
        description="Service type: uvcs (Universe) or udcs (UniData)",
    )
    port: int = Field(
        default=31438,
        alias="U2_PORT",
        description="Server port",
    )
    ssl: bool = Field(
        default=False,
        alias="U2_SSL",
        description="Enable SSL/TLS",
    )
    timeout: int = Field(
        default=30,
        alias="U2_TIMEOUT",
        description="Connection timeout in seconds",
    )

    # Safety settings. Writes are opt-in: like every safety setting, this fails closed.
    read_only: bool = Field(
        default=True,
        alias="U2_READ_ONLY",
        description="Refuse writes. On by default; set false to allow them.",
    )
    max_records: int = Field(
        default=10000,
        alias="U2_MAX_RECORDS",
        description="Maximum SELECT results",
    )
    query_timeout: int = Field(
        default=60,
        alias="U2_QUERY_TIMEOUT",
        description="Maximum seconds for a query to execute before timeout",
    )
    # Store as string to avoid pydantic-settings JSON parsing issues
    blocked_commands_str: str = Field(
        default="DELETE.FILE,CLEAR.FILE,CNAME,CREATE.FILE",
        alias="U2_BLOCKED_COMMANDS",
        description="Comma-separated list of blocked TCL commands",
    )
    basic_files_str: str = Field(
        default="*BP,BP.*",
        alias="U2_BASIC_FILES",
        description="Comma-separated glob patterns naming the files that hold BASIC source",
    )

    # HTTP Server settings (for centralized deployment)
    http_host: str = Field(
        default="127.0.0.1",
        alias="U2_HTTP_HOST",
        description="Host to bind the HTTP server to. Set 0.0.0.0 in a container.",
    )
    http_port: int = Field(
        default=8080,
        alias="U2_HTTP_PORT",
        description="Port for HTTP server",
    )
    http_cors_origins_str: str = Field(
        default="",
        alias="U2_HTTP_CORS_ORIGINS",
        description=(
            "Comma-separated list of browser origins allowed to connect. Empty by "
            "default, which blocks cross-origin browser access; non-browser MCP "
            "clients are unaffected. '*' is refused because this server sends "
            "credentials."
        ),
    )

    max_connections: int = Field(
        default=25,
        alias="U2_MAX_CONNECTIONS",
        description=(
            "Most database sessions to hold open at once. With personal U2 logins each "
            "person holds one, so this bounds what a crowd of callers can consume."
        ),
    )
    # Team mode: settings database, access control and personal access tokens
    secret_key: SecretStr | None = Field(
        default=None,
        alias="U2_SECRET_KEY",
        description=(
            "Required by --streamable-http (team mode); encrypts the secrets in "
            "the settings database. At least 32 characters. Keep it in your vault: "
            "without it, stored U2 passwords cannot be read."
        ),
    )
    data_dir: str = Field(
        default="/data",
        alias="U2_DATA_DIR",
        description="Directory for settings and database knowledge",
    )
    public_url: str | None = Field(
        default=None,
        alias="U2_PUBLIC_URL",
        description="The URL people use to reach this server, e.g. https://u2-mcp.corp.example",
    )
    token_freshness_days: int = Field(
        default=30,
        alias="U2_TOKEN_FRESHNESS_DAYS",
        description=(
            "An SSO user's personal access tokens stop working when they have not "
            "signed in through SSO for this many days"
        ),
    )
    admin_allowed_ips: str | None = Field(
        default=None,
        alias="U2_ADMIN_ALLOWED_IPS",
        description=(
            "Comma-separated addresses or CIDR networks allowed to reach /admin. "
            "Unset means every address that can reach the server."
        ),
    )
    admin_signin_limit: int = Field(
        default=5,
        alias="U2_ADMIN_SIGNIN_LIMIT",
        ge=0,
        description=(
            "Admin sign-in attempts allowed per minute for each address and each "
            "username. 0 turns the limit off (development only)."
        ),
    )
    trusted_proxies: str | None = Field(
        default=None,
        alias="U2_TRUSTED_PROXIES",
        description=(
            "Comma-separated addresses or CIDR networks of reverse proxies whose "
            "X-Forwarded-For and X-Forwarded-Proto headers are believed. Unset trusts none."
        ),
    )
    tls_cert: str | None = Field(
        default=None,
        alias="U2_TLS_CERT",
        description="Certificate file (PEM) for serving https directly, without a proxy",
    )
    tls_key: str | None = Field(
        default=None,
        alias="U2_TLS_KEY",
        description="Private key file (PEM) for U2_TLS_CERT",
    )

    # Token settings
    token_expiry_seconds: int = Field(
        default=3600,
        alias="U2_TOKEN_EXPIRY_SECONDS",
        description="Access token expiry time in seconds",
    )
    refresh_token_expiry_seconds: int = Field(
        default=2592000,  # 30 days
        alias="U2_REFRESH_TOKEN_EXPIRY_SECONDS",
        description="Refresh token expiry time in seconds",
    )

    @computed_field
    @property
    def blocked_commands(self) -> list[str]:
        """Parse comma-separated string into list of commands."""
        return [cmd.strip().upper() for cmd in self.blocked_commands_str.split(",") if cmd.strip()]

    @computed_field
    @property
    def basic_files(self) -> list[str]:
        """Parse U2_BASIC_FILES into glob patterns."""
        return [p.strip() for p in self.basic_files_str.split(",") if p.strip()]

    @computed_field
    @property
    def http_cors_origins(self) -> list[str]:
        """Parse comma-separated CORS origins into list."""
        origins = self.http_cors_origins_str.strip()
        if origins == "*":
            return ["*"]
        return [o.strip() for o in origins.split(",") if o.strip()]

    @field_validator("service")
    @classmethod
    def validate_service(cls, v: str) -> str:
        """Validate service type is uvcs or udcs."""
        v_lower = v.lower()
        if v_lower not in ("uvcs", "udcs"):
            raise ValueError("service must be 'uvcs' (Universe) or 'udcs' (UniData)")
        return v_lower

    @field_validator("secret_key")
    @classmethod
    def _blank_secret_key_is_unset(cls, value: SecretStr | None) -> SecretStr | None:
        """Treat an empty or whitespace U2_SECRET_KEY (common in compose files) as unset."""
        if value is not None and not value.get_secret_value().strip():
            return None
        return value

    @field_validator("admin_allowed_ips", "trusted_proxies")
    @classmethod
    def _check_address_lists(cls, value: str | None, info: ValidationInfo) -> str | None:
        """Reject a list entry that is not an address or network."""
        if value:
            for entry in (part.strip() for part in value.split(",")):
                if not entry:
                    continue
                try:
                    ipaddress.ip_network(entry, strict=False)
                except ValueError as exc:
                    alias = _LIST_ALIASES[str(info.field_name)]
                    raise ValueError(
                        f"{alias} entry '{entry}' is not an address or network"
                    ) from exc
        return value

    @model_validator(mode="after")
    def _tls_pair(self) -> "U2Config":
        """A certificate is useless without its key, and the reverse."""
        if bool(self.tls_cert) != bool(self.tls_key):
            raise ValueError("Set both U2_TLS_CERT and U2_TLS_KEY, or neither.")
        return self

    @property
    def admin_allowed_networks(self) -> list[Network]:
        """Return the /admin allowlist as networks; empty means no restriction."""
        return _networks(self.admin_allowed_ips)

    @property
    def trusted_proxy_networks(self) -> list[Network]:
        """Return U2_TRUSTED_PROXIES as networks; empty means trust no forwarded header."""
        return _networks(self.trusted_proxies)

    model_config = {
        "env_prefix": "",
        "case_sensitive": False,
        # Read environment variables only by their U2_* aliases. Allowing the
        # field name too would fill `user` from the shell's $USER.
        "populate_by_name": False,
    }
