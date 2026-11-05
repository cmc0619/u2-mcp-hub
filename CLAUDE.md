# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

u2-mcp is a Python MCP (Model Context Protocol) server that enables AI assistants to interact with Rocket Universe and UniData MultiValue databases. It uses Rocket's official `uopy` package and preserves native MultiValue semantics (multivalues, subvalues, dynamic arrays) rather than flattening to relational models.

## Development Commands

```bash
pip install -e ".[dev]"                     # Install with dev dependencies

pytest                                      # All tests
pytest tests/test_config.py                 # Single file
pytest tests/test_utils/test_safety.py -k "test_name"  # Single test
pytest --cov=u2_mcp --cov-report=html       # With coverage
pytest tests/integration/ --run-integration # Integration tests (requires DB)

ruff check .                                # Lint
ruff format .                               # Format
mypy src/                                   # Type check
```

## Architecture

### Run modes

`server.py:main` has exactly two:
- **stdio** (default): `u2-mcp`, single user. One U2 login from `U2_HOST`, `U2_USER`, `U2_PASSWORD`, `U2_ACCOUNT` (refuses to start if one is missing). No admin site, OAuth or audit table.
- **Team mode**: `u2-mcp --streamable-http`. Requires `U2_SECRET_KEY`. Connections, people, roles, grants, company sign-in, knowledge, audit and OAuth state live in the settings database (`U2_DATA_DIR/u2-mcp.db`), edited on the admin site at `/admin`. The MCP OAuth bridge is on only when company sign-in is saved and the public address is https (or localhost); otherwise personal access tokens are the only way in.

`u2-mcp admin ...` (cli.py) is a separate recovery command, not a transport.

### Tool registration and the guard

Tools are registered with `@mcp.tool()` on the module-level `ThreadedFastMCP` instance in `server.py`; each `tools/*.py` module imports `mcp` and the bottom of `server.py` imports the tool and resource modules. Every tool is wrapped by `guard.guarded`, which runs on the worker thread (threaded.py), checks the caller's permission (access.py, permissions.py), installs the route (routing.py), runs the tool and, in team mode, records the audit row (`summarize_parameters` shrinks BASIC source to size+hash and redacts secret-named params). `check_tool_coverage()` stops startup if a tool lacks the guard or a permission. Resources use `@mcp.resource("u2://name")`.

### Module Layout

```
src/u2_mcp/
├── server.py           # FastMCP instance; connect/disconnect/list_sessions/list_connections; stdio and team-mode Streamable HTTP entry points
├── guard.py            # The one tool wrapper: permission check, route, worker thread, team-mode audit row
├── threaded.py         # ThreadedFastMCP: sync tools run on worker threads, off the event loop
├── registry.py         # Bounded one-session-per-route registry (U2_MAX_CONNECTIONS); stdio uses the env login
├── connection.py       # ConnectionManager: one uopy session + its info, file handle cache, TCL with timeout, transactions
├── credentials.py      # U2Credentials
├── driver.py           # Which driver module (uopy by default; U2_DRIVER is a test hook)
├── config.py           # U2Config (pydantic-settings): every env var
├── access.py           # Who may do what on which connection (shared by tools and admin)
├── permissions.py      # Permission names and the tool -> permission map
├── routing.py          # Turns an access decision into a route (connection + login)
├── identity.py         # The caller behind the current request
├── team_auth.py        # Personal access token verifier, identity resolver, SSO sign-in handler
├── tokens.py           # Personal access tokens (hashed)
├── passwords.py        # argon2id
├── proxy.py            # U2_TRUSTED_PROXIES handling of X-Forwarded-*
├── sso_config.py       # Company sign-in settings in the settings database
├── setup_code.py       # Setup wizard state and the one-time setup code
├── connection_check.py # The Test button: connect + COUNT VOC within 10 s
├── cli.py              # u2-mcp admin show-setup-code / reset-password / set-public-url
├── admin/              # Admin site at /admin: Starlette + Jinja2 + vendored htmx
│   ├── app.py          # build_admin_app; routes_*.py hold the pages
│   ├── services.py     # Every admin change (wizard and everyday pages share these)
│   └── security.py     # Sessions, CSRF, sign-in rate limit, U2_ADMIN_ALLOWED_IPS
├── auth/               # MCP OAuth bridge (team mode, company sign-in only)
│   ├── provider.py     # U2OAuthProvider: DCR, authorize, token, revoke
│   ├── callback.py     # /oauth/callback route handler
│   ├── storage.py      # AuthStorage: clients, codes, tokens, pending sign-ins in the settings DB
│   ├── oidc_client.py  # OIDC authorization code + PKCE client
│   ├── graph.py        # Microsoft Graph lookup for Entra group overage
│   └── idp/
│       ├── base.py     # Dataclasses the adapter hands the bridge
│       └── stored.py   # StoredSsoAdapter: the admin site's company sign-in
├── store/              # Settings database (team mode)
│   ├── schema.py       # The single schema, incl. oauth_* and knowledge tables
│   ├── db.py           # Open the database, create the schema
│   ├── repo.py         # Every read and write
│   ├── models.py       # Row types
│   ├── crypto.py       # Encryption of stored secrets with U2_SECRET_KEY
│   └── bootstrap.py    # Team-mode startup: open the store
├── tools/              # MCP tools: files, query, dictionary, subroutine, transaction, basic, update, knowledge
├── resources/          # u2://syntax/*, u2://examples/*, u2://knowledge
└── utils/
    ├── dynarray.py     # Dynamic array parsing (AM/VM/SM marks)
    ├── export.py       # records_to_json, records_to_csv
    ├── safety.py       # Command validation, blocklist checking
    ├── basic_source.py # BASIC tool helpers: names, source, hashes, compiler output
    ├── record_lock.py  # Record locking for safe changes
    └── knowledge.py    # KnowledgeStore in SQLite: normalized server/account scopes in both modes
```

### Key Data Flow

1. Client calls an MCP tool; ThreadedFastMCP runs it on a worker thread through `guard.guarded`
2. The guard identifies the caller, decides access, installs the route
3. The tool calls `get_connection_manager()`; the registry hands out (or opens) the route's session
4. `ConnectionManager` uses the driver (`uopy`) to talk to Universe/UniData; a dead session is replaced on the next request
5. In team mode the guard writes the audit row to the settings database

## Key Concepts

**MultiValue Data Structure**: Records use attribute marks (AM `chr(254)`), value marks (VM `chr(253)`), and subvalue marks (SM `chr(252)`) to create nested data. The `dynarray.py` module parses these into Python dicts/lists.

**Connection Pattern**: One `ConnectionManager` (one session) per route, held by the bounded registry. File handles are cached in `_open_files`. TCL commands run in a separate thread with `query_timeout` to prevent hangs. A dead session is replaced on the next request.

**Safety Controls**: Command blocklist (default: `DELETE.FILE,CLEAR.FILE,CNAME,CREATE.FILE`), read-only mode, query timeouts, and record count limits.

## Testing

Tests do not require a live database. The `tests/mocks/mock_uopy.py` module provides `MockSession`, `MockFile`, `MockCommand`, `MockSelect`, and `MockSubroutine` that simulate `uopy` behavior. Key conftest fixtures:
- `mock_env` — patches required env vars (`U2_HOST`, `U2_USER`, etc.)
- `mock_config` / `mock_config_read_only` — creates `U2Config` from mock env
- `mock_uopy` — patches `uopy.connect` to return `MockSession`
- `sample_record_data` — provides AM/VM delimited test records

Browser tests live in `tests/e2e` (Playwright). Run `python -m playwright install chromium` once, then `pytest -m e2e tests/e2e -n 0`. Plain `pytest` skips them, and runs the rest in parallel (`-n auto`, pytest-xdist) with cheap test-only argon2 hashing.

## Environment Variables

stdio requires `U2_HOST`, `U2_USER`, `U2_PASSWORD`, `U2_ACCOUNT`; team mode requires `U2_SECRET_KEY` (connections are added in the admin site).

- **Connection (stdio)**: `U2_SERVICE` (uvcs/udcs), `U2_PORT`, `U2_SSL`, `U2_TIMEOUT`
- **Safety**: `U2_READ_ONLY`, `U2_MAX_RECORDS`, `U2_QUERY_TIMEOUT`, `U2_BLOCKED_COMMANDS`, `U2_BASIC_FILES`
- **HTTP**: `U2_HTTP_HOST`, `U2_HTTP_PORT`, `U2_HTTP_CORS_ORIGINS`, `U2_MAX_CONNECTIONS`
- **Team mode**: `U2_SECRET_KEY`, `U2_DATA_DIR`, `U2_PUBLIC_URL`, `U2_TOKEN_FRESHNESS_DAYS`, `U2_ADMIN_ALLOWED_IPS`, `U2_ADMIN_SIGNIN_LIMIT`, `U2_TRUSTED_PROXIES`, `U2_TLS_CERT`, `U2_TLS_KEY`, `U2_TOKEN_EXPIRY_SECONDS`, `U2_REFRESH_TOKEN_EXPIRY_SECONDS`

All config is in `config.py` (U2Config pydantic-settings class) using Field aliases matching env var names.

## Coding Standards

- Follow PEP 8; use ruff for linting/formatting
- Maximum line length: 100 characters
- Type hints required for all function signatures
- Google-style docstrings for public APIs
- Ruff rules: `select = ["E", "F", "I", "UP", "B", "SIM"]`
- mypy: `disallow_untyped_defs = true`, `ignore_missing_imports = true`
