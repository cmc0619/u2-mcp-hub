# Admin UI phase 2a: sign-in, setup wizard and connections — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give team mode its first web pages: local admin sign-in, the setup wizard (admin account, first connection, server address, done), the Connections pages, the `u2-mcp admin` commands, and browser tests proving the wizard works.

**Architecture:** A Starlette sub-application mounted at `/admin` inside the existing Streamable HTTP app, only in team mode. Pages are server-rendered with Jinja2; htmx (vendored, no CDN) does partial updates such as connection test results. Every write goes through one services module (`admin/services.py`) that both the wizard and the everyday pages call, and that writes an `audit` row of kind `admin`. Admin sessions are stored in the settings database so that signing out, disabling a user or resetting a password ends them at once.

**Tech Stack:** Python 3.10+, Starlette (already a dependency), Jinja2, argon2-cffi, python-multipart, htmx 2.0.4 (vendored), pytest, pytest-playwright (Chromium) for browser tests.

Spec: `docs/superpowers/specs/2026-10-30-admin-ui-design.md` (sections "Sign-in > Local accounts", "Admin site security", "Admin site", "Error handling", "Testing" item 6).
Roadmap: `docs/superpowers/plans/2026-10-30-admin-ui-roadmap.md`. Phase 2 is split: this plan (2a), then 2b (dashboard, users, groups, roles and grants, audit, the rest of settings, My access and tokens, the remaining browser tests), planned after 2a lands.

## Global Constraints

- Python floor 3.10. Ruff (`ruff==0.16.5`, line length 100, rules `E,F,I,UP,B,SIM`), `ruff format`, and `mypy src/` must stay clean. Google-style docstrings on public functions. Type hints on every signature.
- New runtime dependencies, exactly: `jinja2>=3.1.4`, `argon2-cffi>=23.1.0`, `python-multipart>=0.0.18`. New dev dependency: `pytest-playwright>=0.5.0`.
- No CDN. htmx 2.0.4 is vendored at `src/u2_mcp/admin/static/htmx.min.js`.
- Jinja2 autoescape is on for `.html` templates. Never mark user-supplied text `|safe`.
- The admin site is mounted at `/admin` only in team mode (store present). The MCP endpoint stays at `/`. `/health` is added in every HTTP mode and returns `{"status": "ok"}`.
- Session cookie: name `u2_admin_session`, `HttpOnly`, `SameSite=Lax`, `Path=/admin`, `Secure` when the effective public URL starts with `https://`. Absolute lifetime 8 hours (28800 s). Idle timeout 30 minutes (1800 s). Only the SHA-256 hash of the session id is stored.
- CSRF: every state-changing request carries the session's token in form field `csrf_token` or header `X-CSRF-Token`. Forms shown before sign-in (sign-in, setup step 1) use a double-submit cookie `u2_admin_presession` (`HttpOnly`, `SameSite=Strict`, `Path=/admin`) whose value is repeated in the `csrf_token` field.
- Sign-in attempts: at most 5 per 60 seconds per client IP and, separately, per lower-cased username.
- `U2_ADMIN_ALLOWED_IPS` (optional, comma-separated addresses or CIDR networks): when set, every `/admin` request from another address gets 403. The client address is `scope["client"][0]`, the same value `ClientAddressMiddleware` records. (Phase 3 adds trusted-proxy handling.)
- Passwords: argon2id via `argon2.PasswordHasher()` defaults. Minimum length 12.
- Test connection: opens a session and runs `COUNT VOC` with a 10-second limit, off the event loop, never creating a registry slot.
- Setup step names, in order: `admin`, `connection`, `server_address`, `done`. Setting `setup_state` holds the furthest completed step name. Setting `setup_complete` is `true` once Finish is pressed.
- Audit rows for admin changes use `kind="admin"` and these actions: `connection.create`, `connection.update`, `connection.delete`, `connection.switches`, `connection.disconnect`, `user.create`, `user.reset_password`, `settings.public_url`, `setup.finish`. Sign-in events use `kind="auth"` and actions `admin.sign_in` (outcome `ok` or `failed`), `admin.sign_out`, `admin.password_change`.
- User-visible messages, exactly:
  - Wrong credentials (also unknown or disabled user): `Wrong username or password.`
  - Rate limited: `Too many sign-in attempts. Wait a minute and try again.`
  - Local sign-in off for non-admins: `Local sign-in is turned off. Use your company sign-in.`
  - Non-admin on an admin page: `Only admins can use this page.`
  - Wrong setup code: `That setup code is not right. Find the current code in the server log, or run: u2-mcp admin show-setup-code`
  - Concurrent edit: `Someone else changed this connection since you opened it. Reload to see their changes.`
  - Test timeout: `No answer from <host>:<port> within 10 seconds.`
  - Short password: `Use at least 12 characters.`
  - Password equals username: `Don't use your username as your password.`
  - Passwords differ: `The two passwords don't match.`
  - Not https: `This address is not https. Sign-in cookies and tokens would cross the network unencrypted.`
  - Public URL needs restart: `Restart the server for OAuth sign-in and personal access tokens to use a changed address.`
  - Disallowed address: `Not allowed from this address.`
- Every form page follows POST-redirect-GET on success, so Refresh never resubmits.
- Plain `pytest` must not need browsers: browser tests carry the `e2e` marker and `addopts` deselects it. The CI e2e job runs them and must fail, not skip, when browsers are missing.
- Never `git add -f`. `.superpowers/` is git-ignored scratch.

## Decisions taken while planning

| Question | Decision |
|---|---|
| Playwright "against the built Docker image" (spec) while the Dockerfile is phase 3 | Phase 2a runs the browser suite against a real `python -m u2_mcp --streamable-http` subprocess. Server start-up is isolated in one function (`launch_server` in `tests/e2e/conftest.py`) so phase 3 can switch it to the image. |
| Wizard step 4 (SSO) and its Test pop-up | Phase 3. Phase 2a's wizard has steps admin, connection, server address, done. Steps are stored by name, so phase 3 inserts `sso` without a migration. The Done page lists company sign-in as "not available yet". |
| Public URL saved in the UI | Takes effect at once for the cookie `Secure` flag and the Copilot snippets. OAuth issuer and token resource are read at start-up, so the page says a restart is needed for those. |
| Team mode on an empty `/data` with no `U2_HOST` | Allowed. `U2_HOST`, `U2_USER`, `U2_PASSWORD` and `U2_ACCOUNT` become required only outside team mode. With no `U2_HOST`, nothing is imported and the wizard creates the first connection. |
| Per-user connections and Test | The connection form's login fields are saved for `shared` connections. For `per_user` connections they are a test login only and are not saved. |
| Which admin page is the landing page in 2a | `/admin/` goes to the wizard until setup is finished, then to `/admin/connections`. Phase 2b adds the dashboard. |
| Non-admin local users | None can be created in 2a. If one signs in, every page answers `Only admins can use this page.` Phase 2b adds My access. |

## File structure

Create:

| File | Responsibility |
|---|---|
| `src/u2_mcp/store/schema.py` (add `SCHEMA_V2`) | Version 2: `version` columns, `must_change_password`, `admin_sessions` |
| `src/u2_mcp/passwords.py` | argon2id hashing, verification, password rules, one-time passwords |
| `src/u2_mcp/setup_code.py` | Setup state, the one-time setup code, finishing setup |
| `src/u2_mcp/cli.py` | `u2-mcp admin show-setup-code` and `u2-mcp admin reset-password <user>` |
| `src/u2_mcp/connection_check.py` | `check_connection`: connect and run `COUNT VOC` within 10 seconds |
| `src/u2_mcp/admin/__init__.py` | `AdminContext`, `build_admin_app` |
| `src/u2_mcp/admin/templating.py` | Jinja2 environment and `render` |
| `src/u2_mcp/admin/security.py` | Sessions, CSRF, rate limiter, address allowlist, middleware, `require_admin` |
| `src/u2_mcp/admin/services.py` | Every admin write: connections, local users, public URL; audit |
| `src/u2_mcp/admin/routes_auth.py` | Sign-in, sign-out, change password |
| `src/u2_mcp/admin/routes_connections.py` | Connections list, add, edit, test, switches, disconnect, delete |
| `src/u2_mcp/admin/routes_setup.py` | Setup wizard and the Settings page |
| `src/u2_mcp/admin/templates/…` | `base.html`, `message.html`, `sign_in.html`, `change_password.html`, `connections/*.html`, `setup/*.html`, `settings.html`, `partials/*.html` |
| `src/u2_mcp/admin/static/htmx.min.js`, `styles.css` | Vendored htmx, plain CSS |
| `tests/mocks/sim_driver.py` | A `U2_DRIVER` module with scripted failures for browser tests |
| `tests/test_passwords.py`, `tests/test_setup_code.py`, `tests/test_cli.py`, `tests/test_connection_check.py` | Unit tests |
| `tests/test_admin/…` | Services, security and route tests (Starlette `TestClient`) |
| `tests/e2e/conftest.py`, `tests/e2e/test_setup_wizard.py`, `tests/e2e/test_connections_pages.py` | Playwright browser tests |

Modify: `pyproject.toml`, `src/u2_mcp/config.py`, `src/u2_mcp/store/db.py`, `src/u2_mcp/store/models.py`, `src/u2_mcp/store/repo.py`, `src/u2_mcp/store/bootstrap.py`, `src/u2_mcp/registry.py`, `src/u2_mcp/utils/knowledge.py`, `src/u2_mcp/server.py`, `.github/workflows/ci.yml`, `docs/configuration.md`, `CHANGELOG.md`, `docs/superpowers/plans/2026-10-30-admin-ui-roadmap.md`.

---

### Task 1: Dependencies and configuration for an empty team-mode server

**Files:**
- Modify: `pyproject.toml`
- Modify: `src/u2_mcp/config.py`
- Modify: `src/u2_mcp/store/bootstrap.py` (`open_team_store`)
- Modify: `src/u2_mcp/server.py` (`main`, stdio branch)
- Test: `tests/test_config.py`, `tests/test_store/test_bootstrap.py`

**Interfaces:**
- Produces: `U2Config.admin_allowed_ips: str | None` (alias `U2_ADMIN_ALLOWED_IPS`); `U2Config.admin_allowed_networks -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]` (property; empty list when unset); `U2Config.host/user/password/account` default `""` and are required only when `secret_key` is None.
- `open_team_store(config)` skips the environment import when `config.host` is empty.

- [ ] **Step 1: Add dependencies**

In `pyproject.toml`, add to `[project].dependencies` after `"cryptography>=42.0.0",`:

```toml
    "jinja2>=3.1.4",
    "argon2-cffi>=23.1.0",
    "python-multipart>=0.0.18",
```

Add to `[project.optional-dependencies].dev` after `"mypy>=1.0.0",`:

```toml
    "pytest-playwright>=0.5.0",
```

Replace the `[tool.pytest.ini_options]` block with:

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
markers = [
    "integration: marks tests as integration tests (deselect with '-m \"not integration\"')",
    "e2e: browser tests against a running server (run with: pytest -m e2e tests/e2e)",
]
addopts = "-v -m \"not e2e\""
```

Run: `pip install -e ".[dev]"`
Expected: installs jinja2, argon2-cffi, python-multipart, pytest-playwright without error.

- [ ] **Step 2: Write the failing config tests**

Append to `tests/test_config.py`:

```python
class TestTeamModeWithoutEnvironmentConnection:
    """Team mode can start on an empty /data, before any connection exists."""

    def test_connection_settings_are_optional_in_team_mode(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for name in ("U2_HOST", "U2_USER", "U2_PASSWORD", "U2_ACCOUNT"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("U2_SECRET_KEY", "k" * 40)

        config = U2Config()

        assert config.host == ""

    def test_connection_settings_are_required_outside_team_mode(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for name in ("U2_HOST", "U2_USER", "U2_PASSWORD", "U2_ACCOUNT", "U2_SECRET_KEY"):
            monkeypatch.delenv(name, raising=False)

        with pytest.raises(ValidationError, match="U2_HOST"):
            U2Config()

    def test_admin_allowlist_parses_addresses_and_networks(
        self, mock_env: dict[str, str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("U2_ADMIN_ALLOWED_IPS", "10.0.0.0/8, 192.168.1.5")

        networks = U2Config().admin_allowed_networks

        assert [str(n) for n in networks] == ["10.0.0.0/8", "192.168.1.5/32"]

    def test_admin_allowlist_rejects_garbage(
        self, mock_env: dict[str, str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("U2_ADMIN_ALLOWED_IPS", "10.0.0.0/8,not-an-address")

        with pytest.raises(ValidationError, match="not-an-address"):
            U2Config()

    def test_admin_allowlist_defaults_to_everyone(self, mock_env: dict[str, str]) -> None:
        assert U2Config().admin_allowed_networks == []
```

Make sure `tests/test_config.py` imports `pytest`, `ValidationError` (`from pydantic import ValidationError`) and `U2Config`; add any that are missing.

Run: `pytest tests/test_config.py -k "TeamModeWithoutEnvironmentConnection" -v`
Expected: FAIL (`host` is required; `admin_allowed_networks` does not exist).

- [ ] **Step 3: Implement the configuration changes**

In `src/u2_mcp/config.py`:

1. Change the import line to:

```python
import ipaddress

from pydantic import Field, SecretStr, computed_field, field_validator, model_validator
```

2. Replace the four "Required connection settings" fields with:

```python
    # Connection settings. Required outside team mode; in team mode connections
    # live in the settings database and these, when set, seed the first one.
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
```

3. After the `token_freshness_days` field, add:

```python
    admin_allowed_ips: str | None = Field(
        default=None,
        alias="U2_ADMIN_ALLOWED_IPS",
        description=(
            "Comma-separated addresses or CIDR networks allowed to reach /admin. "
            "Unset means every address that can reach the server."
        ),
    )
```

4. Add these methods to the class (beside the other validators):

```python
    @field_validator("admin_allowed_ips")
    @classmethod
    def _check_admin_allowed_ips(cls, value: str | None) -> str | None:
        """Reject an allowlist entry that is not an address or network."""
        if value:
            for entry in (part.strip() for part in value.split(",")):
                if not entry:
                    continue
                try:
                    ipaddress.ip_network(entry, strict=False)
                except ValueError as exc:
                    raise ValueError(
                        f"U2_ADMIN_ALLOWED_IPS entry '{entry}' is not an address or network"
                    ) from exc
        return value

    @model_validator(mode="after")
    def _require_connection_outside_team_mode(self) -> "U2Config":
        """Outside team mode the environment is the only connection, so it must be complete."""
        if self.secret_key is None:
            missing = [
                name
                for name, value in (
                    ("U2_HOST", self.host),
                    ("U2_USER", self.user),
                    ("U2_PASSWORD", self.password),
                    ("U2_ACCOUNT", self.account),
                )
                if not value
            ]
            if missing:
                raise ValueError(
                    f"{', '.join(missing)} must be set. (In team mode, with U2_SECRET_KEY "
                    "set, connections are added in the admin site instead.)"
                )
        return self

    @property
    def admin_allowed_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        """Return the /admin allowlist as networks; empty means no restriction."""
        if not self.admin_allowed_ips:
            return []
        return [
            ipaddress.ip_network(part.strip(), strict=False)
            for part in self.admin_allowed_ips.split(",")
            if part.strip()
        ]
```

5. Update the class docstring's "Required" wording if it lists these four as always required: say they are required unless `U2_SECRET_KEY` is set.

Run: `pytest tests/test_config.py -v`
Expected: PASS, including the existing tests.

- [ ] **Step 4: Write the failing bootstrap test**

Append to `tests/test_store/test_bootstrap.py`:

```python
def test_team_mode_without_u2_host_imports_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty /data with no U2_HOST starts with no connections; the wizard adds one."""
    for name in ("U2_HOST", "U2_USER", "U2_PASSWORD", "U2_ACCOUNT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("U2_SECRET_KEY", "k" * 40)
    monkeypatch.setenv("U2_DATA_DIR", str(tmp_path))

    store = open_team_store(U2Config())

    assert store is not None
    assert store.list_connections() == []
    assert store.get_setting("environment_import") is None
```

Add any missing imports (`Path`, `pytest`, `U2Config`, `open_team_store`) at the top of the file, matching how the file already imports them.

Run: `pytest tests/test_store/test_bootstrap.py -k without_u2_host -v`
Expected: FAIL (the import runs with an empty host and creates a connection, or raises).

- [ ] **Step 5: Skip the import when there is nothing to import**

In `src/u2_mcp/store/bootstrap.py`, in `open_team_store`, change:

```python
    if state is None and not store.has_connections():
        import_environment(store, config)
```

to:

```python
    # With no U2_HOST there is nothing to import: the setup wizard adds the first
    # connection. The import stays pending, so setting U2_HOST before any
    # connection exists still imports it on the next start.
    if state is None and not store.has_connections() and config.host:
        import_environment(store, config)
```

- [ ] **Step 6: Keep stdio honest**

In `src/u2_mcp/server.py`, in `main()`, inside the final `else:` (stdio) branch, directly after `config = U2Config()`, add:

```python
        if not config.host:
            raise SystemExit(
                "U2_HOST, U2_USER, U2_PASSWORD and U2_ACCOUNT must be set for the stdio "
                "server. Team mode (U2_SECRET_KEY) applies only to --streamable-http."
            )
```

Run: `pytest -q`
Expected: all tests pass (the e2e directory does not exist yet).

- [ ] **Step 7: Lint, type-check and commit**

Run: `ruff check . && ruff format --check . && mypy src/`
Expected: clean.

```bash
git add pyproject.toml src/u2_mcp/config.py src/u2_mcp/store/bootstrap.py src/u2_mcp/server.py tests/test_config.py tests/test_store/test_bootstrap.py
git commit -m "feat: team mode starts without U2_HOST; admin allowlist setting; admin-site dependencies"
```

---

### Task 2: Schema version 2

**Files:**
- Modify: `src/u2_mcp/store/schema.py`
- Modify: `src/u2_mcp/store/db.py`
- Modify: `src/u2_mcp/store/models.py`
- Test: `tests/test_store/test_db.py`

**Interfaces:**
- Produces: `SCHEMA_V2` (SQL string); `MIGRATIONS = {1: SCHEMA_V1, 2: SCHEMA_V2}`; `SCHEMA_VERSION == 2`.
- Produces on models: `Connection.version: int = 1`, `Role.version: int = 1`, `User.must_change_password: bool = False` (all appended last, with defaults, so existing constructors keep working); new frozen dataclass `AdminSession(id_hash: str, user_id: int, csrf_token: str, created_at: float, last_seen_at: float, ip: str | None)`.

- [ ] **Step 1: Write the failing migration tests**

Append to `tests/test_store/test_db.py`:

```python
class TestVersionTwo:
    """The first real migration: an existing version-1 database moves to version 2."""

    def _version_one_database(self, path: Path) -> None:
        from u2_mcp.store.schema import SCHEMA_V1

        conn = sqlite3.connect(str(path), isolation_level=None)
        try:
            migrate(conn, path, migrations={1: SCHEMA_V1})
            conn.execute(
                "INSERT INTO connections (name, host, port, service, account, login_mode, "
                "created_at, updated_at) VALUES ('Prod', 'h', 1, 'uvcs', 'A', 'shared', 0, 0)"
            )
            conn.execute(
                "INSERT INTO users (kind, username, created_at) VALUES ('local', 'ann', 0)"
            )
        finally:
            conn.close()

    def test_existing_rows_survive_with_defaults(self, tmp_path: Path) -> None:
        path = tmp_path / DATABASE_FILENAME
        self._version_one_database(path)

        conn = open_database(path)
        try:
            assert current_version(conn) == 2
            assert conn.execute("SELECT version FROM connections").fetchone()[0] == 1
            assert conn.execute("SELECT must_change_password FROM users").fetchone()[0] == 0
        finally:
            conn.close()

    def test_a_backup_is_taken_before_migrating(self, tmp_path: Path) -> None:
        path = tmp_path / DATABASE_FILENAME
        self._version_one_database(path)

        open_database(path).close()

        backups = list(tmp_path.glob(f"{DATABASE_FILENAME}.bak-1-*"))
        assert len(backups) == 1
        copy = sqlite3.connect(str(backups[0]))
        try:
            assert copy.execute("SELECT version FROM schema_version").fetchone()[0] == 1
        finally:
            copy.close()

    def test_admin_sessions_table_exists(self, tmp_path: Path) -> None:
        conn = open_database(tmp_path / DATABASE_FILENAME)
        try:
            columns = {row[1] for row in conn.execute("PRAGMA table_info(admin_sessions)")}
        finally:
            conn.close()

        assert columns == {"id_hash", "user_id", "csrf_token", "created_at", "last_seen_at", "ip"}
```

Make sure the file imports `sqlite3`, `Path`, `DATABASE_FILENAME`, `current_version`, `migrate` and `open_database` (from `u2_mcp.store.db`); add any that are missing.

Run: `pytest tests/test_store/test_db.py -k TestVersionTwo -v`
Expected: FAIL (version stays 1; no `admin_sessions`).

- [ ] **Step 2: Add the migration**

Append to `src/u2_mcp/store/schema.py`:

```python
# Version 2: the admin site.
#   version             -- optimistic locking: an edit names the version it started
#                          from, and a save against a newer one is refused
#   must_change_password -- set by `u2-mcp admin reset-password`
#   admin_sessions      -- server-side sessions, so sign-out, disabling a user and
#                          a password reset end them at once. Only a hash of the
#                          session id is stored.
SCHEMA_V2 = """
ALTER TABLE connections ADD COLUMN version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE roles ADD COLUMN version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0;

CREATE TABLE admin_sessions (
    id_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    created_at REAL NOT NULL,
    last_seen_at REAL NOT NULL,
    ip TEXT
);

CREATE INDEX admin_sessions_user ON admin_sessions (user_id);
"""
```

In `src/u2_mcp/store/db.py`, change the import of `SCHEMA_V1` to also import `SCHEMA_V2`, and change `MIGRATIONS` to:

```python
MIGRATIONS: dict[int, str] = {1: SCHEMA_V1, 2: SCHEMA_V2}
```

- [ ] **Step 3: Extend the models**

In `src/u2_mcp/store/models.py`:

- Append `version: int = 1` as the last field of `Connection` and of `Role`.
- Append `must_change_password: bool = False` as the last field of `User` (after `created_at`, before the `label` property).
- Add at the end of the file:

```python
@dataclass(frozen=True)
class AdminSession:
    """A signed-in admin-site session. The id itself is only ever in the cookie."""

    id_hash: str
    user_id: int
    csrf_token: str
    created_at: float
    last_seen_at: float
    ip: str | None
```

In `src/u2_mcp/store/repo.py`, make the row mappers fill the new fields:

- In `_connection`, add `version=row["version"],`.
- In `_role`, add `version=row["version"],`.
- In `_user`, add `must_change_password=bool(row["must_change_password"]),`.

Run: `pytest tests/test_store -v`
Expected: PASS. If an existing test asserted `SCHEMA_VERSION == 1` or "fresh database is version 1", update it to 2: that is the intended change.

- [ ] **Step 4: Run everything, lint and commit**

Run: `pytest -q && ruff check . && ruff format --check . && mypy src/`
Expected: all pass, clean.

```bash
git add src/u2_mcp/store/schema.py src/u2_mcp/store/db.py src/u2_mcp/store/models.py src/u2_mcp/store/repo.py tests/test_store/test_db.py
git commit -m "feat: settings database version 2 (versions, admin sessions, forced password change)"
```

---

### Task 3: Store support for editing connections, local passwords and admin sessions

**Files:**
- Modify: `src/u2_mcp/store/repo.py`
- Test: `tests/test_store/test_repo_admin.py` (create)

**Interfaces:**
- Consumes: Task 2 columns and `AdminSession`.
- Produces on `Store`:
  - `class StaleEdit(StoreError)` (module level, beside `StoreError`) and `STALE_CONNECTION_MESSAGE = "Someone else changed this connection since you opened it. Reload to see their changes."`
  - `update_connection(connection_id: int, *, expected_version: int, name: str, host: str, port: int, service: str, account: str, ssl: bool, login_mode: str, shared_user: str | None, shared_password: str | None = None, clear_shared_password: bool = False, read_only: bool, enabled: bool, actor: str | None) -> Connection` — `shared_password=None` keeps the stored password; raises `StaleEdit`, or `StoreError` for a missing row, a taken name or a schema violation.
  - `set_connection_flags(...)` (existing) now also bumps `version`.
  - `delete_connection(connection_id: int) -> bool`
  - `get_user_by_username(username: str) -> User | None`
  - `password_hash(user_id: int) -> str | None`
  - `set_password_hash(user_id: int, password_hash: str, *, must_change: bool) -> None`
  - `set_user_admin(user_id: int, is_admin: bool) -> None`
  - `has_local_admin() -> bool` (a local, enabled admin exists)
  - `add_local_user(...)` maps only UNIQUE violations to "already exists".
  - `set_user_disabled(user_id, True)` also ends that user's admin sessions.
  - `get_secret_setting(key: str) -> str | None`, `set_secret_setting(key: str, value: str | None) -> None` (encrypted; `None` deletes)
  - `delete_setting(key: str) -> None`
  - `add_admin_session(*, id_hash: str, user_id: int, csrf_token: str, ip: str | None) -> AdminSession`
  - `get_admin_session(id_hash: str) -> AdminSession | None`
  - `touch_admin_session(id_hash: str, *, at: float) -> None`
  - `delete_admin_session(id_hash: str) -> None`
  - `delete_admin_sessions_for(user_id: int) -> int`
  - `purge_admin_sessions(*, created_before: float, idle_before: float) -> int`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_store/test_repo_admin.py`:

```python
"""Store operations the admin site needs."""

import pytest

from u2_mcp.store.repo import STALE_CONNECTION_MESSAGE, StaleEdit, Store, StoreError


def _prod(store: Store) -> int:
    return store.add_connection(
        name="Prod",
        host="u2.example",
        port=31438,
        service="uvcs",
        account="PROD",
        shared_user="svc",
        shared_password="first",
    ).id


def _edit(store: Store, connection_id: int, version: int, **changes: object) -> object:
    values: dict[str, object] = {
        "name": "Prod",
        "host": "u2.example",
        "port": 31438,
        "service": "uvcs",
        "account": "PROD",
        "ssl": False,
        "login_mode": "shared",
        "shared_user": "svc",
        "read_only": True,
        "enabled": True,
        "actor": "ann",
    }
    values.update(changes)
    return store.update_connection(connection_id, expected_version=version, **values)  # type: ignore[arg-type]


class TestEditingConnections:
    def test_an_edit_saves_and_bumps_the_version(self, store: Store) -> None:
        connection_id = _prod(store)

        _edit(store, connection_id, 1, host="u2-new.example")

        saved = store.get_connection(connection_id)
        assert saved is not None
        assert saved.host == "u2-new.example"
        assert saved.version == 2

    def test_an_edit_from_an_old_version_is_refused(self, store: Store) -> None:
        connection_id = _prod(store)
        _edit(store, connection_id, 1, host="first-save.example")

        with pytest.raises(StaleEdit, match="Someone else changed this connection"):
            _edit(store, connection_id, 1, host="second-save.example")

        saved = store.get_connection(connection_id)
        assert saved is not None and saved.host == "first-save.example"
        assert str(StaleEdit(STALE_CONNECTION_MESSAGE)) == STALE_CONNECTION_MESSAGE

    def test_leaving_the_password_out_keeps_it(self, store: Store) -> None:
        connection_id = _prod(store)

        _edit(store, connection_id, 1)

        assert store.shared_password(connection_id) == "first"

    def test_a_new_password_replaces_it(self, store: Store) -> None:
        connection_id = _prod(store)

        _edit(store, connection_id, 1, shared_password="second")

        assert store.shared_password(connection_id) == "second"

    def test_clearing_the_password(self, store: Store) -> None:
        connection_id = _prod(store)

        _edit(store, connection_id, 1, login_mode="per_user", shared_user=None,
              clear_shared_password=True)

        assert store.shared_password(connection_id) is None

    def test_a_taken_name_is_refused(self, store: Store) -> None:
        connection_id = _prod(store)
        store.add_connection(name="Test", host="h", port=1, service="uvcs", account="T")

        with pytest.raises(StoreError, match="already exists"):
            _edit(store, connection_id, 1, name="Test")

    def test_editing_a_deleted_connection_is_refused(self, store: Store) -> None:
        connection_id = _prod(store)
        assert store.delete_connection(connection_id) is True

        with pytest.raises(StoreError, match="no longer exists"):
            _edit(store, connection_id, 1)

    def test_switches_bump_the_version(self, store: Store) -> None:
        connection_id = _prod(store)

        store.set_connection_flags(connection_id, read_only=False, actor="ann")

        saved = store.get_connection(connection_id)
        assert saved is not None and saved.version == 2

    def test_deleting_removes_its_grants(self, store: Store) -> None:
        connection_id = _prod(store)
        viewer = store.get_role_by_name("Viewer")
        assert viewer is not None
        store.add_grant(connection_id=connection_id, subject_type="everyone",
                        subject_id=None, role_id=viewer.id)

        store.delete_connection(connection_id)

        assert store.grants_on_connection(connection_id) == []


class TestLocalPasswords:
    def test_lookup_by_username(self, store: Store) -> None:
        created = store.add_local_user("ann", password_hash="h1", is_admin=True)

        found = store.get_user_by_username("ann")

        assert found is not None and found.id == created.id
        assert store.get_user_by_username("nobody") is None

    def test_password_hash_round_trip_and_forced_change(self, store: Store) -> None:
        user = store.add_local_user("ann", password_hash="h1")

        store.set_password_hash(user.id, "h2", must_change=True)

        assert store.password_hash(user.id) == "h2"
        refreshed = store.get_user(user.id)
        assert refreshed is not None and refreshed.must_change_password is True

    def test_has_local_admin(self, store: Store) -> None:
        assert store.has_local_admin() is False
        user = store.add_local_user("ann", password_hash="h", is_admin=True)
        assert store.has_local_admin() is True
        store.set_user_disabled(user.id, True)
        assert store.has_local_admin() is False

    def test_admin_flag(self, store: Store) -> None:
        user = store.add_local_user("ann", password_hash="h")

        store.set_user_admin(user.id, True)

        refreshed = store.get_user(user.id)
        assert refreshed is not None and refreshed.is_admin is True

    def test_duplicate_username_is_named(self, store: Store) -> None:
        store.add_local_user("ann", password_hash="h")

        with pytest.raises(StoreError, match="already exists"):
            store.add_local_user("ann", password_hash="h")


class TestSecretSettings:
    def test_round_trip_is_encrypted_at_rest(self, store: Store) -> None:
        store.set_secret_setting("setup_code", "ABCD-EFGH-JKLM")

        assert store.get_secret_setting("setup_code") == "ABCD-EFGH-JKLM"
        assert "ABCD" not in str(store.get_setting("setup_code"))

    def test_none_deletes(self, store: Store) -> None:
        store.set_secret_setting("setup_code", "x")

        store.set_secret_setting("setup_code", None)

        assert store.get_secret_setting("setup_code") is None

    def test_delete_setting(self, store: Store) -> None:
        store.set_setting("k", 1)

        store.delete_setting("k")

        assert store.get_setting("k") is None


class TestAdminSessions:
    def test_add_get_touch_delete(self, store: Store) -> None:
        user = store.add_local_user("ann", password_hash="h", is_admin=True)

        created = store.add_admin_session(id_hash="abc", user_id=user.id, csrf_token="c",
                                          ip="10.0.0.1")
        store.touch_admin_session("abc", at=created.created_at + 60)

        loaded = store.get_admin_session("abc")
        assert loaded is not None
        assert loaded.last_seen_at == created.created_at + 60
        store.delete_admin_session("abc")
        assert store.get_admin_session("abc") is None

    def test_disabling_a_user_ends_their_sessions(self, store: Store) -> None:
        user = store.add_local_user("ann", password_hash="h", is_admin=True)
        store.add_admin_session(id_hash="abc", user_id=user.id, csrf_token="c", ip=None)

        store.set_user_disabled(user.id, True)

        assert store.get_admin_session("abc") is None

    def test_delete_for_user(self, store: Store) -> None:
        user = store.add_local_user("ann", password_hash="h", is_admin=True)
        store.add_admin_session(id_hash="a", user_id=user.id, csrf_token="c", ip=None)
        store.add_admin_session(id_hash="b", user_id=user.id, csrf_token="c", ip=None)

        assert store.delete_admin_sessions_for(user.id) == 2

    def test_purge_old_and_idle(self, store: Store) -> None:
        user = store.add_local_user("ann", password_hash="h", is_admin=True)
        session = store.add_admin_session(id_hash="a", user_id=user.id, csrf_token="c", ip=None)

        removed = store.purge_admin_sessions(
            created_before=session.created_at - 1, idle_before=session.last_seen_at + 1
        )

        assert removed == 1
```

Run: `pytest tests/test_store/test_repo_admin.py -v`
Expected: FAIL with ImportError (`StaleEdit` does not exist).

- [ ] **Step 2: Implement**

In `src/u2_mcp/store/repo.py`:

1. Import `AdminSession` alongside the other models.
2. Below `class StoreError`, add:

```python
STALE_CONNECTION_MESSAGE = (
    "Someone else changed this connection since you opened it. Reload to see their changes."
)


class StaleEdit(StoreError):
    """An edit was based on a version of the record that has since been saved over."""
```

3. Add after `set_connection_flags` (and change `set_connection_flags`'s final UPDATE to `"UPDATE connections SET version = version + 1, updated_at = ?, updated_by = ? WHERE id = ?"`):

```python
    def update_connection(
        self,
        connection_id: int,
        *,
        expected_version: int,
        name: str,
        host: str,
        port: int,
        service: str,
        account: str,
        ssl: bool,
        login_mode: str,
        shared_user: str | None,
        shared_password: str | None = None,
        clear_shared_password: bool = False,
        read_only: bool,
        enabled: bool,
        actor: str | None,
    ) -> Connection:
        """Save an edited connection, unless someone else saved it first.

        Args:
            connection_id: The connection being edited
            expected_version: The version the editor started from
            shared_password: A new password, or None to keep the stored one
            clear_shared_password: Remove the stored password (per-user connections)

        Raises:
            StaleEdit: If the connection was saved since expected_version
            StoreError: If it no longer exists, the name is taken, or a value is invalid
        """
        try:
            with self._tx() as conn:
                row = conn.execute(
                    "SELECT version FROM connections WHERE id = ?", (connection_id,)
                ).fetchone()
                if row is None:
                    raise StoreError("That connection no longer exists.")
                if row[0] != expected_version:
                    raise StaleEdit(STALE_CONNECTION_MESSAGE)
                conn.execute(
                    "UPDATE connections SET name = ?, host = ?, port = ?, service = ?, "
                    "account = ?, ssl = ?, login_mode = ?, shared_user = ?, read_only = ?, "
                    "enabled = ?, version = version + 1, updated_at = ?, updated_by = ? "
                    "WHERE id = ?",
                    (
                        name,
                        host,
                        port,
                        service,
                        account,
                        int(ssl),
                        login_mode,
                        shared_user,
                        int(read_only),
                        int(enabled),
                        self.clock(),
                        actor,
                        connection_id,
                    ),
                )
                if clear_shared_password:
                    conn.execute(
                        "UPDATE connections SET shared_password_enc = NULL WHERE id = ?",
                        (connection_id,),
                    )
                elif shared_password is not None:
                    conn.execute(
                        "UPDATE connections SET shared_password_enc = ? WHERE id = ?",
                        (self._encrypt(shared_password), connection_id),
                    )
        except sqlite3.IntegrityError as exc:
            if "UNIQUE" in str(exc):
                raise StoreError(f"A connection named '{name}' already exists") from exc
            raise StoreError(f"Invalid connection settings: {exc}") from exc
        saved = self.get_connection(connection_id)
        assert saved is not None
        return saved

    def delete_connection(self, connection_id: int) -> bool:
        """Delete a connection and, through the foreign key, its grants.

        Returns:
            Whether a connection was deleted
        """
        with self._tx() as conn:
            cursor = conn.execute("DELETE FROM connections WHERE id = ?", (connection_id,))
            return cursor.rowcount > 0
```

4. Change `add_local_user`'s `except` to:

```python
        except sqlite3.IntegrityError as exc:
            if "UNIQUE" in str(exc):
                raise StoreError(f"A user named '{username}' already exists") from exc
            raise StoreError(f"Invalid user: {exc}") from exc
```

5. Change `set_user_disabled` to:

```python
    def set_user_disabled(self, user_id: int, disabled: bool) -> None:
        """Disable or re-enable a user. Disabling ends their admin-site sessions."""
        with self._tx() as conn:
            conn.execute("UPDATE users SET disabled = ? WHERE id = ?", (int(disabled), user_id))
            if disabled:
                conn.execute("DELETE FROM admin_sessions WHERE user_id = ?", (user_id,))
```

6. Add after `get_user_by_subject`:

```python
    def get_user_by_username(self, username: str) -> User | None:
        """Return the local user with this exact username, or None."""
        row = self._one(
            "SELECT * FROM users WHERE kind = 'local' AND username = ?", (username,)
        )
        return self._user(row) if row else None

    def password_hash(self, user_id: int) -> str | None:
        """Return a local user's stored password hash, or None."""
        row = self._one("SELECT password_hash FROM users WHERE id = ?", (user_id,))
        return None if row is None else row[0]

    def set_password_hash(self, user_id: int, password_hash: str, *, must_change: bool) -> None:
        """Replace a user's password hash and set whether they must change it."""
        with self._tx() as conn:
            conn.execute(
                "UPDATE users SET password_hash = ?, must_change_password = ? WHERE id = ?",
                (password_hash, int(must_change), user_id),
            )

    def set_user_admin(self, user_id: int, is_admin: bool) -> None:
        """Grant or remove admin-site access. This never grants data access."""
        with self._tx() as conn:
            conn.execute("UPDATE users SET is_admin = ? WHERE id = ?", (int(is_admin), user_id))

    def has_local_admin(self) -> bool:
        """Return whether an enabled local admin exists (break-glass access)."""
        row = self._one(
            "SELECT 1 FROM users WHERE kind = 'local' AND is_admin = 1 AND disabled = 0 LIMIT 1"
        )
        return row is not None
```

7. Add to the settings section:

```python
    def delete_setting(self, key: str) -> None:
        """Remove a setting."""
        with self._tx() as conn:
            conn.execute("DELETE FROM settings WHERE key = ?", (key,))

    def get_secret_setting(self, key: str) -> str | None:
        """Return a decrypted secret setting, or None.

        Raises:
            SecretUnreadable: If it was stored under a different U2_SECRET_KEY
        """
        stored = self.get_setting(key)
        return None if stored is None else self._box.decrypt(stored)

    def set_secret_setting(self, key: str, value: str | None) -> None:
        """Store a secret setting encrypted; None removes it."""
        if value is None:
            self.delete_setting(key)
        else:
            self.set_setting(key, self._box.encrypt(value))
```

8. Add a new section after the tokens section:

```python
    # ----------------------------------------------------------- admin sessions

    @staticmethod
    def _admin_session(row: sqlite3.Row) -> AdminSession:
        return AdminSession(
            id_hash=row["id_hash"],
            user_id=row["user_id"],
            csrf_token=row["csrf_token"],
            created_at=row["created_at"],
            last_seen_at=row["last_seen_at"],
            ip=row["ip"],
        )

    def add_admin_session(
        self, *, id_hash: str, user_id: int, csrf_token: str, ip: str | None
    ) -> AdminSession:
        """Record a new admin-site session."""
        now = self.clock()
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO admin_sessions (id_hash, user_id, csrf_token, created_at, "
                "last_seen_at, ip) VALUES (?, ?, ?, ?, ?, ?)",
                (id_hash, user_id, csrf_token, now, now, ip),
            )
        return AdminSession(id_hash, user_id, csrf_token, now, now, ip)

    def get_admin_session(self, id_hash: str) -> AdminSession | None:
        """Return a session by the hash of its id, or None."""
        row = self._one("SELECT * FROM admin_sessions WHERE id_hash = ?", (id_hash,))
        return self._admin_session(row) if row else None

    def touch_admin_session(self, id_hash: str, *, at: float) -> None:
        """Record activity on a session, for the idle timeout."""
        with self._tx() as conn:
            conn.execute(
                "UPDATE admin_sessions SET last_seen_at = ? WHERE id_hash = ?", (at, id_hash)
            )

    def delete_admin_session(self, id_hash: str) -> None:
        """End one session."""
        with self._tx() as conn:
            conn.execute("DELETE FROM admin_sessions WHERE id_hash = ?", (id_hash,))

    def delete_admin_sessions_for(self, user_id: int) -> int:
        """End every session a user has. Returns how many ended."""
        with self._tx() as conn:
            cursor = conn.execute("DELETE FROM admin_sessions WHERE user_id = ?", (user_id,))
            return cursor.rowcount

    def purge_admin_sessions(self, *, created_before: float, idle_before: float) -> int:
        """Delete sessions past their absolute lifetime or idle timeout."""
        with self._tx() as conn:
            cursor = conn.execute(
                "DELETE FROM admin_sessions WHERE created_at < ? OR last_seen_at < ?",
                (created_before, idle_before),
            )
            return cursor.rowcount
```

Run: `pytest tests/test_store -v`
Expected: PASS.

- [ ] **Step 3: Run everything, lint and commit**

Run: `pytest -q && ruff check . && ruff format --check . && mypy src/`
Expected: all pass, clean. (`ruff format` will reflow the test file's long calls; run `ruff format tests/test_store/test_repo_admin.py` first.)

```bash
git add src/u2_mcp/store/repo.py tests/test_store/test_repo_admin.py
git commit -m "feat: store edits connections with version checks, local passwords, admin sessions"
```

---

### Task 4: Passwords, the setup code, and the `u2-mcp admin` commands

**Files:**
- Create: `src/u2_mcp/passwords.py`, `src/u2_mcp/setup_code.py`, `src/u2_mcp/cli.py`
- Modify: `src/u2_mcp/store/bootstrap.py` (add `open_store_for_cli`), `src/u2_mcp/server.py` (`main`)
- Test: `tests/test_passwords.py`, `tests/test_setup_code.py`, `tests/test_cli.py`

**Interfaces:**
- Consumes: Task 3 store methods.
- Produces in `passwords.py`: `MIN_PASSWORD_LENGTH = 12`; `hash_password(password: str) -> str`; `verify_password(password_hash: str | None, password: str) -> bool` (runs a dummy verification when the hash is None, so unknown users take as long as known ones); `password_problem(password: str, *, username: str) -> str | None`; `one_time_password() -> str`.
- Produces in `setup_code.py`: `SETUP_STEPS: tuple[str, ...] = ("admin", "connection", "server_address", "done")`; settings keys `SETUP_STATE_SETTING = "setup_state"`, `SETUP_COMPLETE_SETTING = "setup_complete"`, `SETUP_CODE_SETTING = "setup_code"`; `WRONG_SETUP_CODE_MESSAGE`; `is_setup_complete(store) -> bool`; `completed_step(store) -> str | None`; `next_step(store) -> str`; `mark_step_done(store, step: str) -> None` (never moves backwards); `ensure_setup_code(store) -> str | None`; `check_setup_code(store, presented: str) -> bool`; `finish_setup(store) -> None`.
- Produces in `cli.py`: `run_admin_cli(argv: list[str]) -> int`.
- Produces in `bootstrap.py`: `open_store_for_cli(config: U2Config) -> Store` (raises `TeamModeError` when there is no key or no database; never imports the environment).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_passwords.py`:

```python
"""Local-account passwords."""

from u2_mcp.passwords import (
    MIN_PASSWORD_LENGTH,
    hash_password,
    one_time_password,
    password_problem,
    verify_password,
)


def test_a_hash_verifies_only_its_password() -> None:
    stored = hash_password("correct horse battery")

    assert stored.startswith("$argon2id$")
    assert verify_password(stored, "correct horse battery") is True
    assert verify_password(stored, "wrong horse battery") is False


def test_a_missing_hash_never_verifies() -> None:
    assert verify_password(None, "anything at all") is False


def test_a_garbage_hash_never_verifies() -> None:
    assert verify_password("not-a-hash", "anything at all") is False


def test_short_passwords_are_refused() -> None:
    assert password_problem("x" * (MIN_PASSWORD_LENGTH - 1), username="ann") == (
        "Use at least 12 characters."
    )


def test_the_username_is_refused() -> None:
    assert password_problem("annabelle-lee", username="Annabelle-Lee") == (
        "Don't use your username as your password."
    )


def test_a_good_password_passes() -> None:
    assert password_problem("long enough passphrase", username="ann") is None


def test_one_time_passwords_are_long_and_different() -> None:
    first, second = one_time_password(), one_time_password()

    assert len(first) >= MIN_PASSWORD_LENGTH
    assert first != second
```

Create `tests/test_setup_code.py`:

```python
"""Setup state and the one-time setup code."""

import re

from u2_mcp.setup_code import (
    SETUP_CODE_SETTING,
    check_setup_code,
    completed_step,
    ensure_setup_code,
    finish_setup,
    is_setup_complete,
    mark_step_done,
    next_step,
)
from u2_mcp.store.repo import Store


def test_a_new_server_starts_at_the_admin_step(store: Store) -> None:
    assert completed_step(store) is None
    assert next_step(store) == "admin"
    assert is_setup_complete(store) is False


def test_steps_advance_and_never_go_back(store: Store) -> None:
    mark_step_done(store, "admin")
    mark_step_done(store, "connection")
    mark_step_done(store, "admin")  # pressing Save again on an earlier step

    assert completed_step(store) == "connection"
    assert next_step(store) == "server_address"


def test_the_code_is_stable_until_setup_finishes(store: Store) -> None:
    code = ensure_setup_code(store)

    assert code is not None
    assert re.fullmatch(r"[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}", code)
    assert ensure_setup_code(store) == code


def test_the_code_is_checked_forgivingly(store: Store) -> None:
    code = ensure_setup_code(store)
    assert code is not None

    assert check_setup_code(store, f"  {code.lower()} ") is True
    assert check_setup_code(store, code.replace("-", "")) is True
    assert check_setup_code(store, "AAAA-AAAA-AAAA") is False
    assert check_setup_code(store, "") is False


def test_finishing_removes_the_code(store: Store) -> None:
    ensure_setup_code(store)

    finish_setup(store)

    assert is_setup_complete(store) is True
    assert next_step(store) == "done"
    assert store.get_setting(SETUP_CODE_SETTING) is None
    assert ensure_setup_code(store) is None
```

Create `tests/test_cli.py`:

```python
"""`u2-mcp admin ...` commands, run against a real settings database."""

from pathlib import Path

import pytest

from u2_mcp.cli import run_admin_cli
from u2_mcp.passwords import hash_password, verify_password
from u2_mcp.setup_code import ensure_setup_code, finish_setup
from u2_mcp.store.crypto import SecretBox
from u2_mcp.store.db import DATABASE_FILENAME, open_database
from u2_mcp.store.repo import Store

KEY = "c" * 40


@pytest.fixture
def team_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for name in ("U2_HOST", "U2_USER", "U2_PASSWORD", "U2_ACCOUNT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("U2_SECRET_KEY", KEY)
    monkeypatch.setenv("U2_DATA_DIR", str(tmp_path))
    return tmp_path


def _open(path: Path) -> Store:
    store = Store(open_database(path / DATABASE_FILENAME), SecretBox(KEY), path)
    store.seed_builtin_roles()
    return store


def test_show_setup_code_prints_the_current_code(
    team_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = ensure_setup_code(_open(team_dir))

    assert run_admin_cli(["show-setup-code"]) == 0
    assert capsys.readouterr().out.strip() == code


def test_show_setup_code_after_setup(team_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    finish_setup(_open(team_dir))

    assert run_admin_cli(["show-setup-code"]) == 1
    assert "Setup is finished" in capsys.readouterr().out


def test_without_a_database(team_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run_admin_cli(["show-setup-code"]) == 2
    assert "No settings database" in capsys.readouterr().err


def test_reset_password(team_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    store = _open(team_dir)
    user = store.add_local_user("ann", password_hash=hash_password("old password here"),
                                is_admin=True)
    store.add_admin_session(id_hash="s", user_id=user.id, csrf_token="c", ip=None)

    assert run_admin_cli(["reset-password", "ann"]) == 0

    printed = capsys.readouterr().out
    one_time = printed.split("One-time password for ann: ")[1].split()[0]
    reopened = _open(team_dir)
    assert verify_password(reopened.password_hash(user.id), one_time) is True
    refreshed = reopened.get_user(user.id)
    assert refreshed is not None and refreshed.must_change_password is True
    assert reopened.get_admin_session("s") is None
    assert reopened.recent_audit(1)[0]["action"] == "user.reset_password"


def test_reset_password_for_an_unknown_user(
    team_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _open(team_dir)

    assert run_admin_cli(["reset-password", "nobody"]) == 1
    assert "No local user named 'nobody'" in capsys.readouterr().out
```

Run: `pytest tests/test_passwords.py tests/test_setup_code.py tests/test_cli.py -v`
Expected: FAIL with ImportError.

- [ ] **Step 2: Implement `passwords.py`**

```python
"""Local-account passwords: argon2id hashes and the rules a new password must meet."""

from __future__ import annotations

import secrets
from functools import lru_cache

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

MIN_PASSWORD_LENGTH = 12

_hasher = PasswordHasher()  # argon2id with the library's current defaults


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    """A hash to verify against when the user does not exist, so timing matches."""
    return _hasher.hash("there is no such user")


def hash_password(password: str) -> str:
    """Return an argon2id hash of a password."""
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    """Return whether a password matches a stored hash.

    Args:
        password_hash: The stored hash, or None when the user does not exist
        password: What was typed

    Returns:
        True only for a match. A missing or malformed hash is never a match.
    """
    try:
        _hasher.verify(password_hash or _dummy_hash(), password)
    except (VerificationError, InvalidHashError):
        return False
    return password_hash is not None


def password_problem(password: str, *, username: str) -> str | None:
    """Return why a new password is unacceptable, or None if it is fine."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Use at least {MIN_PASSWORD_LENGTH} characters."
    if password.casefold() == username.casefold():
        return "Don't use your username as your password."
    return None


def one_time_password() -> str:
    """Return a random password for a reset; the user must change it at sign-in."""
    return secrets.token_urlsafe(15)
```

Note: `VerifyMismatchError` is a subclass of `VerificationError`, so the except clause covers a wrong password.

- [ ] **Step 3: Implement `setup_code.py`**

```python
"""Setup state and the one-time code that guards the setup wizard.

Until setup is finished, anyone who can reach /admin/setup could create the
first admin. The code proves they can also read the server's log or run a
command on it. It is stored encrypted, because `u2-mcp admin show-setup-code`
runs in a separate process and must be able to print it.
"""

from __future__ import annotations

import hmac
import secrets

from .store.repo import Store

SETUP_STEPS: tuple[str, ...] = ("admin", "connection", "server_address", "done")
SETUP_STATE_SETTING = "setup_state"
SETUP_COMPLETE_SETTING = "setup_complete"
SETUP_CODE_SETTING = "setup_code"

WRONG_SETUP_CODE_MESSAGE = (
    "That setup code is not right. Find the current code in the server log, "
    "or run: u2-mcp admin show-setup-code"
)

_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O or 1/I to misread


def is_setup_complete(store: Store) -> bool:
    """Return whether the wizard's Finish has been pressed."""
    return bool(store.get_setting(SETUP_COMPLETE_SETTING, False))


def completed_step(store: Store) -> str | None:
    """Return the furthest completed step, or None."""
    value = store.get_setting(SETUP_STATE_SETTING)
    return value if value in SETUP_STEPS else None


def next_step(store: Store) -> str:
    """Return the first step not yet completed ("done" once all others are)."""
    done = completed_step(store)
    if done is None:
        return SETUP_STEPS[0]
    index = SETUP_STEPS.index(done)
    return SETUP_STEPS[min(index + 1, len(SETUP_STEPS) - 1)]


def mark_step_done(store: Store, step: str) -> None:
    """Record a step as completed. Re-saving an earlier step never moves progress back."""
    done = completed_step(store)
    if done is None or SETUP_STEPS.index(step) > SETUP_STEPS.index(done):
        store.set_setting(SETUP_STATE_SETTING, step)


def _generate() -> str:
    raw = "".join(secrets.choice(_ALPHABET) for _ in range(12))
    return f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}"


def _normalise(code: str) -> str:
    return "".join(ch for ch in code.upper() if ch.isalnum())


def ensure_setup_code(store: Store) -> str | None:
    """Return the setup code, creating it if needed; None once setup is finished."""
    if is_setup_complete(store):
        return None
    existing = store.get_secret_setting(SETUP_CODE_SETTING)
    if existing:
        return existing
    code = _generate()
    store.set_secret_setting(SETUP_CODE_SETTING, code)
    return code


def check_setup_code(store: Store, presented: str) -> bool:
    """Return whether a typed code matches, ignoring case, spaces and dashes."""
    expected = store.get_secret_setting(SETUP_CODE_SETTING)
    if not expected or not presented:
        return False
    return hmac.compare_digest(_normalise(expected), _normalise(presented))


def finish_setup(store: Store) -> None:
    """Mark setup finished and destroy the code."""
    store.set_setting(SETUP_STATE_SETTING, SETUP_STEPS[-1])
    store.set_setting(SETUP_COMPLETE_SETTING, True)
    store.set_secret_setting(SETUP_CODE_SETTING, None)
```

- [ ] **Step 4: Implement `open_store_for_cli`**

Append to `src/u2_mcp/store/bootstrap.py`:

```python
def open_store_for_cli(config: U2Config) -> Store:
    """Open the existing settings database for an admin command.

    Unlike open_team_store, this never creates a database and never imports the
    environment: a command run with the wrong U2_DATA_DIR must say so, not start
    a second, empty deployment.

    Raises:
        TeamModeError: If U2_SECRET_KEY is missing or there is no database
    """
    db_path = Path(config.data_dir).expanduser() / DATABASE_FILENAME
    if not db_path.exists():
        raise TeamModeError(
            f"No settings database at {db_path}. Start the server with U2_SECRET_KEY "
            "set first, and run this command with the same U2_DATA_DIR."
        )
    secret = config.secret_key.get_secret_value() if config.secret_key else ""
    if not secret:
        raise TeamModeError("U2_SECRET_KEY is not set. Use the key the server runs with.")
    try:
        box = SecretBox(secret)
    except ValueError as exc:
        raise TeamModeError(str(exc)) from exc
    return Store(open_database(db_path), box, db_path.parent)
```

(`Path`, `DATABASE_FILENAME`, `SecretBox`, `Store` and `open_database` are already imported by `open_team_store`; reuse those imports.)

- [ ] **Step 5: Implement `cli.py`**

```python
"""`u2-mcp admin ...`: break-glass commands run on the server itself.

Typical use, in Docker: docker exec <container> u2-mcp admin show-setup-code
"""

from __future__ import annotations

import argparse
import sys

from .config import U2Config
from .passwords import hash_password, one_time_password
from .setup_code import ensure_setup_code, is_setup_complete
from .store.bootstrap import TeamModeError, open_store_for_cli


def run_admin_cli(argv: list[str]) -> int:
    """Run an admin command.

    Args:
        argv: Arguments after `u2-mcp admin`

    Returns:
        Process exit code: 0 success, 1 refused, 2 cannot open the database
    """
    parser = argparse.ArgumentParser(prog="u2-mcp admin")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("show-setup-code", help="Print the code the setup wizard asks for")
    reset = commands.add_parser(
        "reset-password", help="Give a local user a one-time password"
    )
    reset.add_argument("username")
    args = parser.parse_args(argv)

    try:
        store = open_store_for_cli(U2Config())
    except TeamModeError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if args.command == "show-setup-code":
        if is_setup_complete(store):
            print("Setup is finished, so there is no setup code. Sign in at /admin.")
            return 1
        print(ensure_setup_code(store))
        return 0

    user = store.get_user_by_username(args.username)
    if user is None:
        print(f"No local user named '{args.username}'.")
        return 1
    password = one_time_password()
    store.set_password_hash(user.id, hash_password(password), must_change=True)
    store.delete_admin_sessions_for(user.id)
    store.add_audit(
        kind="admin",
        action="user.reset_password",
        outcome="ok",
        actor_label="command line",
        params={"username": args.username},
    )
    print(f"One-time password for {args.username}: {password}")
    print("They must choose a new password when they next sign in.")
    return 0
```

- [ ] **Step 6: Route `u2-mcp admin` before the server's own arguments**

In `src/u2_mcp/server.py`, make `main()` begin:

```python
def main() -> None:
    """Entry point for the MCP server."""
    # `u2-mcp admin ...` is a separate command, not a transport flag. Checked
    # first so bare `u2-mcp` (Claude Desktop's stdio launch) is unaffected.
    if len(sys.argv) > 1 and sys.argv[1] == "admin":
        from .cli import run_admin_cli

        sys.exit(run_admin_cli(sys.argv[2:]))

    # A tool without an access check must stop the server, not ship open.
    check_tool_coverage(mcp)
```

Add `import sys` to the imports at the top of `server.py` if it is not already there.

- [ ] **Step 7: Run, lint and commit**

Run: `pytest tests/test_passwords.py tests/test_setup_code.py tests/test_cli.py -v`
Expected: PASS.

Run: `pytest -q && ruff check . && ruff format --check . && mypy src/`
Expected: all pass, clean.

```bash
git add src/u2_mcp/passwords.py src/u2_mcp/setup_code.py src/u2_mcp/cli.py src/u2_mcp/store/bootstrap.py src/u2_mcp/server.py tests/test_passwords.py tests/test_setup_code.py tests/test_cli.py
git commit -m "feat: argon2id passwords, setup code, u2-mcp admin show-setup-code and reset-password"
```

---

### Task 5: Testing a connection, the scripted driver, and forgetting a changed connection

**Files:**
- Create: `src/u2_mcp/connection_check.py`, `tests/mocks/sim_driver.py`
- Modify: `src/u2_mcp/registry.py`, `src/u2_mcp/utils/knowledge.py`
- Test: `tests/test_connection_check.py`, `tests/test_registry.py`, `tests/test_tools/test_knowledge_per_connection.py`

**Interfaces:**
- Produces in `connection_check.py`: `CHECK_COMMAND = "COUNT VOC"`, `CHECK_TIMEOUT_SECONDS = 10.0`, frozen dataclass `CheckResult(ok: bool, message: str, elapsed_ms: float)`, `check_connection(base: U2Config, connection: Connection, credentials: U2Credentials, *, timeout: float = CHECK_TIMEOUT_SECONDS) -> CheckResult`. Blocking; callers run it in a worker thread.
- Produces in `tests/mocks/sim_driver.py` (load with `U2_DRIVER=tests.mocks.sim_driver`): `UNREACHABLE_HOST = "unreachable.invalid"`, `SLOW_HOST = "slow.invalid"`, `WRONG_PASSWORD = "wrong-password"`, `COUNT_VOC_RESPONSE = "1234 records counted."`, and module-level `connect`, `File`, `Command`, `List`, `Subroutine`, `UOError`. Error texts: unreachable → `Cannot reach unreachable.invalid:<port>: connection refused`; wrong password → `Login refused: wrong user name or password`.
- Produces on `ConnectionRegistry`: `evict_connection(connection_id: int) -> int` (closes every slot for that connection, any login), `sessions_for_connection(connection_id: int) -> list[str]` (the logins, as `user@account`, with a live slot).
- Produces in `utils/knowledge.py`: `forget_connection_knowledge(data_dir: Path, connection_id: int, *, delete_file: bool) -> None`.

- [ ] **Step 1: Create the scripted driver**

Create `tests/mocks/sim_driver.py`:

```python
"""A scripted U2 driver for browser tests: U2_DRIVER=tests.mocks.sim_driver.

Rocket U2 cannot run in CI, so the browser tests drive the real server against
this module. It answers like a healthy server except for three scripted
failures, each with fixed text a test can assert on.
"""

from __future__ import annotations

import time
from typing import Any

from tests.mocks.mock_uopy import MockCommand as Command
from tests.mocks.mock_uopy import MockFile as File
from tests.mocks.mock_uopy import MockList as List
from tests.mocks.mock_uopy import MockSession
from tests.mocks.mock_uopy import MockSubroutine as Subroutine
from tests.mocks.mock_uopy import UOError

UNREACHABLE_HOST = "unreachable.invalid"
SLOW_HOST = "slow.invalid"
SLOW_SECONDS = 30.0
WRONG_PASSWORD = "wrong-password"
COUNT_VOC_RESPONSE = "1234 records counted."

__all__ = ["Command", "File", "List", "Subroutine", "UOError", "connect"]


def connect(**kwargs: Any) -> MockSession:
    """Open a simulated session, or fail the way a real server would."""
    host = str(kwargs.get("host", ""))
    if host == UNREACHABLE_HOST:
        raise UOError(f"Cannot reach {host}:{kwargs.get('port')}: connection refused")
    if host == SLOW_HOST:
        time.sleep(SLOW_SECONDS)
    if kwargs.get("password") == WRONG_PASSWORD:
        raise UOError("Login refused: wrong user name or password")
    session = MockSession(**kwargs)
    session.command_responses["COUNT VOC"] = COUNT_VOC_RESPONSE
    return session
```

- [ ] **Step 2: Write the failing connection-check tests**

Create `tests/test_connection_check.py`:

```python
"""The Test button: connect, run COUNT VOC, report the driver's own words."""

from collections.abc import Iterator

import pytest

from tests.mocks import sim_driver
from u2_mcp.config import U2Config
from u2_mcp.connection_check import check_connection
from u2_mcp.credentials import U2Credentials
from u2_mcp.driver import reset_driver
from u2_mcp.store.models import Connection


@pytest.fixture(autouse=True)
def scripted_driver(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("U2_DRIVER", "tests.mocks.sim_driver")
    reset_driver()
    yield
    reset_driver()


def _connection(host: str = "u2.example") -> Connection:
    return Connection(
        id=0, name="Prod", host=host, port=31438, service="uvcs", account="PROD",
        ssl=False, login_mode="shared", shared_user="svc", has_shared_password=True,
        read_only=True, enabled=True,
    )


def _login(password: str = "secret") -> U2Credentials:
    return U2Credentials(user="svc", password=password, account="PROD", is_shared=True)


def test_a_working_connection_reports_the_count(mock_config: U2Config) -> None:
    result = check_connection(mock_config, _connection(), _login())

    assert result.ok is True
    assert sim_driver.COUNT_VOC_RESPONSE in result.message


def test_a_wrong_password_shows_the_driver_text(mock_config: U2Config) -> None:
    result = check_connection(mock_config, _connection(), _login(sim_driver.WRONG_PASSWORD))

    assert result.ok is False
    assert "Login refused: wrong user name or password" in result.message


def test_an_unreachable_host_shows_the_driver_text(mock_config: U2Config) -> None:
    result = check_connection(mock_config, _connection(sim_driver.UNREACHABLE_HOST), _login())

    assert result.ok is False
    assert "Cannot reach unreachable.invalid:31438" in result.message


def test_a_silent_host_times_out(mock_config: U2Config) -> None:
    result = check_connection(
        mock_config, _connection(sim_driver.SLOW_HOST), _login(), timeout=0.5
    )

    assert result.ok is False
    assert result.message == "No answer from slow.invalid:31438 within 0.5 seconds."
    assert result.elapsed_ms < 5000
```

Run: `pytest tests/test_connection_check.py -v`
Expected: FAIL with ImportError (`u2_mcp.connection_check`).

- [ ] **Step 3: Implement `connection_check.py`**

```python
"""Checking that a connection's settings work: what the admin site's Test button runs."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from .config import U2Config
from .connection import ConnectionManager
from .credentials import U2Credentials
from .routing import config_for
from .store.models import Connection

CHECK_COMMAND = "COUNT VOC"
CHECK_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True)
class CheckResult:
    """What a test of a connection found."""

    ok: bool
    message: str
    elapsed_ms: float


def _elapsed_ms(started: float) -> float:
    return (time.monotonic() - started) * 1000.0


def check_connection(
    base: U2Config,
    connection: Connection,
    credentials: U2Credentials,
    *,
    timeout: float = CHECK_TIMEOUT_SECONDS,
) -> CheckResult:
    """Open a session with these settings and run COUNT VOC, within a time limit.

    The session is the test's own: it never enters the connection registry, so a
    test can neither reuse nor disturb anyone's live session. This blocks the
    calling thread for up to `timeout` seconds, so call it from a worker thread,
    never on the event loop.

    Args:
        base: Server configuration; safety settings carry over
        connection: The settings to test (need not be saved yet)
        credentials: The login to test with
        timeout: Seconds to wait for the whole attempt

    Returns:
        The result, with the driver's own error text on failure
    """
    started = time.monotonic()
    outcome: list[CheckResult] = []

    def attempt() -> None:
        manager = ConnectionManager(config_for(base, connection), credentials)
        try:
            manager.connect()
            response = manager.execute_command(CHECK_COMMAND, timeout=timeout)
            outcome.append(
                CheckResult(
                    True,
                    f"Connected to {connection.account} on {connection.host}. "
                    f"{CHECK_COMMAND}: {response.strip()}",
                    _elapsed_ms(started),
                )
            )
        except Exception as exc:  # noqa: BLE001 - the driver's own words are the point
            outcome.append(CheckResult(False, str(exc) or type(exc).__name__, _elapsed_ms(started)))
        finally:
            try:
                manager.disconnect_all()
            except Exception:  # noqa: BLE001, S110 - closing a failed test session is best effort
                pass

    # A daemon thread: if the host never answers, the attempt is abandoned rather
    # than holding the admin's request (or the process at shutdown) hostage.
    worker = threading.Thread(target=attempt, name=f"check-{connection.name}", daemon=True)
    worker.start()
    worker.join(timeout)
    if outcome:
        return outcome[0]
    return CheckResult(
        False,
        f"No answer from {connection.host}:{connection.port} within {timeout:g} seconds.",
        _elapsed_ms(started),
    )
```

If bandit flags the `try/except/pass` (B110), keep the `# noqa` comment and add `# nosec B110` on the `except` line.

Run: `pytest tests/test_connection_check.py -v`
Expected: PASS.

- [ ] **Step 4: Write the failing registry and knowledge tests**

Append to `tests/test_registry.py` (reuse the file's existing fixtures for a config and the mock driver; the test below uses `mock_config` and `mock_uopy` from `tests/conftest.py`):

```python
class TestForgettingAConnection:
    """After an admin edits or deletes a connection, no old session may survive."""

    def _route(self, connection_id: int, user: str) -> Route:
        connection = Connection(
            id=connection_id, name=f"c{connection_id}", host="h", port=1, service="uvcs",
            account="A", ssl=False, login_mode="shared", shared_user=user,
            has_shared_password=True, read_only=True, enabled=True,
        )
        return Route(connection, U2Credentials(user=user, password="p", account="A",
                                               is_shared=True))

    def test_evict_closes_every_login_on_that_connection_only(
        self, mock_config: U2Config, mock_uopy: MockSession
    ) -> None:
        registry = ConnectionRegistry(mock_config)
        registry.for_route(self._route(1, "ann"))
        registry.for_route(self._route(1, "bob"))
        registry.for_route(self._route(2, "ann"))

        assert sorted(registry.sessions_for_connection(1)) == ["ann@A", "bob@A"]
        assert registry.evict_connection(1) == 2
        assert registry.sessions_for_connection(1) == []
        assert registry.sessions_for_connection(2) == ["ann@A"]

    def test_id_prefixes_do_not_collide(
        self, mock_config: U2Config, mock_uopy: MockSession
    ) -> None:
        registry = ConnectionRegistry(mock_config)
        registry.for_route(self._route(12, "ann"))

        assert registry.evict_connection(1) == 0
        assert registry.sessions_for_connection(12) == ["ann@A"]
```

Add any missing imports at the top of the file, matching its existing style: `ConnectionRegistry`, `U2Config`, `MockSession`, `from u2_mcp.credentials import U2Credentials`, `from u2_mcp.routing import Route` and `from u2_mcp.store.models import Connection`.

Append to `tests/test_tools/test_knowledge_per_connection.py`:

```python
def test_forgetting_a_deleted_connection_removes_its_notes(tmp_path: Path) -> None:
    """Connection ids can be reused after a delete, so the old notes must go."""
    from u2_mcp.utils.knowledge import forget_connection_knowledge

    notes = tmp_path / "knowledge" / "connection-7.md"
    notes.parent.mkdir(parents=True)
    notes.write_text("# Prod notes\n")

    forget_connection_knowledge(tmp_path, 7, delete_file=True)

    assert not notes.exists()


def test_forgetting_without_deleting_keeps_the_file(tmp_path: Path) -> None:
    from u2_mcp.utils.knowledge import forget_connection_knowledge

    notes = tmp_path / "knowledge" / "connection-7.md"
    notes.parent.mkdir(parents=True)
    notes.write_text("# Prod notes\n")

    forget_connection_knowledge(tmp_path, 7, delete_file=False)

    assert notes.exists()
```

(Add `from pathlib import Path` if the file lacks it.)

Run: `pytest tests/test_registry.py tests/test_tools/test_knowledge_per_connection.py -v`
Expected: FAIL (`evict_connection`, `forget_connection_knowledge` missing).

- [ ] **Step 5: Implement**

Add to `ConnectionRegistry` in `src/u2_mcp/registry.py`, after `for_route`:

```python
    def evict_connection(self, connection_id: int) -> int:
        """Close every slot for one team-mode connection, whatever the login.

        Called when an admin edits, switches off or deletes a connection: a slot
        keeps the host, port and password it was opened with, so it must not
        outlive the settings it was built from.

        Returns:
            How many slots were closed
        """
        prefix = f"{connection_id}:"
        with self._lock:
            keys = [key for key in self._managers if key.startswith(prefix)]
            evicted = [(key, self._managers.pop(key)) for key in keys]
        self._close_evicted(evicted)
        return len(evicted)

    def sessions_for_connection(self, connection_id: int) -> list[str]:
        """Return the logins (user@account) holding a slot on one connection."""
        prefix = f"{connection_id}:"
        with self._lock:
            return [key[len(prefix):] for key in self._managers if key.startswith(prefix)]
```

In `src/u2_mcp/utils/knowledge.py`, add (ensure `from pathlib import Path` is imported):

```python
def _connection_knowledge_path(data_dir: Path, connection_id: int) -> Path:
    """Return where one connection's notes live."""
    return Path(data_dir) / "knowledge" / f"connection-{connection_id}.md"


def forget_connection_knowledge(data_dir: Path, connection_id: int, *, delete_file: bool) -> None:
    """Drop a connection's cached notes store, and optionally its file.

    Args:
        data_dir: The settings store's data directory
        connection_id: The connection edited or deleted
        delete_file: True when the connection was deleted (ids can be reused)
    """
    with _connection_stores_lock:
        _connection_stores.pop(connection_id, None)
    if delete_file:
        _connection_knowledge_path(data_dir, connection_id).unlink(missing_ok=True)
```

and change the line in `get_knowledge_store` that builds the path to:

```python
                path = _connection_knowledge_path(settings.data_dir, connection_id)
```

Run: `pytest tests/test_registry.py tests/test_tools/test_knowledge_per_connection.py tests/test_connection_check.py -v`
Expected: PASS.

- [ ] **Step 6: Run everything, lint and commit**

Run: `pytest -q && ruff check . && ruff format --check . && mypy src/`
Expected: all pass, clean.

```bash
git add src/u2_mcp/connection_check.py src/u2_mcp/registry.py src/u2_mcp/utils/knowledge.py tests/mocks/sim_driver.py tests/test_connection_check.py tests/test_registry.py tests/test_tools/test_knowledge_per_connection.py
git commit -m "feat: connection test with a 10-second limit; evict a connection's sessions and notes"
```

---

### Task 6: Admin services: the one place admin changes are made

**Files:**
- Create: `src/u2_mcp/admin/__init__.py` (temporary: exports only `AdminContext`; Task 7 adds `build_admin_app`), `src/u2_mcp/admin/context.py`, `src/u2_mcp/admin/services.py`
- Test: `tests/test_admin/__init__.py` (empty), `tests/test_admin/conftest.py`, `tests/test_admin/test_services.py`

**Interfaces:**
- Consumes: Tasks 3–5.
- Produces in `admin/context.py`: `@dataclass class AdminContext(store: Store, config: U2Config, registry: Callable[[], ConnectionRegistry], check: Callable[[U2Config, Connection, U2Credentials], CheckResult] = check_connection)`.
- Produces in `admin/services.py`:
  - `class ValidationFailed(Exception)` with `.errors: dict[str, str]` (field name → message).
  - `DEFAULT_PORT = 31438`, `PUBLIC_URL_SETTING = "public_url"`, `LOCAL_ACCOUNTS_SETTING = "local_accounts_enabled"`.
  - `@dataclass class ConnectionForm` with fields `name, host, port (str), service, account, ssl, login_mode, login_user, login_password, read_only, enabled, version (int; 0 = new)`; class methods `from_form(data: Mapping[str, str])`, `from_connection(connection)`, `from_environment(config)`; method `errors(*, password_required: bool) -> dict[str, str]`; property `port_number -> int`.
  - `save_connection(ctx, form, *, actor: User, connection_id: int | None = None, fallback_password: str | None = None) -> Connection`
  - `set_connection_switches(ctx, connection_id, *, read_only: bool | None = None, enabled: bool | None = None, actor: User) -> Connection`
  - `delete_connection(ctx, connection_id, *, actor: User) -> None`
  - `disconnect_connection(ctx, connection_id, *, actor: User) -> int`
  - `check_connection_form(ctx, form, *, connection_id: int | None = None, fallback_password: str | None = None) -> CheckResult`
  - `create_local_user(ctx, *, username, password, password_again, display_name="", is_admin: bool, actor: User | None) -> User`
  - `change_password(ctx, user, *, current: str, new: str, new_again: str) -> None`
  - `effective_public_url(ctx) -> str`, `public_url_warning(url: str) -> str | None`, `save_public_url(ctx, url: str, *, actor: User) -> str`
  - `local_accounts_enabled(ctx) -> bool`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_admin/__init__.py` (empty) and `tests/test_admin/conftest.py`:

```python
"""Shared fixtures for admin-site tests."""

from collections.abc import Callable
from dataclasses import dataclass, field

import pytest

from u2_mcp.admin.context import AdminContext
from u2_mcp.config import U2Config
from u2_mcp.connection_check import CheckResult
from u2_mcp.credentials import U2Credentials
from u2_mcp.store.models import Connection, User
from u2_mcp.store.repo import Store


@dataclass
class FakeRegistry:
    """Records which connections were evicted or disconnected."""

    evicted: list[int] = field(default_factory=list)
    live: dict[int, list[str]] = field(default_factory=dict)

    def evict_connection(self, connection_id: int) -> int:
        self.evicted.append(connection_id)
        return len(self.live.pop(connection_id, []))

    def sessions_for_connection(self, connection_id: int) -> list[str]:
        return list(self.live.get(connection_id, []))


@dataclass
class FakeCheck:
    """Records what was tested and answers with a fixed result."""

    result: CheckResult = field(default_factory=lambda: CheckResult(True, "fine", 1.0))
    calls: list[tuple[Connection, U2Credentials]] = field(default_factory=list)

    def __call__(
        self, base: U2Config, connection: Connection, credentials: U2Credentials
    ) -> CheckResult:
        self.calls.append((connection, credentials))
        return self.result


@pytest.fixture
def registry() -> FakeRegistry:
    return FakeRegistry()


@pytest.fixture
def check() -> FakeCheck:
    return FakeCheck()


@pytest.fixture
def ctx(store: Store, mock_config: U2Config, registry: FakeRegistry, check: FakeCheck
        ) -> AdminContext:
    registry_getter: Callable[[], FakeRegistry] = lambda: registry  # noqa: E731
    return AdminContext(store=store, config=mock_config, registry=registry_getter,  # type: ignore[arg-type]
                        check=check)


@pytest.fixture
def admin(store: Store) -> User:
    return store.add_local_user("root", password_hash="unused", is_admin=True)
```

Create `tests/test_admin/test_services.py`:

```python
"""Admin services: validation, saving, eviction and audit in one place."""

import pytest

from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.services import (
    ConnectionForm,
    ValidationFailed,
    change_password,
    check_connection_form,
    create_local_user,
    delete_connection,
    effective_public_url,
    public_url_warning,
    save_connection,
    save_public_url,
    set_connection_switches,
)
from u2_mcp.passwords import hash_password, verify_password
from u2_mcp.store.models import User
from u2_mcp.store.repo import StaleEdit

from .conftest import FakeCheck, FakeRegistry


def _form(**changes: object) -> ConnectionForm:
    values: dict[str, str] = {
        "name": "Prod", "host": "u2.example", "port": "31438", "service": "uvcs",
        "account": "PROD", "login_mode": "shared", "login_user": "svc",
        "login_password": "secret", "read_only": "on", "enabled": "on",
    }
    values.update({key: str(value) for key, value in changes.items()})
    return ConnectionForm.from_form(values)


class TestConnectionForm:
    def test_unchecked_boxes_are_false(self) -> None:
        form = ConnectionForm.from_form({"name": "x"})

        assert form.read_only is False and form.enabled is False and form.ssl is False

    @pytest.mark.parametrize(
        ("field", "value", "message"),
        [
            ("name", "", "Give the connection a name."),
            ("name", "bad/name", "Use letters, digits, spaces, dots, dashes or underscores"),
            ("host", "", "Enter the U2 server's host name or address."),
            ("port", "0", "Enter a port between 1 and 65535."),
            ("port", "abc", "Enter a port between 1 and 65535."),
            ("service", "xyz", "Choose UniVerse (uvcs) or UniData (udcs)."),
            ("account", "", "Enter the U2 account name."),
            ("login_mode", "magic", "Choose shared or per-user logins."),
            ("login_user", "", "Enter the U2 login the server uses."),
        ],
    )
    def test_each_field_is_checked(self, field: str, value: str, message: str) -> None:
        errors = _form(**{field: value}).errors(password_required=False)

        assert message in errors[field]

    def test_a_password_can_be_required(self) -> None:
        errors = _form(login_password="").errors(password_required=True)

        assert errors == {"login_password": "Enter the password for that login."}

    def test_per_user_connections_need_no_login(self) -> None:
        assert _form(login_mode="per_user", login_user="").errors(password_required=False) == {}

    def test_environment_prefill_never_carries_the_password(self, ctx: AdminContext) -> None:
        form = ConnectionForm.from_environment(ctx.config)

        assert form.host == ctx.config.host
        assert form.login_user == ctx.config.user
        assert form.login_password == ""


class TestSavingConnections:
    def test_create_audits_without_the_password(self, ctx: AdminContext, admin: User) -> None:
        saved = save_connection(ctx, _form(), actor=admin)

        assert ctx.store.shared_password(saved.id) == "secret"
        entry = ctx.store.recent_audit(1)[0]
        assert entry["action"] == "connection.create" and entry["kind"] == "admin"
        assert entry["actor_label"] == admin.label
        assert "secret" not in str(entry["params"])

    def test_create_requires_a_password(self, ctx: AdminContext, admin: User) -> None:
        with pytest.raises(ValidationFailed) as failed:
            save_connection(ctx, _form(login_password=""), actor=admin)

        assert "login_password" in failed.value.errors

    def test_the_environment_password_can_stand_in(self, ctx: AdminContext, admin: User) -> None:
        saved = save_connection(ctx, _form(login_password=""), actor=admin,
                                fallback_password="from-env")

        assert ctx.store.shared_password(saved.id) == "from-env"

    def test_edit_keeps_the_password_and_evicts_sessions(
        self, ctx: AdminContext, admin: User, registry: FakeRegistry
    ) -> None:
        saved = save_connection(ctx, _form(), actor=admin)

        edited = save_connection(ctx, _form(host="u2-new.example", login_password="",
                                            version=saved.version),
                                 actor=admin, connection_id=saved.id)

        assert edited.host == "u2-new.example"
        assert ctx.store.shared_password(saved.id) == "secret"
        assert registry.evicted == [saved.id]
        assert ctx.store.recent_audit(1)[0]["action"] == "connection.update"

    def test_a_stale_edit_is_refused(self, ctx: AdminContext, admin: User) -> None:
        saved = save_connection(ctx, _form(), actor=admin)
        save_connection(ctx, _form(host="a.example", version=saved.version), actor=admin,
                        connection_id=saved.id)

        with pytest.raises(StaleEdit):
            save_connection(ctx, _form(host="b.example", version=saved.version), actor=admin,
                            connection_id=saved.id)

    def test_switching_to_per_user_drops_the_shared_login(
        self, ctx: AdminContext, admin: User
    ) -> None:
        saved = save_connection(ctx, _form(), actor=admin)

        edited = save_connection(ctx, _form(login_mode="per_user", version=saved.version),
                                 actor=admin, connection_id=saved.id)

        assert edited.shared_user is None
        assert ctx.store.shared_password(saved.id) is None


class TestSwitchesAndDelete:
    def test_switches_save_audit_and_evict(
        self, ctx: AdminContext, admin: User, registry: FakeRegistry
    ) -> None:
        saved = save_connection(ctx, _form(), actor=admin)

        switched = set_connection_switches(ctx, saved.id, read_only=False, actor=admin)

        assert switched.read_only is False
        assert registry.evicted == [saved.id]
        assert ctx.store.recent_audit(1)[0]["action"] == "connection.switches"

    def test_delete_removes_and_audits(
        self, ctx: AdminContext, admin: User, registry: FakeRegistry
    ) -> None:
        saved = save_connection(ctx, _form(), actor=admin)

        delete_connection(ctx, saved.id, actor=admin)

        assert ctx.store.get_connection(saved.id) is None
        assert registry.evicted == [saved.id]
        entry = ctx.store.recent_audit(1)[0]
        assert entry["action"] == "connection.delete"
        assert entry["params"] == {"name": "Prod"}


class TestCheckingAForm:
    def test_the_typed_password_is_used(self, ctx: AdminContext, check: FakeCheck) -> None:
        check_connection_form(ctx, _form(login_password="typed"))

        tested, login = check.calls[0]
        assert tested.host == "u2.example" and login.password == "typed"

    def test_a_blank_password_falls_back_to_the_stored_one(
        self, ctx: AdminContext, admin: User, check: FakeCheck
    ) -> None:
        saved = save_connection(ctx, _form(), actor=admin)

        check_connection_form(ctx, _form(login_password=""), connection_id=saved.id)

        assert check.calls[0][1].password == "secret"

    def test_invalid_settings_are_not_tested(self, ctx: AdminContext, check: FakeCheck) -> None:
        with pytest.raises(ValidationFailed):
            check_connection_form(ctx, _form(host=""))

        assert check.calls == []

    def test_per_user_needs_a_test_login(self, ctx: AdminContext) -> None:
        with pytest.raises(ValidationFailed) as failed:
            check_connection_form(ctx, _form(login_mode="per_user", login_user=""))

        assert failed.value.errors == {"login_user": "Enter a U2 login to test with."}


class TestLocalUsers:
    def test_create_hashes_and_audits(self, ctx: AdminContext) -> None:
        user = create_local_user(ctx, username="ann", password="long enough pass",
                                 password_again="long enough pass", is_admin=True, actor=None)

        assert verify_password(ctx.store.password_hash(user.id), "long enough pass")
        entry = ctx.store.recent_audit(1)[0]
        assert entry["action"] == "user.create" and entry["actor_label"] == "setup wizard"

    @pytest.mark.parametrize(
        ("username", "password", "again", "field", "message"),
        [
            ("bad name!", "long enough pass", "long enough pass", "username", "Use 1 to 64"),
            ("ann", "short", "short", "password", "Use at least 12 characters."),
            ("ann", "long enough pass", "different pass!", "password_again",
             "The two passwords don't match."),
        ],
    )
    def test_problems_are_reported_per_field(
        self, ctx: AdminContext, username: str, password: str, again: str, field: str,
        message: str
    ) -> None:
        with pytest.raises(ValidationFailed) as failed:
            create_local_user(ctx, username=username, password=password, password_again=again,
                              is_admin=True, actor=None)

        assert message in failed.value.errors[field]

    def test_a_taken_username(self, ctx: AdminContext) -> None:
        create_local_user(ctx, username="ann", password="long enough pass",
                          password_again="long enough pass", is_admin=True, actor=None)

        with pytest.raises(ValidationFailed) as failed:
            create_local_user(ctx, username="ann", password="long enough pass",
                              password_again="long enough pass", is_admin=True, actor=None)

        assert "already exists" in failed.value.errors["username"]

    def test_change_password(self, ctx: AdminContext) -> None:
        user = ctx.store.add_local_user("ann", password_hash=hash_password("old password 1"))
        ctx.store.set_password_hash(user.id, hash_password("old password 1"), must_change=True)

        change_password(ctx, user, current="old password 1", new="new password 22",
                        new_again="new password 22")

        assert verify_password(ctx.store.password_hash(user.id), "new password 22")
        refreshed = ctx.store.get_user(user.id)
        assert refreshed is not None and refreshed.must_change_password is False
        assert ctx.store.recent_audit(1)[0]["action"] == "admin.password_change"

    def test_change_password_checks_the_current_one(self, ctx: AdminContext) -> None:
        user = ctx.store.add_local_user("ann", password_hash=hash_password("old password 1"))

        with pytest.raises(ValidationFailed) as failed:
            change_password(ctx, user, current="wrong", new="new password 22",
                            new_again="new password 22")

        assert failed.value.errors == {"current_password": "That is not your current password."}


class TestPublicUrl:
    def test_save_trims_and_audits(self, ctx: AdminContext, admin: User) -> None:
        saved = save_public_url(ctx, " https://u2.example.com/ ", actor=admin)

        assert saved == "https://u2.example.com"
        assert effective_public_url(ctx) == "https://u2.example.com"
        assert ctx.store.recent_audit(1)[0]["action"] == "settings.public_url"

    def test_bad_addresses_are_refused(self, ctx: AdminContext, admin: User) -> None:
        with pytest.raises(ValidationFailed):
            save_public_url(ctx, "u2.example.com", actor=admin)

    def test_http_gets_a_warning(self) -> None:
        assert public_url_warning("http://u2.example.com") == (
            "This address is not https. Sign-in cookies and tokens would cross the "
            "network unencrypted."
        )
        assert public_url_warning("https://u2.example.com") is None

    def test_default_comes_from_the_environment(self, ctx: AdminContext) -> None:
        expected = ctx.config.public_url or f"http://{ctx.config.http_host}:{ctx.config.http_port}"

        assert effective_public_url(ctx) == expected
```

Run: `pytest tests/test_admin/test_services.py -v`
Expected: FAIL with ImportError.

- [ ] **Step 2: Implement `admin/context.py` and the temporary `admin/__init__.py`**

`src/u2_mcp/admin/context.py`:

```python
"""What every admin-site handler and service needs, passed explicitly."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..config import U2Config
from ..connection_check import CheckResult, check_connection
from ..credentials import U2Credentials
from ..registry import ConnectionRegistry
from ..store.models import Connection
from ..store.repo import Store


@dataclass
class AdminContext:
    """The admin site's dependencies.

    Attributes:
        store: The settings database
        config: Server configuration
        registry: Returns the live connection registry (created lazily by the server)
        check: Tests a connection; replaced in tests
    """

    store: Store
    config: U2Config
    registry: Callable[[], ConnectionRegistry]
    check: Callable[[U2Config, Connection, U2Credentials], CheckResult] = check_connection
```

`src/u2_mcp/admin/__init__.py`:

```python
"""The admin site, mounted at /admin in team mode."""

from .context import AdminContext

__all__ = ["AdminContext"]
```

- [ ] **Step 3: Implement `admin/services.py`**

```python
"""Every change the admin site makes, in one place.

The setup wizard and the everyday pages both call these functions, so the
wizard has no logic of its own (spec: setup wizard rule 1). Each change is
validated here, saved, and written to the audit table with kind "admin".
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from ..config import U2Config
from ..connection_check import CheckResult
from ..credentials import U2Credentials
from ..passwords import hash_password, password_problem, verify_password
from ..store.crypto import SecretUnreadable
from ..store.models import Connection, User
from ..store.repo import StoreError
from ..utils.knowledge import forget_connection_knowledge
from .context import AdminContext

DEFAULT_PORT = 31438
PUBLIC_URL_SETTING = "public_url"
LOCAL_ACCOUNTS_SETTING = "local_accounts_enabled"

_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}")
_USERNAME = re.compile(r"[A-Za-z0-9._@-]{1,64}")


class ValidationFailed(Exception):
    """A form had problems; `errors` maps each field to its message."""

    def __init__(self, errors: dict[str, str]) -> None:
        super().__init__("; ".join(errors.values()))
        self.errors = errors


def _int(value: str | None) -> int:
    try:
        return int(value or 0)
    except ValueError:
        return 0


@dataclass
class ConnectionForm:
    """The connection form's values, as typed. The password is never shown back."""

    name: str = ""
    host: str = ""
    port: str = str(DEFAULT_PORT)
    service: str = "uvcs"
    account: str = ""
    ssl: bool = False
    login_mode: str = "shared"
    login_user: str = ""
    login_password: str = ""
    read_only: bool = True
    enabled: bool = True
    version: int = 0  # 0 means a new connection

    @classmethod
    def from_form(cls, data: Mapping[str, str]) -> ConnectionForm:
        """Read a submitted form. Unchecked checkboxes are absent, so they read as False."""
        return cls(
            name=data.get("name", "").strip(),
            host=data.get("host", "").strip(),
            port=data.get("port", "").strip(),
            service=data.get("service", "uvcs").strip(),
            account=data.get("account", "").strip(),
            ssl=data.get("ssl") == "on",
            login_mode=data.get("login_mode", "shared").strip(),
            login_user=data.get("login_user", "").strip(),
            login_password=data.get("login_password", ""),
            read_only=data.get("read_only") == "on",
            enabled=data.get("enabled") == "on",
            version=_int(data.get("version")),
        )

    @classmethod
    def from_connection(cls, connection: Connection) -> ConnectionForm:
        """Fill the form from a saved connection, for editing."""
        return cls(
            name=connection.name,
            host=connection.host,
            port=str(connection.port),
            service=connection.service,
            account=connection.account,
            ssl=connection.ssl,
            login_mode=connection.login_mode,
            login_user=connection.shared_user or "",
            read_only=connection.read_only,
            enabled=connection.enabled,
            version=connection.version,
        )

    @classmethod
    def from_environment(cls, config: U2Config) -> ConnectionForm:
        """Pre-fill a new connection from U2_* variables. The password stays server-side."""
        if not config.host:
            return cls()
        return cls(
            name="default",
            host=config.host,
            port=str(config.port),
            service=config.service,
            account=config.account,
            ssl=config.ssl,
            login_user=config.user,
        )

    @property
    def port_number(self) -> int:
        """The port as a number (call errors() first)."""
        return int(self.port)

    def errors(self, *, password_required: bool) -> dict[str, str]:
        """Return each field's problem; empty when the form is valid."""
        found: dict[str, str] = {}
        if not self.name:
            found["name"] = "Give the connection a name."
        elif not _NAME.fullmatch(self.name):
            found["name"] = (
                "Use letters, digits, spaces, dots, dashes or underscores (up to 64), "
                "starting with a letter or digit."
            )
        if not self.host:
            found["host"] = "Enter the U2 server's host name or address."
        if not self.port.isdigit() or not 1 <= int(self.port) <= 65535:
            found["port"] = "Enter a port between 1 and 65535."
        if self.service not in ("uvcs", "udcs"):
            found["service"] = "Choose UniVerse (uvcs) or UniData (udcs)."
        if not self.account:
            found["account"] = "Enter the U2 account name."
        if self.login_mode not in ("shared", "per_user"):
            found["login_mode"] = "Choose shared or per-user logins."
        elif self.login_mode == "shared":
            if not self.login_user:
                found["login_user"] = "Enter the U2 login the server uses."
            if password_required and not self.login_password:
                found["login_password"] = "Enter the password for that login."
        return found

    def described(self) -> dict[str, Any]:
        """The form's values for the audit trail, never the password."""
        return {
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "service": self.service,
            "account": self.account,
            "ssl": self.ssl,
            "login_mode": self.login_mode,
            "login_user": self.login_user,
            "read_only": self.read_only,
            "enabled": self.enabled,
        }


def _audit(
    ctx: AdminContext,
    actor: User | None,
    action: str,
    *,
    kind: str = "admin",
    connection_id: int | None = None,
    params: dict[str, Any] | None = None,
    outcome: str = "ok",
) -> None:
    ctx.store.add_audit(
        kind=kind,
        action=action,
        outcome=outcome,
        actor_user_id=actor.id if actor else None,
        actor_label=actor.label if actor else "setup wizard",
        connection_id=connection_id,
        params=params,
    )


def _existing(ctx: AdminContext, connection_id: int) -> Connection:
    connection = ctx.store.get_connection(connection_id)
    if connection is None:
        raise StoreError("That connection no longer exists.")
    return connection


def save_connection(
    ctx: AdminContext,
    form: ConnectionForm,
    *,
    actor: User,
    connection_id: int | None = None,
    fallback_password: str | None = None,
) -> Connection:
    """Create or update a connection.

    Args:
        form: What was submitted
        actor: Who is saving
        connection_id: The connection being edited, or None to create one
        fallback_password: Used when the password box is blank on a new shared
            connection (the setup wizard passes U2_PASSWORD)

    Raises:
        ValidationFailed: With per-field messages
        StaleEdit: If someone saved the connection since this form was opened
        StoreError: If the name is taken or the connection is gone
    """
    existing = _existing(ctx, connection_id) if connection_id is not None else None
    shared = form.login_mode == "shared"
    has_stored = (
        existing is not None and existing.login_mode == "shared" and existing.has_shared_password
    )
    password = form.login_password or None
    if shared and password is None and not has_stored:
        password = fallback_password or None
    errors = form.errors(password_required=shared and password is None and not has_stored)
    if errors:
        raise ValidationFailed(errors)

    try:
        if existing is None:
            saved = ctx.store.add_connection(
                name=form.name,
                host=form.host,
                port=form.port_number,
                service=form.service,
                account=form.account,
                ssl=form.ssl,
                login_mode=form.login_mode,
                shared_user=form.login_user if shared else None,
                shared_password=password if shared else None,
                read_only=form.read_only,
                enabled=form.enabled,
                actor=actor.label,
            )
            action = "connection.create"
        else:
            saved = ctx.store.update_connection(
                existing.id,
                expected_version=form.version,
                name=form.name,
                host=form.host,
                port=form.port_number,
                service=form.service,
                account=form.account,
                ssl=form.ssl,
                login_mode=form.login_mode,
                shared_user=form.login_user if shared else None,
                shared_password=password if shared else None,
                clear_shared_password=not shared,
                read_only=form.read_only,
                enabled=form.enabled,
                actor=actor.label,
            )
            ctx.registry().evict_connection(saved.id)
            action = "connection.update"
    except StoreError as exc:
        if "already exists" in str(exc):
            raise ValidationFailed({"name": str(exc)}) from exc
        raise
    _audit(ctx, actor, action, connection_id=saved.id, params=form.described())
    return saved


def set_connection_switches(
    ctx: AdminContext,
    connection_id: int,
    *,
    read_only: bool | None = None,
    enabled: bool | None = None,
    actor: User,
) -> Connection:
    """Flip a connection's read-only or enabled switch; live sessions are closed."""
    _existing(ctx, connection_id)
    ctx.store.set_connection_flags(
        connection_id, read_only=read_only, enabled=enabled, actor=actor.label
    )
    # A session keeps the read-only setting it was opened with, so close them all.
    ctx.registry().evict_connection(connection_id)
    params = {key: value for key, value in (("read_only", read_only), ("enabled", enabled))
              if value is not None}
    _audit(ctx, actor, "connection.switches", connection_id=connection_id, params=params)
    return _existing(ctx, connection_id)


def delete_connection(ctx: AdminContext, connection_id: int, *, actor: User) -> None:
    """Delete a connection, its grants, its live sessions and its knowledge notes."""
    existing = _existing(ctx, connection_id)
    ctx.store.delete_connection(connection_id)
    ctx.registry().evict_connection(connection_id)
    forget_connection_knowledge(ctx.store.data_dir, connection_id, delete_file=True)
    _audit(ctx, actor, "connection.delete", connection_id=connection_id,
           params={"name": existing.name})


def disconnect_connection(ctx: AdminContext, connection_id: int, *, actor: User) -> int:
    """Close every live session on a connection. Returns how many closed."""
    _existing(ctx, connection_id)
    closed = ctx.registry().evict_connection(connection_id)
    _audit(ctx, actor, "connection.disconnect", connection_id=connection_id,
           params={"closed": closed})
    return closed


def check_connection_form(
    ctx: AdminContext,
    form: ConnectionForm,
    *,
    connection_id: int | None = None,
    fallback_password: str | None = None,
) -> CheckResult:
    """Test the settings on a form, saved or not.

    A blank password box means the stored password (when editing) or the
    fallback (the wizard's U2_PASSWORD). Per-user connections are tested with
    the login typed on the form, which is not saved.

    Raises:
        ValidationFailed: If the settings are not complete enough to try
    """
    errors = form.errors(password_required=False)
    if form.login_mode == "per_user" and not form.login_user:
        errors["login_user"] = "Enter a U2 login to test with."
    if errors:
        raise ValidationFailed(errors)

    password = form.login_password
    if not password and connection_id is not None:
        try:
            password = ctx.store.shared_password(connection_id) or ""
        except SecretUnreadable:
            return CheckResult(
                False,
                "The stored password can't be read; U2_SECRET_KEY may have changed. "
                "Type the password again.",
                0.0,
            )
    if not password:
        password = fallback_password or ""

    transient = Connection(
        id=connection_id or 0,
        name=form.name,
        host=form.host,
        port=form.port_number,
        service=form.service,
        account=form.account,
        ssl=form.ssl,
        login_mode=form.login_mode,
        shared_user=form.login_user,
        has_shared_password=bool(password),
        read_only=True,
        enabled=True,
    )
    login = U2Credentials(
        user=form.login_user, password=password, account=form.account, is_shared=True
    )
    return ctx.check(ctx.config, transient, login)


def create_local_user(
    ctx: AdminContext,
    *,
    username: str,
    password: str,
    password_again: str,
    display_name: str = "",
    is_admin: bool,
    actor: User | None,
) -> User:
    """Create a local (password) account.

    Raises:
        ValidationFailed: With per-field messages
    """
    username = username.strip()
    errors: dict[str, str] = {}
    if not _USERNAME.fullmatch(username):
        errors["username"] = "Use 1 to 64 letters, digits, dots, dashes, underscores or @."
    problem = password_problem(password, username=username)
    if problem:
        errors["password"] = problem
    elif password != password_again:
        errors["password_again"] = "The two passwords don't match."
    if errors:
        raise ValidationFailed(errors)
    try:
        user = ctx.store.add_local_user(
            username,
            display_name=display_name.strip() or None,
            password_hash=hash_password(password),
            is_admin=is_admin,
        )
    except StoreError as exc:
        raise ValidationFailed({"username": str(exc)}) from exc
    _audit(ctx, actor, "user.create", params={"username": username, "is_admin": is_admin})
    return user


def change_password(
    ctx: AdminContext, user: User, *, current: str, new: str, new_again: str
) -> None:
    """Change a local user's own password and clear any forced change.

    Raises:
        ValidationFailed: With per-field messages
    """
    if not verify_password(ctx.store.password_hash(user.id), current):
        raise ValidationFailed({"current_password": "That is not your current password."})
    problem = password_problem(new, username=user.username or "")
    if problem:
        raise ValidationFailed({"new_password": problem})
    if new != new_again:
        raise ValidationFailed({"new_password_again": "The two passwords don't match."})
    ctx.store.set_password_hash(user.id, hash_password(new), must_change=False)
    _audit(ctx, user, "admin.password_change", kind="auth")


def effective_public_url(ctx: AdminContext) -> str:
    """The address people use: saved in the UI, else U2_PUBLIC_URL, else host and port."""
    saved = ctx.store.get_setting(PUBLIC_URL_SETTING)
    if saved:
        return str(saved)
    if ctx.config.public_url:
        return ctx.config.public_url.rstrip("/")
    return f"http://{ctx.config.http_host}:{ctx.config.http_port}"


def public_url_warning(url: str) -> str | None:
    """Return a warning when the address is not https."""
    if url.lower().startswith("https://"):
        return None
    return (
        "This address is not https. Sign-in cookies and tokens would cross the "
        "network unencrypted."
    )


def save_public_url(ctx: AdminContext, url: str, *, actor: User) -> str:
    """Save the server's public address.

    Raises:
        ValidationFailed: If it is not an http(s) URL
    """
    cleaned = url.strip().rstrip("/")
    parts = urlsplit(cleaned)
    if parts.scheme not in ("http", "https") or not parts.netloc or parts.query or parts.fragment:
        raise ValidationFailed(
            {"public_url": "Enter the full address people use, such as https://u2-mcp.example.com"}
        )
    ctx.store.set_setting(PUBLIC_URL_SETTING, cleaned)
    _audit(ctx, actor, "settings.public_url", params={"public_url": cleaned})
    return cleaned


def local_accounts_enabled(ctx: AdminContext) -> bool:
    """Whether non-admin local accounts may sign in (admins always may)."""
    return bool(ctx.store.get_setting(LOCAL_ACCOUNTS_SETTING, True))
```

Run: `pytest tests/test_admin/test_services.py -v`
Expected: PASS.

- [ ] **Step 4: Run everything, lint and commit**

Run: `ruff format src tests && pytest -q && ruff check . && ruff format --check . && mypy src/`
Expected: all pass, clean.

```bash
git add src/u2_mcp/admin tests/test_admin
git commit -m "feat: admin services for connections, local users and the public address"
```

---

### Task 7: The admin site skeleton, mounted at `/admin`, and `/health`

**Files:**
- Create: `src/u2_mcp/admin/templating.py`, `src/u2_mcp/admin/app.py`
- Create: `src/u2_mcp/admin/templates/base.html`, `templates/message.html`, `templates/partials/fields.html`
- Create: `src/u2_mcp/admin/static/styles.css`, `static/htmx.min.js` (downloaded), `static/README.md`
- Modify: `src/u2_mcp/admin/__init__.py`, `src/u2_mcp/server.py` (`build_streamable_http_app`)
- Test: `tests/test_admin/test_app.py`

**Interfaces:**
- Consumes: `AdminContext` (Task 6), `ensure_setup_code` (Task 4), `effective_public_url` (Task 6).
- Produces in `admin/templating.py`: `render(request: Request, template: str, *, status_code: int = 200, **context: Any) -> HTMLResponse` (adds `request`, `user`, `csrf_token`, `setup_complete`, `notice` to every template), `admin_context(request: Request) -> AdminContext`, `NOTICES: dict[str, str]`.
- Produces in `admin/app.py`: `build_admin_app(ctx: AdminContext) -> Starlette`. The app keeps `ctx` on `app.state.ctx`. Later tasks add their routes to the list built here.
- Produces in templates: `base.html` with blocks `title` and `content`; `partials/fields.html` macros `text(name, label, value, errors, type="text", hint="", autocomplete="off", required=false)`, `checkbox(name, label, checked, hint="")`, `select(name, label, value, options, errors)` where `options` is a list of `(value, label)` pairs.
- `server.build_streamable_http_app` mounts the admin site at `/admin` when a store exists, adds `GET /health` in every case, and logs the setup code while setup is unfinished.

- [ ] **Step 1: Vendor htmx**

Run (from the repository root):

```bash
mkdir -p src/u2_mcp/admin/static
curl -fsSL https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js -o src/u2_mcp/admin/static/htmx.min.js
python -c "import hashlib,pathlib;p=pathlib.Path('src/u2_mcp/admin/static/htmx.min.js');print(p.stat().st_size, hashlib.sha256(p.read_bytes()).hexdigest())"
```

Expected: a size above 40000 bytes and a SHA-256. Open the file's first 200 characters and check it is minified JavaScript mentioning `htmx`, not an HTML error page.

Create `src/u2_mcp/admin/static/README.md` (replace `<sha256>` with the printed hash):

```markdown
# Vendored files

- `htmx.min.js`: htmx 2.0.4, from https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js
  (BSD 0-Clause licence). SHA-256 `<sha256>`. Vendored so the admin site works on
  servers without internet access. To upgrade, replace the file and this entry.
```

- [ ] **Step 2: Write the failing tests**

Create `tests/test_admin/test_app.py`:

```python
"""The admin site is mounted beside MCP without disturbing it."""

import os
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest
from starlette.testclient import TestClient

import u2_mcp.server as server
from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.templating import _environment
from u2_mcp.config import U2Config
from u2_mcp.identity import set_identity_resolver
from u2_mcp.store import install_store


@pytest.fixture
def team_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    for name in ("U2_HOST", "U2_USER", "U2_PASSWORD", "U2_ACCOUNT"):
        monkeypatch.delenv(name, raising=False)
    env = {
        "U2_SECRET_KEY": "a" * 40,
        "U2_DATA_DIR": str(tmp_path),
        "U2_WATCHDOG_ENABLED": "false",
        "U2_AUDIT_ENABLED": "false",
    }
    with patch.dict(os.environ, env):
        app = server.build_streamable_http_app(U2Config())
        try:
            with TestClient(app) as client:
                yield client
        finally:
            # Team mode installs a store and an identity resolver; undo both, as
            # tests/test_team_mode_e2e.py does, or later tests see this server's state.
            install_store(None)
            set_identity_resolver(None)
            server.reset_connection_manager()


def test_health_answers_without_authentication(team_app: TestClient) -> None:
    response = team_app.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_the_admin_site_is_served(team_app: TestClient) -> None:
    response = team_app.get("/admin/", follow_redirects=False)

    assert response.status_code in (200, 302, 303)


def test_static_files_are_served(team_app: TestClient) -> None:
    assert team_app.get("/admin/static/htmx.min.js").status_code == 200
    assert team_app.get("/admin/static/styles.css").status_code == 200


def test_mcp_still_requires_a_token(team_app: TestClient) -> None:
    response = team_app.post("/", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})

    assert response.status_code == 401


def test_no_admin_site_without_team_mode(mock_env: dict[str, str]) -> None:
    with patch.dict(os.environ, {"U2_WATCHDOG_ENABLED": "false", "U2_AUDIT_ENABLED": "false",
                                 "U2_ALLOW_UNAUTHENTICATED_NETWORK_ACCESS": "true",
                                 "U2_HTTP_HOST": "127.0.0.1"}):
        app = server.build_streamable_http_app(U2Config())
    try:
        with TestClient(app) as client:
            assert client.get("/admin/").status_code == 404
            assert client.get("/health").status_code == 200
    finally:
        server.reset_connection_manager()


def test_the_setup_code_is_logged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                  caplog: pytest.LogCaptureFixture) -> None:
    for name in ("U2_HOST", "U2_USER", "U2_PASSWORD", "U2_ACCOUNT"):
        monkeypatch.delenv(name, raising=False)
    env = {"U2_SECRET_KEY": "a" * 40, "U2_DATA_DIR": str(tmp_path),
           "U2_WATCHDOG_ENABLED": "false", "U2_AUDIT_ENABLED": "false"}
    with patch.dict(os.environ, env), caplog.at_level("WARNING"):
        server.build_streamable_http_app(U2Config())
    install_store(None)
    set_identity_resolver(None)

    assert "/admin/setup" in caplog.text
    assert "setup code" in caplog.text


def test_templates_escape_user_text() -> None:
    template = _environment().from_string("{{ value }}")

    assert template.render(value="<script>") == "&lt;script&gt;"


def test_render_supplies_the_context(store: object, mock_config: U2Config) -> None:
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.routing import Route

    from u2_mcp.admin.templating import render

    async def page(request: Request):  # type: ignore[no-untyped-def]
        return render(request, "message.html", title="Hello", message="Body text")

    app = Starlette(routes=[Route("/", page)])
    app.state.ctx = AdminContext(store=store, config=mock_config,  # type: ignore[arg-type]
                                 registry=lambda: None)  # type: ignore[arg-type,return-value]
    response = TestClient(app).get("/?notice=saved")

    assert "Body text" in response.text
    assert "Saved." in response.text
    assert response.headers["cache-control"] == "no-store"
```

If `test_no_admin_site_without_team_mode` cannot build the app because of a network-exposure check, read `check_network_exposure` in `src/u2_mcp/exposure.py` and set whichever environment variable it documents for a loopback, unauthenticated test server; the assertion that matters is that `/admin/` is 404 without team mode.

Run: `pytest tests/test_admin/test_app.py -v`
Expected: FAIL with ImportError (`u2_mcp.admin.templating`).

- [ ] **Step 3: Implement templating**

`src/u2_mcp/admin/templating.py`:

```python
"""Server-rendered pages: one Jinja2 environment, autoescaped."""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape
from starlette.requests import Request
from starlette.responses import HTMLResponse

from ..setup_code import is_setup_complete
from .context import AdminContext

# Notices are chosen by a short code in the query string, never by free text, so
# a link cannot put words of its own on an admin page.
NOTICES: dict[str, str] = {
    "saved": "Saved.",
    "deleted": "Deleted.",
    "disconnected": "Sessions closed.",
    "signed_out": "You are signed out.",
    "password_changed": "Your password is changed.",
    "setup_done": "Setup is finished.",
}


@lru_cache(maxsize=1)
def _environment() -> Environment:
    return Environment(
        loader=PackageLoader("u2_mcp.admin", "templates"),
        autoescape=select_autoescape(["html"], default_for_string=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def admin_context(request: Request) -> AdminContext:
    """Return the admin site's dependencies for this request."""
    ctx: AdminContext = request.app.state.ctx
    return ctx


def render(
    request: Request, template: str, *, status_code: int = 200, **context: Any
) -> HTMLResponse:
    """Render a template with the values every page uses.

    Args:
        request: The current request
        template: Path under admin/templates
        status_code: HTTP status
        **context: Page values; these override the defaults below
    """
    ctx = admin_context(request)
    values: dict[str, Any] = {
        "request": request,
        "user": getattr(request.state, "user", None),
        "csrf_token": getattr(request.state, "csrf_token", ""),
        "setup_complete": is_setup_complete(ctx.store),
        "notice": NOTICES.get(request.query_params.get("notice", "")),
    }
    values.update(context)
    page = _environment().get_template(template).render(**values)
    # Admin pages show settings and sessions; never let a browser or proxy keep them.
    return HTMLResponse(page, status_code=status_code, headers={"Cache-Control": "no-store"})
```

- [ ] **Step 4: Create the templates and stylesheet**

`src/u2_mcp/admin/templates/base.html`:

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{% block title %}u2-mcp admin{% endblock %}</title>
  <link rel="stylesheet" href="/admin/static/styles.css">
  <script src="/admin/static/htmx.min.js" defer></script>
</head>
<body hx-headers='{"X-CSRF-Token": "{{ csrf_token }}"}'>
  <header class="top">
    <a class="brand" href="/admin/">u2-mcp admin</a>
    {% if user and user.is_admin and setup_complete %}
    <nav>
      <a href="/admin/connections">Connections</a>
      <a href="/admin/settings">Settings</a>
    </nav>
    {% endif %}
    {% if user %}
    <form method="post" action="/admin/sign-out" class="inline">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <span class="who">{{ user.label }}</span>
      <button type="submit">Sign out</button>
    </form>
    {% endif %}
  </header>
  <main>
    {% if notice %}<p class="notice" role="status">{{ notice }}</p>{% endif %}
    {% block content %}{% endblock %}
  </main>
</body>
</html>
```

`src/u2_mcp/admin/templates/message.html`:

```html
{% extends "base.html" %}
{% block title %}{{ title }} · u2-mcp admin{% endblock %}
{% block content %}
<h1>{{ title }}</h1>
<p>{{ message }}</p>
{% if link %}<p><a href="{{ link }}">{{ link_text or "Continue" }}</a></p>{% endif %}
{% endblock %}
```

`src/u2_mcp/admin/templates/partials/fields.html`:

```html
{% macro text(name, label, value, errors, type="text", hint="", autocomplete="off", required=false) %}
<div class="field{% if errors and errors.get(name) %} has-error{% endif %}">
  <label for="f-{{ name }}">{{ label }}</label>
  <input id="f-{{ name }}" name="{{ name }}" type="{{ type }}"
         value="{{ value if type != 'password' else '' }}" autocomplete="{{ autocomplete }}"
         {% if required %}required{% endif %}
         {% if errors and errors.get(name) %}aria-invalid="true" aria-describedby="e-{{ name }}"{% endif %}>
  {% if hint %}<p class="hint">{{ hint }}</p>{% endif %}
  {% if errors and errors.get(name) %}<p class="error" id="e-{{ name }}">{{ errors[name] }}</p>{% endif %}
</div>
{% endmacro %}

{% macro checkbox(name, label, checked, hint="") %}
<div class="field checkbox">
  <label><input type="checkbox" name="{{ name }}" {% if checked %}checked{% endif %}> {{ label }}</label>
  {% if hint %}<p class="hint">{{ hint }}</p>{% endif %}
</div>
{% endmacro %}

{% macro select(name, label, value, options, errors) %}
<div class="field{% if errors and errors.get(name) %} has-error{% endif %}">
  <label for="f-{{ name }}">{{ label }}</label>
  <select id="f-{{ name }}" name="{{ name }}">
    {% for option_value, option_label in options %}
    <option value="{{ option_value }}" {% if option_value == value %}selected{% endif %}>{{ option_label }}</option>
    {% endfor %}
  </select>
  {% if errors and errors.get(name) %}<p class="error">{{ errors[name] }}</p>{% endif %}
</div>
{% endmacro %}
```

`src/u2_mcp/admin/static/styles.css`:

```css
:root { --ink: #1d2433; --muted: #5b6475; --line: #d7dce5; --accent: #1f5fbf;
        --bad: #b42318; --good: #067647; --paper: #ffffff; --wash: #f5f7fa; }
* { box-sizing: border-box; }
body { margin: 0; font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
       color: var(--ink); background: var(--wash); }
.top { display: flex; gap: 1.5rem; align-items: center; padding: .75rem 1.5rem;
       background: var(--paper); border-bottom: 1px solid var(--line); }
.top nav { display: flex; gap: 1rem; flex: 1; }
.brand { font-weight: 600; color: var(--ink); text-decoration: none; }
.inline { display: inline-flex; gap: .5rem; align-items: center; margin: 0; }
.who { color: var(--muted); }
main { max-width: 60rem; margin: 2rem auto; padding: 0 1.5rem; }
h1 { font-size: 1.5rem; margin-top: 0; }
a { color: var(--accent); }
.field { margin: 0 0 1rem; display: flex; flex-direction: column; gap: .25rem; max-width: 32rem; }
.field.checkbox { flex-direction: column; }
input[type=text], input[type=password], input[type=number], input[type=url], select {
  font: inherit; padding: .45rem .6rem; border: 1px solid var(--line); border-radius: 6px; }
.has-error input, .has-error select { border-color: var(--bad); }
.hint { margin: 0; color: var(--muted); font-size: .875rem; }
.error { margin: 0; color: var(--bad); font-size: .875rem; }
button, .button { font: inherit; padding: .45rem .9rem; border-radius: 6px; cursor: pointer;
                  border: 1px solid var(--accent); background: var(--accent); color: #fff; }
button.secondary { background: var(--paper); color: var(--accent); }
button.danger { background: var(--bad); border-color: var(--bad); }
.actions { display: flex; gap: .75rem; align-items: center; margin-top: 1.25rem; }
.notice { padding: .6rem .9rem; background: #ecfdf3; border: 1px solid #abefc6; border-radius: 6px; }
.warning { padding: .6rem .9rem; background: #fffaeb; border: 1px solid #fedf89; border-radius: 6px; }
.alert { padding: .6rem .9rem; background: #fef3f2; border: 1px solid #fecdca; border-radius: 6px;
         color: var(--bad); }
.result.ok { color: var(--good); } .result.bad { color: var(--bad); }
table { width: 100%; border-collapse: collapse; background: var(--paper); }
th, td { text-align: left; padding: .5rem .75rem; border-bottom: 1px solid var(--line); }
.steps { display: flex; gap: 1rem; list-style: none; padding: 0; color: var(--muted); }
.steps .current { color: var(--ink); font-weight: 600; }
pre { background: var(--paper); border: 1px solid var(--line); padding: 1rem; overflow-x: auto; }
```

- [ ] **Step 5: Implement `build_admin_app`**

`src/u2_mcp/admin/app.py`:

```python
"""The admin site as a Starlette application, mounted by the server at /admin."""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import BaseRoute, Mount, Route
from starlette.staticfiles import StaticFiles

from .context import AdminContext
from .templating import render


async def index(request: Request) -> Response:
    """Placeholder landing page; Task 10 replaces it with the setup-aware redirect."""
    return render(request, "message.html", title="u2-mcp admin", message="Admin site.")


def build_admin_app(ctx: AdminContext) -> Starlette:
    """Build the admin site.

    Args:
        ctx: The site's dependencies, kept on app.state.ctx

    Returns:
        A Starlette app whose paths are relative to its mount point
    """
    routes: list[BaseRoute] = [
        Route("/", index, methods=["GET"]),
        Mount("/static", app=StaticFiles(packages=[("u2_mcp.admin", "static")]), name="static"),
    ]
    app = Starlette(routes=routes)
    app.state.ctx = ctx
    return app
```

Replace `src/u2_mcp/admin/__init__.py` with:

```python
"""The admin site, mounted at /admin in team mode."""

from .app import build_admin_app
from .context import AdminContext

__all__ = ["AdminContext", "build_admin_app"]
```

- [ ] **Step 6: Mount it in the server**

In `src/u2_mcp/server.py`, inside `build_streamable_http_app`, add `Mount` to the starlette import (`from starlette.routing import Mount, Route`). Then, after the OAuth callback block and before `return app`, add:

```python
    async def health(_request: Any) -> Any:
        from starlette.responses import JSONResponse

        return JSONResponse({"status": "ok"})

    app.routes.append(Route("/health", health, methods=["GET"]))

    # The admin site exists only in team mode: it edits the settings database.
    if store is not None:
        from .admin import AdminContext, build_admin_app
        from .admin.services import effective_public_url
        from .setup_code import ensure_setup_code

        admin_ctx = AdminContext(store=store, config=config, registry=get_connection_registry)
        app.routes.append(Mount("/admin", app=build_admin_app(admin_ctx)))
        setup_code = ensure_setup_code(store)
        if setup_code:
            logger.warning(
                "Admin setup is not finished. Open %s/admin/setup and enter the setup "
                "code %s (also shown by: u2-mcp admin show-setup-code)",
                effective_public_url(admin_ctx),
                setup_code,
            )
```

Run: `pytest tests/test_admin/test_app.py -v`
Expected: PASS.

- [ ] **Step 7: Check that the templates ship in the wheel**

Run:

```bash
pip wheel . --no-deps -w dist -q && python -c "import zipfile,glob;n=zipfile.ZipFile(sorted(glob.glob('dist/u2_mcp-*.whl'))[-1]).namelist();print([x for x in n if '/admin/' in x])"
```

Expected: the list includes `u2_mcp/admin/templates/base.html`, `u2_mcp/admin/static/htmx.min.js` and `u2_mcp/admin/static/styles.css`. If they are missing, add to `pyproject.toml` under `[tool.hatch.build.targets.wheel]`: `artifacts = ["src/u2_mcp/admin/templates/**", "src/u2_mcp/admin/static/**"]`, and re-run. Add `dist/` to `.gitignore` if it is not already listed, then delete `dist/`.

- [ ] **Step 8: Run everything, lint and commit**

Run: `pytest -q && ruff check . && ruff format --check . && mypy src/ && bandit -r src/ --severity-level medium --confidence-level medium -q`
Expected: all pass, clean.

```bash
git add src/u2_mcp/admin src/u2_mcp/server.py tests/test_admin/test_app.py pyproject.toml
git commit -m "feat: admin site skeleton at /admin, vendored htmx, /health"
```

---

### Task 8: Admin sign-in, sessions, CSRF, rate limiting and the address allowlist

**Files:**
- Create: `src/u2_mcp/admin/security.py`, `src/u2_mcp/admin/routes_auth.py`
- Create: `src/u2_mcp/admin/templates/sign_in.html`, `templates/change_password.html`
- Modify: `src/u2_mcp/admin/app.py`
- Test: `tests/test_admin/test_security.py`, `tests/test_admin/test_routes_auth.py`

**Interfaces:**
- Consumes: Task 3 session store methods; Task 6 `change_password`, `local_accounts_enabled`, `effective_public_url`; Task 7 `render`, `admin_context`.
- Produces in `admin/security.py`:
  - Constants: `SESSION_COOKIE = "u2_admin_session"`, `PRESESSION_COOKIE = "u2_admin_presession"`, `SESSION_ABSOLUTE_SECONDS = 28800`, `SESSION_IDLE_SECONDS = 1800`, `CSRF_FIELD = "csrf_token"`, `CSRF_HEADER = "X-CSRF-Token"`, `SIGN_IN_LIMIT = 5`, `SIGN_IN_WINDOW_SECONDS = 60.0`.
  - `class RateLimiter(limit: int = SIGN_IN_LIMIT, window: float = SIGN_IN_WINDOW_SECONDS, clock: Callable[[], float] = time.monotonic)` with `allow(*keys: str) -> bool`.
  - `start_session(store, user: User, ip: str | None) -> tuple[str, AdminSession]` (raw id for the cookie, stored session).
  - `load_session(store, raw_id: str) -> tuple[AdminSession, User] | None`.
  - `set_session_cookie(response, raw_id: str, *, secure: bool) -> None`, `clear_session_cookie(response) -> None`.
  - `class AdminGuard` (ASGI middleware, constructor `AdminGuard(app, ctx: AdminContext)`): enforces the allowlist; loads the session into `request.state.user`, `request.state.session`, `request.state.csrf_token`.
  - `async def read_form(request: Request) -> FormData`: reads the body and checks CSRF; raises `HTTPException(403)`.
  - `presession_token(request) -> str` and `set_presession_cookie(response, token: str, *, secure: bool) -> None`.
  - Decorators `signed_in(handler)` and `admin_only(handler)` for `async def handler(request) -> Response`.
  - `client_ip(request) -> str | None`, `is_secure(ctx) -> bool`, `safe_next(value: str | None) -> str`.
- Produces routes: `GET/POST /sign-in`, `POST /sign-out`, `GET/POST /account/password` (relative to `/admin`).

- [ ] **Step 1: Write the failing unit tests**

Create `tests/test_admin/test_security.py`:

```python
"""Sessions, the rate limiter and safe redirects."""

import pytest

from u2_mcp.admin.security import (
    SESSION_ABSOLUTE_SECONDS,
    SESSION_IDLE_SECONDS,
    RateLimiter,
    load_session,
    safe_next,
    start_session,
)
from u2_mcp.store.repo import Store


class Clock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class TestRateLimiter:
    def test_five_per_minute_then_refused(self) -> None:
        clock = Clock()
        limiter = RateLimiter(clock=clock)

        assert all(limiter.allow("ip:1") for _ in range(5))
        assert limiter.allow("ip:1") is False

    def test_the_window_slides(self) -> None:
        clock = Clock()
        limiter = RateLimiter(clock=clock)
        for _ in range(5):
            limiter.allow("ip:1")

        clock.now += 61

        assert limiter.allow("ip:1") is True

    def test_any_exhausted_key_refuses(self) -> None:
        limiter = RateLimiter(clock=Clock())
        for _ in range(5):
            limiter.allow("user:ann")

        assert limiter.allow("ip:2", "user:ann") is False
        assert limiter.allow("ip:2") is True


class TestSessions:
    def _store(self, store: Store, clock: Clock) -> Store:
        store.clock = clock
        return store

    def test_a_session_loads_its_user(self, store: Store) -> None:
        clock = Clock()
        self._store(store, clock)
        user = store.add_local_user("ann", password_hash="h", is_admin=True)

        raw, session = start_session(store, user, "10.0.0.1")
        loaded = load_session(store, raw)

        assert loaded is not None
        assert loaded[1].id == user.id
        assert session.id_hash != raw  # only the hash is stored

    def test_idle_sessions_end(self, store: Store) -> None:
        clock = Clock()
        self._store(store, clock)
        user = store.add_local_user("ann", password_hash="h", is_admin=True)
        raw, _ = start_session(store, user, None)

        clock.now += SESSION_IDLE_SECONDS + 1

        assert load_session(store, raw) is None

    def test_activity_keeps_a_session_alive_until_the_absolute_limit(self, store: Store) -> None:
        clock = Clock()
        self._store(store, clock)
        user = store.add_local_user("ann", password_hash="h", is_admin=True)
        raw, _ = start_session(store, user, None)

        for _ in range(SESSION_ABSOLUTE_SECONDS // (SESSION_IDLE_SECONDS - 60) + 2):
            clock.now += SESSION_IDLE_SECONDS - 60
            if load_session(store, raw) is None:
                break
        else:
            pytest.fail("the session outlived its absolute lifetime")

        assert clock.now - 1_000_000.0 >= SESSION_ABSOLUTE_SECONDS - SESSION_IDLE_SECONDS

    def test_a_disabled_user_has_no_session(self, store: Store) -> None:
        self._store(store, Clock())
        user = store.add_local_user("ann", password_hash="h", is_admin=True)
        raw, _ = start_session(store, user, None)

        store.set_user_disabled(user.id, True)

        assert load_session(store, raw) is None

    def test_an_unknown_id(self, store: Store) -> None:
        assert load_session(store, "nonsense") is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("/admin/connections", "/admin/connections"),
        ("/admin/connections?x=1", "/admin/connections?x=1"),
        ("https://evil.example/admin/", "/admin/"),
        ("//evil.example/admin/", "/admin/"),
        ("/elsewhere", "/admin/"),
        ("/admin/\\evil", "/admin/"),
        (None, "/admin/"),
    ],
)
def test_safe_next(value: str | None, expected: str) -> None:
    assert safe_next(value) == expected
```

Create `tests/test_admin/test_routes_auth.py`:

```python
"""Signing in and out of the admin site, over HTTP."""

import re
from collections.abc import Iterator

import pytest
from starlette.applications import Starlette
from starlette.routing import Mount
from starlette.testclient import TestClient

from u2_mcp.admin.app import build_admin_app
from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.security import SESSION_COOKIE
from u2_mcp.admin.services import LOCAL_ACCOUNTS_SETTING
from u2_mcp.passwords import hash_password, verify_password
from u2_mcp.setup_code import finish_setup
from u2_mcp.store.models import User

PASSWORD = "correct horse battery"


def _client(ctx: AdminContext, client: tuple[str, int] = ("10.0.0.1", 5000)) -> TestClient:
    app = Starlette(routes=[Mount("/admin", app=build_admin_app(ctx))])
    return TestClient(app, client=client)


@pytest.fixture
def admin_user(ctx: AdminContext) -> User:
    finish_setup(ctx.store)
    return ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)


@pytest.fixture
def client(ctx: AdminContext, admin_user: User) -> Iterator[TestClient]:
    with _client(ctx) as test_client:
        yield test_client


def _token(page: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', page)
    assert match, "no CSRF token on the page"
    return match.group(1)


def sign_in(client: TestClient, username: str = "ann", password: str = PASSWORD,
            next_url: str = "") -> object:
    page = client.get("/admin/sign-in")
    data = {"csrf_token": _token(page.text), "username": username, "password": password,
            "next": next_url}
    return client.post("/admin/sign-in", data=data, follow_redirects=False)


class TestSigningIn:
    def test_the_right_password_signs_in(self, client: TestClient) -> None:
        response = sign_in(client)

        assert response.status_code == 303  # type: ignore[attr-defined]
        assert SESSION_COOKIE in client.cookies
        assert client.get("/admin/account/password").status_code == 200

    def test_the_cookie_is_locked_down(self, client: TestClient) -> None:
        response = sign_in(client)

        cookie = response.headers["set-cookie"]  # type: ignore[attr-defined]
        assert "HttpOnly" in cookie and "SameSite=lax" in cookie and "Path=/admin" in cookie

    def test_a_wrong_password_is_refused_and_audited(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        response = sign_in(client, password="wrong password!")

        assert response.status_code == 401  # type: ignore[attr-defined]
        assert "Wrong username or password." in response.text  # type: ignore[attr-defined]
        entry = ctx.store.recent_audit(1)[0]
        assert (entry["kind"], entry["action"], entry["outcome"]) == (
            "auth", "admin.sign_in", "failed")

    def test_an_unknown_user_gets_the_same_message(self, client: TestClient) -> None:
        response = sign_in(client, username="nobody")

        assert "Wrong username or password." in response.text  # type: ignore[attr-defined]

    def test_a_missing_csrf_token_is_refused(self, client: TestClient) -> None:
        client.get("/admin/sign-in")

        response = client.post("/admin/sign-in", data={"username": "ann", "password": PASSWORD})

        assert response.status_code == 403

    def test_the_sixth_attempt_in_a_minute_is_refused(self, client: TestClient) -> None:
        for _ in range(5):
            sign_in(client, password="wrong password!")

        response = sign_in(client)

        assert response.status_code == 429  # type: ignore[attr-defined]
        assert "Too many sign-in attempts. Wait a minute and try again." in (
            response.text)  # type: ignore[attr-defined]

    def test_next_is_followed_only_inside_the_admin_site(self, client: TestClient) -> None:
        inside = sign_in(client, next_url="/admin/account/password")
        assert inside.headers["location"] == "/admin/account/password"  # type: ignore[attr-defined]

    def test_local_sign_in_can_be_off_for_non_admins(
        self, ctx: AdminContext, client: TestClient
    ) -> None:
        ctx.store.add_local_user("bob", password_hash=hash_password(PASSWORD))
        ctx.store.set_setting(LOCAL_ACCOUNTS_SETTING, False)

        refused = sign_in(client, username="bob")
        allowed = sign_in(client, username="ann")

        assert "Local sign-in is turned off. Use your company sign-in." in (
            refused.text)  # type: ignore[attr-defined]
        assert allowed.status_code == 303  # type: ignore[attr-defined]


class TestSignedInPages:
    def test_pages_redirect_to_sign_in(self, client: TestClient) -> None:
        response = client.get("/admin/account/password", follow_redirects=False)

        assert response.status_code == 303
        assert response.headers["location"] == "/admin/sign-in?next=/admin/account/password"

    def test_sign_out_ends_the_session(self, client: TestClient, ctx: AdminContext) -> None:
        sign_in(client)
        page = client.get("/admin/account/password")

        client.post("/admin/sign-out", data={"csrf_token": _token(page.text)})

        assert client.get("/admin/account/password", follow_redirects=False).status_code == 303
        assert ctx.store.recent_audit(1)[0]["action"] == "admin.sign_out"

    def test_a_forced_change_comes_first(
        self, client: TestClient, ctx: AdminContext, admin_user: User
    ) -> None:
        ctx.store.set_password_hash(admin_user.id, hash_password(PASSWORD), must_change=True)
        sign_in(client)

        response = client.get("/admin/", follow_redirects=False)

        assert response.headers["location"] == "/admin/account/password"

    def test_changing_the_password(
        self, client: TestClient, ctx: AdminContext, admin_user: User
    ) -> None:
        sign_in(client)
        page = client.get("/admin/account/password")

        response = client.post(
            "/admin/account/password",
            data={"csrf_token": _token(page.text), "current_password": PASSWORD,
                  "new_password": "a brand new passphrase",
                  "new_password_again": "a brand new passphrase"},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert verify_password(ctx.store.password_hash(admin_user.id), "a brand new passphrase")
        assert client.get("/admin/account/password").status_code == 200  # still signed in

    def test_a_non_admin_sees_the_refusal(self, ctx: AdminContext, client: TestClient) -> None:
        ctx.store.add_local_user("bob", password_hash=hash_password(PASSWORD))
        sign_in(client, username="bob")

        response = client.get("/admin/")

        assert response.status_code == 403
        assert "Only admins can use this page." in response.text


class TestAllowlist:
    def test_other_addresses_are_refused(self, ctx: AdminContext, admin_user: User) -> None:
        ctx.config = ctx.config.model_copy(update={"admin_allowed_ips": "192.168.1.0/24"})

        with _client(ctx, client=("10.0.0.1", 5000)) as outside:
            response = outside.get("/admin/sign-in")
        with _client(ctx, client=("192.168.1.20", 5000)) as inside:
            allowed = inside.get("/admin/sign-in")

        assert response.status_code == 403
        assert response.text == "Not allowed from this address."
        assert allowed.status_code == 200
```

Note on `test_a_non_admin_sees_the_refusal`: in Task 8 the index route is still the Task 7 placeholder; wrap it with `admin_only` in this task (Step 4) so the test is meaningful now. Task 10 replaces the placeholder and keeps `admin_only`.

Run: `pytest tests/test_admin/test_security.py tests/test_admin/test_routes_auth.py -v`
Expected: FAIL with ImportError (`u2_mcp.admin.security`).

- [ ] **Step 2: Implement `admin/security.py`**

```python
"""Admin-site security: sessions, CSRF, sign-in rate limits and the address allowlist."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets
import threading
import time
from collections import deque
from collections.abc import Awaitable, Callable
from functools import wraps
from typing import Any
from urllib.parse import quote

from starlette.datastructures import FormData
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse, Response

from ..store.models import AdminSession, User
from ..store.repo import Store
from .context import AdminContext
from .services import effective_public_url

SESSION_COOKIE = "u2_admin_session"
PRESESSION_COOKIE = "u2_admin_presession"
SESSION_ABSOLUTE_SECONDS = 8 * 60 * 60
SESSION_IDLE_SECONDS = 30 * 60
CSRF_FIELD = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"
SIGN_IN_LIMIT = 5
SIGN_IN_WINDOW_SECONDS = 60.0

_TOUCH_SECONDS = 60.0
_COOKIE_PATH = "/admin"

Handler = Callable[[Request], Awaitable[Response]]


class RateLimiter:
    """At most `limit` attempts per `window` seconds for each key."""

    def __init__(
        self,
        limit: int = SIGN_IN_LIMIT,
        window: float = SIGN_IN_WINDOW_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._limit = limit
        self._window = window
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, *keys: str) -> bool:
        """Record an attempt against every key, unless any key is already exhausted."""
        now = self._clock()
        with self._lock:
            for key in keys:
                hits = self._hits.setdefault(key, deque())
                while hits and now - hits[0] >= self._window:
                    hits.popleft()
                if len(hits) >= self._limit:
                    return False
            for key in keys:
                self._hits[key].append(now)
            return True


def _hash(raw_id: str) -> str:
    return hashlib.sha256(raw_id.encode()).hexdigest()


def start_session(store: Store, user: User, ip: str | None) -> tuple[str, AdminSession]:
    """Create a session; returns the raw id (for the cookie only) and the stored row."""
    now = store.clock()
    store.purge_admin_sessions(
        created_before=now - SESSION_ABSOLUTE_SECONDS, idle_before=now - SESSION_IDLE_SECONDS
    )
    raw_id = secrets.token_urlsafe(32)
    session = store.add_admin_session(
        id_hash=_hash(raw_id), user_id=user.id, csrf_token=secrets.token_urlsafe(32), ip=ip
    )
    return raw_id, session


def load_session(store: Store, raw_id: str) -> tuple[AdminSession, User] | None:
    """Return the live session and its user, ending it if it has expired."""
    id_hash = _hash(raw_id)
    session = store.get_admin_session(id_hash)
    if session is None:
        return None
    now = store.clock()
    expired = (
        now - session.created_at >= SESSION_ABSOLUTE_SECONDS
        or now - session.last_seen_at >= SESSION_IDLE_SECONDS
    )
    user = None if expired else store.get_user(session.user_id)
    if user is None or user.disabled:
        store.delete_admin_session(id_hash)
        return None
    if now - session.last_seen_at >= _TOUCH_SECONDS:
        store.touch_admin_session(id_hash, at=now)
    return session, user


def is_secure(ctx: AdminContext) -> bool:
    """Whether cookies get the Secure flag: the public address is https."""
    return effective_public_url(ctx).lower().startswith("https://")


def set_session_cookie(response: Response, raw_id: str, *, secure: bool) -> None:
    """Set the session cookie: HttpOnly, SameSite=Lax, scoped to /admin."""
    response.set_cookie(
        SESSION_COOKIE,
        raw_id,
        max_age=SESSION_ABSOLUTE_SECONDS,
        path=_COOKIE_PATH,
        httponly=True,
        samesite="lax",
        secure=secure,
    )


def clear_session_cookie(response: Response) -> None:
    """Remove the session cookie."""
    response.delete_cookie(SESSION_COOKIE, path=_COOKIE_PATH)


def presession_token(request: Request) -> str:
    """The CSRF token for forms shown before sign-in (double-submit cookie)."""
    return request.cookies.get(PRESESSION_COOKIE) or secrets.token_urlsafe(32)


def set_presession_cookie(response: Response, token: str, *, secure: bool) -> None:
    """Set the pre-sign-in CSRF cookie."""
    response.set_cookie(
        PRESESSION_COOKIE,
        token,
        path=_COOKIE_PATH,
        httponly=True,
        samesite="strict",
        secure=secure,
    )


def client_ip(request: Request) -> str | None:
    """The caller's address, as ClientAddressMiddleware records it."""
    return request.client.host if request.client else None


def safe_next(value: str | None) -> str:
    """Return a redirect target inside the admin site, or the admin home."""
    if (
        value
        and value.startswith("/admin/")
        and not value.startswith("//")
        and "\\" not in value
    ):
        return value
    return "/admin/"


async def read_form(request: Request) -> FormData:
    """Read a submitted form, refusing it unless it carries the right CSRF token.

    Signed-in forms carry the session's token; forms shown before sign-in carry
    the pre-session cookie's value.

    Raises:
        HTTPException: 403 when the token is missing or wrong
    """
    form = await request.form()
    presented = str(form.get(CSRF_FIELD) or request.headers.get(CSRF_HEADER) or "")
    # A signed-in admin may still submit a pre-sign-in form (the sign-in page in
    # another tab), so either token is accepted; each is unguessable by another site.
    expected = [
        token
        for token in (
            getattr(request.state, "csrf_token", ""),
            request.cookies.get(PRESESSION_COOKIE, ""),
        )
        if token
    ]
    if not presented or not any(hmac.compare_digest(presented, token) for token in expected):
        raise HTTPException(403, "The form expired. Reload the page and try again.")
    return form


def signed_in(handler: Handler) -> Handler:
    """Require a signed-in user, and a password change first when one is due."""

    @wraps(handler)
    async def wrapper(request: Request) -> Response:
        user: User | None = getattr(request.state, "user", None)
        path = request.url.path
        if user is None:
            if request.method == "GET":
                return RedirectResponse(f"/admin/sign-in?next={quote(path)}", status_code=303)
            raise HTTPException(403, "Sign in first.")
        if user.must_change_password and path not in ("/admin/account/password",
                                                      "/admin/sign-out"):
            return RedirectResponse("/admin/account/password", status_code=303)
        return await handler(request)

    return wrapper


def admin_only(handler: Handler) -> Handler:
    """Require a signed-in admin."""

    @signed_in
    @wraps(handler)
    async def wrapper(request: Request) -> Response:
        if not request.state.user.is_admin:
            from .templating import render

            return render(
                request,
                "message.html",
                status_code=403,
                title="Not available",
                message="Only admins can use this page.",
            )
        return await handler(request)

    return wrapper


class AdminGuard:
    """ASGI middleware for the admin site: allowlist first, then the session."""

    def __init__(self, app: Any, ctx: AdminContext) -> None:
        self.app = app
        self.ctx = ctx

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope)
        networks = self.ctx.config.admin_allowed_networks
        if networks and not _allowed(client_ip(request), networks):
            await PlainTextResponse("Not allowed from this address.", status_code=403)(
                scope, receive, send
            )
            return

        state = scope.setdefault("state", {})
        state["user"] = None
        state["session"] = None
        state["csrf_token"] = ""
        raw_id = request.cookies.get(SESSION_COOKIE)
        if raw_id:
            loaded = load_session(self.ctx.store, raw_id)
            if loaded is not None:
                state["session"], state["user"] = loaded
                state["csrf_token"] = loaded[0].csrf_token
        await self.app(scope, receive, send)


def _allowed(ip: str | None, networks: list[Any]) -> bool:
    if ip is None:
        return False
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in network for network in networks)
```

- [ ] **Step 3: Implement the sign-in routes and templates**

`src/u2_mcp/admin/routes_auth.py`:

```python
"""Signing in to and out of the admin site with a local account."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from ..passwords import verify_password
from ..setup_code import is_setup_complete
from .security import (
    RateLimiter,
    clear_session_cookie,
    client_ip,
    is_secure,
    presession_token,
    read_form,
    safe_next,
    set_presession_cookie,
    set_session_cookie,
    signed_in,
    start_session,
)
from .services import ValidationFailed, change_password, local_accounts_enabled
from .templating import admin_context, render

WRONG_CREDENTIALS = "Wrong username or password."
RATE_LIMITED = "Too many sign-in attempts. Wait a minute and try again."
LOCAL_SIGN_IN_OFF = "Local sign-in is turned off. Use your company sign-in."

_limiter = RateLimiter()


def _sign_in_page(
    request: Request, *, error: str = "", username: str = "", next_url: str = "",
    status_code: int = 200,
) -> Response:
    ctx = admin_context(request)
    token = presession_token(request)
    response = render(
        request,
        "sign_in.html",
        status_code=status_code,
        csrf_token=token,
        error=error,
        username=username,
        next_url=next_url,
    )
    set_presession_cookie(response, token, secure=is_secure(ctx))
    return response


async def sign_in_form(request: Request) -> Response:
    """Show the sign-in form (or send a brand-new server to setup)."""
    ctx = admin_context(request)
    if not is_setup_complete(ctx.store) and not ctx.store.has_local_admin():
        return RedirectResponse("/admin/setup", status_code=303)
    return _sign_in_page(request, next_url=request.query_params.get("next", ""))


async def sign_in(request: Request) -> Response:
    """Check a username and password and start a session."""
    ctx = admin_context(request)
    form = await read_form(request)
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))
    next_url = str(form.get("next", ""))
    ip = client_ip(request)

    if not _limiter.allow(f"ip:{ip}", f"user:{username.casefold()}"):
        return _sign_in_page(request, error=RATE_LIMITED, username=username,
                             next_url=next_url, status_code=429)

    user = ctx.store.get_user_by_username(username) if username else None
    stored_hash = ctx.store.password_hash(user.id) if user is not None else None
    if not verify_password(stored_hash, password) or user is None or user.disabled:
        ctx.store.add_audit(kind="auth", action="admin.sign_in", outcome="failed",
                            actor_label=username or None, params={"ip": ip})
        return _sign_in_page(request, error=WRONG_CREDENTIALS, username=username,
                             next_url=next_url, status_code=401)
    if not user.is_admin and not local_accounts_enabled(ctx):
        return _sign_in_page(request, error=LOCAL_SIGN_IN_OFF, username=username,
                             next_url=next_url, status_code=403)

    raw_id, _ = start_session(ctx.store, user, ip)
    ctx.store.add_audit(kind="auth", action="admin.sign_in", outcome="ok",
                        actor_user_id=user.id, actor_label=user.label, params={"ip": ip})
    response = RedirectResponse(safe_next(next_url), status_code=303)
    set_session_cookie(response, raw_id, secure=is_secure(ctx))
    return response


async def sign_out(request: Request) -> Response:
    """End the current session."""
    ctx = admin_context(request)
    await read_form(request)
    session = request.state.session
    user = request.state.user
    if session is not None:
        ctx.store.delete_admin_session(session.id_hash)
        ctx.store.add_audit(kind="auth", action="admin.sign_out", outcome="ok",
                            actor_user_id=user.id, actor_label=user.label)
    response = RedirectResponse("/admin/sign-in?notice=signed_out", status_code=303)
    clear_session_cookie(response)
    return response


@signed_in
async def password_form(request: Request) -> Response:
    """Show the change-password form."""
    return render(request, "change_password.html", errors={})


@signed_in
async def password_save(request: Request) -> Response:
    """Change the signed-in user's password; other sessions end."""
    ctx = admin_context(request)
    form = await read_form(request)
    user = request.state.user
    try:
        change_password(
            ctx,
            user,
            current=str(form.get("current_password", "")),
            new=str(form.get("new_password", "")),
            new_again=str(form.get("new_password_again", "")),
        )
    except ValidationFailed as failed:
        return render(request, "change_password.html", status_code=400, errors=failed.errors)
    # Every session this user had, including stolen ones, ends; this browser gets a new one.
    ctx.store.delete_admin_sessions_for(user.id)
    refreshed = ctx.store.get_user(user.id)
    assert refreshed is not None
    raw_id, _ = start_session(ctx.store, refreshed, client_ip(request))
    response = RedirectResponse("/admin/?notice=password_changed", status_code=303)
    set_session_cookie(response, raw_id, secure=is_secure(ctx))
    return response


routes = [
    Route("/sign-in", sign_in_form, methods=["GET"]),
    Route("/sign-in", sign_in, methods=["POST"]),
    Route("/sign-out", sign_out, methods=["POST"]),
    Route("/account/password", password_form, methods=["GET"]),
    Route("/account/password", password_save, methods=["POST"]),
]
```

Note: `_limiter` is process-wide. Tests that exhaust it must not leak into other tests: add an autouse fixture to `tests/test_admin/conftest.py`:

```python
@pytest.fixture(autouse=True)
def fresh_sign_in_limiter(monkeypatch: pytest.MonkeyPatch) -> None:
    from u2_mcp.admin import routes_auth
    from u2_mcp.admin.security import RateLimiter

    monkeypatch.setattr(routes_auth, "_limiter", RateLimiter())
```

`src/u2_mcp/admin/templates/sign_in.html`:

```html
{% extends "base.html" %}
{% from "partials/fields.html" import text %}
{% block title %}Sign in · u2-mcp admin{% endblock %}
{% block content %}
<h1>Sign in</h1>
{% if error %}<p class="alert" role="alert">{{ error }}</p>{% endif %}
<form method="post" action="/admin/sign-in">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <input type="hidden" name="next" value="{{ next_url }}">
  {{ text("username", "Username", username, {}, autocomplete="username", required=true) }}
  {{ text("password", "Password", "", {}, type="password", autocomplete="current-password", required=true) }}
  <div class="actions"><button type="submit">Sign in</button></div>
</form>
{% endblock %}
```

`src/u2_mcp/admin/templates/change_password.html`:

```html
{% extends "base.html" %}
{% from "partials/fields.html" import text %}
{% block title %}Change password · u2-mcp admin{% endblock %}
{% block content %}
<h1>Change your password</h1>
{% if user and user.must_change_password %}
<p class="warning">You signed in with a one-time password. Choose your own to continue.</p>
{% endif %}
<form method="post" action="/admin/account/password">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  {{ text("current_password", "Current password", "", errors, type="password", autocomplete="current-password", required=true) }}
  {{ text("new_password", "New password", "", errors, type="password", autocomplete="new-password", hint="At least 12 characters.", required=true) }}
  {{ text("new_password_again", "New password again", "", errors, type="password", autocomplete="new-password", required=true) }}
  <div class="actions"><button type="submit">Change password</button></div>
</form>
{% endblock %}
```

- [ ] **Step 4: Wire the routes and middleware into the app**

In `src/u2_mcp/admin/app.py`:

```python
from starlette.middleware import Middleware

from . import routes_auth
from .security import AdminGuard, admin_only
```

Decorate the placeholder `index` with `@admin_only`, and change `build_admin_app` so the route list and app are:

```python
    routes: list[BaseRoute] = [
        Route("/", index, methods=["GET"]),
        *routes_auth.routes,
        Mount("/static", app=StaticFiles(packages=[("u2_mcp.admin", "static")]), name="static"),
    ]
    app = Starlette(routes=routes, middleware=[Middleware(AdminGuard, ctx=ctx)])
```

Run: `pytest tests/test_admin -v`
Expected: PASS. (`test_app.py::test_the_admin_site_is_served` accepts the redirect to sign-in or setup.)

- [ ] **Step 5: Run everything, lint and commit**

Run: `ruff format src tests && pytest -q && ruff check . && ruff format --check . && mypy src/ && bandit -r src/ --severity-level medium --confidence-level medium -q`
Expected: all pass, clean.

```bash
git add src/u2_mcp/admin tests/test_admin
git commit -m "feat: admin sign-in with database sessions, CSRF, rate limits and IP allowlist"
```

---

### Task 9: The Connections pages

**Files:**
- Create: `src/u2_mcp/admin/routes_connections.py`
- Create: `src/u2_mcp/admin/templates/connections/list.html`, `connections/edit.html`, `connections/delete.html`, `partials/connection_form.html`, `partials/test_result.html`
- Create: `tests/test_admin/helpers.py`; move `PASSWORD`, `_client` (rename `admin_client`), `_token` (rename `csrf_from`) and `sign_in` there from `tests/test_admin/test_routes_auth.py` and import them back into that file
- Modify: `src/u2_mcp/admin/app.py`
- Test: `tests/test_admin/test_routes_connections.py`

**Interfaces:**
- Consumes: Task 6 services, Task 8 `admin_only`, `read_form`.
- Produces in `routes_connections.py`:
  - `routes` (list of `Route`) for `GET /connections`, `GET/POST /connections/new`, `GET/POST /connections/{id:int}`, `POST /connections/{id:int}/switches`, `POST /connections/{id:int}/disconnect`, `GET/POST /connections/{id:int}/delete`.
  - `async def connection_submission(request, *, connection_id: int | None, fallback_password: str | None, page: Callable[[ConnectionForm, dict[str, str], CheckResult | None, int], Response], on_saved: Callable[[Connection], Response]) -> Response` — the one handler for every connection form POST (everyday pages and the wizard). `page(form, errors, result, status_code)` renders whichever page holds the form.
  - `def password_hint(connection: Connection | None, env_password: bool) -> str`.
- Template contract for `partials/connection_form.html`: variables `form`, `errors`, `action_url`, `submit_label`, `password_hint`, `result`, `test_errors`, `csrf_token`.

- [ ] **Step 1: Move the shared test helpers**

Create `tests/test_admin/helpers.py`:

```python
"""Helpers for admin-site HTTP tests."""

import re

from starlette.applications import Starlette
from starlette.routing import Mount
from starlette.testclient import TestClient

from u2_mcp.admin.app import build_admin_app
from u2_mcp.admin.context import AdminContext

PASSWORD = "correct horse battery"


def admin_client(ctx: AdminContext, client: tuple[str, int] = ("10.0.0.1", 5000)) -> TestClient:
    """A test client for the admin site mounted at /admin, as the server mounts it."""
    app = Starlette(routes=[Mount("/admin", app=build_admin_app(ctx))])
    return TestClient(app, client=client)


def csrf_from(page: str) -> str:
    """Return the CSRF token embedded in a rendered form."""
    match = re.search(r'name="csrf_token" value="([^"]+)"', page)
    assert match, "no CSRF token on the page"
    return match.group(1)


def sign_in(client: TestClient, username: str = "ann", password: str = PASSWORD,
            next_url: str = "") -> object:
    """Sign in through the real form."""
    page = client.get("/admin/sign-in")
    data = {"csrf_token": csrf_from(page.text), "username": username, "password": password,
            "next": next_url}
    return client.post("/admin/sign-in", data=data, follow_redirects=False)
```

Edit `tests/test_admin/test_routes_auth.py` to delete its own copies and `from .helpers import PASSWORD, admin_client, csrf_from, sign_in`, renaming uses of `_client` and `_token`.

Run: `pytest tests/test_admin -q`
Expected: PASS (pure move).

- [ ] **Step 2: Write the failing route tests**

Create `tests/test_admin/test_routes_connections.py`:

```python
"""The Connections pages, over HTTP."""

from collections.abc import Iterator

import pytest
from starlette.testclient import TestClient

from u2_mcp.admin.context import AdminContext
from u2_mcp.connection_check import CheckResult
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import finish_setup
from u2_mcp.store.models import Connection

from .conftest import FakeCheck, FakeRegistry
from .helpers import PASSWORD, admin_client, csrf_from, sign_in

FORM = {
    "name": "Prod", "host": "u2.example", "port": "31438", "service": "uvcs",
    "account": "PROD", "login_mode": "shared", "login_user": "svc",
    "login_password": "secret", "read_only": "on", "enabled": "on", "version": "0",
}


@pytest.fixture
def client(ctx: AdminContext) -> Iterator[TestClient]:
    finish_setup(ctx.store)
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    with admin_client(ctx) as test_client:
        sign_in(test_client)
        yield test_client


def _post(client: TestClient, url: str, data: dict[str, str], **kwargs: object) -> object:
    token = csrf_from(client.get("/admin/connections/new").text)
    return client.post(url, data={**data, "csrf_token": token}, follow_redirects=False,
                       **kwargs)  # type: ignore[arg-type]


def _create(client: TestClient, ctx: AdminContext) -> Connection:
    _post(client, "/admin/connections/new", {**FORM, "action": "save"})
    created = ctx.store.get_connection_by_name("Prod")
    assert created is not None
    return created


def test_the_list_needs_an_admin(ctx: AdminContext) -> None:
    finish_setup(ctx.store)
    with admin_client(ctx) as anonymous:
        response = anonymous.get("/admin/connections", follow_redirects=False)

    assert response.status_code == 303


def test_adding_a_connection(client: TestClient, ctx: AdminContext) -> None:
    response = _post(client, "/admin/connections/new", {**FORM, "action": "save"})

    created = ctx.store.get_connection_by_name("Prod")
    assert created is not None
    assert response.headers["location"] == (  # type: ignore[attr-defined]
        f"/admin/connections/{created.id}?notice=saved")
    assert "Prod" in client.get("/admin/connections").text


def test_problems_are_shown_beside_the_fields(client: TestClient) -> None:
    response = _post(client, "/admin/connections/new",
                     {**FORM, "host": "", "login_password": "typed-secret", "action": "save"})

    assert response.status_code == 400  # type: ignore[attr-defined]
    assert "Enter the U2 server&#39;s host name or address." in response.text  # type: ignore[attr-defined]
    assert "typed-secret" not in response.text  # type: ignore[attr-defined]


def test_testing_with_htmx_returns_only_the_result(client: TestClient, check: FakeCheck) -> None:
    check.result = CheckResult(True, "Connected to PROD on u2.example. COUNT VOC: 7", 3.0)

    response = _post(client, "/admin/connections/new", {**FORM, "action": "test"},
                     headers={"HX-Request": "true"})

    assert response.status_code == 200  # type: ignore[attr-defined]
    assert 'id="test-result"' in response.text  # type: ignore[attr-defined]
    assert "COUNT VOC: 7" in response.text  # type: ignore[attr-defined]
    assert "<html" not in response.text  # type: ignore[attr-defined]


def test_testing_without_javascript_shows_the_whole_page(
    client: TestClient, check: FakeCheck
) -> None:
    check.result = CheckResult(False, "Login refused: wrong user name or password", 3.0)

    response = _post(client, "/admin/connections/new", {**FORM, "action": "test"})

    assert "Test failed: Login refused: wrong user name or password" in (
        response.text)  # type: ignore[attr-defined]
    assert 'value="u2.example"' in response.text  # type: ignore[attr-defined]


def test_testing_does_not_save(client: TestClient, ctx: AdminContext) -> None:
    _post(client, "/admin/connections/new", {**FORM, "action": "test"})

    assert ctx.store.get_connection_by_name("Prod") is None


def test_editing_keeps_a_blank_password(client: TestClient, ctx: AdminContext) -> None:
    created = _create(client, ctx)

    _post(client, f"/admin/connections/{created.id}",
          {**FORM, "host": "u2-new.example", "login_password": "",
           "version": str(created.version), "action": "save"})

    assert ctx.store.shared_password(created.id) == "secret"
    edited = ctx.store.get_connection(created.id)
    assert edited is not None and edited.host == "u2-new.example"


def test_a_stale_edit_is_refused_with_the_message(client: TestClient, ctx: AdminContext) -> None:
    created = _create(client, ctx)
    _post(client, f"/admin/connections/{created.id}",
          {**FORM, "host": "first.example", "version": str(created.version), "action": "save"})

    response = _post(client, f"/admin/connections/{created.id}",
                     {**FORM, "host": "second.example", "version": str(created.version),
                      "action": "save"})

    assert response.status_code == 409  # type: ignore[attr-defined]
    assert ("Someone else changed this connection since you opened it. "
            "Reload to see their changes.") in response.text  # type: ignore[attr-defined]
    saved = ctx.store.get_connection(created.id)
    assert saved is not None and saved.host == "first.example"


def test_switches(client: TestClient, ctx: AdminContext, registry: FakeRegistry) -> None:
    created = _create(client, ctx)

    _post(client, f"/admin/connections/{created.id}/switches", {"read_only": "off"})

    switched = ctx.store.get_connection(created.id)
    assert switched is not None and switched.read_only is False
    assert created.id in registry.evicted


def test_disconnect(client: TestClient, ctx: AdminContext, registry: FakeRegistry) -> None:
    created = _create(client, ctx)
    registry.live[created.id] = ["svc@PROD"]
    assert "svc@PROD" in client.get(f"/admin/connections/{created.id}").text

    response = _post(client, f"/admin/connections/{created.id}/disconnect", {})

    assert response.headers["location"] == (  # type: ignore[attr-defined]
        f"/admin/connections/{created.id}?notice=disconnected")
    assert registry.live == {}


def test_delete_asks_first(client: TestClient, ctx: AdminContext) -> None:
    created = _create(client, ctx)

    page = client.get(f"/admin/connections/{created.id}/delete")
    response = _post(client, f"/admin/connections/{created.id}/delete", {})

    assert "Delete Prod?" in page.text
    assert response.headers["location"] == (  # type: ignore[attr-defined]
        "/admin/connections?notice=deleted")
    assert ctx.store.get_connection(created.id) is None


def test_an_unknown_connection_is_404(client: TestClient) -> None:
    assert client.get("/admin/connections/999").status_code == 404
```

Run: `pytest tests/test_admin/test_routes_connections.py -v`
Expected: FAIL (404 for every connections URL).

- [ ] **Step 3: Implement the routes**

`src/u2_mcp/admin/routes_connections.py`:

```python
"""Connections: list, add, edit, test, switches, live sessions and delete."""

from __future__ import annotations

from collections.abc import Callable

import anyio
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from ..connection_check import CheckResult
from ..store.models import Connection
from ..store.repo import StaleEdit, StoreError
from .security import admin_only, read_form
from .services import (
    ConnectionForm,
    ValidationFailed,
    check_connection_form,
    delete_connection,
    disconnect_connection,
    save_connection,
    set_connection_switches,
)
from .templating import admin_context, render

Page = Callable[[ConnectionForm, dict[str, str], CheckResult | None, int], Response]


def password_hint(connection: Connection | None, env_password: bool) -> str:
    """Explain what a blank password box means on this form."""
    if connection is not None and connection.has_shared_password:
        return "Leave blank to keep the saved password."
    if env_password:
        return "Leave blank to use U2_PASSWORD from the server's environment."
    return ""


async def connection_submission(
    request: Request,
    *,
    connection_id: int | None,
    fallback_password: str | None,
    page: Page,
    on_saved: Callable[[Connection], Response],
) -> Response:
    """Handle a connection form POST: Test (action=test) or Save.

    Used by the Connections pages and the setup wizard alike, so both behave the
    same way and the wizard has no logic of its own.
    """
    ctx = admin_context(request)
    data = await read_form(request)
    form = ConnectionForm.from_form({key: str(value) for key, value in data.items()})

    if data.get("action") == "test":
        try:
            result = await anyio.to_thread.run_sync(
                lambda: check_connection_form(
                    ctx, form, connection_id=connection_id, fallback_password=fallback_password
                )
            )
            errors: dict[str, str] = {}
        except ValidationFailed as failed:
            result, errors = None, failed.errors
        if request.headers.get("HX-Request"):
            return render(
                request,
                "partials/test_result.html",
                result=result,
                test_errors=list(errors.values()),
            )
        return page(form, errors, result, 200 if not errors else 400)

    try:
        saved = save_connection(
            ctx,
            form,
            actor=request.state.user,
            connection_id=connection_id,
            fallback_password=fallback_password,
        )
    except ValidationFailed as failed:
        return page(form, failed.errors, None, 400)
    except StaleEdit as stale:
        return page(form, {"_stale": str(stale)}, None, 409)
    except StoreError as exc:
        raise HTTPException(404, str(exc)) from exc
    return on_saved(saved)


def _connection_or_404(request: Request) -> Connection:
    connection = admin_context(request).store.get_connection(request.path_params["id"])
    if connection is None:
        raise HTTPException(404, "There is no such connection.")
    return connection


@admin_only
async def list_connections(request: Request) -> Response:
    """All connections with their switches and live session counts."""
    ctx = admin_context(request)
    connections = ctx.store.list_connections()
    registry = ctx.registry()
    sessions = {c.id: len(registry.sessions_for_connection(c.id)) for c in connections}
    return render(request, "connections/list.html", connections=connections, sessions=sessions)


def _edit_page(request: Request, connection: Connection | None) -> Page:
    def page(
        form: ConnectionForm, errors: dict[str, str], result: CheckResult | None, status: int
    ) -> Response:
        ctx = admin_context(request)
        sessions = (
            ctx.registry().sessions_for_connection(connection.id) if connection else []
        )
        return render(
            request,
            "connections/edit.html",
            status_code=status,
            connection=connection,
            form=form,
            errors=errors,
            result=result,
            test_errors=[],
            sessions=sessions,
            action_url=(
                f"/admin/connections/{connection.id}" if connection else "/admin/connections/new"
            ),
            submit_label="Save" if connection else "Add connection",
            password_hint=password_hint(connection, False),
        )

    return page


def _saved(connection: Connection) -> Response:
    return RedirectResponse(f"/admin/connections/{connection.id}?notice=saved", status_code=303)


@admin_only
async def new_connection_form(request: Request) -> Response:
    """An empty connection form."""
    return _edit_page(request, None)(ConnectionForm(), {}, None, 200)


@admin_only
async def new_connection(request: Request) -> Response:
    """Test or save a new connection."""
    return await connection_submission(
        request,
        connection_id=None,
        fallback_password=None,
        page=_edit_page(request, None),
        on_saved=_saved,
    )


@admin_only
async def edit_connection_form(request: Request) -> Response:
    """A saved connection's form, switches and live sessions."""
    connection = _connection_or_404(request)
    return _edit_page(request, connection)(ConnectionForm.from_connection(connection), {}, None, 200)


@admin_only
async def edit_connection(request: Request) -> Response:
    """Test or save changes to a connection."""
    connection = _connection_or_404(request)
    return await connection_submission(
        request,
        connection_id=connection.id,
        fallback_password=None,
        page=_edit_page(request, connection),
        on_saved=_saved,
    )


@admin_only
async def switches(request: Request) -> Response:
    """Turn read-only or enabled on or off."""
    connection = _connection_or_404(request)
    data = await read_form(request)

    def flag(name: str) -> bool | None:
        value = data.get(name)
        return None if value is None else value == "on"

    set_connection_switches(
        admin_context(request),
        connection.id,
        read_only=flag("read_only"),
        enabled=flag("enabled"),
        actor=request.state.user,
    )
    return RedirectResponse(f"/admin/connections/{connection.id}?notice=saved", status_code=303)


@admin_only
async def disconnect(request: Request) -> Response:
    """Close every live session on the connection."""
    connection = _connection_or_404(request)
    await read_form(request)
    disconnect_connection(admin_context(request), connection.id, actor=request.state.user)
    return RedirectResponse(
        f"/admin/connections/{connection.id}?notice=disconnected", status_code=303
    )


@admin_only
async def delete_form(request: Request) -> Response:
    """Ask before deleting."""
    return render(request, "connections/delete.html", connection=_connection_or_404(request))


@admin_only
async def delete(request: Request) -> Response:
    """Delete the connection, its grants, sessions and notes."""
    connection = _connection_or_404(request)
    await read_form(request)
    delete_connection(admin_context(request), connection.id, actor=request.state.user)
    return RedirectResponse("/admin/connections?notice=deleted", status_code=303)


routes = [
    Route("/connections", list_connections, methods=["GET"]),
    Route("/connections/new", new_connection_form, methods=["GET"]),
    Route("/connections/new", new_connection, methods=["POST"]),
    Route("/connections/{id:int}", edit_connection_form, methods=["GET"]),
    Route("/connections/{id:int}", edit_connection, methods=["POST"]),
    Route("/connections/{id:int}/switches", switches, methods=["POST"]),
    Route("/connections/{id:int}/disconnect", disconnect, methods=["POST"]),
    Route("/connections/{id:int}/delete", delete_form, methods=["GET"]),
    Route("/connections/{id:int}/delete", delete, methods=["POST"]),
]
```

In `src/u2_mcp/admin/app.py`, import `routes_connections` and add `*routes_connections.routes,` after `*routes_auth.routes,`.

- [ ] **Step 4: Create the templates**

`src/u2_mcp/admin/templates/partials/test_result.html`:

```html
<div id="test-result" class="result{% if result %}{{ ' ok' if result.ok else ' bad' }}{% endif %}" role="status" aria-live="polite">
  {% if result %}<p>{{ "Test passed: " if result.ok else "Test failed: " }}{{ result.message }}</p>{% endif %}
  {% if test_errors %}<p class="error">Fix these first: {{ test_errors | join(" ") }}</p>{% endif %}
</div>
```

`src/u2_mcp/admin/templates/partials/connection_form.html`:

```html
{% from "partials/fields.html" import text, checkbox, select %}
{% if errors and errors.get("_stale") %}<p class="alert" role="alert">{{ errors["_stale"] }} <a href="">Reload</a></p>{% endif %}
<form method="post" action="{{ action_url }}" class="connection-form">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <input type="hidden" name="version" value="{{ form.version }}">
  {{ text("name", "Name", form.name, errors, hint="What people see in Copilot, such as Prod or Test.", required=true) }}
  {{ text("host", "Host", form.host, errors, required=true) }}
  {{ text("port", "Port", form.port, errors, type="number") }}
  {{ select("service", "Database", form.service, [("uvcs", "UniVerse (uvcs)"), ("udcs", "UniData (udcs)")], errors) }}
  {{ text("account", "Account", form.account, errors, required=true) }}
  {{ checkbox("ssl", "Use SSL", form.ssl) }}
  {{ select("login_mode", "Logins", form.login_mode, [("shared", "One shared U2 login for everyone"), ("per_user", "Each person's own U2 login, set on their grant")], errors) }}
  <fieldset>
    <legend>U2 login</legend>
    <p class="hint">Saved for a shared connection. For per-user connections it is only used to test, and is not saved.</p>
    {{ text("login_user", "U2 user", form.login_user, errors) }}
    {{ text("login_password", "Password", "", errors, type="password", autocomplete="new-password", hint=password_hint) }}
  </fieldset>
  {{ checkbox("read_only", "Read-only", form.read_only, hint="Refuse every write on this connection. U2_READ_ONLY, when set, overrides this for all connections.") }}
  {{ checkbox("enabled", "Enabled", form.enabled) }}
  <div class="actions">
    <button type="submit" name="action" value="save">{{ submit_label }}</button>
    <button type="submit" name="action" value="test" class="secondary"
            hx-post="{{ action_url }}" hx-vals='{"action": "test"}'
            hx-target="#test-result" hx-swap="outerHTML" hx-disabled-elt="this">Test connection</button>
  </div>
  {% include "partials/test_result.html" %}
</form>
```

`src/u2_mcp/admin/templates/connections/list.html`:

```html
{% extends "base.html" %}
{% block title %}Connections · u2-mcp admin{% endblock %}
{% block content %}
<h1>Connections</h1>
<p><a class="button" href="/admin/connections/new">Add a connection</a></p>
{% if connections %}
<table>
  <thead><tr><th>Name</th><th>Server</th><th>Account</th><th>Logins</th><th>Read-only</th><th>Enabled</th><th>Live sessions</th></tr></thead>
  <tbody>
  {% for c in connections %}
    <tr>
      <td><a href="/admin/connections/{{ c.id }}">{{ c.name }}</a></td>
      <td>{{ c.host }}:{{ c.port }} ({{ c.service }})</td>
      <td>{{ c.account }}</td>
      <td>{{ "Shared" if c.login_mode == "shared" else "Per person" }}</td>
      <td>{{ "Yes" if c.read_only else "No" }}</td>
      <td>{{ "Yes" if c.enabled else "No" }}</td>
      <td>{{ sessions[c.id] }}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>
{% else %}
<p>No connections yet.</p>
{% endif %}
{% endblock %}
```

`src/u2_mcp/admin/templates/connections/edit.html`:

```html
{% extends "base.html" %}
{% block title %}{{ connection.name if connection else "Add a connection" }} · u2-mcp admin{% endblock %}
{% block content %}
<p><a href="/admin/connections">All connections</a></p>
<h1>{{ connection.name if connection else "Add a connection" }}</h1>
{% include "partials/connection_form.html" %}
{% if connection %}
<h2>Switches</h2>
<form method="post" action="/admin/connections/{{ connection.id }}/switches" class="actions">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  {% if connection.read_only %}
  <button type="submit" name="read_only" value="off" class="secondary">Allow writes</button>
  {% else %}
  <button type="submit" name="read_only" value="on" class="secondary">Make read-only</button>
  {% endif %}
  {% if connection.enabled %}
  <button type="submit" name="enabled" value="off" class="secondary">Disable</button>
  {% else %}
  <button type="submit" name="enabled" value="on" class="secondary">Enable</button>
  {% endif %}
</form>
<h2>Live sessions</h2>
{% if sessions %}
<ul>{% for login in sessions %}<li>{{ login }}</li>{% endfor %}</ul>
<form method="post" action="/admin/connections/{{ connection.id }}/disconnect">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <button type="submit" class="secondary">Disconnect all</button>
</form>
{% else %}
<p>None.</p>
{% endif %}
<h2>Delete</h2>
<p><a href="/admin/connections/{{ connection.id }}/delete">Delete this connection…</a></p>
{% endif %}
{% endblock %}
```

`src/u2_mcp/admin/templates/connections/delete.html`:

```html
{% extends "base.html" %}
{% block title %}Delete {{ connection.name }} · u2-mcp admin{% endblock %}
{% block content %}
<h1>Delete {{ connection.name }}?</h1>
<p>This removes the connection, every grant on it, its live sessions and its knowledge notes. It cannot be undone.</p>
<form method="post" action="/admin/connections/{{ connection.id }}/delete" class="actions">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <button type="submit" class="danger">Delete {{ connection.name }}</button>
  <a href="/admin/connections/{{ connection.id }}">Cancel</a>
</form>
{% endblock %}
```

Run: `pytest tests/test_admin -v`
Expected: PASS.

- [ ] **Step 5: Run everything, lint and commit**

Run: `ruff format src tests && pytest -q && ruff check . && ruff format --check . && mypy src/`
Expected: all pass, clean.

```bash
git add src/u2_mcp/admin tests/test_admin
git commit -m "feat: Connections pages with test, switches, live sessions and delete"
```

---

### Task 10: The setup wizard and the Settings page

**Files:**
- Create: `src/u2_mcp/admin/routes_setup.py`
- Create: `src/u2_mcp/admin/templates/setup/_steps.html`, `setup/admin.html`, `setup/connection.html`, `setup/server_address.html`, `setup/done.html`, `settings.html`, `partials/local_user_form.html`, `partials/server_address_form.html`
- Modify: `src/u2_mcp/admin/app.py` (replace the placeholder index; add routes)
- Test: `tests/test_admin/test_routes_setup.py`

**Interfaces:**
- Consumes: Task 4 setup state functions, Task 6 services, Task 8 security helpers, Task 9 `connection_submission`, `password_hint`.
- Produces routes: `GET /` (index), `GET /setup`, `GET/POST /setup/admin`, `GET/POST /setup/connection`, `GET/POST /setup/server_address`, `GET/POST /setup/done`, `GET/POST /settings`.
- Produces in `routes_setup.py`: `STEP_TITLES: dict[str, str]`; `async def server_address_submission(request, *, page: Callable[[str, dict[str, str], int], Response], on_saved: Callable[[str], Response]) -> Response` (shared by the wizard step and the Settings page).
- Template contracts: `partials/local_user_form.html` (variables `values`, `errors`, `action_url`, `submit_label`, `csrf_token`, `show_setup_code`); `partials/server_address_form.html` (variables `public_url`, `warning`, `errors`, `action_url`, `submit_label`, `csrf_token`).
- Wizard rules enforced here: a step after `next_step` redirects to `next_step`; every step but the first creation needs a signed-in admin; once `setup_complete`, every `/setup` URL redirects to `/admin/`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_admin/test_routes_setup.py`:

```python
"""The setup wizard, over HTTP: resumable, guarded by the setup code, logic-free."""

from collections.abc import Iterator

import pytest
from starlette.testclient import TestClient

from u2_mcp.admin.context import AdminContext
from u2_mcp.setup_code import (
    WRONG_SETUP_CODE_MESSAGE,
    completed_step,
    ensure_setup_code,
    is_setup_complete,
)

from .conftest import FakeCheck
from .helpers import admin_client, csrf_from, sign_in

ADMIN_PASSWORD = "a long admin passphrase"
CONNECTION = {
    "name": "Prod", "host": "u2.example", "port": "31438", "service": "uvcs",
    "account": "PROD", "login_mode": "shared", "login_user": "svc",
    "login_password": "secret", "read_only": "on", "enabled": "on", "version": "0",
}


@pytest.fixture
def client(ctx: AdminContext) -> Iterator[TestClient]:
    with admin_client(ctx) as test_client:
        yield test_client


def _create_admin(client: TestClient, ctx: AdminContext, code: str | None = None) -> object:
    page = client.get("/admin/setup/admin")
    return client.post(
        "/admin/setup/admin",
        data={"csrf_token": csrf_from(page.text),
              "setup_code": code if code is not None else ensure_setup_code(ctx.store),
              "username": "admin", "display_name": "Admin", "password": ADMIN_PASSWORD,
              "password_again": ADMIN_PASSWORD},
        follow_redirects=False,
    )


def _post(client: TestClient, url: str, data: dict[str, str]) -> object:
    token = csrf_from(client.get(url).text)
    return client.post(url, data={**data, "csrf_token": token}, follow_redirects=False)


def _through_connection(client: TestClient, ctx: AdminContext) -> None:
    _create_admin(client, ctx)
    _post(client, "/admin/setup/connection", {**CONNECTION, "action": "save"})


class TestStart:
    def test_a_new_server_goes_to_the_first_step(self, client: TestClient) -> None:
        first = client.get("/admin/", follow_redirects=False)
        second = client.get(first.headers["location"], follow_redirects=False)

        assert first.headers["location"] == "/admin/setup"
        assert second.headers["location"] == "/admin/setup/admin"

    def test_later_steps_redirect_back(self, client: TestClient) -> None:
        response = client.get("/admin/setup/server_address", follow_redirects=False)

        assert response.headers["location"] == "/admin/setup/admin"

    def test_the_sign_in_page_sends_a_new_server_to_setup(self, client: TestClient) -> None:
        response = client.get("/admin/sign-in", follow_redirects=False)

        assert response.headers["location"] == "/admin/setup"


class TestAdminStep:
    def test_a_wrong_code_creates_nobody(self, client: TestClient, ctx: AdminContext) -> None:
        ensure_setup_code(ctx.store)

        response = _create_admin(client, ctx, code="AAAA-AAAA-AAAA")

        assert response.status_code == 400  # type: ignore[attr-defined]
        assert WRONG_SETUP_CODE_MESSAGE.replace("'", "&#39;") in (
            response.text)  # type: ignore[attr-defined]
        assert ctx.store.has_local_admin() is False

    def test_the_right_code_creates_the_admin_and_signs_in(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        response = _create_admin(client, ctx)

        assert response.headers["location"] == "/admin/setup/connection"  # type: ignore[attr-defined]
        assert ctx.store.has_local_admin() is True
        assert completed_step(ctx.store) == "admin"
        assert client.get("/admin/setup/connection").status_code == 200

    def test_password_rules_apply(self, client: TestClient, ctx: AdminContext) -> None:
        page = client.get("/admin/setup/admin")
        response = client.post("/admin/setup/admin", data={
            "csrf_token": csrf_from(page.text), "setup_code": ensure_setup_code(ctx.store),
            "username": "admin", "password": "short", "password_again": "short"})

        assert "Use at least 12 characters." in response.text

    def test_back_to_a_finished_admin_step_shows_it_done(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        _create_admin(client, ctx)

        page = client.get("/admin/setup/admin")

        assert "The admin account is created" in page.text
        assert 'name="setup_code"' not in page.text


class TestConnectionStep:
    def test_a_new_browser_must_sign_in_to_continue(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        _create_admin(client, ctx)

        with admin_client(ctx) as other:
            response = other.get("/admin/setup/connection", follow_redirects=False)
            assert response.headers["location"] == (
                "/admin/sign-in?next=/admin/setup/connection")
            sign_in(other, username="admin", password=ADMIN_PASSWORD,
                    next_url="/admin/setup/connection")
            assert other.get("/admin/setup/connection").status_code == 200

    def test_the_environment_prefills_but_never_shows_the_password(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        _create_admin(client, ctx)

        page = client.get("/admin/setup/connection").text

        assert f'value="{ctx.config.host}"' in page
        assert ctx.config.password not in page
        assert "Leave blank to use U2_PASSWORD" in page

    def test_test_and_save(self, client: TestClient, ctx: AdminContext, check: FakeCheck) -> None:
        _create_admin(client, ctx)

        tested = _post(client, "/admin/setup/connection", {**CONNECTION, "action": "test"})
        saved = _post(client, "/admin/setup/connection", {**CONNECTION, "action": "save"})

        assert "Test passed: fine" in tested.text  # type: ignore[attr-defined]
        assert saved.headers["location"] == "/admin/setup/server_address"  # type: ignore[attr-defined]
        assert completed_step(ctx.store) == "connection"

    def test_a_blank_password_uses_the_environment(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        _create_admin(client, ctx)

        _post(client, "/admin/setup/connection",
              {**CONNECTION, "login_password": "", "action": "save"})

        created = ctx.store.get_connection_by_name("Prod")
        assert created is not None
        assert ctx.store.shared_password(created.id) == ctx.config.password

    def test_returning_edits_the_same_connection(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        _through_connection(client, ctx)

        page = client.get("/admin/setup/connection").text
        created = ctx.store.get_connection_by_name("Prod")
        assert created is not None
        _post(client, "/admin/setup/connection",
              {**CONNECTION, "host": "u2-new.example", "login_password": "",
               "version": str(created.version), "action": "save"})

        assert 'value="u2.example"' in page
        assert [c.host for c in ctx.store.list_connections()] == ["u2-new.example"]
        assert completed_step(ctx.store) == "connection"


class TestServerAddressAndDone:
    def test_server_address_saves_and_warns_about_http(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        _through_connection(client, ctx)

        page = client.get("/admin/setup/server_address").text
        response = _post(client, "/admin/setup/server_address",
                         {"public_url": "https://u2.example.com"})

        assert "This address is not https." in page  # the default is http://host:port
        assert response.headers["location"] == "/admin/setup/done"  # type: ignore[attr-defined]

    def test_done_lists_everything_and_finishes(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        _through_connection(client, ctx)
        _post(client, "/admin/setup/server_address", {"public_url": "https://u2.example.com"})

        page = client.get("/admin/setup/done").text
        finished = _post(client, "/admin/setup/done", {})

        assert "Prod" in page and "https://u2.example.com/" in page
        assert "Company sign-in (SSO)" in page
        assert finished.headers["location"] == (  # type: ignore[attr-defined]
            "/admin/connections?notice=setup_done")
        assert is_setup_complete(ctx.store) is True
        assert ctx.store.recent_audit(1)[0]["action"] == "setup.finish"
        assert client.get("/admin/setup", follow_redirects=False).headers["location"] == "/admin/"
        assert client.get("/admin/", follow_redirects=False).headers["location"] == (
            "/admin/connections")


class TestSettingsPage:
    def test_settings_saves_the_address_with_the_same_rules(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        _through_connection(client, ctx)
        _post(client, "/admin/setup/server_address", {"public_url": "https://u2.example.com"})
        _post(client, "/admin/setup/done", {})

        bad = _post(client, "/admin/settings", {"public_url": "not a url"})
        good = _post(client, "/admin/settings", {"public_url": "https://mcp.example.com/"})

        assert "Enter the full address people use" in bad.text  # type: ignore[attr-defined]
        assert good.headers["location"] == "/admin/settings?notice=saved"  # type: ignore[attr-defined]
        page = client.get("/admin/settings").text
        assert 'value="https://mcp.example.com"' in page
        assert "Restart the server" in page
```

Run: `pytest tests/test_admin/test_routes_setup.py -v`
Expected: FAIL (404s; the index is still the placeholder).

- [ ] **Step 2: Implement `routes_setup.py`**

```python
"""The setup wizard and the Settings page.

Every step renders the same form partial and calls the same service as its
everyday page (spec: setup wizard rule 1). Progress is saved on every submit,
so Refresh, Back and a new browser all resume at the right step.
"""

from __future__ import annotations

from collections.abc import Callable

from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from ..connection_check import CheckResult
from ..setup_code import (
    SETUP_STEPS,
    WRONG_SETUP_CODE_MESSAGE,
    check_setup_code,
    completed_step,
    finish_setup,
    is_setup_complete,
    mark_step_done,
    next_step,
)
from ..store.models import Connection
from .routes_connections import connection_submission, password_hint
from .security import (
    admin_only,
    client_ip,
    is_secure,
    presession_token,
    read_form,
    set_presession_cookie,
    set_session_cookie,
    start_session,
)
from .services import (
    ConnectionForm,
    ValidationFailed,
    create_local_user,
    effective_public_url,
    public_url_warning,
    save_public_url,
)
from .templating import admin_context, render

STEP_TITLES: dict[str, str] = {
    "admin": "Admin account",
    "connection": "First connection",
    "server_address": "Server address",
    "done": "Done",
}
RESTART_NOTE = (
    "Restart the server for OAuth sign-in and personal access tokens to use a changed address."
)


def _redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def _guard(request: Request, step: str) -> Response | None:
    """Return a redirect when this step may not be shown now, else None."""
    store = admin_context(request).store
    if is_setup_complete(store):
        return _redirect("/admin/")
    upcoming = next_step(store)
    if SETUP_STEPS.index(step) > SETUP_STEPS.index(upcoming):
        return _redirect(f"/admin/setup/{upcoming}")
    first_creation = step == "admin" and completed_step(store) is None
    user = request.state.user
    if not first_creation and (user is None or not user.is_admin):
        return _redirect(f"/admin/sign-in?next=/admin/setup/{step}")
    return None


def _step_page(request: Request, template: str, step: str, *, status_code: int = 200,
               **context: object) -> Response:
    store = admin_context(request).store
    done = completed_step(store)
    done_index = SETUP_STEPS.index(done) if done else -1
    return render(
        request,
        template,
        status_code=status_code,
        step=step,
        steps=[(name, STEP_TITLES[name], SETUP_STEPS.index(name) <= done_index + 1)
               for name in SETUP_STEPS],
        **context,
    )


async def index(request: Request) -> Response:
    """The admin home: the wizard until setup is finished, then Connections."""
    if not is_setup_complete(admin_context(request).store):
        return _redirect("/admin/setup")
    return await _home(request)


@admin_only
async def _home(request: Request) -> Response:
    return _redirect("/admin/connections")


async def setup_start(request: Request) -> Response:
    """Resume at the first unfinished step."""
    store = admin_context(request).store
    if is_setup_complete(store):
        return _redirect("/admin/")
    return _redirect(f"/admin/setup/{next_step(store)}")


# ------------------------------------------------------------------ admin step

def _admin_page(request: Request, *, values: dict[str, str], errors: dict[str, str],
                status_code: int = 200) -> Response:
    ctx = admin_context(request)
    created = completed_step(ctx.store) is not None
    token = request.state.csrf_token or presession_token(request)
    response = _step_page(
        request, "setup/admin.html", "admin", status_code=status_code, created=created,
        values=values, errors=errors, csrf_token=token, action_url="/admin/setup/admin",
        submit_label="Create admin and continue", show_setup_code=True,
    )
    if not request.state.csrf_token:
        set_presession_cookie(response, token, secure=is_secure(ctx))
    return response


async def setup_admin_form(request: Request) -> Response:
    """Step 1: the setup code and the first local admin."""
    return _guard(request, "admin") or _admin_page(request, values={}, errors={})


async def setup_admin(request: Request) -> Response:
    """Create the first admin, then sign them in."""
    blocked = _guard(request, "admin")
    if blocked is not None:
        return blocked
    ctx = admin_context(request)
    if completed_step(ctx.store) is not None:
        return _redirect("/admin/setup/connection")
    form = await read_form(request)
    values = {key: str(form.get(key, "")) for key in ("username", "display_name")}
    if not check_setup_code(ctx.store, str(form.get("setup_code", ""))):
        return _admin_page(request, values=values,
                           errors={"setup_code": WRONG_SETUP_CODE_MESSAGE}, status_code=400)
    try:
        user = create_local_user(
            ctx,
            username=values["username"],
            display_name=values["display_name"],
            password=str(form.get("password", "")),
            password_again=str(form.get("password_again", "")),
            is_admin=True,
            actor=None,
        )
    except ValidationFailed as failed:
        return _admin_page(request, values=values, errors=failed.errors, status_code=400)
    mark_step_done(ctx.store, "admin")
    raw_id, _ = start_session(ctx.store, user, client_ip(request))
    response = _redirect("/admin/setup/connection")
    set_session_cookie(response, raw_id, secure=is_secure(ctx))
    return response


# ------------------------------------------------------------- connection step

def _first_connection(request: Request) -> Connection | None:
    connections = admin_context(request).store.list_connections()
    return min(connections, key=lambda c: c.id) if connections else None


def _connection_page(request: Request, connection: Connection | None):  # type: ignore[no-untyped-def]
    env_password = bool(admin_context(request).config.password)

    def page(form: ConnectionForm, errors: dict[str, str], result: CheckResult | None,
             status: int) -> Response:
        return _step_page(
            request, "setup/connection.html", "connection", status_code=status, form=form,
            errors=errors, result=result, test_errors=[], action_url="/admin/setup/connection",
            submit_label="Save and continue",
            password_hint=password_hint(connection, env_password and connection is None),
        )

    return page


async def setup_connection_form(request: Request) -> Response:
    """Step 2: the first connection, pre-filled from U2_* variables when present."""
    blocked = _guard(request, "connection")
    if blocked is not None:
        return blocked
    connection = _first_connection(request)
    form = (
        ConnectionForm.from_connection(connection)
        if connection
        else ConnectionForm.from_environment(admin_context(request).config)
    )
    return _connection_page(request, connection)(form, {}, None, 200)


async def setup_connection(request: Request) -> Response:
    """Test or save the first connection."""
    blocked = _guard(request, "connection")
    if blocked is not None:
        return blocked
    ctx = admin_context(request)
    connection = _first_connection(request)

    def on_saved(_saved: Connection) -> Response:
        mark_step_done(ctx.store, "connection")
        return _redirect("/admin/setup/server_address")

    return await connection_submission(
        request,
        connection_id=connection.id if connection else None,
        fallback_password=(ctx.config.password or None) if connection is None else None,
        page=_connection_page(request, connection),
        on_saved=on_saved,
    )


# --------------------------------------------------------- server address step

async def server_address_submission(
    request: Request,
    *,
    page: Callable[[str, dict[str, str], int], Response],
    on_saved: Callable[[str], Response],
) -> Response:
    """Handle a server-address form POST for the wizard and the Settings page."""
    ctx = admin_context(request)
    form = await read_form(request)
    typed = str(form.get("public_url", ""))
    try:
        saved = save_public_url(ctx, typed, actor=request.state.user)
    except ValidationFailed as failed:
        return page(typed, failed.errors, 400)
    return on_saved(saved)


def _address_page(request: Request, template: str, step: str | None, action_url: str,
                  submit_label: str) -> Callable[[str, dict[str, str], int], Response]:
    def page(public_url: str, errors: dict[str, str], status: int) -> Response:
        context = {
            "public_url": public_url,
            "warning": public_url_warning(public_url),
            "errors": errors,
            "action_url": action_url,
            "submit_label": submit_label,
            "restart_note": RESTART_NOTE,
        }
        if step is None:
            return render(request, template, status_code=status, **context)
        return _step_page(request, template, step, status_code=status, **context)

    return page


async def setup_server_address_form(request: Request) -> Response:
    """Step 3: the address people use to reach this server."""
    blocked = _guard(request, "server_address")
    if blocked is not None:
        return blocked
    page = _address_page(request, "setup/server_address.html", "server_address",
                         "/admin/setup/server_address", "Save and continue")
    return page(effective_public_url(admin_context(request)), {}, 200)


async def setup_server_address(request: Request) -> Response:
    """Save the address and continue."""
    blocked = _guard(request, "server_address")
    if blocked is not None:
        return blocked
    ctx = admin_context(request)

    def on_saved(_url: str) -> Response:
        mark_step_done(ctx.store, "server_address")
        return _redirect("/admin/setup/done")

    return await server_address_submission(
        request,
        page=_address_page(request, "setup/server_address.html", "server_address",
                           "/admin/setup/server_address", "Save and continue"),
        on_saved=on_saved,
    )


# ------------------------------------------------------------------- done step

async def setup_done_form(request: Request) -> Response:
    """Step 4: what is set up, what is not yet, and the Copilot configuration."""
    blocked = _guard(request, "done")
    if blocked is not None:
        return blocked
    ctx = admin_context(request)
    public_url = effective_public_url(ctx)
    return _step_page(
        request, "setup/done.html", "done", connection=_first_connection(request),
        public_url=public_url, warning=public_url_warning(public_url),
    )


async def setup_done(request: Request) -> Response:
    """Finish setup: the setup code stops working and /admin/setup closes."""
    blocked = _guard(request, "done")
    if blocked is not None:
        return blocked
    ctx = admin_context(request)
    await read_form(request)
    finish_setup(ctx.store)
    user = request.state.user
    ctx.store.add_audit(kind="admin", action="setup.finish", outcome="ok",
                        actor_user_id=user.id, actor_label=user.label)
    return _redirect("/admin/connections?notice=setup_done")


# ----------------------------------------------------------------- settings

@admin_only
async def settings_form(request: Request) -> Response:
    """Settings: the server address (phase 2b adds token policy and local accounts)."""
    page = _address_page(request, "settings.html", None, "/admin/settings", "Save")
    return page(effective_public_url(admin_context(request)), {}, 200)


@admin_only
async def settings_save(request: Request) -> Response:
    """Save the server address from the Settings page."""
    return await server_address_submission(
        request,
        page=_address_page(request, "settings.html", None, "/admin/settings", "Save"),
        on_saved=lambda _url: _redirect("/admin/settings?notice=saved"),
    )


routes = [
    Route("/", index, methods=["GET"]),
    Route("/setup", setup_start, methods=["GET"]),
    Route("/setup/admin", setup_admin_form, methods=["GET"]),
    Route("/setup/admin", setup_admin, methods=["POST"]),
    Route("/setup/connection", setup_connection_form, methods=["GET"]),
    Route("/setup/connection", setup_connection, methods=["POST"]),
    Route("/setup/server_address", setup_server_address_form, methods=["GET"]),
    Route("/setup/server_address", setup_server_address, methods=["POST"]),
    Route("/setup/done", setup_done_form, methods=["GET"]),
    Route("/setup/done", setup_done, methods=["POST"]),
    Route("/settings", settings_form, methods=["GET"]),
    Route("/settings", settings_save, methods=["POST"]),
]
```

Fix the `_connection_page` return annotation for mypy by importing `Page` from `routes_connections` and annotating `-> Page` (then drop the `type: ignore`).

In `src/u2_mcp/admin/app.py`: delete the placeholder `index` and its `Route("/", ...)`, import `routes_setup`, and make the route list:

```python
    routes: list[BaseRoute] = [
        *routes_setup.routes,
        *routes_auth.routes,
        *routes_connections.routes,
        Mount("/static", app=StaticFiles(packages=[("u2_mcp.admin", "static")]), name="static"),
    ]
```

(The `admin_only` import in `app.py` is no longer needed; remove it.)

- [ ] **Step 3: Create the templates**

`src/u2_mcp/admin/templates/setup/_steps.html`:

```html
<ol class="steps" aria-label="Setup steps">
  {% for name, title, reachable in steps %}
  <li class="{{ 'current' if name == step else '' }}">
    {% if reachable and name != step %}<a href="/admin/setup/{{ name }}">{{ title }}</a>{% else %}{{ title }}{% endif %}
  </li>
  {% endfor %}
</ol>
```

`src/u2_mcp/admin/templates/partials/local_user_form.html`:

```html
{% from "partials/fields.html" import text %}
<form method="post" action="{{ action_url }}">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  {% if show_setup_code %}
  {{ text("setup_code", "Setup code", "", errors, hint="Printed in the server log at start-up, or run: u2-mcp admin show-setup-code", required=true) }}
  {% endif %}
  {{ text("username", "Username", values.get("username", ""), errors, autocomplete="username", required=true) }}
  {{ text("display_name", "Display name (optional)", values.get("display_name", ""), errors) }}
  {{ text("password", "Password", "", errors, type="password", autocomplete="new-password", hint="At least 12 characters.", required=true) }}
  {{ text("password_again", "Password again", "", errors, type="password", autocomplete="new-password", required=true) }}
  <div class="actions"><button type="submit">{{ submit_label }}</button></div>
</form>
```

`src/u2_mcp/admin/templates/partials/server_address_form.html`:

```html
{% from "partials/fields.html" import text %}
<form method="post" action="{{ action_url }}">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  {{ text("public_url", "Server address", public_url, errors, type="url", hint="The address people and Copilot use, such as https://u2-mcp.example.com", required=true) }}
  {% if warning %}<p class="warning">{{ warning }}</p>{% endif %}
  <p class="hint">{{ restart_note }}</p>
  <div class="actions"><button type="submit">{{ submit_label }}</button></div>
</form>
```

`src/u2_mcp/admin/templates/setup/admin.html`:

```html
{% extends "base.html" %}
{% block title %}Setup: admin account · u2-mcp admin{% endblock %}
{% block content %}
<h1>Set up u2-mcp</h1>
{% include "setup/_steps.html" %}
<h2>Admin account</h2>
{% if created %}
<p>The admin account is created{% if user %} ({{ user.label }}){% endif %}.</p>
<p><a class="button" href="/admin/setup/connection">Next: first connection</a></p>
{% else %}
<p>This local account is the break-glass admin: it works even when company sign-in does not.</p>
{% include "partials/local_user_form.html" %}
{% endif %}
{% endblock %}
```

`src/u2_mcp/admin/templates/setup/connection.html`:

```html
{% extends "base.html" %}
{% block title %}Setup: first connection · u2-mcp admin{% endblock %}
{% block content %}
<h1>Set up u2-mcp</h1>
{% include "setup/_steps.html" %}
<h2>First connection</h2>
<p>The U2 server and account people will reach through Copilot. Test it before you continue.</p>
{% include "partials/connection_form.html" %}
{% endblock %}
```

`src/u2_mcp/admin/templates/setup/server_address.html`:

```html
{% extends "base.html" %}
{% block title %}Setup: server address · u2-mcp admin{% endblock %}
{% block content %}
<h1>Set up u2-mcp</h1>
{% include "setup/_steps.html" %}
<h2>Server address</h2>
{% include "partials/server_address_form.html" %}
{% endblock %}
```

`src/u2_mcp/admin/templates/setup/done.html`:

```html
{% extends "base.html" %}
{% block title %}Setup: done · u2-mcp admin{% endblock %}
{% block content %}
<h1>Set up u2-mcp</h1>
{% include "setup/_steps.html" %}
<h2>Done</h2>
<table>
  <tbody>
    <tr><th>Admin account</th><td>Created{% if user %}: {{ user.label }}{% endif %}</td></tr>
    <tr><th>First connection</th><td>{% if connection %}{{ connection.name }} ({{ connection.host }}, {{ connection.account }}){% else %}Not set{% endif %}</td></tr>
    <tr><th>Server address</th><td>{{ public_url }}{% if warning %}<p class="warning">{{ warning }}</p>{% endif %}</td></tr>
    <tr><th>Company sign-in (SSO)</th><td>Not available yet. It arrives in a later version of u2-mcp.</td></tr>
  </tbody>
</table>
<h3>Copilot in VS Code</h3>
<p>Add this to <code>.vscode/mcp.json</code> in a project, or to your user MCP configuration:</p>
<pre>{
  "servers": {
    "u2": {
      "type": "http",
      "url": "{{ public_url }}/"
    }
  }
}</pre>
<p class="warning">Nobody can use this connection from Copilot yet. Access is granted to people and groups on the Users and Groups pages, and personal access tokens are created on the My access page; both arrive in the next version of u2-mcp. (A connection imported from U2_HOST at first start keeps the access it had before.)</p>
<form method="post" action="/admin/setup/done" class="actions">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <button type="submit">Finish setup</button>
</form>
{% endblock %}
```

`src/u2_mcp/admin/templates/settings.html`:

```html
{% extends "base.html" %}
{% block title %}Settings · u2-mcp admin{% endblock %}
{% block content %}
<h1>Settings</h1>
<h2>Server address</h2>
{% include "partials/server_address_form.html" %}
{% endblock %}
```

Run: `pytest tests/test_admin -v`
Expected: PASS (including Task 8's tests, which now reach the real index).

- [ ] **Step 4: Run everything, lint and commit**

Run: `ruff format src tests && pytest -q && ruff check . && ruff format --check . && mypy src/ && bandit -r src/ --severity-level medium --confidence-level medium -q`
Expected: all pass, clean.

```bash
git add src/u2_mcp/admin tests/test_admin
git commit -m "feat: setup wizard (admin, connection, server address, done) and Settings page"
```

---

### Task 11: Browser tests (Playwright) against a real server process

**Files:**
- Create: `tests/e2e/__init__.py` (empty), `tests/e2e/conftest.py`, `tests/e2e/wizard.py`, `tests/e2e/test_setup_wizard.py`, `tests/e2e/test_connections_pages.py`

**Interfaces:**
- Consumes: everything above; `tests/mocks/sim_driver.py` constants.
- Produces in `tests/e2e/conftest.py`: `REPO_ROOT`, `@dataclass Server(base_url: str, data_dir: Path, env: dict[str, str])` with `setup_code() -> str` (runs `python -m u2_mcp admin show-setup-code`), `launch_server(data_dir: Path) -> tuple[subprocess.Popen[bytes], Server]` (the one function phase 3 changes to start the Docker image), fixture `server` (function scope: a fresh, empty `/data` per test).
- Produces in `tests/e2e/wizard.py`: `ADMIN_USER = "admin"`, `ADMIN_PASSWORD = "a long admin passphrase"`, `create_admin(page, server)`, `fill_connection(page, **values)`, `finish_wizard(page, server)`, `sign_in(page, server)`.

- [ ] **Step 1: Install a browser locally**

Run: `python -m playwright install chromium`
Expected: Chromium downloads (once per machine).

- [ ] **Step 2: Write the harness**

`tests/e2e/conftest.py`:

```python
"""Browser tests: a real server process, a real browser, the scripted U2 driver.

Run with: pytest -m e2e tests/e2e
Plain `pytest` deselects these (see addopts), so it never needs a browser.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SECRET_KEY = "e2e-secret-key-" + "k" * 32
START_TIMEOUT_SECONDS = 30.0


@dataclass
class Server:
    """A running server under test."""

    base_url: str
    data_dir: Path
    env: dict[str, str]

    def url(self, path: str) -> str:
        """Return an absolute URL on this server."""
        return f"{self.base_url}{path}"

    def setup_code(self) -> str:
        """Read the setup code the way an operator would: from the CLI."""
        completed = subprocess.run(  # noqa: S603 - fixed argv, test-only
            [sys.executable, "-m", "u2_mcp", "admin", "show-setup-code"],
            env=self.env, cwd=REPO_ROOT, capture_output=True, text=True, check=True,
            timeout=30,
        )
        return completed.stdout.strip()


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def launch_server(data_dir: Path) -> tuple[subprocess.Popen[bytes], Server]:
    """Start the server on an empty data directory and wait until /health answers.

    This is the only place that knows how the server is started. Phase 3 changes
    it to run the Docker image instead of a local process.
    """
    port = _free_port()
    env = {key: value for key, value in os.environ.items() if not key.startswith("U2_")}
    env.update(
        {
            "U2_SECRET_KEY": SECRET_KEY,
            "U2_DATA_DIR": str(data_dir),
            "U2_HTTP_HOST": "127.0.0.1",
            "U2_HTTP_PORT": str(port),
            "U2_DRIVER": "tests.mocks.sim_driver",
            # The watchdog stays at its default (on): a fresh server must run with it.
            "U2_AUDIT_ENABLED": "false",
            "PYTHONPATH": str(REPO_ROOT),
        }
    )
    log_path = data_dir / "server.log"
    with log_path.open("wb") as log:
        process = subprocess.Popen(  # noqa: S603 - fixed argv, test-only
            [sys.executable, "-m", "u2_mcp", "--streamable-http"],
            env=env, cwd=REPO_ROOT, stdout=log, stderr=subprocess.STDOUT,
        )
    server = Server(f"http://127.0.0.1:{port}", data_dir, env)
    deadline = time.monotonic() + START_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"The server exited early:\n{log_path.read_text()}")
        try:
            if httpx.get(server.url("/health"), timeout=1.0).status_code == 200:
                return process, server
        except httpx.HTTPError:
            pass
        time.sleep(0.2)
    process.kill()
    raise RuntimeError(f"The server did not answer /health:\n{log_path.read_text()}")


@pytest.fixture
def server(tmp_path: Path) -> Iterator[Server]:
    """A fresh server with an empty data directory."""
    process, running = launch_server(tmp_path)
    try:
        yield running
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
```

`tests/e2e/wizard.py`:

```python
"""Steps shared by browser tests, written the way a person uses the pages."""

from __future__ import annotations

import re

from playwright.sync_api import Page, expect

from .conftest import Server

ADMIN_USER = "admin"
ADMIN_PASSWORD = "a long admin passphrase"


def create_admin(page: Page, server: Server) -> None:
    """Open a new server and complete step 1."""
    page.goto(server.url("/admin/"))
    expect(page).to_have_url(re.compile(r"/admin/setup/admin$"))
    page.get_by_label("Setup code").fill(server.setup_code())
    page.get_by_label("Username").fill(ADMIN_USER)
    page.get_by_label("Password", exact=True).fill(ADMIN_PASSWORD)
    page.get_by_label("Password again").fill(ADMIN_PASSWORD)
    page.get_by_role("button", name="Create admin and continue").click()
    expect(page).to_have_url(re.compile(r"/admin/setup/connection$"))


def fill_connection(
    page: Page,
    *,
    name: str = "Prod",
    host: str = "u2.example",
    account: str = "PROD",
    user: str = "svc",
    password: str = "secret",
) -> None:
    """Fill the connection form (wizard or everyday page: it is the same form)."""
    page.get_by_label("Name").fill(name)
    page.get_by_label("Host").fill(host)
    page.get_by_label("Account").fill(account)
    page.get_by_label("U2 user").fill(user)
    page.get_by_label("Password", exact=True).fill(password)


def finish_wizard(page: Page, server: Server, *, public_url: str | None = None) -> None:
    """Run the whole wizard with good values.

    The server address defaults to the test server's own http URL: an https
    address would make later sign-ins set Secure cookies the browser drops over
    plain http.
    """
    create_admin(page, server)
    fill_connection(page)
    page.get_by_role("button", name="Save and continue").click()
    expect(page).to_have_url(re.compile(r"/admin/setup/server_address$"))
    page.get_by_label("Server address").fill(public_url or server.base_url)
    page.get_by_role("button", name="Save and continue").click()
    expect(page).to_have_url(re.compile(r"/admin/setup/done$"))
    page.get_by_role("button", name="Finish setup").click()
    expect(page).to_have_url(re.compile(r"/admin/connections\?notice=setup_done$"))


def sign_in(page: Page, server: Server) -> None:
    """Sign in as the admin from the sign-in page."""
    page.goto(server.url("/admin/sign-in"))
    page.get_by_label("Username").fill(ADMIN_USER)
    page.get_by_label("Password").fill(ADMIN_PASSWORD)
    page.get_by_role("button", name="Sign in").click()
```

- [ ] **Step 3: Write the wizard tests**

`tests/e2e/test_setup_wizard.py`:

```python
"""The setup wizard in a real browser: the part of UOFastMCP that did not work."""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import Browser, Page, expect

from tests.mocks import sim_driver

from .conftest import Server
from .wizard import (
    ADMIN_PASSWORD,
    ADMIN_USER,
    create_admin,
    fill_connection,
    finish_wizard,
)

pytestmark = pytest.mark.e2e


def test_the_whole_wizard_from_an_empty_data_directory(page: Page, server: Server) -> None:
    create_admin(page, server)

    fill_connection(page)
    page.get_by_role("button", name="Test connection").click()
    expect(page.locator("#test-result")).to_contain_text(
        f"Test passed: Connected to PROD on u2.example. COUNT VOC: {sim_driver.COUNT_VOC_RESPONSE}"
    )
    page.get_by_role("button", name="Save and continue").click()

    expect(page.locator(".warning")).to_contain_text("This address is not https.")
    page.get_by_label("Server address").fill("https://u2.example.com")
    page.get_by_role("button", name="Save and continue").click()

    expect(page.locator("pre")).to_contain_text('"url": "https://u2.example.com/"')
    expect(page.get_by_text("Prod (u2.example, PROD)")).to_be_visible()
    page.get_by_role("button", name="Finish setup").click()

    expect(page.locator(".notice")).to_have_text("Setup is finished.")
    expect(page.get_by_role("link", name="Prod")).to_be_visible()
    page.goto(server.url("/admin/setup"))
    expect(page).to_have_url(re.compile(r"/admin/connections$"))


def test_refresh_and_back_at_every_step(page: Page, server: Server) -> None:
    create_admin(page, server)
    page.reload()
    expect(page).to_have_url(re.compile(r"/admin/setup/connection$"))

    fill_connection(page, host="saved.example")
    page.get_by_role("button", name="Save and continue").click()
    expect(page).to_have_url(re.compile(r"/admin/setup/server_address$"))
    page.reload()
    expect(page).to_have_url(re.compile(r"/admin/setup/server_address$"))

    page.go_back()
    expect(page).to_have_url(re.compile(r"/admin/setup/connection$"))
    expect(page.get_by_label("Host")).to_have_value("saved.example")

    page.get_by_role("link", name="Admin account").click()
    expect(page.get_by_text("The admin account is created")).to_be_visible()

    page.get_by_role("link", name="Server address").click()
    page.get_by_label("Server address").fill("https://u2.example.com")
    page.get_by_role("button", name="Save and continue").click()
    expect(page).to_have_url(re.compile(r"/admin/setup/done$"))
    page.reload()
    expect(page).to_have_url(re.compile(r"/admin/setup/done$"))

    page.go_back()
    expect(page.get_by_label("Server address")).to_have_value("https://u2.example.com")

    # Back at the connection step and saving again edits, never duplicates.
    page.goto(server.url("/admin/setup/connection"))
    page.get_by_role("button", name="Save and continue").click()
    page.goto(server.url("/admin/setup/done"))
    expect(page.get_by_text("Prod (saved.example, PROD)")).to_be_visible()


def test_a_closed_browser_resumes_after_signing_in(
    page: Page, browser: Browser, server: Server
) -> None:
    create_admin(page, server)

    other = browser.new_context().new_page()
    other.goto(server.url("/admin/"))
    expect(other).to_have_url(re.compile(r"/admin/sign-in\?next=/admin/setup/connection$"))
    other.get_by_label("Username").fill(ADMIN_USER)
    other.get_by_label("Password").fill(ADMIN_PASSWORD)
    other.get_by_role("button", name="Sign in").click()
    expect(other).to_have_url(re.compile(r"/admin/setup/connection$"))


def test_a_wrong_setup_code(page: Page, server: Server) -> None:
    page.goto(server.url("/admin/setup/admin"))
    page.get_by_label("Setup code").fill("AAAA-AAAA-AAAA")
    page.get_by_label("Username").fill(ADMIN_USER)
    page.get_by_label("Password", exact=True).fill(ADMIN_PASSWORD)
    page.get_by_label("Password again").fill(ADMIN_PASSWORD)
    page.get_by_role("button", name="Create admin and continue").click()

    expect(page.locator(".error")).to_contain_text("That setup code is not right.")
    expect(page).to_have_url(re.compile(r"/admin/setup/admin$"))


def test_a_wrong_u2_password_shows_the_driver_text(page: Page, server: Server) -> None:
    create_admin(page, server)
    fill_connection(page, password=sim_driver.WRONG_PASSWORD)

    page.get_by_role("button", name="Test connection").click()

    expect(page.locator("#test-result")).to_contain_text(
        "Test failed: Failed to connect to u2.example: Login refused: wrong user name or password"
    )


def test_an_unreachable_host_shows_the_driver_text(page: Page, server: Server) -> None:
    create_admin(page, server)
    fill_connection(page, host=sim_driver.UNREACHABLE_HOST)

    page.get_by_role("button", name="Test connection").click()

    expect(page.locator("#test-result")).to_contain_text(
        "Cannot reach unreachable.invalid:31438: connection refused"
    )


def test_testing_needs_the_fields_first(page: Page, server: Server) -> None:
    create_admin(page, server)
    page.get_by_label("Host").fill("")

    page.get_by_role("button", name="Test connection").click()

    expect(page.locator("#test-result")).to_contain_text(
        "Enter the U2 server's host name or address."
    )


def test_finishing_twice_is_harmless(page: Page, server: Server) -> None:
    finish_wizard(page, server)

    page.goto(server.url("/admin/setup/done"))

    expect(page).to_have_url(re.compile(r"/admin/connections$"))
```

If `test_testing_needs_the_fields_first` finds the Host box is filled from the environment, that is expected only when `U2_HOST` is set; `launch_server` removes every `U2_*` variable, so the box starts empty and the fill is a no-op. Keep the test: it proves the htmx path reports validation problems.

- [ ] **Step 4: Write the Connections tests**

`tests/e2e/test_connections_pages.py`:

```python
"""The Connections pages in a real browser."""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import Browser, Page, expect

from .conftest import Server
from .wizard import fill_connection, finish_wizard, sign_in

pytestmark = pytest.mark.e2e

STALE = (
    "Someone else changed this connection since you opened it. Reload to see their changes."
)


def test_two_admins_editing_the_same_connection(
    page: Page, browser: Browser, server: Server
) -> None:
    finish_wizard(page, server)
    page.get_by_role("link", name="Prod").click()
    edit_url = page.url

    other = browser.new_context().new_page()
    sign_in(other, server)
    other.goto(edit_url)

    page.get_by_label("Host").fill("first.example")
    page.get_by_role("button", name="Save", exact=True).click()
    expect(page.locator(".notice")).to_have_text("Saved.")

    other.get_by_label("Host").fill("second.example")
    other.get_by_role("button", name="Save", exact=True).click()
    expect(other.locator(".alert")).to_contain_text(STALE)

    other.goto(edit_url)
    expect(other.get_by_label("Host")).to_have_value("first.example")


def test_add_test_switch_and_delete_a_connection(page: Page, server: Server) -> None:
    finish_wizard(page, server)

    page.get_by_role("link", name="Add a connection").click()
    fill_connection(page, name="Test", host="test.example", account="TEST")
    page.get_by_role("button", name="Test connection").click()
    expect(page.locator("#test-result")).to_contain_text("Test passed")
    page.get_by_role("button", name="Add connection").click()
    expect(page.locator(".notice")).to_have_text("Saved.")

    page.get_by_role("button", name="Allow writes").click()
    expect(page.get_by_role("button", name="Make read-only")).to_be_visible()

    page.get_by_role("link", name="Delete this connection…").click()
    page.get_by_role("button", name="Delete Test").click()
    expect(page.locator(".notice")).to_have_text("Deleted.")
    expect(page.get_by_role("link", name="Test")).to_have_count(0)
    expect(page.get_by_role("link", name="Prod")).to_be_visible()


def test_sign_out_and_back_in(page: Page, server: Server) -> None:
    finish_wizard(page, server)

    page.get_by_role("button", name="Sign out").click()
    expect(page.locator(".notice")).to_have_text("You are signed out.")
    page.goto(server.url("/admin/connections"))
    expect(page).to_have_url(re.compile(r"/admin/sign-in\?next=/admin/connections$"))

    page.get_by_label("Username").fill("admin")
    page.get_by_label("Password").fill("a long admin passphrase")
    page.get_by_role("button", name="Sign in").click()
    expect(page).to_have_url(re.compile(r"/admin/connections$"))


def test_a_wrong_password_on_sign_in(page: Page, server: Server) -> None:
    finish_wizard(page, server)
    page.get_by_role("button", name="Sign out").click()

    page.get_by_label("Username").fill("admin")
    page.get_by_label("Password").fill("not the password")
    page.get_by_role("button", name="Sign in").click()

    expect(page.locator(".alert")).to_have_text("Wrong username or password.")
```

- [ ] **Step 5: Run the browser suite**

Run: `pytest -m e2e tests/e2e -v`
Expected: all PASS. On failure, read `server.log` in the test's temporary directory (pytest prints the path), fix the product code (not the test's expectations, unless the plan's exact strings say otherwise), and re-run.

Run: `pytest -q`
Expected: the e2e tests are deselected; everything else passes.

- [ ] **Step 6: Commit**

```bash
git add tests/e2e
git commit -m "test: browser tests for the setup wizard and Connections pages"
```

---

### Task 12: CI, documentation and the roadmap

**Files:**
- Modify: `.github/workflows/ci.yml`, `docs/configuration.md`, `CHANGELOG.md`, `CLAUDE.md`, `docs/superpowers/plans/2026-10-30-admin-ui-roadmap.md`

**Interfaces:** none (documentation and CI only).

- [ ] **Step 1: Add the browser job to CI**

In `.github/workflows/ci.yml`, add a job after `test`:

```yaml
  # Browser tests: the setup wizard and admin pages, driven by Chromium against a
  # real server process and a scripted U2 driver. A missing browser is an error
  # here, never a skip.
  e2e:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install dependencies and Chromium
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[dev]"
          python -m playwright install --with-deps chromium

      - name: Browser tests
        run: pytest -m e2e tests/e2e --browser chromium

      - name: Keep server logs when they fail
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: e2e-server-logs
          path: /tmp/pytest-of-*/**/server.log
          if-no-files-found: ignore
```

Also, in the `test` job, after "Run tests", add a wheel check so templates cannot silently go missing from a release:

```yaml
      - name: Check the admin site ships in the wheel
        if: matrix.python-version == '3.12'
        run: |
          pip wheel . --no-deps -w dist -q
          python -c "import zipfile,glob,sys; n=zipfile.ZipFile(glob.glob('dist/u2_mcp-*.whl')[0]).namelist(); need=['u2_mcp/admin/templates/base.html','u2_mcp/admin/static/htmx.min.js']; missing=[x for x in need if x not in n]; sys.exit(f'missing from wheel: {missing}' if missing else 0)"
```

- [ ] **Step 2: Document the admin site**

In `docs/configuration.md`, in the "Team mode" section, add a subsection:

```markdown
### Admin site and first-time setup

In team mode the server also serves an admin site at `/admin` on the same port.

1. Start the server with `U2_SECRET_KEY` and `U2_DATA_DIR` set. `U2_HOST`,
   `U2_USER`, `U2_PASSWORD` and `U2_ACCOUNT` are optional in team mode: when set,
   they become the first connection (and pre-fill the wizard); when not, the wizard
   asks for it.
2. The server log shows a setup code while setup is unfinished. You can also print
   it on the server: `u2-mcp admin show-setup-code` (in Docker:
   `docker exec <container> u2-mcp admin show-setup-code`).
3. Open `<server address>/admin/` and follow the wizard: the first local admin, the
   first connection (with a Test button that runs `COUNT VOC`), and the server
   address. Every step saves as you go, so you can close the browser and resume.

| Setting | Meaning |
|---|---|
| `U2_ADMIN_ALLOWED_IPS` | Optional. Comma-separated addresses or CIDR networks allowed to reach `/admin`. Other addresses get 403. |

If every admin is locked out, run `u2-mcp admin reset-password <username>` on the
server. It prints a one-time password, ends that user's sessions, and requires a
new password at the next sign-in.

The address saved on the Settings page takes effect at once for sign-in cookies
and the Copilot configuration shown in the UI. OAuth sign-in and personal access
tokens read it at start-up, so restart the server after changing it.
```

- [ ] **Step 3: CHANGELOG, CLAUDE.md and the roadmap**

In `CHANGELOG.md` under `## [Unreleased]`, add to `### Added`:

```markdown
- Admin site at `/admin` (team mode): local admin sign-in, a resumable setup wizard (admin account, first connection with Test, server address), Connections pages (add, edit, test, read-only and enabled switches, live sessions, disconnect, delete) and a Settings page for the server address.
- `u2-mcp admin show-setup-code` and `u2-mcp admin reset-password <user>`.
- `/health` endpoint on the HTTP transports.
- `U2_ADMIN_ALLOWED_IPS` to restrict `/admin` by address.
```

and to `### Changed` (create it if absent):

```markdown
- In team mode `U2_HOST`, `U2_USER`, `U2_PASSWORD` and `U2_ACCOUNT` are optional; connections can be added in the admin site.
- Editing, switching off or deleting a connection closes its live sessions; deleting it also removes its knowledge notes.
```

In `CLAUDE.md`, add to the module layout tree, under `src/u2_mcp/`:

```
├── admin/              # Admin site at /admin (team mode): Starlette + Jinja2 + vendored htmx
│   ├── app.py          # build_admin_app; routes_*.py hold the pages
│   ├── services.py     # Every admin change (wizard and everyday pages share these)
│   └── security.py     # Sessions, CSRF, sign-in rate limit, U2_ADMIN_ALLOWED_IPS
├── cli.py              # u2-mcp admin show-setup-code / reset-password
├── connection_check.py # The Test button: connect + COUNT VOC within 10 s
├── passwords.py        # argon2id
└── setup_code.py       # Setup wizard state and the one-time setup code
```

change the Environment Variables line "Required: `U2_HOST`, `U2_USER`, `U2_PASSWORD`, `U2_ACCOUNT`" to "Required outside team mode: `U2_HOST`, `U2_USER`, `U2_PASSWORD`, `U2_ACCOUNT` (in team mode, with `U2_SECRET_KEY` set, connections are added in the admin site)",

and to the Testing section: "Browser tests live in `tests/e2e` (Playwright). Run `python -m playwright install chromium` once, then `pytest -m e2e tests/e2e`. Plain `pytest` skips them."

In `docs/superpowers/plans/2026-10-30-admin-ui-roadmap.md`, replace the phase 2 row with two rows:

```markdown
| 2a. Setup and connections | `2026-10-30-admin-ui-phase2a-setup-and-connections.md` | Local sign-in, database sessions, CSRF, sign-in rate limits, the address allowlist, the setup wizard (admin, connection, server address, done), the Connections pages, the Settings page's server address, `u2-mcp admin reset-password` and `show-setup-code`, and Playwright tests against a real server process. | Yes. |
| 2b. Everyday pages | `2026-10-30-admin-ui-phase2b-everyday-pages.md` (written after 2a lands) | Dashboard, Users (with effective access), Groups, Roles, grants editor, Audit with CSV export, the rest of Settings (token policy, local accounts), My access with tokens and Copilot configuration, and the remaining browser tests. | Yes. |
```

and change phase 3's description to also say: "the setup wizard's SSO step, and running the browser suite against the Docker image (`launch_server` in `tests/e2e/conftest.py`)". Add one line under the table: "Phase 3 also handles trusted reverse-proxy headers, so the sign-in rate limit and `U2_ADMIN_ALLOWED_IPS` see the real client address behind a proxy."

- [ ] **Step 4: Final verification and commit**

Run: `pytest -q && pytest -m e2e tests/e2e -q && ruff check . && ruff format --check . && mypy src/ && bandit -r src/ --severity-level medium --confidence-level medium -q`
Expected: everything passes, clean.

```bash
git add .github/workflows/ci.yml docs/configuration.md CHANGELOG.md CLAUDE.md docs/superpowers/plans/2026-10-30-admin-ui-roadmap.md
git commit -m "docs: admin site setup, CLI and CI browser job; roadmap splits phase 2"
```

---

## Phase 2b and 3 follow-ups recorded by this plan

- Phase 2b: Users page must call `store.set_user_disabled` (which now ends sessions) and use `create_local_user`; Roles use the `version` column added here; `local_accounts_enabled` gets its Settings toggle; non-admin users get My access; grants and tokens (until then a connection created in the wizard has no grants, so nobody can use it from Copilot, and the Done page says so); per-connection watchdog health on the dashboard (phase 1 follow-up: the watchdog checks only live slots, not each connection).- Phase 3: insert the `sso` wizard step between `server_address` and `done` (steps are stored by name); trusted proxy headers for `client_ip`; `launch_server` runs the Docker image; reject an empty subject in `exchange_authorization_code` (phase 1 follow-up).

