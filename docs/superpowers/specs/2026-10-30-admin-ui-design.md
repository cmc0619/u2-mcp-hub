# Admin UI, multi-connection access control, and team sign-in

Date: 2026-10-30
Status: Approved design, awaiting spec review
Scope: Project 1 of 2. Project 2 (BASIC tools) builds on the permissions defined here and gets its own spec.

## Goal

Turn u2-mcp from a single-operator server into a team server that:

- serves several U2 connections (for example Prod, Test, Training) from one container;
- controls, per connection, which people and SSO groups can use it and with which granular permissions;
- is set up and administered through a web UI whose setup wizard demonstrably works;
- is used mainly from GitHub Copilot (VS Code first, other editors through personal access tokens).

## Non-goals

- Per-file allow/deny inside a connection. Finer limits come from the U2 login each connection uses.
- A JavaScript single-page app or a front-end build step.
- Running the admin UI as a separate service.
- BASIC tools (project 2). Their permission names are reserved here so project 2 adds no schema change.

## Decisions taken during design

| Question | Decision |
|---|---|
| Sign-in | Company SSO (OIDC, Duo or Auth0, via the existing `auth/idp` adapters) plus local accounts. Setup creates one local break-glass admin. Local accounts can be disabled by one setting. |
| Clients | GitHub Copilot, almost exclusively. VS Code uses the OAuth browser flow. Other editors use personal access tokens. |
| Hosting | Docker on an internal server that can reach the U2 hosts. |
| Granularity | Grants give a role on a connection to a user or an SSO group. Roles are sets of granular permissions. |
| SSO groups | Supported from day one. |
| Architecture | Admin UI built into the u2-mcp process (approach A). |

## Architecture

```
 Copilot (VS Code) ──►  /mcp   ─┐
                                ├─►  access.py ──► ConnectionRegistry ──► U2 Prod
 Browser (admins)  ──►  /admin ─┘                  (key: connection +     U2 Test
                         │                          U2 login)             U2 Training
                         ▼
                   Settings DB (SQLite on the /data volume)
```

One process serves the MCP Streamable HTTP endpoint at `/` and the admin site at `/admin`. The MCP endpoint stays at `/`, where it is today, so connectors configured against the current server keep working. Both read the settings database, and both decide permissions through the same function in `access.py`.

The stdio transport keeps working for a single local operator. In stdio mode there is no admin UI. Behaviour is unchanged, and the caller has full rights within the environment-variable connection, subject to `U2_READ_ONLY` and the blocked-command list.

### New modules

| Module | Responsibility | Depends on |
|---|---|---|
| `store/` | SQLite schema, versioned migrations, repositories for each table, encryption of stored secrets | `cryptography` (Fernet), `U2_SECRET_KEY` |
| `access.py` | `decide(caller, connection_id, permission) -> Decision` and `effective_access(user) -> report`. Pure function over data loaded from `store`. | `store`, `identity` |
| `tokens.py` | Create, hash (SHA-256 of a 256-bit random token), verify and revoke personal access tokens. Applies the SSO freshness rule. | `store` |
| `admin/` | Starlette routes, Jinja2 templates, htmx, sessions, CSRF, rate limiting, setup wizard | `store`, `access`, `tokens`, `registry` |
| `cli.py` additions | `u2-mcp admin reset-password <user>` and `u2-mcp admin show-setup-code` | `store` |

### Changed modules

- `registry.py`: managers are keyed by `(connection_id, u2_login)` instead of the login alone. Credentials come from the connection record (shared login) or the grant's per-user login.
- `credentials.py`: `MappedCredentialResolver`'s JSON file is replaced by per-user U2 logins stored on grants. The `shared` resolver reads the connection record. The JSON file is imported once on first start if `U2_CREDENTIAL_MAP_PATH` is set.
- `identity.py`: `CallerIdentity` gains `user_id` (settings-database id) and `auth_method` (`oauth`, `token`, `local`, `stdio`). Group membership is read from the settings database at decision time, not carried on the identity.
- `auth/provider.py`: gains an `on_sign_in` hook, called once per completed IdP sign-in with the IdP's user info. Token refreshes are not sign-ins. Team mode uses the hook to create or update the user, record `last_sso_login_at` and replace group membership.
- `server.py`: mounts `/admin`. Accepts `Authorization: Bearer u2pat_…` alongside OAuth access tokens.
- `tools/*`: every tool except `list_connections` takes an optional `connection: str` argument. When it is omitted and the caller can see exactly one connection, that connection is used. Otherwise the tool returns an error that lists the caller's connections.
- `list_connections` changes meaning: it returns the connections this caller can see, with the caller's role and effective permissions on each. Today's named-session listing moves to `list_sessions`.
- `config.py`: unchanged settings keep working. New settings: `U2_SECRET_KEY` (setting it turns on team mode, which means the settings database, access control and tokens, in the HTTP transports; without it the HTTP transports behave as they do today), `U2_DATA_DIR` (default `/data`), `U2_PUBLIC_URL`, `U2_SSO_GROUPS_CLAIM` (default `groups`), `U2_ADMIN_ALLOWED_IPS` (optional), and `U2_TLS_CERT`/`U2_TLS_KEY` (optional). SSO settings entered in the UI take precedence over the existing `U2_IDP_*` variables, which seed them on first start.

### First-start migration

When the settings database is empty and `U2_HOST` and the related settings are present, those settings become a connection named `default`. The import reproduces what today's server allows:

- **Shared mode** (`U2_IDENTITY_MODE=shared`): the connection uses the shared login, and one grant with subject `everyone` gives every authenticated user the `Imported access` role on it. This custom, editable role holds Developer's permissions minus every `basic.*` permission: exactly what today's tools can do. It is not Developer, so that grants nobody chose do not gain BASIC compile rights when project 2 lands. The global `U2_READ_ONLY` keeps capping every connection, this one included, and the imported connection's own `read_only` switch starts off, so changing `U2_READ_ONLY` later still takes effect. Today's behaviour is that every authenticated caller has full access subject to `U2_READ_ONLY`, so this grant is no wider than what exists now. The grant is logged at startup and shown as a warning on the admin dashboard until an admin removes it.
- **Mapped mode** (`U2_IDENTITY_MODE=mapped`): the connection is `per_user`. Each entry in the credential map becomes an SSO user record (keyed by its subject) with an `Imported access` user grant that carries that entry's U2 login. Nobody outside the map gets access. This matches today, where unmapped callers are refused.

Existing single-server deployments keep working without visiting the UI.

The `grants.subject_type` column therefore accepts `user`, `group` or `everyone`. An `everyone` grant applies to every authenticated user who is not disabled. Admins can create one in the UI too, which is labelled with a warning.

Stdio mode and the legacy unauthenticated SSE mode do not use the settings database. The caller is the local operator, and the only connection is `default` from environment variables.

## Data model

| Table | Key columns |
|---|---|
| `connections` | id, name (unique, shown to users), host, port, service (`uvcs`/`udcs`), account, ssl, login_mode (`shared`/`per_user`), shared_user, shared_password_enc, read_only (bool), enabled, created/updated by and at |
| `users` | id, kind (`sso`/`local`), username (unique; required when kind = local), sso_subject (unique; required when kind = sso), email, display_name, password_hash (argon2id, local only), is_admin, disabled, last_sso_login_at, groups_unavailable (bool), created_at |
| `groups` | id, external_id (the claim value), label (admin-editable), first_seen_at, last_seen_at |
| `user_groups` | user_id, group_id, recorded_at (replaced in full at each SSO sign-in) |
| `roles` | id, name, builtin (bool), permissions (JSON list of permission names) |
| `grants` | id, connection_id, subject_type (`user`/`group`/`everyone`), subject_id (null for `everyone`), role_id, per_user_u2_user, per_user_u2_password_enc (user grants on `per_user` connections only) |
| `tokens` | id, user_id, name, token_hash, created_at, expires_at, last_used_at, last_used_ip, revoked_at |
| `audit` | id, at, actor_user_id, actor_label, kind (`tool`/`admin`/`auth`), connection_id, action, params (JSON, secrets redacted), outcome, duration_ms |
| `settings` | key, value (SSO configuration with an encrypted client secret, token policy, local accounts on/off, setup state) |
| `schema_version` | version |

Secrets (U2 passwords, the SSO client secret) are encrypted with Fernet using a key derived from `U2_SECRET_KEY`. A copied database file without that key does not reveal them.

The existing JSONL audit files remain available as an optional extra sink. The `audit` table is the source the UI reads.

## Permissions and roles

| Permission | Tools |
|---|---|
| `schema.read` | `list_files`, `get_file_info`, `list_dictionary`, `get_field_definition`, `describe_file`, `analyze_file_structure`, `get_account_info` |
| `records.read` | `read_record`, `read_records`, `export_to_json`, `export_to_csv` |
| `query.run` | `execute_query`, `get_select_list`, `validate_query` |
| `records.write` | `write_record`, `update_value`, `begin_transaction`, `commit_transaction`, `rollback_transaction` |
| `records.delete` | `delete_record` |
| `tcl.run` | `execute_tcl` (the blocked-command list still applies) |
| `subroutine.call` | `call_subroutine`. `list_catalog` is under `schema.read`: it lists the catalog with the read-only `MAP` verb, never `CATALOG` |
| `basic.read`, `basic.write`, `basic.compile`, `basic.catalog` | Reserved for project 2 |

Every tool belongs to exactly one permission. A test enforces this. `connect`, `disconnect`, `list_sessions`, `get_transaction_status` and `watchdog_status` need any grant on the connection. `list_connections` needs only authentication.

The knowledge tools need any grant on the selected connection, including
read-only connections, with two exceptions: `delete_knowledge`, and replacing an
existing topic with `save_knowledge`, need an admin (`ADMIN_ONLY`), because notes
are shared by everyone on the database. Notes are shared by normalized database
server/account, independent of connection names or logins.

Write permissions are `records.write`, `records.delete`, `tcl.run`, `subroutine.call`, `basic.write`, `basic.compile` and `basic.catalog`. These are refused when the connection's `read_only` switch or the global `U2_READ_ONLY` is on.

Built-in roles cannot be edited. Admins clone them to make custom roles.

| Role | Permissions |
|---|---|
| Viewer | `schema.read`, `records.read`, `query.run` |
| Analyst | Same as Viewer (retained for existing grants) |
| Developer | Analyst + `records.write`, `records.delete`, `tcl.run`, `subroutine.call`, `basic.read`, `basic.write`, `basic.compile` |
| Owner | Developer + `basic.catalog` |

## Access decision

`access.decide(caller, connection_id, permission)`:

1. If the caller is disabled, refuse with "account disabled".
2. If the connection does not exist, is disabled, or the caller has no grant on it (directly or through a group), refuse with "unknown connection". This text is identical in all three cases, so connection names do not leak.
3. Take the union of permissions from the caller's user grant, from grants to each of the caller's groups, and from any `everyone` grant on the connection.
4. If the permission is not in the union, refuse with "you need `<permission>` on `<connection>`; ask an admin".
5. If the permission is a write permission and the connection's `read_only` or the global `U2_READ_ONLY` is on, refuse with "`<connection>` is read-only".
6. Otherwise allow.

`is_admin` grants admin-site access only. It grants no data access.

The decision is made on every tool call from current data. Changes to roles, grants, groups or users take effect on the next call.

### U2 login for a call

- A `shared` connection uses the connection's login.
- A `per_user` connection uses the per-user login on the caller's own user grant. A caller who reaches a `per_user` connection only through a group grant, with no personal U2 login recorded, is refused with "no U2 login set for you on `<connection>`; ask an admin". There is no fallback to a shared login.

## Sign-in

### SSO users

- The admin site signs users in through the configured IdP, reusing the `auth/idp` adapters.
- MCP clients sign in through the existing OAuth flow, which already bridges to the same IdP.
- At each SSO sign-in the user record is created if missing (no grants, so no access), and `last_sso_login_at` is set. Group membership is replaced from the configured claim (`U2_SSO_GROUPS_CLAIM`, default `groups`). Unseen groups are added to `groups`.
- If the IdP signals a group overage (Entra's `_claim_names`/`hasgroups`), `groups_unavailable` is set. The UI flags the user, and group grants do not apply to them until a later sign-in carries groups. The docs explain how to configure Entra to emit only the groups assigned to the application.

### Local accounts

- Passwords are hashed with argon2id.
- Setup creates the first local admin.
- When `local_accounts_enabled` is off, only local admins can sign in locally. This keeps break-glass access.

### Personal access tokens

- Format: `u2pat_` + 43 characters of url-safe base64. Only the SHA-256 hash is stored, and the token is shown once.
- Default lifetime is 90 days. Admins set a maximum.
- A token belonging to an SSO user is accepted only if that user has signed in through SSO within `token_sso_freshness_days` (default 30). Otherwise the call is refused with "sign in to the admin site to reactivate your tokens". Tokens belonging to local users are exempt.
- `last_used_at` and `last_used_ip` are updated at most once a minute per token.

### Admin site security

- The session cookie is `Secure` when `U2_PUBLIC_URL` is https, and always `HttpOnly` and `SameSite=Lax`.
- Sessions last 8 hours, with a 30-minute idle timeout.
- Every state-changing form carries a CSRF token.
- Sign-in attempts are limited to 5 per minute per IP and per username.
- An optional `U2_ADMIN_ALLOWED_IPS` allowlist covers `/admin`.
- All admin changes are written to `audit` with `kind = admin`.

## Admin site

### Setup wizard

Rules:

1. Every wizard step renders and submits the same form component, and calls the same save function, as the matching everyday settings page. The wizard holds no separate logic.
2. Every step saves to the database on submit. `setup_state` records the furthest completed step. Refresh, Back and reopening the browser resume correctly.
3. Test buttons perform the real action and show the underlying error text:
   - Test connection opens a session and runs `COUNT VOC` with a 10-second limit.
   - Test SSO completes a real sign-in round trip in a pop-up.
4. Until setup is finished, `/admin/setup` requires a one-time setup code. The code is written to the container log at startup and is also available from `u2-mcp admin show-setup-code`. After setup, `/admin/setup` redirects to the dashboard.

Steps:

1. **Admin account**: setup code, then the local admin's username and password.
2. **First connection**: the connection form, pre-filled from environment variables if present, with Test.
3. **Server address**: `U2_PUBLIC_URL`, with a warning if it is not https.
4. **SSO** (skippable): provider, discovery URL, client id, client secret and group claim, with Test sign-in.
5. **Done**: a checklist of configured and skipped items, plus the Copilot configuration.

### Everyday pages

- **Dashboard**: health of each connection, active sessions, and the last 20 audit entries.
- **Connections**: list, add, edit and test. Also the `read_only` and `enabled` switches, live sessions, and a Disconnect button.
- **Users**: list with filters, create a local user, admin flag, disable, view and revoke tokens, and grants. Each user has an **Effective access** view that shows, for every connection, the effective permissions and which grant or group supplied each one.
- **Groups**: groups seen at sign-in, editable labels, and grants.
- **Roles**: built-in roles (read-only), and clone, edit and delete for custom roles. A role in use cannot be deleted.
- **Audit**: filter by user, connection, kind, action and date range, with CSV export.
- **Settings**: SSO, token policy, local accounts on/off, and the setup checklist.
- **My access** (every signed-in user): my connections with role and permissions, my tokens (create and revoke), and copy-ready configuration for VS Code (OAuth and token variants) and Visual Studio or JetBrains (token).

The pages are server-rendered with Jinja2. htmx handles partial updates such as test results and table filters. The UI works without JavaScript except for those partial updates.

## Error handling

- Tool refusals use the messages defined in the access-decision section. They name the missing permission so that Copilot can relay it.
- A U2 connection failure names the connection and includes the driver's error text. The dashboard marks the connection unhealthy, and the existing watchdog handles reconnection.
- A database migration first copies the settings database (`/data/u2-mcp.db`) to `/data/u2-mcp.db.bak-<version>-<timestamp>`. The process refuses to start if a migration fails, and leaves the backup in place.
- If `U2_SECRET_KEY` is missing, the HTTP transports run without team mode, exactly as today. If a settings database exists in `U2_DATA_DIR` but `U2_SECRET_KEY` is missing, the process refuses to start, so that team mode cannot be switched off by accident. If the key is wrong, the encrypted fields cannot be decrypted. The UI then marks the affected connections and SSO settings "secret unreadable, re-enter", and everything else keeps working.
- For admin lockout, `u2-mcp admin reset-password <user>` prints a one-time password and requires a change at next sign-in.

## Deployment

- A `Dockerfile` (non-root user) and `docker-compose.yml` are added to the repository. The compose file sets a `/data` volume, the required environment variables, a health check on `/health`, and port 8000.
- HTTPS is terminated by a reverse proxy. Example Caddy and nginx configurations are included. Alternatively, certificate files are mounted and `U2_TLS_CERT`/`U2_TLS_KEY` are set.
- `docs/admin.md` covers deployment, SSO setup for Entra, Okta and Google, the Entra groups-claim configuration, the GitHub Copilot org policy that allows MCP servers, and backing up `/data` and `U2_SECRET_KEY`.

## Testing

All the following run in CI except the last item.

1. **Access decision**: table-driven tests over role, connection read-only, global read-only, user grant, group grants, disabled user, disabled connection, missing connection, `per_user` connection without a login, and group overage.
2. **Tool coverage**: every registered tool maps to exactly one permission, refuses without it, and returns the identical "unknown connection" error for a hidden or nonexistent connection.
3. **Registry**: sessions are isolated per `(connection, login)`, eviction works, and two users on one `per_user` connection never share a session.
4. **Tokens**: hashing, expiry, revocation, the freshness rule, and last-used throttling.
5. **Store**: migrations from an empty database and from each prior version, the backup is created before migrating, and encrypted fields round-trip.
6. **Browser end-to-end (Playwright, against the built Docker image)**:
   - the full wizard from an empty `/data`;
   - refresh and Back at every wizard step;
   - wrong U2 password, unreachable host and bad SSO settings, each asserting the error text;
   - two admins editing the same record;
   - every everyday page's main path;
   - creating a token and using it from an MCP client.

   The U2 server in these tests is the existing simulated driver in `tests/mocks/mock_uopy.py`, selected through `U2_DRIVER`. The image used for these tests includes that module. The release image does not.
7. **SSO end-to-end**: a containerised OIDC test provider issues tokens with group claims. Tests cover sign-in, group refresh, group grants, overage handling and the 30-day freshness rule.
8. **Manual acceptance against real U2**: a checklist using `scripts/try-it-here.py` against a real UniVerse or UniData server. This runs before each release, because Rocket U2 cannot run in CI.
