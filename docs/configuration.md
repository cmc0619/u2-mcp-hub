# Configuration Reference

u2-mcp runs in one of two ways, and both are configured with environment variables:

- **`u2-mcp`** (stdio): one person, one U2 login from `U2_HOST`, `U2_USER`,
  `U2_PASSWORD` and `U2_ACCOUNT`, launched by a desktop client. It refuses to start
  if any of those four is missing. There is no admin site, no OAuth and no audit
  trail beyond ordinary logging.
- **`u2-mcp --streamable-http`**: team mode. `U2_SECRET_KEY` is required; without it
  the server refuses to start. Connections, logins, company sign-in, roles and grants
  live in the admin site at `/admin` and its settings database in `U2_DATA_DIR`.

## U2 login (stdio)

| Variable | Description | Example |
|----------|-------------|---------|
| `U2_HOST` | Universe/UniData server hostname or IP | `server.example.com` |
| `U2_USER` | Username | `myuser` |
| `U2_PASSWORD` | Password | `mypassword` |
| `U2_ACCOUNT` | Account name | `PRODUCTION` |

Team mode ignores these: connections are added in the admin site.

## Connection settings (stdio)

| Variable | Description | Default |
|----------|-------------|---------|
| `U2_SERVICE` | `uvcs` (Universe) or `udcs` (UniData) | `uvcs` |
| `U2_PORT` | Server port | `31438` |
| `U2_SSL` | Enable SSL/TLS | `false` |
| `U2_TIMEOUT` | Connection timeout in seconds | `30` |

## Safety settings (both modes)

| Variable | Description | Default |
|----------|-------------|---------|
| `U2_READ_ONLY` | Refuse writes to U2. In team mode it caps every connection. Knowledge notes are still saved | `true` |
| `U2_MAX_RECORDS` | Maximum records returned by SELECT/LIST | `10000` |
| `U2_QUERY_TIMEOUT` | Seconds a query may run before it is stopped | `60` |
| `U2_BLOCKED_COMMANDS` | Comma-separated TCL commands to block | `DELETE.FILE,CLEAR.FILE,CNAME,CREATE.FILE` |
| `U2_BASIC_FILES` | Comma-separated glob patterns naming the files the BASIC tools may use | `*BP,BP.*` |

## Knowledge notes

What the assistant learns is kept per system, in SQLite:

- **Team mode:** in the settings database, per connection. Deleting a connection
  deletes its notes.
- **stdio:** in `~/.u2-mcp/u2-mcp.db`, per `host@account`.

Topic names match exactly, ignoring case and extra whitespace.

## Team mode settings

| Variable | Default | Purpose |
|---|---|---|
| `U2_SECRET_KEY` | (unset) | Required. Encrypts stored secrets. At least 32 characters. Keep a copy in your vault: without it, stored U2 passwords cannot be read. A blank value counts as unset. |
| `U2_DATA_DIR` | `/data` | Holds the settings database `u2-mcp.db` (with its `-wal` and `-shm` files). See [admin.md](admin.md#5-backups). |
| `U2_PUBLIC_URL` | (unset) | The URL people use to reach the server. The address saved on the admin site overrides it. |
| `U2_HTTP_HOST` | `127.0.0.1` | Address to bind. Use `0.0.0.0` in a container (the image does). |
| `U2_HTTP_PORT` | `8080` | Port (the image uses `8000`). `--host` and `--port` override both. |
| `U2_HTTP_CORS_ORIGINS` | (empty) | Comma-separated browser origins allowed to connect. Empty blocks cross-origin browser access; MCP clients are unaffected. `*` is refused. |
| `U2_MAX_CONNECTIONS` | `25` | Most U2 sessions held open at once. |
| `U2_TOKEN_FRESHNESS_DAYS` | `30` | An SSO user's tokens pause after this many days without an SSO sign-in. |
| `U2_ADMIN_ALLOWED_IPS` | (unset) | Addresses or CIDR networks allowed to reach `/admin`. Others get 403. |
| `U2_ADMIN_SIGNIN_LIMIT` | `5` | Attempts allowed per minute: password sign-in (per address and per username), starting company sign-in (20 times the limit per address) and testing or saving your own U2 login on My access (per person). `0` turns these off and logs a warning: development only. |
| `U2_TRUSTED_PROXIES` | (unset) | Addresses or CIDR networks of reverse proxies whose `X-Forwarded-For` and `X-Forwarded-Proto` are believed. See [admin.md](admin.md#4-behind-a-reverse-proxy-https). |
| `U2_TLS_CERT`, `U2_TLS_KEY` | (unset) | Certificate and key files (PEM) to serve https without a proxy. Set both or neither. |
| `U2_TOKEN_EXPIRY_SECONDS` | `3600` | Lifetime of access tokens issued to MCP clients through company sign-in. |
| `U2_REFRESH_TOKEN_EXPIRY_SECONDS` | `2592000` | Lifetime of their refresh tokens (30 days). |

## Examples

### Claude Desktop (stdio)

```json
{
  "mcpServers": {
    "u2-mcp": {
      "command": "u2-mcp",
      "env": {
        "U2_HOST": "universe.example.com",
        "U2_USER": "myuser",
        "U2_PASSWORD": "mypassword",
        "U2_ACCOUNT": "MYACCOUNT",
        "U2_SERVICE": "uvcs",
        "U2_READ_ONLY": "true",
        "U2_MAX_RECORDS": "5000",
        "U2_BLOCKED_COMMANDS": "DELETE.FILE,CLEAR.FILE,CNAME,CREATE.FILE,ED"
      }
    }
  }
}
```

For UniData set `U2_SERVICE=udcs`; for SSL set `U2_SSL=true` and the SSL port.

### Team mode

```bash
export U2_SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
export U2_DATA_DIR=/var/lib/u2-mcp
export U2_HTTP_HOST=0.0.0.0
u2-mcp --streamable-http
```

## Team mode: the admin site

The server serves an admin site at `/admin` on the same port.

1. Start the server with `U2_SECRET_KEY` set.
2. The log shows a setup code while setup is unfinished. You can also print it:
   `u2-mcp admin show-setup-code` (in Docker:
   `docker exec <container> u2-mcp admin show-setup-code`).
3. Open `<server address>/admin/` and follow the wizard: the first local admin, the
   first connection (with a Test button that runs `COUNT VOC`), the server address
   and, optionally, company sign-in. Every step saves as you go.

If every admin is locked out, run `u2-mcp admin reset-password <username>` on the
server. It prints a one-time password, re-enables the user, ends their sessions,
and requires a new password at the next sign-in. Add `--admin` to also make the
user an admin.

The server address saved in the wizard or on the Settings page overrides
`U2_PUBLIC_URL`. It takes effect at once for sign-in cookies (`Secure` when the
address is https) and the configuration shown on My access. Restart after changing
the address or company sign-in: MCP client sign-in and personal access tokens pick
them up at startup.

Saving an https address while you reach the admin site over plain http asks you
to confirm first: the browser drops `Secure` cookies over http. If that locks you
out, fix the address on the server:

```bash
u2-mcp admin set-public-url http://10.0.0.5:8080   # or the address that works now
u2-mcp admin set-public-url --clear                 # back to U2_PUBLIC_URL
```

Both are audited as `settings.public_url` by "command line".

How the admin site behaves:

- Forms shown after sign-in accept only that session's CSRF token. Signing in
  replaces the browser's previous session.
- A blank password box keeps the saved U2 password (or, in the wizard, uses
  `U2_PASSWORD`) only while host, port, service, SSL and account are unchanged.
- Editing a connection, changing its read-only or enabled switch, or deleting it
  closes that connection's live sessions. Database knowledge notes are kept when
  a connection is deleted.
- Admin pages are never cached by the browser (`Cache-Control: no-store`).
- Every tool call, including refusals and `list_connections`, is recorded in the
  settings database's audit table and shown on the **Audit** page. BASIC program
  source is recorded as its size and hash, and parameters with secret-like names
  are redacted.

### Choosing a connection

Every tool except `list_connections` takes an optional `connection` argument.
`list_connections` shows the connections you can use and your permissions on each.
If you can use only one, `connection` can be left out.

### Everyday admin pages

Admins land on Connections after sign-in; people who are not admins land on
My access.

- **Connections**: plus **Access**, the grants editor. On a per-person
  connection, Access also lists everyone who can use it and whether their own U2
  login is set.
- **Users**: create local users, admin and disabled flags (you cannot demote or
  disable yourself, or the last enabled local admin), tokens, grants, and
  **Effective access**. A person's page also edits their name and email, resets a
  local user's password and deletes them. For an SSO person, disable them to keep
  them out: deleting doesn't stop them signing in again.
- **Groups**: shown once company sign-in is set up. Groups seen at sign-in, with
  labels and grants.
- **Roles**: built-in roles are read-only; clone them into custom roles. A role
  used by a grant cannot be deleted.
- **Audit**: filter by person, connection, kind, action prefix and UTC dates;
  Export CSV downloads every matching row.
- **Settings**: server address, company sign-in, token policy, sign-in for people
  who are not admins, and the setup checklist.
- **My access**: your connections, role and permissions, your own U2 login on each
  per-person connection, your tokens, and MCP client setup.

### Personal U2 logins

A per-person connection uses each person's own U2 login, so the database sees who
made each call. People set it on **My access** under **Your U2 login**, with
**Test** and **Remove**. Until it is set, their calls on that connection are
refused with a pointer to My access. The password is stored encrypted and never
shown again, not even to admins, who see only whether a login is set, its U2 user
name and when it changed, and can **Clear** it. Changing the connection's server
forgets every login on it.

### Sign-in and passwords

- Failed sign-ins and wrong current passwords on Change password are audited
  (`admin.sign_in` failed, `admin.password_check` failed) and rate-limited by
  `U2_ADMIN_SIGNIN_LIMIT`. A sign-in refused while sign-in for people who are
  not admins is off is audited with outcome `refused`.
- Turning sign-in off for people who are not admins keeps them off this site,
  local and company sign-in alike, and ends their open sessions. Their MCP access
  (tokens, signed-in apps) keeps working.
- `u2-mcp admin set-public-url` and the Settings page refuse an address that
  contains a user name or password.

### Personal access tokens

Clients that cannot do a browser sign-in use a personal access token:
`Authorization: Bearer u2pat_...`. People create and revoke their own on **My
access**, which also shows the server address and a `curl` example. A token is shown once and lasts 90 days by default (never more than
3650; an admin can set a lower maximum under Settings). Admins can revoke anyone's
token. A token proves who is calling, not what they may do: nobody, admins
included, can use a connection without a grant.

### Company sign-in (SSO)

Company sign-in is set up only on the admin site, in the wizard or under
**Settings → Company sign-in**, including the groups claim. It is stored in the
settings database, with the client secret encrypted under `U2_SECRET_KEY`. The
admin site uses it at once. MCP clients' browser sign-in (the OAuth bridge) uses
the same OIDC client after a restart, and only when the server address is https
(or localhost). Without company sign-in, personal access tokens are the only way
in. See [admin.md](admin.md#3-company-sign-in-sso).
