# u2-mcp

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)


**Let your team ask Rocket Universe and UniData questions in plain English, from VS Code, Claude or any MCP client.**

u2-mcp is an MCP server for the Pick/MultiValue family. It runs as one team server that reaches several U2 systems (for example Prod, Test and Training). Each person signs in, with their company account or a local one. An admin decides, per connection, who may read, query, write or run commands. Everything is set up in a web admin site with a setup wizard.

## What can you do with it?

| You ask | Your assistant does |
|---|---|
| "How many customers are in California?" | Runs a query and answers "1,247 customers" |
| "Show me order ORD001" | Reads the record and shows every field |
| "What files are available on Test?" | Lists the files in that connection's account |
| "Describe the CUSTOMERS file" | Shows the field definitions from the dictionary |

## How it works

```
 Your AI assistant  ──►  u2-mcp  ──►  U2 Prod
 (each person signs in)    │     ──►  U2 Test
                           │     ──►  U2 Training
 Browser (admins) ──► /admin: connections, people, groups, roles, audit
```

1. You ask your assistant a question.
2. It calls a u2-mcp tool on a connection you have access to.
3. u2-mcp checks your permissions, then queries that U2 server with the connection's login (or your own U2 login).
4. The answer comes back in plain language. The admin site's audit log records the call.

**New to MCP?** See [What is MCP?](docs/what-is-mcp.md).

## Screenshots

![Groups page](docs/screenshots/groups.png)

<details>
<summary>Setup wizard</summary>

**Step 1: admin account**

![Step 1: admin account](docs/screenshots/setup-1-admin.png)

**Step 2: first connection**

![Step 2: first connection](docs/screenshots/setup-2-connection.png)

**Step 3: server address**

![Step 3: server address](docs/screenshots/setup-3-server-address.png)

**Step 4: company sign-in (optional)**

![Step 4: company sign-in (optional)](docs/screenshots/setup-4-company-sign-in.png)

**Step 5: done**

![Step 5: done](docs/screenshots/setup-5-done.png)

</details>

<details>
<summary>Connections</summary>

**All connections**

![All connections](docs/screenshots/connections.png)

**A connection, its live sessions and who has access**

![A connection, its live sessions and who has access](docs/screenshots/connection.png)

**Add a connection**

![Add a connection](docs/screenshots/connection-new.png)

</details>

<details>
<summary>People</summary>

**Users**

![Users](docs/screenshots/users.png)

**A person**

![A person](docs/screenshots/user.png)

**A person's effective access, and where it comes from**

![A person's effective access, and where it comes from](docs/screenshots/user-access.png)

**Add a local user**

![Add a local user](docs/screenshots/user-new.png)

</details>

<details>
<summary>Groups</summary>

**Groups from company sign-in, with their access and when each was last seen**

![Groups from company sign-in, with their access and when each was last seen](docs/screenshots/groups.png)

**Filtered to groups not seen in 90 days that have no access**

![Filtered to groups not seen in 90 days that have no access](docs/screenshots/groups-filtered.png)

**A group**

![A group](docs/screenshots/group.png)

**Deleting a group that has access asks first**

![Deleting a group that has access asks first](docs/screenshots/group-delete.png)

</details>

<details>
<summary>Roles</summary>

**Built-in and custom roles**

![Built-in and custom roles](docs/screenshots/roles.png)

**A role's permissions**

![A role's permissions](docs/screenshots/role.png)

</details>

<details>
<summary>Knowledge</summary>

**Pick a server and account**

![Pick a server and account](docs/screenshots/knowledge.png)

**Its saved topics**

![Its saved topics](docs/screenshots/knowledge-topics.png)

**Review or edit a topic**

![Review or edit a topic](docs/screenshots/knowledge-topic.png)

</details>

<details>
<summary>Audit, settings and your own access</summary>

**Audit log with filters and CSV export**

![Audit log with filters and CSV export](docs/screenshots/audit.png)

**Settings**

![Settings](docs/screenshots/settings.png)

**My access: connections, tokens and how to connect a client**

![My access: connections, tokens and how to connect a client](docs/screenshots/me.png)

**Change your password**

![Change your password](docs/screenshots/account-password.png)

**Sign-in**

![Sign-in](docs/screenshots/sign-in.png)

</details>

## Quick start (Docker)

You need Docker with the compose plugin, on a host that can reach your U2 servers.

```bash
git clone https://github.com/cmc0619/u2-mcp-hub.git
cd u2-mcp-hub
python -c "import secrets; print('U2_SECRET_KEY=' + secrets.token_urlsafe(48))" > .env
docker compose up -d
docker compose exec u2-mcp u2-mcp admin show-setup-code
```

Open `http://<host>:8000/admin/` and follow the setup wizard:

1. **Admin account**: enter the setup code, then create the first (local) admin.
2. **First connection**: host, account, service and how people log in to U2. **Test connection** really connects.
3. **Server address**: the URL people use, ideally https behind a proxy.
4. **Company sign-in** (optional): Microsoft Entra ID, Okta, Google or any OpenID Connect provider, with a real **Test sign-in**.
5. **Done**: then give people access under the connection's **Access** section.

U2 servers, accounts, logins, people and permissions all live in the admin site, not in environment variables. Each connection uses either one shared U2 login, or each person's own U2 login, which they enter themselves on **My access** (with a **Test** button). Admins never see a personal password.

The settings database encrypts every stored password with `U2_SECRET_KEY`. **Keep that key in your password vault.** Without it, stored passwords cannot be read.

Everything persistent lives in one volume, `/data` (`U2_DATA_DIR`): the settings database `u2-mcp.db` with its `-wal` and `-shm` files, and the uopy driver's log under `/data/logs/`. Without `U2_SECRET_KEY`, `--streamable-http` refuses to start.

Startup needs only `U2_SECRET_KEY`. These deployment settings are optional:

| Variable | Use |
|---|---|
| `U2_PUBLIC_URL` | The address people use (the wizard can set it instead) |
| `U2_TRUSTED_PROXIES` | Your reverse proxy's address, so the real client address is seen behind it |
| `U2_ADMIN_ALLOWED_IPS` | Addresses or networks allowed to reach `/admin` |
| `U2_TLS_CERT`, `U2_TLS_KEY` | Serve https without a proxy (set both or neither) |

The [admin guide](docs/admin.md) covers https with Caddy or nginx, company sign-in for Entra, Okta and Google, backups and recovery.

## Connect your editor

Each person opens **My access** on the admin site. It shows their connections and the server address:

- **Clients that support sign-in** (GitHub Copilot, VS Code, JetBrains AI Assistant and others) need only the address; they open company sign-in themselves once it is set up.
- **Scripts and clients that can't sign in** send a personal access token from My access as `Authorization: Bearer <token>`; My access shows a `curl` example.
- **Claude Desktop**: add the server as a custom connector with its URL, or use a token through `mcp-remote`:

```json
{
  "mcpServers": {
    "u2": {
      "command": "npx",
      "args": ["mcp-remote", "https://u2-mcp.example.com/", "--header", "Authorization:${U2_MCP_AUTH}"],
      "env": { "U2_MCP_AUTH": "Bearer u2pat_your_token_here" }
    }
  }
}
```

A person sees only the connections they have a grant on. Being an admin gives no data access by itself.

## Features

- **Several connections, per-person access**: grants give a role on a connection to a person, an SSO group or everyone. Roles are sets of granular permissions (schema, records, queries, writes, deletes, TCL, subroutines, BASIC). Database knowledge is baseline access through any authorized connection, including read-only connections.
- **Sign-in**: company SSO (OIDC, with groups) and local accounts. Personal access tokens are available for editors without browser sign-in. An SSO user's tokens pause after 30 days without a company sign-in.
- **Admin site**: a setup wizard, connections with live tests, users with effective access, groups (once company sign-in is set up), roles, and audit with CSV export.
- **MultiValue-native tools**: read, write and delete records with multivalues and subvalues intact. RetrieVe/UniQuery queries, dictionaries, BASIC subroutine calls and transactions.
- **Safety**: global and per-connection read-only switches, a TCL command blocklist, query timeouts and record limits.
- **Knowledge notes**: what the assistant learns about a connection's files is saved per connection.

## Available tools

Every tool except `list_connections` takes an optional `connection` argument. When you can see exactly one connection, it is used.

- **Connections**: `list_connections` (yours, with your role and permissions), `connect`, `disconnect`, `list_sessions`
- **Files**: `list_files`, `get_file_info`, `read_record`, `read_records`, `write_record`, `update_value`, `delete_record`
- **Queries**: `execute_query`, `get_select_list`, `validate_query`, `execute_tcl`
- **Dictionary**: `list_dictionary`, `get_field_definition`, `describe_file`, `analyze_file_structure`, `get_account_info`
- **Export**: `export_to_json`, `export_to_csv`
- **BASIC**: `call_subroutine`, `list_catalog`, `list_programs`, `read_program`, `search_programs`, `write_program`, `compile_program`, `catalog_program`
- **Transactions**: `begin_transaction`, `commit_transaction`, `rollback_transaction`, `get_transaction_status`
- **Knowledge**: `save_knowledge`, `list_knowledge`, `get_all_knowledge`, `get_knowledge_topic`, `search_knowledge`, `delete_knowledge`

See the [tools reference](docs/tools.md).

## Single-user (stdio) mode

Plain `u2-mcp` (no `--streamable-http`) serves one person over stdio, with one U2 login from environment variables, launched by a desktop client. It refuses to start unless `U2_HOST`, `U2_USER`, `U2_PASSWORD` and `U2_ACCOUNT` are all set. There is no admin site, no OAuth and no audit trail beyond ordinary logging; the caller has full rights within that login, subject to `U2_READ_ONLY` and the command blocklist. Knowledge notes are kept in `~/.u2-mcp/u2-mcp.db`, per host and account.

```json
{
  "mcpServers": {
    "u2": {
      "command": "u2-mcp",
      "env": {
        "U2_HOST": "server.example.com",
        "U2_USER": "user",
        "U2_PASSWORD": "password",
        "U2_ACCOUNT": "MYACCOUNT"
      }
    }
  }
}
```

Team mode (`--streamable-http`) does not connect with these variables; connections are added on the admin site. See [Configuration](docs/configuration.md) for every variable.

## Documentation

| Guide | Description |
|---|---|
| [Admin guide](docs/admin.md) | Docker, the setup wizard, SSO, reverse proxies, backups, recovery, connecting AI assistants |
| [Configuration](docs/configuration.md) | Every setting, team mode and stdio |
| [Tools reference](docs/tools.md) | Each tool in detail |
| [Usage examples](docs/examples.md) | Common usage patterns |
| [What is MCP?](docs/what-is-mcp.md) | MCP, and how u2-mcp fits |
| [Installation](docs/installation.md) and [Quickstart](docs/quickstart.md) | Installing from a clone, and single-user set-up |
| [Hardening](docs/hardening.md) | Security and reliability behaviour |

## Security

- Every tool call is decided per person and per connection, from current data. Changes apply on the next call.
- U2 passwords and the SSO client secret are encrypted at rest with `U2_SECRET_KEY`. Personal access tokens are stored only as hashes.
- Admin sessions are HttpOnly, SameSite and Secure over https. Every form carries a CSRF token, and sign-in attempts are rate-limited.
- Credentials are never logged. Every admin change and tool call is audited.

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [bpamiri/u2-mcp](https://github.com/bpamiri/u2-mcp), the MCP server this project is copied from and builds on
- [RoKiPaRk/UOFastMCP](https://github.com/RoKiPaRk/UOFastMCP), whose ideas for a team server with an admin setup screen were adapted here
- [Rocket Software](https://www.rocketsoftware.com/) for the `uopy` package
- [Anthropic](https://www.anthropic.com/) for the Model Context Protocol specification
- The MultiValue database community
