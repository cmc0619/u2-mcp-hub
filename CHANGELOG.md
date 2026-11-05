# Changelog

All notable changes to this project are recorded here. It is a team MCP server
for Rocket U2 (UniVerse and UniData) with security and reliability hardening, an
admin site, team mode, single sign-on, Docker deployment and BASIC tools. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Entries describe what changed and why; the security findings behind many of
them are written up in [docs/hardening.md](docs/hardening.md).

## [Unreleased]

### Added

- The admin site's footer shows which code is running to signed-in people:
  `u2-mcp 0.9.0 · 1a2b3c4`. The Docker build stamps the commit, read from the
  build context's .git files (only HEAD and the refs get past .dockerignore).
- The Groups page lists each group's access (connection and role) on an indented
  line under it, and shows the identity provider only when groups come from more
  than one.
- Denser admin layout: buttons beside their field, forms with several fields
  laid out side by side, Test / Save / Remove in one row on My access, and the
  company sign-in buttons in one row on Settings.
- Admins can sign out another person's apps: a red **Sign out apps** button
  next to each person on **Users** (all their apps), and per-app **Sign out**
  buttons on the person's page. Audited with the admin as actor.
- The admin site uses the full width of a desktop screen (up to 110rem) instead
  of a 60rem column.
- The admin Knowledge page sorts a database's topics by **Topic** or
  **Updated**; click a column heading to sort by it, again to reverse.

### Changed

- The Settings switch is now **Sign-in for people who are not admins**: off,
  it keeps every non-admin off the admin site, local and company sign-in
  alike, and ends their open sessions. MCP access (tokens, signed-in apps) is
  not affected. It used to cover only new local sign-ins.
- Database knowledge now uses baseline connection access, not separate role
  permissions. Deleting a note, or replacing an existing one, needs an admin:
  notes are shared by everyone on the database, so a Viewer can add to them but
  not take them away. The admin site's Knowledge page is admins-only. Viewer and Analyst have the same database privileges.
  Notes share a SQLite namespace hashed from normalized server/account, regardless
  of connection name or login mode. Deleting a connection keeps the database's
  notes.
- **Knowledge notes can be saved on read-only connections.** Read-only protects the
  U2 database; notes live in this server's own store, so saving knowledge is no
  longer refused by a connection's read-only switch or `U2_READ_ONLY`.
- `execute_query` reports `max_rows` only for LIST and SORT, the verbs it caps.
- The `execute_query` and `validate_query` docs list every allowed verb, point
  SELECT users to `get_select_list`, and say that `validate_query` does not ask
  the server.

### Removed

- Every upgrade path for old data: the settings database's schema 1/2 upgrade
  (it stays schema 3, and a database from another version is refused), the
  move of old per-connection and host@account knowledge notes, the admin
  site's unmapped-scope screens, password re-hashing at sign-in, and hiding a
  stored secret on old public OAuth client rows. Nothing deployed needs them.
- The built-in Analyst role, identical to Viewer since database notes came with
  any grant.
- The Switches section on a connection's page (Allow writes / Make read-only,
  Disable / Enable). The Read-only and Enabled boxes in its form do the same;
  Save closes live sessions as the buttons did.
- The admin Dashboard and its Check now button. Admins land on Connections;
  activity is on Audit, everyone-grant warnings on each connection's Access,
  and group overage on Users.

### Fixed

- A command that stops to ask for input (uopy `EXEC_REPLY`) is cancelled and
  reported as rejected with the server's own text. It used to stay waiting,
  so the next call on the session failed with `[30114] An Execute is currently
  active on the server`, hiding the real message: a `get_select_list` on a
  missing file showed 30114 instead of the file error.
- `list_catalog` is read-only: it lists the UniVerse catalog with `MAP` instead
  of running `CATALOG`, the verb that makes code live, and no longer guesses
  at `&SYSCAT&` or VOC entries. It now needs `schema.read` instead of
  `subroutine.call`, and returns an error on UniData.
- A person's page shows a company sign-in user by name, not by the provider's
  opaque subject ID.
- The query docs state that no select list outlives a call, with one example
  for each of COUNT, `get_select_list` and LIST.
- **Records are no longer garbled in the Docker image.** Without NLS, uopy decoded
  record bytes as UTF-8, the container's default, and every field, value and
  subvalue mark became `�`, so each record arrived as one field. A non-NLS
  session now decodes as Latin-1, byte for character. This broke `read_record`,
  `read_records`, the exports, `analyze_file_structure` and every dictionary tool.
- `list_files`, `get_account_info`, `list_dictionary` and `describe_file` read names
  from `SSELECT VOC` and `SSELECT DICT` select lists. They used to cut names from
  LISTFILES and LIST printouts and returned column headings such as `DICT` and `DATA`.
- `get_file_info` parses UniVerse's `label = value` FILE.STAT lines; type, modulo,
  separation and record count were always null.
- A dictionary type code followed by a description (`D Customer name`) is read as
  its type, with the rest as `description`.
- `execute_query` holds every LIST and SORT to `max_rows` again. A caller's
  `SAMPLE 1000000`, any query mentioning `TOTAL` or `BREAK.ON`, and a field named
  `TOTAL` all used to return the whole file. A larger `SAMPLE` is lowered to the
  limit; only `DET.SUP` totals reports run uncapped.
- QSELECT, GET.LIST and SEARCH in `execute_query` clear the select list they
  leave, as SELECT does; the next query on the session ran against it.
- When clearing a select list fails during an open transaction, the dropped
  session rolls the transaction back; `get_select_list` and `execute_query` now
  report that as an error instead of success.
- `execute_query` returns `status: "error"` when the server rejects the statement
  (a negative `@SYSTEM.RETURN.CODE`), with the server's message in `output`.

## [0.9.0] - 2026-11-04

### Added

- **Signed-in apps on My access.** Each person sees the MCP apps that signed in
  with their company account (for example GitHub Copilot): name, sign-in time,
  last token refresh and expiry, with a **Sign out** button that revokes that
  app's tokens for that person only (audited as `oauth_app.sign_out`). Tokens now
  record when the person signed in, carried across refreshes.
- BASIC program tools: `list_programs`, `read_program`, `search_programs` (`basic.read`), `write_program` (`basic.write`, saves only over the version you read, under the program's record lock: another user's lock gives "<program> is locked by another user; try again later"), `compile_program` (`basic.compile`, errors by line on UniVerse and UniData) and `catalog_program` (`basic.catalog`, local catalog only). Built-in roles: Developer reads, writes and compiles; Owner also catalogs.
- `U2_BASIC_FILES`: which files the BASIC tools may use (default `*BP,BP.*`).
- The audit log never holds BASIC source: saved source, `read_program` results and `compile_program` output are logged as size and hash, and `search_programs` matches keep only program and line number.
- Program names that CATALOG or BASIC read as options (`DIRECT`, `GLOBAL`, `FORCE`, `LOCAL`, `NEWVERSION`, `COMPLETE`, ...) are refused.
- Company sign-in (OIDC) for the admin site: authorization code with PKCE, state and nonce, ID tokens checked against the provider's keys. It is set up in the wizard's new optional step or under Settings, with a real **Test sign-in**. Microsoft Entra ID is set up from the Directory (tenant) ID, Application (client) ID and client secret.
- SSO groups from the ID token, with Entra group-overage handling: optional Microsoft Graph lookup, otherwise the person is flagged and the Dashboard warns. The Groups page appears once company sign-in is set up.
- VS Code browser sign-in from the admin site's company sign-in, after a restart, with an https address.
- People set their own U2 login for per-person connections on My access (Save, Test, Remove). It applies through any grant. Admins see only whether it is set and can clear it; logins stored on grants move across on upgrade.
- Admins can reset a local user's password (typed or generated), edit a person's name, email and username, and delete a person.
- `U2_ADMIN_SIGNIN_LIMIT`: sign-in attempts per minute per address and per username (default 5; 0 turns the limit off, for development only).
- `U2_TRUSTED_PROXIES`: behind a reverse proxy, the sign-in rate limit, `U2_ADMIN_ALLOWED_IPS`, audit and https detection see the real client.
- `U2_TLS_CERT` and `U2_TLS_KEY` to serve https without a proxy.
- `Dockerfile`, `docker-compose.yml`, and Caddy and nginx examples under `deploy/`. CI builds the image and runs the browser suite against it.
- `docs/admin.md`: install, setup, SSO for Entra, Okta and Google, proxies, backups, recovery and AI assistant set-up.

### Changed

- **Python 3.12 or later is required.** The server only ever runs on the `python:3.12` Docker image, so 3.10 and 3.11 are no longer supported or tested: CI runs on 3.12 only, and ruff and mypy target 3.12.
- **My access: Connect your MCP client is one address and one example.** The VS Code, Visual Studio and JetBrains configuration snippets are gone. The page shows the server address (clients that support sign-in need only that and open company sign-in themselves), a line on sending a token as `Authorization: Bearer <token>`, and one `curl` example that initializes an MCP session.
- Personal access tokens of SSO users show as **Paused** after 30 days without a company sign-in. My access says when they would pause.
- My access and Effective access say when a per-person connection still needs the person's own U2 login.
- The grants editor no longer asks for a personal U2 login.
- The pre-sign-in CSRF cookie is `__Host-` prefixed over https. Password checks run off the event loop. CORS no longer applies to `/admin`.
- Uvicorn no longer believes `X-Forwarded-*` from 127.0.0.1 by itself. Only `U2_TRUSTED_PROXIES` is believed.
- The restart note now covers company sign-in.
- Pages, messages and docs speak of AI assistants and MCP clients in general rather than one product.
- Connection ids are never reused, so a new connection never inherits a deleted one's audit history.
- Changing a per-person connection's server forgets the personal U2 passwords stored for it.
- `set-public-url` and the Settings page refuse an address that contains a user name or password.
- `u2-mcp admin reset-password` re-enables the user; `--admin` also makes them an admin.
- Oversized ids in admin URLs and forms are treated as not found instead of an error.
- Password hashes are upgraded at sign-in when the argon2 parameters change.
- Signing in from a link keeps the page's query string; signing out with no live session redirects to sign-in instead of answering 403.
- Testing a per-person connection needs a password; `change_password` reports every field's problem at once.
- In team mode `U2_HOST`, `U2_USER`, `U2_PASSWORD` and `U2_ACCOUNT` are optional; connections can be added in the admin site.
- Editing, switching off or deleting a connection closes its live sessions; database knowledge notes are retained.
- The tool that listed open database sessions is now `list_sessions`.
- The server refuses to start if any tool lacks an access check.
- **Writes are now refused unless someone asks for them.** `U2_READ_ONLY`
  defaulted to false, and the hardening notes already named it: describing what
  unauthenticated network exposure cost, they say "read-only mode is off by
  default, so that includes writing and deleting records." The fix that followed
  closed the bind address and the CORS policy and left the default alone, so the
  sentence stayed true. It matters most in the case this server is offered for —
  someone points it at a database they care about, having read that it is
  read-only, and gets a server that writes if a caller asks twice. Setting
  `U2_READ_ONLY=false` still works, and choosing it is the moment somebody is
  actually thinking about writes.


### Security

- **The Docker image no longer ships pip.** A builder stage installs the server
  into a venv created without pip; the release image copies that venv and deletes
  the base image's pip, its bundled wheel and any setuptools or wheel. This
  removes the six pip 25.0.1 CVEs Trivy reported (including CVE-2026-8643, CVSS
  8.0), which only build time needed.

- **Company sign-in hardening.** A password reset that lands while a sign-in is
  being checked now wins (the rehash is a compare-and-set, and the account is
  re-read before the session starts). Deleting a person revokes their MCP OAuth
  tokens, and a leftover token never re-creates them. People are identified by the
  provider's issuer plus subject (settings database version 4), so a provider
  change cannot hand one person's grants to another with the same subject.

- **The HTTP transport no longer serves an unauthenticated database to the
  network.** The legacy `--http` (SSE) transport performs no authentication at
  all, and defaulted to binding every interface with `U2_HTTP_CORS_ORIGINS='*'`
  and credentials enabled — so `u2-mcp --http` exposed `write_record`,
  `delete_record` and `execute_tcl` to anyone who could reach the port.
  `U2_HTTP_HOST` now defaults to `127.0.0.1`, `U2_HTTP_CORS_ORIGINS` defaults to
  empty (a literal `*` is refused), and the server refuses to start when
  unauthenticated on a reachable interface unless
  `U2_ALLOW_UNAUTHENTICATED_NETWORK_ACCESS=true` is set deliberately. **These are
  the only defaults chosen for safety over convenience.**

- **CI now fails on security findings.** `bandit` (medium severity and above) and
  `pip-audit` run before the build job, so the assurance renews itself rather
  than describing the day it was run.

- **Authorization codes can no longer be replayed** (defect introduced by the
  durable-storage change). Consuming a one-time code was a `SELECT`
  followed by a separate `DELETE`, replacing an atomic `dict.pop()`. Racing forty
  threads through a deliberately widened window let all forty exchange the same
  code. Codes and pending authorization state are now claimed atomically with
  `DELETE ... RETURNING`.

- **Identity resolution now fails closed.** A resolver error fell back to the
  unauthenticated local operator, which would let a caller launder their identity
  out of the audit trail. With no resolver installed the local operator is still
  the honest answer for stdio mode; with one installed, a failure to name the
  caller raises.

- **Files holding credentials are restricted to their owner** where the operating
  system enforces permissions.

- **Per-user connections are bounded** by `U2_MAX_CONNECTIONS` (default 25) on a
  least-recently-used basis, so a crowd of callers cannot exhaust the database's
  connection limit.

- **Credential map entries may name an environment variable** with `password_env`
  instead of storing a password on disk, and errors never echo the map's contents.

### Fixed

- **GitHub Copilot can finish sign-in.** Copilot sends its client credentials only in an `Authorization: Basic` header at `/token`, with no `client_id` in the form, as RFC 6749 allows; the MCP SDK reads `client_id` only from the form and refused it with 401 "Missing client_id". `/token` and `/revoke` now take a missing `client_id` (and `client_secret`) from Basic credentials. Public clients' secrets are still ignored and PKCE is still checked; confidential clients' secrets are still compared.

- **Public MCP clients can finish sign-in.** Clients that register with
  `token_endpoint_auth_method` `none` (PKCE only, such as GitHub Copilot) were
  given a client secret they never send, so `/token` refused them with 401
  "Client secret is required" and the client waited forever. They are now
  registered without a secret, and clients already stored with one are treated as
  public, so no database change is needed. Confidential clients still need their
  secret at `/token` and `/revoke`, and PKCE is still checked.

- **MCP company sign-in** now sends PKCE to the provider and authenticates the way
  its discovery offers (`client_secret_basic` included); with `U2_AUTH_ENABLED` it
  reads `U2_SSO_GROUPS_CLAIM`. A failed first start still seeds `U2_IDP_*` on the
  retry, and a saved client secret that differs from `U2_IDP_CLIENT_SECRET` is
  warned about. The nginx example requires `U2_PUBLIC_URL`; backups cover the
  whole `/data` volume, knowledge notes included.

- **A file was dropped from `list_files` when its name contained a header word.**
  The same defect as the dictionary one, in the same shape: any line containing
  RECORDS, LISTED or SELECTED anywhere was treated as a header. `RECORDS` is a
  plausible MultiValue file name and so is `SELECTED.ITEMS`. A file that vanishes
  here is one the caller never learns exists, which is worse than almost anywhere
  else — telling somebody what is in an account they do not know is the entire
  purpose of the call.

- **A dictionary item was dropped when its name began like the command.**
  `list_dictionary` decided which lines of a listing were items by prefix: a line
  beginning "LIST" was the echoed command, and a line containing "listed" was the
  closing summary. Both tests are too loose to survive ordinary data —
  `LIST.PRICE` and `LIST.COST` are everyday MultiValue dictionary names, and a
  wholesale distributor's product file has one of each. Every such item was
  dropped with no error and no gap where it had been, so the only way to notice
  was to already know what should have come back. Someone points this tool at a
  database to find out what is in it, which makes them by definition the person
  who cannot tell. The distinction is a word boundary: Universe echoes
  `LIST DICT PRODUCT` with a space, and `LIST.PRICE` has none. Found by running
  the discovery path end to end rather than by reading it.

- **Refreshing a token no longer crashes, and no longer loses the user.**
  `exchange_refresh_token` read an attribute the SDK's `RefreshToken` does not
  have, so every refresh raised `AttributeError`; and the replacement tokens were
  stored with an empty `user_subject` under a comment claiming the identity was
  preserved. From the first refresh onward the audit trail would have recorded an
  empty user and per-user credentials could not resolve at all. Rotation now
  recovers the stored token, carries its subject, claims and resource across, and
  refuses a refresh token this server did not issue.

- **Type checking passes.** CI ran `mypy src/` against 14 errors, so
  that step was already failing. Each was fixed rather than suppressed, which is
  how the two refresh defects above were found. `strict_equality`,
  `warn_unused_ignores` and `warn_redundant_casts` are now on.

- **Non-ASCII business data is no longer deleted from query output**
  `_sanitize_output()` kept only plain ASCII, so accented customer names
  (`MÜLLER`, `José Peña`) and currency symbols (`£`, `€`, `¥`) disappeared from
  results with no error. Output is now filtered by Unicode category, which keeps
  ordinary printable text in any alphabet while still stripping terminal control
  codes.

- **Auto-reconnect now actually reconnects**
  When a session went inactive, `get_session()` cleared the session and called
  `connect()` — which returned early because the connection record was still
  marked active — and then handed the caller `None`. Every subsequent request
  failed with `AttributeError: 'NoneType' object has no attribute ...`. The stale
  record is now discarded before reconnecting. This mattered most in stdio mode,
  the default for desktop clients, where no watchdog exists to clear the record.

- **Truncated results are now reported as truncated**
  `execute_query` appended a `SAMPLE` clause to `LIST` statements without marking
  the answer partial, so a capped result read exactly like a complete one. Both
  `execute_query` and `get_select_list` now return `is_complete`, plus a `warning`
  in plain language when a limit was applied. An explicit caller-supplied `SAMPLE`
  is respected rather than doubled.

- **A timed-out query no longer keeps running**
  The timeout raised an error but never stopped the work: the query continued on
  the server, its thread stayed alive, and the session was handed to the next
  request with a command still in flight. Since uopy cannot cancel a command, the
  session is now closed — which drops the socket and lets the server abandon the
  work — and the next request reconnects. Commands are also serialized per session,
  and abandoned queries are counted and exposed as `abandoned_query_count`.

- **The audit trail now names who acted**
  Records carried a session id generated at server start, not the authenticated
  user, so no record could say who ran a query. Every entry now carries the
  identity provider's subject, a readable name and email, the OAuth client that
  presented the token, whether the caller was authenticated at all, and the
  database login the work ran under -- including whether that login was shared.
  Passwords never reach the file.

- **Each caller can now reach the database as themselves**
  One connection served the whole process under one account, so Universe's own
  file and field security could not act on the real caller. `U2_IDENTITY_MODE`
  now selects `shared` (one login for everyone, the default, but logged
  and flagged in the audit trail) or `mapped`, where each authenticated person
  connects under their own Universe login from `U2_CREDENTIAL_MAP_PATH`. An
  unmapped caller is refused rather than silently falling back to the shared
  account.

### Added

- Admin site, phase 2b: a grants editor on the connection, user and group pages; My access with personal access tokens (shown once, 90 days by default, at most 3650 days) and copy-ready VS Code, Visual Studio and JetBrains configuration; Dashboard (connection health with Check now, sessions, `everyone` warnings, latest audit), Users with effective access, Groups, Roles (clone, edit, delete with optimistic locking), Audit with filters and CSV export, and Settings for token policy, local sign-in for non-admins and the setup checklist. Admins land on the Dashboard; people who are not admins land on My access.
- `u2-mcp admin set-public-url <url>` (and `--clear`) sets the server address from the command line.
- Wrong current passwords on Change password are audited (`admin.password_check`) and rate-limited; a sign-in refused because local sign-in is off is audited.
- Admin site at `/admin` (team mode): local admin sign-in, a resumable setup wizard (admin account, first connection with Test, server address), Connections pages (add, edit, test, read-only and enabled switches, live sessions, disconnect, delete) and a Settings page for the server address.
- `u2-mcp admin show-setup-code` and `u2-mcp admin reset-password <user>`.
- `/health` endpoint on the HTTP transports.
- `U2_ADMIN_ALLOWED_IPS` to restrict `/admin` by address.
- Team mode (`U2_SECRET_KEY`): a settings database with connections, users, SSO
  groups, roles, grants, personal access tokens and an audit table.
- Several U2 connections from one server; every tool takes `connection`.
- `list_connections` lists the caller's connections, roles and permissions.

- **`update_value` — change one value of one field, in place.** Separate from
  `write_record`, and the separation is the point. `write_record` takes a whole
  record, which puts responsibility for the record's *shape* on whoever assembled
  the fields — and in a MultiValue file the shape is load-bearing: position *n* of
  a set of parallel fields describes one branch. Assemble it carelessly and a
  field comes back a different length; the record is still well formed, nothing
  errors, and what has changed is which branch a quantity belongs to. This tool
  names the field and the value instead, so the shape stays the server's problem
  where it is enforced once. It returns the record before and after with the
  number of values each field held both times, and says outright whether the
  alignment survived — the one outcome nothing downstream can detect.

- **`U2_DRIVER` names the database library**, so this server can be evaluated
  without a Universe instance — which licensing puts out of reach for most people
  who might assess it. The default remains `uopy` and a test asserts it; a
  replacement must provide all six names the server calls or it is refused at
  startup rather than failing mid-request; and running against anything but a
  database logs a warning, so nobody later mistakes the figures for production
  data.

- **Durable OAuth state**
  Registrations, tokens and in-flight logins lived only in process memory, so a
  restart signed everyone out and a second instance could not recognise the
  first one's tokens. `SQLiteAuthStorage` keeps the same behaviour in a file:
  set `U2_AUTH_STORAGE=sqlite` (path via `U2_AUTH_STORAGE_PATH`). Bearer tokens
  are stored as SHA-256 hashes, so a stolen database file yields no usable
  credentials. SQLite is in the standard library, so this adds no dependency.
  Both backends are held to one shared contract test suite.

- **Test doubles that match the code they double.** The previous mocks modelled an
  obsolete `uopy` API (`session.open()`, `cmd.exec()`, `session.transaction_start()`)
  that the server has not called for some time, which is why `tests/test_tools/`
  was empty. They now mirror the `uopy` 1.4 surface actually in use
  (`uopy.File(name, session=...)`, `uopy.Command(text, session=...)`, `cmd.run()`,
  `session.tx_start()`), so a passing test exercises the real code path.

- **Connection test suite** — 22 tests covering connect/reuse/disconnect, session
  recovery, file-handle caching, command execution, output sanitization, query
  timeouts and transaction state.

- **Tool-layer test suite.** `tests/test_tools/` was empty; every tool
  module that touches business data now has tests, taking the tool package from
  0% to 65% statement coverage and the suite from 45 to 203 tests. The emphasis
  is on the safety guarantees an operator relies on: read-only mode genuinely
  leaves data untouched rather than only returning an error, writes and deletes
  require explicit confirmation, refused commands never reach the server,
  MultiValue structure survives a write-then-read round trip, and batch reads
  name what they could not find.
