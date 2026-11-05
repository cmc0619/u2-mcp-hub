# Admin UI phase 3: SSO and deployment — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let people sign in to the admin site (and, after a restart, VS Code) with their company account, keep their SSO groups and token freshness right, and ship the server as a Docker image whose browser suite runs in CI against the image itself.

**Architecture:**
- **Client address first.** A pure-ASGI middleware (the existing `ClientAddressMiddleware`, now outermost and proxy-aware) rewrites `scope["client"]` and `scope["scheme"]` when the direct peer is in `U2_TRUSTED_PROXIES`. The allowlist, the sign-in limiter, audit rows, Secure-cookie and https checks, and token last-used IPs all read the resolved values with no other change. Uvicorn's own forwarded-header handling is switched off.
- **One OIDC client, one recorder.**
  - `auth/oidc_client.py` does discovery, authorization code + PKCE + state + nonce, the token exchange and RS256 ID-token validation against the provider's JWKS (PyJWT, already installed through `mcp`).
  - `auth/graph.py` resolves Entra's group overage through Microsoft Graph, injectable and off by default.
  - `team_auth.record_sign_in` is the single place that turns validated claims into a user, groups and a fresh `last_sso_login_at`. The admin-site callback and the MCP OAuth callback both use it.
- **Settings in the database.** Company sign-in settings live in the `settings` table (the client secret through `SecretBox`), are seeded once from `U2_IDP_*`, and are edited by one form partial and one save function shared by the wizard's new SSO step and Settings (spec rule 1).
  - The admin site reads them on every sign-in.
  - The MCP OAuth bridge reads them at startup, so a restart applies changes. `RESTART_NOTE` says so.
- **Deployment.** A multi-stage `Dockerfile` (release and test targets), `docker-compose.yml`, and Caddy and nginx examples under `deploy/`. A CI job builds the image, starts it with compose, waits for health, checks both proxy examples, and runs the whole Playwright suite against one container per test (`U2_E2E_IMAGE`). Nothing local needs Docker.

**Tech Stack:** Python 3.10+, Starlette, Jinja2, htmx 2.0.4 (vendored), SQLite via `store/repo.py`, httpx, PyJWT (RS256, `PyJWKSet`), cryptography, pytest, pytest-asyncio, pytest-playwright (Chromium), Docker and docker compose v2 (CI only), Caddy 2 and nginx 1.27 (CI only, as examples).

Spec: `docs/superpowers/specs/2026-10-30-admin-ui-design.md`. The relevant sections are "Sign-in" (SSO users, Personal access tokens, Admin site security), "Setup wizard" (step 4 and rules 1 to 3), "Error handling", "Deployment" and "Testing" items 6 and 7.
Roadmap: `docs/superpowers/plans/2026-10-30-admin-ui-roadmap.md` (row 3, and the trusted reverse-proxy note).
Follow-ups folded in: the "Phase 3" lists in `.superpowers/sdd/final-2a-review.md` and `.superpowers/sdd/final-2b-review.md`, and the phase 3 notes in `.superpowers/sdd/progress.md`. Each is either a task step or a line in "Deferred" below.

## Global Constraints

Everything in 2b's Global Constraints still holds:
- Python 3.10; `ruff==0.16.5` (line length 100, `E,F,I,UP,B,SIM`) and `ruff format`; `mypy src/`; Google docstrings; type hints.
- No CDN. Autoescape on, and never `|safe` on user text.
- POST-redirect-GET. The CSRF field is `csrf_token` or the header `X-CSRF-Token`.
- `admin_only`/`signed_in` on every handler. Errors after a redirect are fixed codes (`PROBLEMS`, `NOTICES`).
- 2a's and 2b's exact messages.

In addition:

- **Every task ends with** (run through the venv: `.venv/Scripts/python -m ...`):

  ```
  pytest -q
  ruff check . && ruff format --check .
  mypy src/ --ignore-missing-imports
  bandit -r src/ --severity-level medium --confidence-level medium
  ```

  Tasks that touch pages or `tests/e2e` also run `pytest -m e2e tests/e2e --browser chromium`. All must pass, with no new warnings.
- **Code blocks are compacted.** Run `ruff format .` after pasting code, and before the checks.
- **No schema migration.** New data lives in the `settings` table.
- **Dependencies.** `pyjwt[crypto]>=2.8.0` is added to `pyproject.toml`. It is already installed (a dependency of `mcp`), so nothing is downloaded. No other new package. Docker is not available on the development machine: no local step, test or fixture may need it. Docker-only checks run in CI.
- **No real network in tests.** Identity providers are `tests/mocks/oidc_provider.py`. Unit tests reach it through `httpx.ASGITransport`, or answer with `httpx.MockTransport`. Browser tests run it as a local process on `127.0.0.1`. Microsoft Graph is only ever an `httpx.MockTransport` in tests.
- **New settings keys:**
  - `sso`: `{"provider", "discovery_url", "client_id", "groups_claim", "graph_overage"}`
  - `sso_client_secret`: encrypted with `SecretBox` through `set_secret_setting`
  - `sso_seeded_from_environment`: `true` once `U2_IDP_*` has seeded `sso`
- **New environment variables:**
  - `U2_TRUSTED_PROXIES`: addresses or CIDRs, comma-separated. Unset trusts nothing.
  - `U2_TLS_CERT` and `U2_TLS_KEY`: both or neither.
  - Test-only: `U2_E2E_IMAGE`.
- **Trusting forwarded headers.**
  - Only a direct peer inside `U2_TRUSTED_PROXIES` is believed.
  - `X-Forwarded-For` is walked from the right, and the first address not in `U2_TRUSTED_PROXIES` is the client.
  - `X-Forwarded-Proto` (its rightmost value, `http` or `https` only) becomes the scheme.
  - `X-Forwarded-Host` is not applied (see Decisions).
  - Uvicorn runs with `proxy_headers=False`.
- **Cookies.**
  - The session cookie is unchanged: `u2_admin_session`, `Path=/admin`.
  - The pre-session CSRF cookie and the new SSO cookie are named `__Host-<name>` with `Path=/` and `Secure` when the effective public URL is https. Otherwise they keep the plain name with `Path=/admin`.
  - The SSO cookie is `u2_admin_sso`: `HttpOnly`, `SameSite=Lax` (it must come back on the identity provider's redirect), 600 seconds, sealed with `Store.seal`.
- **Redirect URIs** are built from `effective_public_url(ctx)` (or `public_url_for(store, config)`), never from the request's Host:
  - `<public URL>/admin/sign-in/sso/callback` for the admin site;
  - `<public URL>/oauth/callback` for MCP clients.
- **ID tokens:**
  - only RS256;
  - signature checked against the JWKS from discovery;
  - `iss` equal to the discovery issuer, `aud` containing the client id, `azp` equal to it when `aud` has several values;
  - `exp`, `iat` and `sub` required; 60 seconds of leeway; `nonce` equal to the one sent (admin site);
  - a discovery issuer containing `{` (Entra's `/common` template) is refused.
- **Graph** is called only at the fixed `https://login.microsoftonline.com/<tid>/oauth2/v2.0/token` and `https://graph.microsoft.com/v1.0/users/<oid>/getMemberGroups`, with `tid` and `oid` checked as GUIDs. The `_claim_sources` endpoint inside a token is never fetched.
- **Audit actions:**
  - `kind="admin"`: `settings.sso` (params without the secret, plus `secret_changed`), `settings.sso_clear`, `settings.sso_test` (outcome `ok` or `failed`). Seeding from the environment writes `settings.sso` with `actor_label="startup"`.
  - `kind="auth"`: `admin.sign_in` gains `params.method = "sso"` for company sign-ins (outcomes `ok`, `failed`, `refused`). `sso_sign_in` gains `params.via` (`"admin"` or `"mcp"`).
- **New user-visible messages.** Use them exactly:
  - `SSO_EXPIRED`: `This sign-in expired or was started in another browser. Start again from the sign-in page.`
  - `SSO_FAILED`: `Company sign-in failed: {reason}`
  - `SSO_NOT_SET_UP`: `Company sign-in is not set up.`
  - `SSO_DISABLED`: `This account is disabled. Ask an admin.`
  - Sign-in button: `Sign in with your company account`
  - Wizard step title: `Company sign-in`. Buttons: `Save company sign-in`, `Test sign-in`, `Continue`, `Skip this step`, `Turn off company sign-in`.
  - Test page heading: `Company sign-in works`
  - Form problems (in `admin/sso_services.py`):
    - `PROVIDER_PROBLEM` = `Choose a provider.`
    - `DISCOVERY_PROBLEM` = `Enter the discovery URL, ending in /.well-known/openid-configuration.`
    - `DISCOVERY_HTTPS` = `The discovery URL must be https.`
    - `ENTRA_TENANT` = `Use your tenant's own discovery URL (with your tenant ID), not /common or /organizations.`
    - `CLIENT_ID_PROBLEM` = `Enter the client (application) ID.`
    - `SECRET_NEEDED` = `Enter the client secret.`
    - `SECRET_AGAIN` = `Enter the client secret again: the client ID changed.`
    - `CLAIM_PROBLEM` = `Use up to 64 letters, digits, dots, dashes, underscores, colons or slashes.`
- **`RESTART_NOTE`** becomes (Task 8): `Restart the server after changing the address or company sign-in: VS Code sign-in and personal access tokens pick them up at startup. With U2_AUTH_ENABLED set, they use U2_AUTH_ISSUER_URL instead.`
- **Token freshness.** An SSO user's tokens are refused after `U2_TOKEN_FRESHNESS_DAYS` (default 30) days without an SSO sign-in, with the existing `TokenRejected("sign in to the admin site to reactivate your tokens")`. Pages show such tokens as `Paused`.
- **Branch and commits.**
  - The branch is `feature/phase3-sso-deploy`. After each commit, run `git push origin feature/phase3-sso-deploy` (pre-approved). Never force-push.
  - End every commit message with `Co-Authored-By: Claude <model name> <noreply@anthropic.com>`, using the implementer's own model name.
  - `.superpowers/` is git-ignored scratch. Never `git add -f`.

## Decisions taken while planning

| Question | Decision |
|---|---|
| OIDC test provider without Docker | `tests/mocks/oidc_provider.py` is a Starlette app that provides discovery, JWKS, authorize (auto-approve, no login page), token (basic or post client auth, PKCE S256) and userinfo (no groups, like Entra). It also has `POST /_control/next-user`, which queues the next person and their claims (groups, or an Entra-style overage with `_claim_names`/`_claim_sources`, plus extra claims such as `tid`/`oid`). It signs RS256 with a key generated at start. Unit tests mount it through `httpx.ASGITransport`. Browser tests run `python -m tests.mocks.oidc_provider` on a free local port. It is not shipped in any image. |
| `U2_E2E_BASE_URL` vs a container per test | Every browser test needs an empty `/data` (the wizard tests, the wrong setup code, finishing twice), so one long-running server cannot serve the suite. `launch_server` therefore gains a Docker mode chosen by `U2_E2E_IMAGE`. It runs `docker run -d` per test with a fresh named volume and `--network host` (so the browser and the server reach the mock provider at the same issuer URL), and reaches the CLI through `docker exec`. This replaces the brief's example `U2_E2E_BASE_URL`, which could not reset state between tests. |
| `X-Forwarded-Host` | Not applied. Every URL the server builds comes from the saved public address, so Host is never needed. Rewriting Host would also trip the MCP SDK's DNS-rebinding check (it answers 421) when the server binds to loopback behind a local proxy. `X-Forwarded-For` and `X-Forwarded-Proto` are applied as the brief says. |
| Uvicorn's own proxy handling | Uvicorn 0.54 trusts `X-Forwarded-*` from `127.0.0.1` and `::1` by default (`proxy_headers=True`). Both `uvicorn.run` calls pass `proxy_headers=False`, so `U2_TRUSTED_PROXIES` is the only source of trust ("default: trust nothing"). |
| OIDC library | PyJWT, already installed through `mcp` and now declared explicitly. JWKS is fetched with the injected httpx client and parsed with `jwt.PyJWKSet`. `PyJWKClient` is not used, because it calls urllib directly and cannot be injected. |
| Token endpoint authentication | `client_secret_basic` when discovery lists it (or lists nothing, per OIDC defaults), otherwise `client_secret_post`. Entra, Okta and Google accept either. |
| Which providers the admin site supports | Two choices: `Microsoft Entra ID`, and `Other OpenID Connect provider (Okta, Google, Auth0, Duo, Keycloak)`. Both use the same generic OIDC code with discovery. The Entra choice adds the tenant check and the optional Graph lookup. The Duo and Auth0 adapters in `auth/idp` stay as they are, for the env-configured MCP bridge (`U2_AUTH_ENABLED`). |
| Where the pending sign-in lives | Not in the database. State, nonce, PKCE verifier, purpose and `next` are sealed (Fernet, through `SecretBox`) into the `u2_admin_sso` cookie, with a 600-second TTL. That binds the round trip to the browser that started it, which is the login-CSRF protection for the callback. The cookie is deleted on every callback outcome, so a code cannot be replayed. |
| Starting sign-in | `POST /admin/sign-in/sso` with the pre-session CSRF token, from a button on the sign-in page. The Settings and wizard Test button is `POST /admin/settings/sso/test` (admin only), which opens in a new window (`target="_blank"`) as the spec's pop-up. |
| Test sign-in side effects | None in the users, groups or sessions tables. The callback shows the subject, email, name and groups (or the overage) and writes one `settings.sso_test` audit row. The admin's own session is untouched. |
| Entra group overage | When the token signals overage, the groups are looked up through Graph if the admin ticked the Graph option (Entra only), using the same client id and secret with the client-credentials grant. If Graph is off or fails, the user signs in with no groups and `groups_unavailable` set. That is the existing store behaviour, and the Users pages already flag it. The Dashboard now also warns and names them. The Graph resolver is a constructor argument everywhere (`http` factory), so tests never touch the network. |
| MCP OAuth from the stored settings | **Env-configured OAuth** (`U2_AUTH_ENABLED=true`) keeps working as before. In team mode the bridge now validates the ID token, when the identity provider returns one, and merges its claims, so Entra groups survive (userinfo carries none). It also records sign-ins through the shared recorder. **Stored settings:** when `U2_AUTH_ENABLED` is off, team mode has stored company sign-in with a readable secret, and the public URL is https (or localhost), the server builds the bridge at startup with `GenericOIDCAdapter` and issuer = the public URL. A restart applies changes, and `RESTART_NOTE` says so. My access shows the VS Code OAuth snippet only when the bridge is actually on (`AdminContext.mcp_oauth`). |
| `make_sign_in_handler` becomes async | Graph is an HTTP call, so the handler is a coroutine function. `U2OAuthProvider` awaits `on_sign_in` when it returns an awaitable, so a plain function (`seen.append` in the tests) still works. The four existing synchronous `TestSignIn` tests become async. |
| Freshness days | Still `U2_TOKEN_FRESHNESS_DAYS` from the environment. It is not a Settings field (YAGNI). `tokens.is_fresh` is the one rule, used by `verify_token` and by the pages (`Paused`). |
| Argon2 off the event loop | Sign-in runs `verify_password` and the rehash in a 4-thread `ThreadPoolExecutor` (thread names `argon2…`), so a burst of sign-ins cannot stall MCP traffic. At most four 64 MiB hashes run at once. The executor works with any event loop, unlike an anyio limiter created at import. |
| CORS and `/admin` (2a review M-5) | `U2_HTTP_CORS_ORIGINS` applies to everything except `/admin`. A small ASGI wrapper (`CorsOutsideAdmin`) sends `/admin` past `CORSMiddleware`, so a listed origin can never read admin pages with the session. |
| TLS without a proxy | `U2_TLS_CERT` and `U2_TLS_KEY` (spec "Deployment") are passed to uvicorn as `ssl_certfile` and `ssl_keyfile`. Setting only one of them is a configuration error. |
| `uopy` in the image | `uopy` 1.4.0 is on PyPI (`pip index versions uopy` lists 1.1.0 to 1.4.0), so `pip install .` in the Dockerfile installs it normally. The test target adds `tests/mocks` and sets `U2_DRIVER=tests.mocks.sim_driver`. The release target has no test code. A CI step proves that. |
| Health check | `python:3.12-slim` has no curl, so the Dockerfile `HEALTHCHECK` uses `python -c` with `urllib.request` against `http://127.0.0.1:${U2_HTTP_PORT}/health`. |
| Proxy examples | `deploy/caddy/` and `deploy/nginx/` each have a compose file (u2-mcp plus the proxy on a fixed-subnet network, with `U2_TRUSTED_PROXIES` set to the proxy's fixed address) and the proxy config. CI starts both on port 80 and checks `/health` and `/admin/sign-in` through the proxy. The forwarded-header semantics themselves are proven by unit tests (Task 1). |
| README | Rewritten for team mode (coordinator's extra requirement, Task 13). It leads with Docker and the setup wizard: servers, accounts and U2 logins are added on the admin site. Single-user stdio moves into a short section that links to `docs/configuration.md`. Acknowledgments stay verbatim. |
| Cheap 2b minors folded in | Task 2 moves the rehash after the local-sign-in-off refusal (2b Minor 7). Task 6 changes the checklist to say `Created`, without naming the viewer (2b Minor 6). Task 2 adds the non-admin route-table sweep (2b Minor 12). Task 9 adds the per-person U2 login hint (2b ledger T1). |

## Deferred (not in phase 3), with reasons

| Item | Source | Why it waits |
|---|---|---|
| `__Host-` prefix on the session cookie | 2a review, phase 3 | `__Host-` forces `Path=/`, which would send the admin session to the MCP endpoint too. The login-CSRF risk the review named comes from the pre-session cookie, which this phase prefixes. |
| SQLite calls on the event loop | 2a review, Task 8 concern | Each is sub-millisecond on a local file. Argon2 was the real stall, and it moves to a thread pool. Moving the store would touch every handler. |
| Per-process limiter, reveal store and registry | 2a/2b ledgers | The server is one process by design. `docs/admin.md` says to run one replica. |
| Cap on stuck connection-check threads | 2a Task 5 | Needs a check-runner redesign. A stuck check is bounded by its own 10-second timeout, and only admins can start checks. |
| e2e free-port race | 2a Task 11 | Rare (bind between probe and use), and a retry would hide real start-up failures. |
| Whether turning local sign-in off ends live sessions and tokens | 2b Minor 3 | Product decision. It stays "new sign-ins only", as documented in 2b. `docs/admin.md` repeats it. |
| The reactivation message reaching the MCP client | Spec, personal access tokens | The MCP SDK's bearer middleware answers every refused token with a fixed 401. The reason is logged, and My access and Users explain it. |
| `grant_u2_password` vs `grant_u2_login` when no login was stored; cleared count outside the transaction; N+1 in `grant_rows` | 2b ledger T1 | No behaviour or security effect. Small refactors best done with the next grants change. |
| VS snippet keys `type`/`headers` unconfirmed | 2b ledger T2 | Needs a real Visual Studio. It goes into `docs/admin.md`'s manual acceptance checklist (Task 12). |
| htmx admin GET from a non-admin gets the full My access page | 2b ledger T2 | Reachable only by a non-admin who already holds an admin page's htmx form. No data is exposed. |
| Role tests (crafted POST to a built-in role, FK backstop, stale-edit re-read), StoreError substring mapping | 2b ledger T5 | Test hygiene; guarded in both services and store today. |
| Stale `last_check:<id>` rows after delete; CSV built in memory | 2b ledger T6 | Ids are never reused, so stale rows are invisible. Audit volumes are small. |
| Token-policy 400 re-render shows the stored cap; rate limiter counts successful password changes; two unused store setters (`set_user_admin`, `set_user_disabled`, still used by many tests); duplicate `_redirect` and digit parsing | 2b Minors 5, 8, 9, 13 | Polish with no user-facing risk. |
| Test-hygiene items 2b deferred: `filterwarnings` on base `Warning`, docstrings on 2a config tests, the no-op `.replace`, migration tests from `SCHEMA_VERSION` | 2b plan | Unchanged reasoning: no behaviour change. |
| JWKS and discovery caching | New | Two extra requests per sign-in are acceptable for an admin site. Caching adds key-rotation edge cases. |
| ES256 and other ID-token algorithms | New | Entra, Okta, Google, Auth0 and Duo all sign ID tokens with RS256 by default. |

## File structure

Create:

| File | Responsibility |
|---|---|
| `src/u2_mcp/proxy.py` | `resolve()`: the real client address and scheme behind trusted proxies |
| `src/u2_mcp/auth/oidc_client.py` | `OidcClient`, `PendingLogin`, `OidcError`, `default_http`: discovery, PKCE, exchange, ID-token validation |
| `src/u2_mcp/auth/graph.py` | `GraphGroups`: Entra overage lookup |
| `src/u2_mcp/sso_config.py` | `SsoSettings`, load/store/clear, seeding from `U2_IDP_*`, builders for the OIDC client and overage resolver |
| `src/u2_mcp/admin/sso_services.py` | `SsoForm`, `save_sso`, `remove_sso`, `sso_context`: the one save path for the wizard and Settings |
| `src/u2_mcp/admin/routes_sso.py` | `POST /sign-in/sso`, `GET /sign-in/sso/callback`, `POST /settings/sso/test` (saving and clearing SSO live in `routes_setup.py` beside the other Settings handlers) |
| `src/u2_mcp/admin/templates/partials/sso_form.html`, `setup/sso.html`, `sso_test.html` | The SSO form, the wizard step, the test result |
| `tests/mocks/oidc_provider.py` | The mock OIDC provider |
| `tests/test_proxy.py`, `tests/test_mock_oidc_provider.py`, `tests/test_auth/test_oidc_client.py`, `tests/test_auth/test_graph.py`, `tests/test_sso_config.py` | Unit tests |
| `tests/test_admin/test_proxy_headers.py`, `test_hardening_3.py`, `test_sso_settings.py`, `test_sso_sign_in.py`, `test_mcp_sso.py`, `test_freshness_ui.py` | Admin and server tests |
| `tests/e2e/test_sso.py` | SSO browser tests |
| `Dockerfile`, `.dockerignore`, `docker-compose.yml`, `deploy/caddy/Caddyfile`, `deploy/caddy/docker-compose.yml`, `deploy/nginx/default.conf`, `deploy/nginx/docker-compose.yml` | Deployment |
| `docs/admin.md` | The admin guide |

Modify: `pyproject.toml`, `src/u2_mcp/config.py`, `server.py`, `team_auth.py`, `tokens.py`, `access.py`, `cli.py`, `setup_code.py`, `store/crypto.py`, `store/repo.py`, `store/bootstrap.py`, `auth/provider.py`, `admin/context.py`, `admin/security.py`, `admin/app.py`, `admin/routes_auth.py`, `admin/routes_setup.py`, `admin/routes_me.py`, `admin/routes_users.py`, `admin/routes_audit.py`, `admin/services.py`, templates (`sign_in.html`, `settings.html`, `setup/done.html`, `partials/setup_checklist.html`, `me.html`, `users/detail.html`, `users/access.html`, `dashboard.html`), `tests/test_admin/helpers.py`, `tests/test_admin/test_route_table.py`, `tests/test_admin/test_routes_setup.py`, `tests/test_team_auth.py`, `tests/e2e/conftest.py`, `tests/e2e/wizard.py`, `tests/e2e/test_setup_wizard.py`, `tests/e2e/test_everyday_pages.py`, `.github/workflows/ci.yml`, `README.md`, `docs/configuration.md`, `docs/oauth.md`, `CHANGELOG.md`, `docs/superpowers/plans/2026-10-30-admin-ui-roadmap.md`.

Task order:
1. trusted proxies (everything later reads the resolved client)
2. small sign-in hardening
3. mock provider
4. OIDC client and Graph
5. the shared recorder
6. SSO settings and the wizard step
7. admin SSO sign-in
8. MCP OAuth from the stored settings
9. freshness in the UI
10. Docker and CI
11. SSO browser tests
12. docs
13. README

The server works after each task.

---

### Task 1: Trusted reverse-proxy headers

**Files:**
- Create: `src/u2_mcp/proxy.py`, `tests/test_proxy.py`, `tests/test_admin/test_proxy_headers.py`
- Modify:
  - `src/u2_mcp/config.py`: the new field, and network parsing shared with the allowlist
  - `src/u2_mcp/team_auth.py`: `ClientAddressMiddleware`
  - `src/u2_mcp/server.py`: the middleware argument, and `proxy_headers=False` in both `uvicorn.run` calls
  - `tests/test_admin/helpers.py`: `team_server`
  - `tests/test_config.py`

**Interfaces:**
- **Produces, `config.py`:**
  - `Network = ipaddress.IPv4Network | ipaddress.IPv6Network`
  - `U2Config.trusted_proxies: str | None`, with the alias `U2_TRUSTED_PROXIES`
  - `U2Config.trusted_proxy_networks -> list[Network]`, a property
- **Produces, `proxy.py`:**
  - `parse_ip(value: str) -> IPv4Address | IPv6Address | None`. It unwraps IPv4-mapped IPv6 and drops the port from an IPv4 `a.b.c.d:port`.
  - `resolve(peer: str | None, headers: Sequence[tuple[bytes, bytes]], scheme: str, trusted: Sequence[Network]) -> tuple[str | None, str]`
- **Produces, `team_auth.py`:** `ClientAddressMiddleware(app, trusted_proxies: Sequence[Network] = ())`. It rewrites `scope["client"]` and `scope["scheme"]` for everything inside it.
- **Produces, `tests/test_admin/helpers.py`:** `team_server(tmp_path, monkeypatch, *, client=("testclient", 50000), **env) -> ContextManager[TestClient]`. It runs the whole server in team mode and tears it down afterwards. Later tasks use it.

- [ ] **Step 1: Write the failing unit tests**

Create `tests/test_proxy.py`:

```python
"""Believing X-Forwarded-* only from the proxies named in U2_TRUSTED_PROXIES."""

import ipaddress

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from u2_mcp.proxy import parse_ip, resolve
from u2_mcp.team_auth import ClientAddressMiddleware

PROXY = [ipaddress.ip_network("10.0.0.0/8")]


def _h(**values: str) -> list[tuple[bytes, bytes]]:
    return [(k.replace("_", "-").encode(), v.encode()) for k, v in values.items()]


@pytest.mark.parametrize(
    ("peer", "headers", "trusted", "expected"),
    [
        ("203.0.113.9", _h(x_forwarded_for="198.51.100.1"), [], ("203.0.113.9", "http")),
        ("203.0.113.9", _h(x_forwarded_for="198.51.100.1"), PROXY, ("203.0.113.9", "http")),
        ("10.0.0.2", _h(x_forwarded_for="198.51.100.1"), PROXY, ("198.51.100.1", "http")),
        # A client-supplied leftmost entry is never believed: the walk stops at the
        # first address the trusted proxy itself saw.
        ("10.0.0.2", _h(x_forwarded_for="6.6.6.6, 198.51.100.1, 10.0.0.3"), PROXY,
         ("198.51.100.1", "http")),
        ("10.0.0.2", _h(x_forwarded_for="10.0.0.5, 10.0.0.3"), PROXY, ("10.0.0.5", "http")),
        ("10.0.0.2", _h(x_forwarded_for="garbage, 10.0.0.3"), PROXY, ("10.0.0.3", "http")),
        ("10.0.0.2", [], PROXY, ("10.0.0.2", "http")),
        ("::ffff:10.0.0.2", _h(x_forwarded_for="198.51.100.1"), PROXY, ("198.51.100.1", "http")),
        ("10.0.0.2", _h(x_forwarded_proto="https"), PROXY, ("10.0.0.2", "https")),
        ("10.0.0.2", _h(x_forwarded_proto="http, https"), PROXY, ("10.0.0.2", "https")),
        ("10.0.0.2", _h(x_forwarded_proto="gopher"), PROXY, ("10.0.0.2", "http")),
        ("203.0.113.9", _h(x_forwarded_proto="https"), PROXY, ("203.0.113.9", "http")),
        ("testclient", _h(x_forwarded_for="198.51.100.1"), PROXY, ("testclient", "http")),
        (None, _h(x_forwarded_for="198.51.100.1"), PROXY, (None, "http")),
    ],
)
def test_resolve(
    peer: str | None,
    headers: list[tuple[bytes, bytes]],
    trusted: list[ipaddress.IPv4Network],
    expected: tuple[str | None, str],
) -> None:
    assert resolve(peer, headers, "http", trusted) == expected


def test_several_forwarded_for_headers_are_read_as_one_list() -> None:
    headers = [(b"x-forwarded-for", b"198.51.100.1"), (b"x-forwarded-for", b"10.0.0.3")]
    assert resolve("10.0.0.2", headers, "http", PROXY) == ("198.51.100.1", "http")


@pytest.mark.parametrize(
    ("value", "expected"),
    [("1.2.3.4", "1.2.3.4"), ("1.2.3.4:5678", "1.2.3.4"), ("[::1]", "::1"),
     ("::ffff:1.2.3.4", "1.2.3.4"), ("nope", None), ("", None)],
)
def test_parse_ip(value: str, expected: str | None) -> None:
    parsed = parse_ip(value)
    assert (str(parsed) if parsed is not None else None) == expected


def _echo_app(trusted: list[ipaddress.IPv4Network]) -> TestClient:
    async def echo(request: Request) -> PlainTextResponse:
        host = request.client.host if request.client else "-"
        return PlainTextResponse(f"{host} {request.url.scheme}")

    app = ClientAddressMiddleware(Starlette(routes=[Route("/", echo)]), trusted_proxies=trusted)
    return TestClient(app, client=("10.0.0.2", 4000))


def test_the_middleware_rewrites_client_and_scheme_for_everything_inside_it() -> None:
    with _echo_app(PROXY) as client:
        response = client.get(
            "/", headers={"X-Forwarded-For": "198.51.100.1", "X-Forwarded-Proto": "https"}
        )
    assert response.text == "198.51.100.1 https"


def test_without_trusted_proxies_the_headers_change_nothing() -> None:
    with _echo_app([]) as client:
        response = client.get(
            "/", headers={"X-Forwarded-For": "198.51.100.1", "X-Forwarded-Proto": "https"}
        )
    assert response.text == "10.0.0.2 http"
```

Then add to `tests/test_config.py`. If the file lacks the `pytest` or `U2Config` import, add it.

```python
def test_trusted_proxies_parse_and_reject_garbage(
    monkeypatch: pytest.MonkeyPatch, mock_env: dict[str, str]
) -> None:
    monkeypatch.setenv("U2_TRUSTED_PROXIES", "10.0.0.1, 172.16.0.0/12,")
    networks = [str(n) for n in U2Config().trusted_proxy_networks]
    assert networks == ["10.0.0.1/32", "172.16.0.0/12"]
    monkeypatch.setenv("U2_TRUSTED_PROXIES", "proxy.local")
    with pytest.raises(ValueError, match="U2_TRUSTED_PROXIES entry 'proxy.local'"):
        U2Config()


def test_no_trusted_proxies_by_default(mock_env: dict[str, str]) -> None:
    assert U2Config().trusted_proxy_networks == []
```

- [ ] **Step 2: Run them and confirm they fail**

Run: `.venv/Scripts/python -m pytest tests/test_proxy.py tests/test_config.py -q`

Expected:
- The proxy tests FAIL with `ModuleNotFoundError: No module named 'u2_mcp.proxy'`.
- The config tests FAIL with an `AttributeError` on `trusted_proxy_networks`.

- [ ] **Step 3: Implement `src/u2_mcp/proxy.py`**

```python
"""Believe X-Forwarded-* headers only from the reverse proxies named in U2_TRUSTED_PROXIES.

Behind a proxy every request arrives from the proxy's address. Without this, one
person's failed sign-ins would lock everyone out (the limiter keys on address),
U2_ADMIN_ALLOWED_IPS would see only the proxy, and https would look like http.

Anyone can send these headers, so they are believed only when the direct peer is
a configured proxy. X-Forwarded-For is walked from the right, the end the proxies
appended to, and the first address that is not itself a trusted proxy is the
client. Entries further left were written by the client and are ignored.
X-Forwarded-Host is not applied: every URL this server builds comes from its
saved public address.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
Address = ipaddress.IPv4Address | ipaddress.IPv6Address


def parse_ip(value: str) -> Address | None:
    """Parse one address as proxies write it: bare, bracketed, or IPv4 with a port."""
    text = value.strip()
    if text.startswith("[") and "]" in text:
        text = text[1 : text.index("]")]
    elif text.count(":") == 1 and "." in text:
        text = text.split(":", 1)[0]
    try:
        address: Address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _trusted(address: Address, networks: Sequence[Network]) -> bool:
    return any(address in network for network in networks)


def _values(headers: Sequence[tuple[bytes, bytes]], name: bytes) -> list[str]:
    found: list[str] = []
    for key, value in headers:
        if key.lower() == name:
            found += [part.strip() for part in value.decode("latin-1").split(",")]
    return [part for part in found if part]


def resolve(
    peer: str | None,
    headers: Sequence[tuple[bytes, bytes]],
    scheme: str,
    trusted: Sequence[Network],
) -> tuple[str | None, str]:
    """Return the address and scheme the request really came from.

    Args:
        peer: The direct peer's address (ASGI scope["client"][0])
        headers: The raw ASGI headers
        scheme: The scheme of the connection to this server
        trusted: U2_TRUSTED_PROXIES as networks

    Returns:
        (client address, scheme); the peer and scheme unchanged unless the peer
        is a trusted proxy
    """
    peer_address = parse_ip(peer) if peer else None
    if peer_address is None or not _trusted(peer_address, trusted):
        return peer, scheme
    client = str(peer_address)
    for hop in reversed(_values(headers, b"x-forwarded-for")):
        address = parse_ip(hop)
        if address is None:
            break  # unreadable: keep the last address a trusted proxy vouched for
        client = str(address)
        if not _trusted(address, trusted):
            break
    protos = _values(headers, b"x-forwarded-proto")
    if protos and protos[-1].lower() in ("http", "https"):
        scheme = protos[-1].lower()
    return client, scheme
```

- [ ] **Step 4: Add the config field and shared parsing** (`src/u2_mcp/config.py`)

1. Add a module-level helper after the imports:

   ```python
   Network = ipaddress.IPv4Network | ipaddress.IPv6Network
   _LIST_ALIASES = {"admin_allowed_ips": "U2_ADMIN_ALLOWED_IPS", "trusted_proxies": "U2_TRUSTED_PROXIES"}


   def _networks(value: str | None) -> list[Network]:
       """Parse a comma-separated list of addresses or CIDR networks; blank entries are skipped."""
       if not value:
           return []
       return [
           ipaddress.ip_network(part.strip(), strict=False)
           for part in value.split(",")
           if part.strip()
       ]
   ```

2. Add the field after `admin_allowed_ips`:

   ```python
       trusted_proxies: str | None = Field(
           default=None,
           alias="U2_TRUSTED_PROXIES",
           description=(
               "Comma-separated addresses or CIDR networks of reverse proxies whose "
               "X-Forwarded-For and X-Forwarded-Proto headers are believed. Unset trusts none."
           ),
       )
   ```

3. Replace `_check_admin_allowed_ips` with one validator for both fields. Import `ValidationInfo` from `pydantic`. The error text for `U2_ADMIN_ALLOWED_IPS` stays the same.

   ```python
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
   ```

4. Change the body of `admin_allowed_networks` to `return _networks(self.admin_allowed_ips)` and its return annotation to `list[Network]`.

5. Add the new property:

   ```python
       @property
       def trusted_proxy_networks(self) -> list[Network]:
           """Return U2_TRUSTED_PROXIES as networks; empty means trust no forwarded header."""
           return _networks(self.trusted_proxies)
   ```

- [ ] **Step 5: Replace the middleware** (`ClientAddressMiddleware` in `src/u2_mcp/team_auth.py`)

```python
class ClientAddressMiddleware:
    """Resolve the caller's real address and scheme, and record the address.

    Outermost on the app, so the admin allowlist, the sign-in limiter, audit rows,
    https detection and token last-used addresses all see the client behind a
    trusted proxy (U2_TRUSTED_PROXIES), never the proxy. Pure ASGI rather than
    BaseHTTPMiddleware, so the context variable is set in the same task the
    authentication middleware runs in.
    """

    def __init__(self, app: Any, trusted_proxies: Sequence[Network] = ()) -> None:
        self.app = app
        self.trusted = list(trusted_proxies)

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        peer = client[0] if client else None
        address, scheme = resolve(
            peer, scope.get("headers") or [], scope.get("scheme", "http"), self.trusted
        )
        if address != peer or scheme != scope.get("scheme"):
            scope = dict(scope)
            scope["client"] = (address, client[1] if client else 0)
            scope["scheme"] = scheme
        token = _client_ip.set(address)
        try:
            await self.app(scope, receive, send)
        finally:
            _client_ip.reset(token)
```

Add the imports: extend the existing line to `from collections.abc import Callable, Sequence`, and add `from .proxy import Network, resolve`.

- [ ] **Step 6: Wire the middleware into `server.py`**

In `build_streamable_http_app`, change the last middleware line:

```python
    # Outermost, so every layer (and the admin site) sees the client behind a trusted proxy.
    app.add_middleware(ClientAddressMiddleware, trusted_proxies=config.trusted_proxy_networks)
```

In `run_sse_server` and in `run_streamable_http_server`, add `proxy_headers=False` to `uvicorn.run(...)`. Put this comment above each call:

```python
    # Uvicorn would otherwise believe X-Forwarded-* from 127.0.0.1 by itself;
    # U2_TRUSTED_PROXIES (ClientAddressMiddleware) is the only source of that trust.
```

- [ ] **Step 7: Add the `team_server` helper** (append to `tests/test_admin/helpers.py`)

Move the new imports to the top of the file, next to the existing ones.

```python
import contextlib
from collections.abc import Iterator
from pathlib import Path

import pytest

from u2_mcp import server
from u2_mcp.config import U2Config
from u2_mcp.identity import set_identity_resolver
from u2_mcp.store import install_store


@contextlib.contextmanager
def team_server(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    client: tuple[str, int] = ("testclient", 50000),
    **env: str,
) -> Iterator[TestClient]:
    """The whole server in team mode, as `u2-mcp --streamable-http` serves it.

    Global state the server installs (store, identity resolver, registry) is undone
    afterwards, as tests/test_admin/test_app.py's team_app fixture does.
    """
    for name in ("U2_HOST", "U2_USER", "U2_PASSWORD", "U2_ACCOUNT"):
        monkeypatch.delenv(name, raising=False)
    base = {
        "U2_SECRET_KEY": "a" * 40,
        "U2_DATA_DIR": str(tmp_path),
        "U2_WATCHDOG_ENABLED": "false",
        "U2_AUDIT_ENABLED": "false",
    }
    for key, value in {**base, **env}.items():
        monkeypatch.setenv(key, value)
    app = server.build_streamable_http_app(U2Config())
    try:
        with TestClient(app, client=client) as test_client:
            yield test_client
    finally:
        install_store(None)
        set_identity_resolver(None)
        server.reset_connection_manager()
```

- [ ] **Step 8: Write the server-level tests** (`tests/test_admin/test_proxy_headers.py`)

```python
"""The admin site sees the client behind a trusted proxy, and nobody else's claims."""

from pathlib import Path

import pytest
import uvicorn

from u2_mcp import server
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import finish_setup
from u2_mcp.store import get_store

from .helpers import PASSWORD, csrf_from, team_server

PROXY_PEER = ("10.0.0.1", 5000)


def test_the_allowlist_sees_the_client_behind_a_trusted_proxy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with team_server(
        tmp_path, monkeypatch, client=PROXY_PEER,
        U2_TRUSTED_PROXIES="10.0.0.1", U2_ADMIN_ALLOWED_IPS="203.0.113.7",
    ) as client:
        allowed = client.get(
            "/admin/sign-in", headers={"X-Forwarded-For": "203.0.113.7"}, follow_redirects=False
        )
        proxy_itself = client.get("/admin/sign-in", follow_redirects=False)
        other = client.get(
            "/admin/sign-in", headers={"X-Forwarded-For": "198.51.100.1"}, follow_redirects=False
        )
    assert allowed.status_code in (200, 303)
    assert proxy_itself.status_code == 403
    assert other.status_code == 403


def test_forwarded_headers_from_an_untrusted_peer_are_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with team_server(
        tmp_path, monkeypatch, client=PROXY_PEER, U2_ADMIN_ALLOWED_IPS="203.0.113.7"
    ) as client:
        response = client.get(
            "/admin/sign-in", headers={"X-Forwarded-For": "203.0.113.7"}, follow_redirects=False
        )
    assert response.status_code == 403


def test_people_behind_one_proxy_have_their_own_sign_in_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with team_server(
        tmp_path, monkeypatch, client=PROXY_PEER, U2_TRUSTED_PROXIES="10.0.0.1"
    ) as client:
        store = get_store()
        store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
        finish_setup(store)

        def attempt(ip: str, username: str) -> int:
            headers = {"X-Forwarded-For": ip}
            page = client.get("/admin/sign-in", headers=headers)
            data = {"csrf_token": csrf_from(page.text), "username": username,
                    "password": "wrong", "next": ""}
            response = client.post(
                "/admin/sign-in", headers=headers, data=data, follow_redirects=False
            )
            return response.status_code

        # Different usernames, so only the per-address bucket can trip.
        assert [attempt("198.51.100.1", f"user{i}") for i in range(6)] == [401] * 5 + [429]
        assert attempt("198.51.100.2", "someone") == 401
        assert "198.51.100.2" in str(store.recent_audit(1)[0])


def test_uvicorn_believes_no_forwarded_headers_itself(
    monkeypatch: pytest.MonkeyPatch, mock_env: dict[str, str]
) -> None:
    seen: dict[str, object] = {}
    monkeypatch.setenv("U2_WATCHDOG_ENABLED", "false")
    monkeypatch.setenv("U2_AUDIT_ENABLED", "false")
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: seen.update(kwargs))
    server.run_streamable_http_server()
    assert seen["proxy_headers"] is False
```

`get_store()` is the accessor `server.py` imports from `.store`. `build_streamable_http_app` installs the store, so it is available here.

- [ ] **Step 9: Run the tests and confirm they pass**

Run: `.venv/Scripts/python -m pytest tests/test_proxy.py tests/test_config.py tests/test_admin/test_proxy_headers.py -q`
Expected: PASS.

Then run the Global Constraints checks. No page changes, so the e2e suite is not needed.

- [ ] **Step 10: Commit**

```bash
git add src/u2_mcp/proxy.py src/u2_mcp/config.py src/u2_mcp/team_auth.py src/u2_mcp/server.py tests/test_proxy.py tests/test_config.py tests/test_admin/test_proxy_headers.py tests/test_admin/helpers.py
git commit -m "feat: trusted reverse-proxy headers (U2_TRUSTED_PROXIES)

The allowlist, sign-in limiter, audit and https detection see the client
behind a configured proxy. Uvicorn's own forwarded-header trust is off.

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
git push origin feature/phase3-sso-deploy
```

---

### Task 2: Sign-in hardening

Four changes: the pre-session cookie gets the `__Host-` prefix, argon2 moves off the event loop, CORS no longer covers `/admin`, and a route-table sweep covers non-admins.

**Files:**
- Modify:
  - `src/u2_mcp/admin/security.py`
  - `src/u2_mcp/admin/routes_auth.py`
  - `src/u2_mcp/admin/routes_setup.py` (`_admin_page`)
  - `src/u2_mcp/server.py` (CORS)
  - `tests/test_admin/helpers.py` (the `admin_client` base URL)
  - `tests/test_admin/test_route_table.py`
- Create: `tests/test_admin/test_hardening_3.py`

**Interfaces:**
- **Consumes:** `team_server` (Task 1).
- **Produces, `security.py`:**
  - `HOST_PREFIX = "__Host-"`
  - `cookie_name(base: str, secure: bool) -> str`
  - `cookie_path(secure: bool) -> str`: `"/"` when secure, otherwise `"/admin"`
  - `presession_token(request, *, secure: bool) -> str`: the signature changes
  - `set_presession_cookie(response, token, *, secure)`: the cookie is now prefixed when secure
  - `read_form`: reads whichever pre-session cookie name applies
- **Produces, `routes_auth.py`:** `argon2_call(fn, *args) -> Awaitable[T]`. It runs `fn` in a 4-thread pool named `argon2`.
- **Produces, `server.py`:** `class CorsOutsideAdmin` (ASGI), built as `CorsOutsideAdmin(app, **cors_kwargs)`.
- **Produces, `helpers.py`:** `admin_client(ctx, client=..., base_url="http://testserver")`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_admin/test_hardening_3.py`:

```python
"""Phase 3 hardening: __Host- pre-session cookie, argon2 off the loop, CORS outside /admin."""

import threading
from pathlib import Path

import pytest

from u2_mcp.admin import routes_auth
from u2_mcp.admin.context import AdminContext
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import finish_setup

from .helpers import PASSWORD, admin_client, sign_in, team_server


def _ready(ctx: AdminContext, public_url: str | None = None) -> None:
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    finish_setup(ctx.store)
    if public_url:
        ctx.store.set_setting("public_url", public_url)


def test_over_https_the_presession_cookie_is_host_prefixed(ctx: AdminContext) -> None:
    _ready(ctx, "https://u2.example.com")
    with admin_client(ctx, base_url="https://testserver") as client:
        page = client.get("/admin/sign-in")
        cookie = page.headers["set-cookie"]
        assert cookie.startswith("__Host-u2_admin_presession=")
        assert "Path=/;" in cookie and "Secure" in cookie
        assert sign_in(client).status_code == 303  # type: ignore[attr-defined]


def test_over_https_a_planted_unprefixed_cookie_is_not_a_csrf_token(ctx: AdminContext) -> None:
    _ready(ctx, "https://u2.example.com")
    with admin_client(ctx, base_url="https://testserver") as client:
        client.cookies.set("u2_admin_presession", "planted", domain="testserver", path="/admin")
        response = client.post(
            "/admin/sign-in",
            data={"csrf_token": "planted", "username": "ann", "password": PASSWORD, "next": ""},
            follow_redirects=False,
        )
    assert response.status_code == 403


def test_over_http_the_cookie_keeps_its_plain_name(ctx: AdminContext) -> None:
    _ready(ctx)
    with admin_client(ctx) as client:
        cookie = client.get("/admin/sign-in").headers["set-cookie"]
    assert cookie.startswith("u2_admin_presession=") and "Path=/admin" in cookie


def test_sign_in_checks_the_password_off_the_event_loop(
    ctx: AdminContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    threads: list[str] = []
    real = routes_auth.verify_password

    def spy(stored: str | None, password: str) -> bool:
        threads.append(threading.current_thread().name)
        return real(stored, password)

    monkeypatch.setattr(routes_auth, "verify_password", spy)
    _ready(ctx)
    with admin_client(ctx) as client:
        assert sign_in(client).status_code == 303  # type: ignore[attr-defined]
    assert threads and threads[0].startswith("argon2")


def test_a_refused_local_sign_in_does_not_rehash(
    ctx: AdminContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    bob = ctx.store.add_local_user("bob", password_hash=hash_password(PASSWORD))
    _ready(ctx)
    ctx.store.set_setting("local_accounts_enabled", False)
    monkeypatch.setattr(routes_auth, "needs_rehash", lambda _hash: True)
    before = ctx.store.password_hash(bob.id)
    with admin_client(ctx) as client:
        assert sign_in(client, "bob").status_code == 403  # type: ignore[attr-defined]
    assert ctx.store.password_hash(bob.id) == before


def test_cors_headers_are_never_sent_for_the_admin_site(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    origin = {"Origin": "https://app.example"}
    with team_server(
        tmp_path, monkeypatch, U2_HTTP_CORS_ORIGINS="https://app.example"
    ) as client:
        health = client.get("/health", headers=origin)
        admin = client.get("/admin/sign-in", headers=origin, follow_redirects=False)
    assert health.headers.get("access-control-allow-origin") == "https://app.example"
    assert "access-control-allow-origin" not in admin.headers
```

Then add this test to `tests/test_admin/test_route_table.py`. Import `csrf_from` from `.helpers`.

```python
NON_ADMIN_GETS = {"/sign-in", "/me", "/account/password"}
NON_ADMIN_POSTS = {"/sign-in", "/sign-out", "/me/tokens", "/me/tokens/1/revoke", "/account/password"}


def test_people_who_are_not_admins_reach_only_their_own_pages(ctx: AdminContext) -> None:
    finish_setup(ctx.store)
    _seed(ctx)
    ctx.store.add_local_user("bob", password_hash=hash_password(PASSWORD))
    with admin_client(ctx) as client:
        sign_in(client, "bob")
        token = csrf_from(client.get("/admin/me").text)
        before = len(ctx.store.recent_audit(1000))
        for method, path in _routes(ctx):
            if path.startswith("/setup"):
                continue  # setup is finished: those answer with a redirect home
            if method == "GET" and path not in NON_ADMIN_GETS:
                response = client.get(f"/admin{path}", follow_redirects=False)
                assert response.status_code == 303, path
                assert response.headers["location"] == "/admin/me", path
            elif method == "POST" and path not in NON_ADMIN_POSTS:
                response = client.post(
                    f"/admin{path}", data={"csrf_token": token}, follow_redirects=False
                )
                assert response.status_code == 403, path
                assert "Only admins can use this page." in response.text, path
        assert len(ctx.store.recent_audit(1000)) == before
```

- [ ] **Step 2: Run them and check the failures**

Run: `.venv/Scripts/python -m pytest tests/test_admin/test_hardening_3.py tests/test_admin/test_route_table.py -q`

Expected:
- The `__Host-`, argon2, rehash and CORS tests FAIL.
- Tests that pass `base_url` to `admin_client` FAIL with a `TypeError`, because it does not accept that argument yet.
- The non-admin sweep already PASSES. It locks in today's behaviour (2b Minor 12).

- [ ] **Step 3: Let `admin_client` take a base URL** (`tests/test_admin/helpers.py`)

```python
def admin_client(
    ctx: AdminContext,
    client: tuple[str, int] = ("10.0.0.1", 5000),
    base_url: str = "http://testserver",
) -> TestClient:
    """A test client for the admin site mounted at /admin, as the server mounts it."""
    app = Starlette(routes=[Mount("/admin", app=build_admin_app(ctx))])
    return TestClient(app, client=client, base_url=base_url)
```

- [ ] **Step 4: Name the pre-session cookie by scheme** (`src/u2_mcp/admin/security.py`)

Add these after the constants:

```python
HOST_PREFIX = "__Host-"


def cookie_name(base: str, secure: bool) -> str:
    """The cookie's name: `__Host-` over https, which binds it to this exact host.

    A sibling subdomain cannot plant a `__Host-` cookie, which closes login CSRF
    through a planted pre-session token. Browsers accept the prefix only together
    with Secure and Path=/, so over plain http the plain name is used.
    """
    return HOST_PREFIX + base if secure else base


def cookie_path(secure: bool) -> str:
    """`__Host-` cookies must use Path=/; plain ones stay scoped to /admin."""
    return "/" if secure else _COOKIE_PATH
```

Replace `presession_token` and `set_presession_cookie`:

```python
def presession_token(request: Request, *, secure: bool) -> str:
    """The CSRF token for forms shown before sign-in (double-submit cookie)."""
    return request.cookies.get(cookie_name(PRESESSION_COOKIE, secure)) or secrets.token_urlsafe(32)


def set_presession_cookie(response: Response, token: str, *, secure: bool) -> None:
    """Set the pre-sign-in CSRF cookie (`__Host-` prefixed over https)."""
    response.set_cookie(
        cookie_name(PRESESSION_COOKIE, secure),
        token,
        path=cookie_path(secure),
        httponly=True,
        samesite="strict",
        secure=secure,
    )
```

In `read_form`, replace the presession line with:

```python
    if presession:
        secure = is_secure(request.app.state.ctx)
        candidates.append(request.cookies.get(cookie_name(PRESESSION_COOKIE, secure), ""))
```

Then make both callers pass `secure`:
- `routes_auth._sign_in_page`: `token = presession_token(request, secure=is_secure(ctx))`
- `routes_setup._admin_page`: `token = request.state.csrf_token or presession_token(request, secure=is_secure(ctx))`

Existing tests that read `PRESESSION_COOKIE` directly run over http, so they keep working.

- [ ] **Step 5: Run argon2 in a bounded pool** (`src/u2_mcp/admin/routes_auth.py`)

```python
import asyncio
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import TypeVar

T = TypeVar("T")

# Each argon2 hash takes ~64 MiB and tens of milliseconds. Running them on the event
# loop let a burst of sign-ins stall MCP traffic; four threads bound both the stall
# and the memory.
ARGON2_THREADS = 4
_argon2_pool = ThreadPoolExecutor(max_workers=ARGON2_THREADS, thread_name_prefix="argon2")


async def argon2_call(fn: Callable[..., T], *args: object) -> T:
    """Run a password hash or check in the argon2 pool."""
    return await asyncio.get_running_loop().run_in_executor(_argon2_pool, fn, *args)
```

In `sign_in`, replace everything from `user = ctx.store.get_user_by_username(...)` down to, but not including, `previous = request.state.session` with the code below. The password check moves into the pool, and the local-sign-in-off refusal now comes before the rehash (2b Minor 7). Both audit rows and pages are the same as before.

```python
    user = ctx.store.get_user_by_username(username) if username else None
    stored_hash = ctx.store.password_hash(user.id) if user is not None else None
    checked = await argon2_call(verify_password, stored_hash, password)
    if not checked or user is None or user.disabled:
        ctx.store.add_audit(
            kind="auth",
            action="admin.sign_in",
            outcome="failed",
            actor_label=username[:64] or None,
            params={"ip": ip},
        )
        return _sign_in_page(
            request, error=WRONG_CREDENTIALS, username=username, next_url=next_url, status_code=401
        )
    if not user.is_admin and not local_accounts_enabled(ctx):
        ctx.store.add_audit(
            kind="auth",
            action="admin.sign_in",
            outcome="refused",
            actor_user_id=user.id,
            actor_label=user.label,
            params={"ip": ip, "reason": "local sign-in off"},
        )
        return _sign_in_page(
            request, error=LOCAL_SIGN_IN_OFF, username=username, next_url=next_url, status_code=403
        )
    if stored_hash and needs_rehash(stored_hash):
        # The argon2 defaults changed since this hash was made: store a fresh one.
        fresh = await argon2_call(hash_password, password)
        ctx.store.set_password_hash(user.id, fresh, must_change=user.must_change_password)
```

- [ ] **Step 6: Keep CORS outside `/admin`** (`src/u2_mcp/server.py`)

Add this at module level:

```python
class CorsOutsideAdmin:
    """CORS for the MCP endpoints, never for the admin site (2a review M-5).

    With allow_credentials, a listed origin could read admin pages with the
    signed-in admin's cookie. The admin site needs no cross-origin access at all.
    """

    def __init__(self, app: Any, **cors: Any) -> None:
        from starlette.middleware.cors import CORSMiddleware

        self.app = app
        self.cors = CORSMiddleware(app, **cors)

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        path = scope.get("path", "")
        if scope.get("type") == "http" and (path == "/admin" or path.startswith("/admin/")):
            await self.app(scope, receive, send)
            return
        await self.cors(scope, receive, send)
```

In `build_streamable_http_app`, replace the `app.add_middleware(CORSMiddleware, ...)` call:

```python
    app.add_middleware(
        CorsOutsideAdmin,
        allow_origins=config.http_cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
```

Remove the local `CORSMiddleware` import from that function. `build_sse_app` keeps its own.

- [ ] **Step 7: Run the tests and confirm they pass**

Run: `.venv/Scripts/python -m pytest tests/test_admin -q`
Expected: PASS.

Then run the Global Constraints checks. The sign-in and setup pages changed, so also run `pytest -m e2e tests/e2e --browser chromium`.

- [ ] **Step 8: Commit**

```bash
git add src/u2_mcp/admin/security.py src/u2_mcp/admin/routes_auth.py src/u2_mcp/admin/routes_setup.py src/u2_mcp/server.py tests/test_admin/helpers.py tests/test_admin/test_hardening_3.py tests/test_admin/test_route_table.py
git commit -m "fix(admin): __Host- pre-session cookie, argon2 off the event loop, no CORS on /admin

Also: the rehash runs only after a sign-in is allowed, and a route-table
sweep proves non-admins reach only their own pages.

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
git push origin feature/phase3-sso-deploy
```

---

### Task 3: Mock OIDC provider

The provider is test infrastructure. It has its own tests because every later SSO test depends on it.

**Files:**
- Create: `tests/mocks/oidc_provider.py`, `tests/test_mock_oidc_provider.py`
- Modify: `pyproject.toml` (declare `pyjwt[crypto]`)

**Interfaces:**
- **Produces, `tests/mocks/oidc_provider.py`:**
  - `KID = "mock-key-1"`
  - `@dataclass Person(sub="user-1", email="user1@example.com", name="User One", groups=[], overage=False, extra={})`
  - `class MockIdP(issuer: str, clients: dict[str, str])`:
    - `.next_user(person: Person) -> None`
    - `.claims_for(person, *, client_id, nonce) -> dict`
    - `.sign(claims, *, key=None, kid=KID, alg="RS256") -> str`
    - `.jwks() -> dict`
    - `.key` (an RSA private key)
  - `build_app(idp: MockIdP) -> Starlette`. It serves `GET /.well-known/openid-configuration`, `GET /jwks`, `GET /authorize`, `POST /token`, `GET /userinfo` and `POST /_control/next-user`. The last one takes a JSON body with the `Person` fields.
  - `main(argv: list[str] | None = None) -> None`. Run it as `python -m tests.mocks.oidc_provider --port N --client-id ID --client-secret SECRET`. The issuer is `http://127.0.0.1:N`.

- [ ] **Step 1: Declare PyJWT**

In `pyproject.toml` `dependencies`, add `"pyjwt[crypto]>=2.8.0",` after `"cryptography>=42.0.0",`. It is already installed (2.15.1, through `mcp`), so nothing is downloaded. Check with `.venv/Scripts/python -c "import jwt; print(jwt.__version__)"`.

- [ ] **Step 2: Write the failing tests** (`tests/test_mock_oidc_provider.py`)

```python
"""The mock identity provider behaves like a real one where our tests depend on it."""

import base64
import hashlib
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from starlette.testclient import TestClient

from tests.mocks.oidc_provider import KID, MockIdP, Person, build_app

ISSUER = "http://idp.test"
REDIRECT = "http://u2.test/admin/sign-in/sso/callback"


@pytest.fixture
def idp() -> MockIdP:
    return MockIdP(ISSUER, {"u2-mcp": "s3cret"})


def _challenge(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def _authorize(client: TestClient, verifier: str = "v" * 50, nonce: str = "n-1") -> str:
    response = client.get(
        "/authorize",
        params={"response_type": "code", "client_id": "u2-mcp", "redirect_uri": REDIRECT,
                "state": "st-1", "nonce": nonce, "scope": "openid",
                "code_challenge": _challenge(verifier), "code_challenge_method": "S256"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    location = urlsplit(response.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == REDIRECT
    query = parse_qs(location.query)
    assert query["state"] == ["st-1"]
    return query["code"][0]


def _token(client: TestClient, code: str, verifier: str = "v" * 50, secret: str = "s3cret") -> object:
    return client.post(
        "/token",
        data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
              "code_verifier": verifier},
        auth=("u2-mcp", secret),
    )


def test_discovery_names_the_endpoints(idp: MockIdP) -> None:
    with TestClient(build_app(idp)) as client:
        doc = client.get("/.well-known/openid-configuration").json()
    assert doc["issuer"] == ISSUER
    assert doc["jwks_uri"] == f"{ISSUER}/jwks"
    assert doc["token_endpoint"] == f"{ISSUER}/token"
    assert "S256" in doc["code_challenge_methods_supported"]


def test_a_full_round_trip_gives_a_verifiable_id_token(idp: MockIdP) -> None:
    idp.next_user(Person(sub="sam", email="sam@x.com", name="Sam", groups=["eng"]))
    with TestClient(build_app(idp)) as client:
        response = _token(client, _authorize(client))
        jwks = client.get("/jwks").json()
    assert response.status_code == 200  # type: ignore[attr-defined]
    id_token = response.json()["id_token"]  # type: ignore[attr-defined]
    key = jwt.PyJWKSet.from_dict(jwks).keys[0]
    assert key.key_id == KID
    claims = jwt.decode(id_token, key.key, algorithms=["RS256"], audience="u2-mcp", issuer=ISSUER)
    assert (claims["sub"], claims["groups"], claims["nonce"]) == ("sam", ["eng"], "n-1")


def test_overage_people_get_claim_names_instead_of_groups(idp: MockIdP) -> None:
    claims = idp.claims_for(Person(overage=True, groups=["x"]), client_id="u2-mcp", nonce=None)
    assert "groups" not in claims
    assert claims["_claim_names"] == {"groups": "src1"}


def test_a_wrong_verifier_secret_or_reused_code_is_refused(idp: MockIdP) -> None:
    with TestClient(build_app(idp)) as client:
        assert _token(client, _authorize(client), verifier="w" * 50).status_code == 400  # type: ignore[attr-defined]
        assert _token(client, _authorize(client), secret="nope").status_code == 401  # type: ignore[attr-defined]
        code = _authorize(client)
        assert _token(client, code).status_code == 200  # type: ignore[attr-defined]
        assert _token(client, code).status_code == 400  # type: ignore[attr-defined]


def test_client_secret_post_is_accepted(idp: MockIdP) -> None:
    with TestClient(build_app(idp)) as client:
        code = _authorize(client)
        response = client.post(
            "/token",
            data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
                  "code_verifier": "v" * 50, "client_id": "u2-mcp", "client_secret": "s3cret"},
        )
    assert response.status_code == 200


def test_the_control_endpoint_queues_the_next_person(idp: MockIdP) -> None:
    with TestClient(build_app(idp)) as client:
        client.post("/_control/next-user", json={"sub": "olga", "overage": True})
        code = _authorize(client)
        token = _token(client, code).json()  # type: ignore[attr-defined]
        userinfo = client.get(
            "/userinfo", headers={"Authorization": f"Bearer {token['access_token']}"}
        ).json()
    assert userinfo["sub"] == "olga"
    assert "groups" not in userinfo  # like Entra: userinfo carries no groups
```

- [ ] **Step 3: Run them and confirm they fail**

Run: `.venv/Scripts/python -m pytest tests/test_mock_oidc_provider.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'tests.mocks.oidc_provider'`.

- [ ] **Step 4: Implement `tests/mocks/oidc_provider.py`**

```python
"""A small OpenID Connect provider for tests: discovery, JWKS, authorize, token, userinfo.

It signs RS256 ID tokens with a key made at start. Who signs in next, and with
which claims, is queued over POST /_control/next-user, so a browser test can
script a person and their groups (or an Entra-style group overage). It approves
every authorization request at once: there is no login page.

Run: python -m tests.mocks.oidc_provider --port 8901 --client-id u2-mcp --client-secret s3cret
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field, fields
from typing import Any
from urllib.parse import unquote, urlencode

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Route

KID = "mock-key-1"


@dataclass
class Person:
    """Who signs in, and what the provider says about them."""

    sub: str = "user-1"
    email: str | None = "user1@example.com"
    name: str | None = "User One"
    groups: list[str] = field(default_factory=list)
    overage: bool = False  # Entra-style: groups left out, _claim_names says where
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class _Code:
    client_id: str
    redirect_uri: str
    person: Person
    nonce: str | None
    challenge: str | None


class MockIdP:
    """The provider's state: its key, clients, queued people and issued codes."""

    def __init__(self, issuer: str, clients: dict[str, str]) -> None:
        self.issuer = issuer.rstrip("/")
        self.clients = dict(clients)
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.queue: list[Person] = []
        self.default = Person()
        self.codes: dict[str, _Code] = {}
        self.access_tokens: dict[str, Person] = {}

    def next_user(self, person: Person) -> None:
        """Queue the person the next authorization request signs in."""
        self.queue.append(person)

    def claims_for(self, person: Person, *, client_id: str, nonce: str | None) -> dict[str, Any]:
        """The ID token's claims for this person."""
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": self.issuer, "aud": client_id, "sub": person.sub, "iat": now, "exp": now + 300,
        }
        if nonce:
            claims["nonce"] = nonce
        if person.email:
            claims["email"] = person.email
        if person.name:
            claims["name"] = person.name
        if person.overage:
            claims["_claim_names"] = {"groups": "src1"}
            claims["_claim_sources"] = {
                "src1": {"endpoint": "https://graph.windows.net/t/users/u/getMemberObjects"}
            }
        else:
            claims["groups"] = list(person.groups)
        claims.update(person.extra)
        return claims

    def sign(self, claims: dict[str, Any], *, key: Any = None, kid: str = KID,
             alg: str = "RS256") -> str:
        """Sign claims as an ID token (another key or algorithm makes a bad one)."""
        return jwt.encode(claims, key if key is not None else self.key, algorithm=alg,
                          headers={"kid": kid})

    def jwks(self) -> dict[str, Any]:
        """The public key set."""
        jwk = json.loads(RSAAlgorithm.to_jwk(self.key.public_key()))
        jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})
        return {"keys": [jwk]}


def _idp(request: Request) -> MockIdP:
    idp: MockIdP = request.app.state.idp
    return idp


async def discovery(request: Request) -> Response:
    issuer = _idp(request).issuer
    return JSONResponse({
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "jwks_uri": f"{issuer}/jwks",
        "userinfo_endpoint": f"{issuer}/userinfo",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
    })


async def jwks(request: Request) -> Response:
    return JSONResponse(_idp(request).jwks())


async def authorize(request: Request) -> Response:
    idp = _idp(request)
    query = request.query_params
    if (
        query.get("client_id") not in idp.clients
        or query.get("response_type") != "code"
        or not query.get("redirect_uri")
    ):
        return JSONResponse({"error": "invalid_request"}, status_code=400)
    person = idp.queue.pop(0) if idp.queue else idp.default
    code = secrets.token_urlsafe(16)
    idp.codes[code] = _Code(
        query["client_id"], query["redirect_uri"], person, query.get("nonce"),
        query.get("code_challenge"),
    )
    target = f"{query['redirect_uri']}?{urlencode({'code': code, 'state': query.get('state', '')})}"
    return RedirectResponse(target, status_code=302)


def _client_credentials(request: Request, form: dict[str, str]) -> tuple[str, str]:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("basic "):
        decoded = base64.b64decode(header[6:]).decode()
        client_id, _, secret = decoded.partition(":")
        return unquote(client_id), unquote(secret)
    return form.get("client_id", ""), form.get("client_secret", "")


async def token(request: Request) -> Response:
    idp = _idp(request)
    form = {key: str(value) for key, value in (await request.form()).items()}
    client_id, secret = _client_credentials(request, form)
    expected = idp.clients.get(client_id)
    if expected is None or not hmac.compare_digest(expected, secret):
        return JSONResponse({"error": "invalid_client"}, status_code=401)
    if form.get("grant_type") != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
    issued = idp.codes.pop(form.get("code", ""), None)
    if issued is None or issued.client_id != client_id or issued.redirect_uri != form.get("redirect_uri"):
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    if issued.challenge is not None:
        verifier = form.get("code_verifier", "")
        digest = hashlib.sha256(verifier.encode()).digest()
        if base64.urlsafe_b64encode(digest).rstrip(b"=").decode() != issued.challenge:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "PKCE verification failed"},
                status_code=400,
            )
    access_token = secrets.token_urlsafe(24)
    idp.access_tokens[access_token] = issued.person
    claims = idp.claims_for(issued.person, client_id=client_id, nonce=issued.nonce)
    return JSONResponse({
        "access_token": access_token, "token_type": "Bearer", "expires_in": 300,
        "id_token": idp.sign(claims),
    })


async def userinfo(request: Request) -> Response:
    idp = _idp(request)
    header = request.headers.get("authorization", "")
    person = idp.access_tokens.get(header[7:]) if header.lower().startswith("bearer ") else None
    if person is None:
        return JSONResponse({"error": "invalid_token"}, status_code=401)
    body: dict[str, Any] = {"sub": person.sub}
    if person.email:
        body["email"] = person.email
    if person.name:
        body["name"] = person.name
    return JSONResponse(body)


async def next_user(request: Request) -> Response:
    data = await request.json()
    known = {f.name for f in fields(Person)}
    _idp(request).next_user(Person(**{k: v for k, v in data.items() if k in known}))
    return JSONResponse({"queued": True})


def build_app(idp: MockIdP) -> Starlette:
    """The provider as an ASGI app (mount it with httpx.ASGITransport, or serve it)."""
    app = Starlette(routes=[
        Route("/.well-known/openid-configuration", discovery, methods=["GET"]),
        Route("/jwks", jwks, methods=["GET"]),
        Route("/authorize", authorize, methods=["GET"]),
        Route("/token", token, methods=["POST"]),
        Route("/userinfo", userinfo, methods=["GET"]),
        Route("/_control/next-user", next_user, methods=["POST"]),
    ])
    app.state.idp = idp
    return app


def main(argv: list[str] | None = None) -> None:
    """Serve the provider on 127.0.0.1 until stopped."""
    import uvicorn

    parser = argparse.ArgumentParser(prog="python -m tests.mocks.oidc_provider")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--client-secret", required=True)
    args = parser.parse_args(argv)
    idp = MockIdP(f"http://127.0.0.1:{args.port}", {args.client_id: args.client_secret})
    uvicorn.run(build_app(idp), host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `.venv/Scripts/python -m pytest tests/test_mock_oidc_provider.py -q`
Expected: PASS.

Then smoke-test the CLI. Start `python -m tests.mocks.oidc_provider --port 8911 --client-id a --client-secret b` in the background, check that `curl http://127.0.0.1:8911/.well-known/openid-configuration` returns JSON, then stop it. Run the Global Constraints checks.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml tests/mocks/oidc_provider.py tests/test_mock_oidc_provider.py
git commit -m "test: an in-repo mock OIDC provider (RS256, PKCE, groups and Entra overage)

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
git push origin feature/phase3-sso-deploy
```

---

### Task 4: OIDC client and the Microsoft Graph overage lookup

**Files:**
- Create: `src/u2_mcp/auth/oidc_client.py`, `src/u2_mcp/auth/graph.py`, `tests/test_auth/test_oidc_client.py`, `tests/test_auth/test_graph.py`

**Interfaces:**
- **Consumes:** `MockIdP`, `Person` and `build_app` from Task 3.
- **Produces, `auth/oidc_client.py`:**
  - `HttpFactory = Callable[[], httpx.AsyncClient]`
  - `default_http() -> httpx.AsyncClient` (10-second timeout)
  - `class OidcError(Exception)`: its message is safe to show an admin
  - `@dataclass(frozen=True) Discovery(issuer, authorization_endpoint, token_endpoint, jwks_uri, basic_auth: bool)`
  - `@dataclass(frozen=True) PendingLogin(state, nonce, verifier)`, with `PendingLogin.new()` and the `.challenge` property
  - `class OidcClient(discovery_url, client_id, client_secret, *, http=default_http, scopes=("openid", "profile", "email"))` with these methods:
    - `async discover() -> Discovery`
    - `async authorization_url(redirect_uri, login) -> str`
    - `async sign_in(code, redirect_uri, login) -> dict[str, Any]`: the validated ID-token claims
    - `async validate_id_token(id_token, *, nonce: str | None = None) -> dict[str, Any]`
- **Produces, `auth/graph.py`:** `class GraphGroups(client_id, client_secret, *, http=default_http, login_base=LOGIN_BASE, graph_base=GRAPH_BASE)`. Calling it, `async __call__(claims) -> list[str] | None`, never raises.

- [ ] **Step 1: Write the failing OIDC client tests** (`tests/test_auth/test_oidc_client.py`)

```python
"""ID tokens are believed only after signature, issuer, audience, expiry and nonce checks."""

import dataclasses
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from tests.mocks.oidc_provider import MockIdP, Person, build_app
from u2_mcp.auth.oidc_client import OidcClient, OidcError, PendingLogin

ISSUER = "http://idp.test"
DISCOVERY = f"{ISSUER}/.well-known/openid-configuration"
REDIRECT = "http://u2.test/admin/sign-in/sso/callback"


@pytest.fixture
def idp() -> MockIdP:
    return MockIdP(ISSUER, {"u2-mcp": "s3cret"})


def _http(idp: MockIdP) -> Any:
    app = build_app(idp)
    return lambda: httpx.AsyncClient(transport=httpx.ASGITransport(app=app))


def _client(idp: MockIdP, secret: str = "s3cret") -> OidcClient:
    return OidcClient(DISCOVERY, "u2-mcp", secret, http=_http(idp))


async def _code(idp: MockIdP, client: OidcClient, login: PendingLogin) -> str:
    url = await client.authorization_url(REDIRECT, login)
    query = parse_qs(urlsplit(url).query)
    assert query["code_challenge_method"] == ["S256"] and query["nonce"] == [login.nonce]
    async with _http(idp)() as http:
        response = await http.get(url)
    location = parse_qs(urlsplit(response.headers["location"]).query)
    assert location["state"] == [login.state]
    return location["code"][0]


@pytest.mark.asyncio
async def test_a_round_trip_returns_the_validated_claims(idp: MockIdP) -> None:
    idp.next_user(Person(sub="sam", groups=["eng"]))
    client, login = _client(idp), PendingLogin.new()
    claims = await client.sign_in(await _code(idp, client, login), REDIRECT, login)
    assert claims["sub"] == "sam" and claims["groups"] == ["eng"]


@pytest.mark.asyncio
async def test_a_wrong_secret_is_reported(idp: MockIdP) -> None:
    client, login = _client(idp, secret="nope"), PendingLogin.new()
    with pytest.raises(OidcError, match="refused the code"):
        await client.sign_in(await _code(idp, client, login), REDIRECT, login)


@pytest.mark.asyncio
async def test_a_different_nonce_is_refused(idp: MockIdP) -> None:
    client, login = _client(idp), PendingLogin.new()
    code = await _code(idp, client, login)
    with pytest.raises(OidcError, match="nonce"):
        await client.sign_in(code, REDIRECT, dataclasses.replace(login, nonce="other"))


@pytest.mark.asyncio
async def test_a_different_pkce_verifier_is_refused(idp: MockIdP) -> None:
    client, login = _client(idp), PendingLogin.new()
    code = await _code(idp, client, login)
    with pytest.raises(OidcError, match="refused the code"):
        await client.sign_in(code, REDIRECT, dataclasses.replace(login, verifier="x" * 50))


def _claims(idp: MockIdP, **changes: Any) -> dict[str, Any]:
    claims = idp.claims_for(Person(), client_id="u2-mcp", nonce=None)
    claims.update(changes)
    return claims


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("make", "message"),
    [
        (lambda idp: idp.sign(_claims(idp, exp=int(time.time()) - 600)), "not valid"),
        (lambda idp: idp.sign(_claims(idp, aud="someone-else")), "not valid"),
        (lambda idp: idp.sign(_claims(idp, iss="http://evil.test")), "not valid"),
        (lambda idp: idp.sign(_claims(idp), key=rsa.generate_private_key(65537, 2048)), "not valid"),
        (lambda idp: idp.sign(_claims(idp), kid="unknown"), "does not publish"),
        (lambda idp: idp.sign(_claims(idp), key="k" * 32, alg="HS256"), "only RS256"),
        (lambda idp: idp.sign(_claims(idp, aud=["u2-mcp", "other"], azp="other")), "azp"),
        (lambda idp: "not-a-token", "malformed"),
    ],
)
async def test_bad_id_tokens_are_refused(idp: MockIdP, make: Any, message: str) -> None:
    with pytest.raises(OidcError, match=message):
        await _client(idp).validate_id_token(make(idp))


@pytest.mark.asyncio
async def test_entra_common_discovery_is_refused() -> None:
    doc = {"issuer": "https://login.microsoftonline.com/{tenantid}/v2.0",
           "authorization_endpoint": "https://a", "token_endpoint": "https://t", "jwks_uri": "https://j"}
    http = lambda: httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=doc)))  # noqa: E731
    with pytest.raises(OidcError, match="tenantid"):
        await OidcClient("https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
                         "id", "s", http=http).discover()


@pytest.mark.asyncio
async def test_an_unreachable_provider_names_the_url() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    http = lambda: httpx.AsyncClient(transport=httpx.MockTransport(refuse))  # noqa: E731
    with pytest.raises(OidcError, match="Could not reach the identity provider at http://idp.test"):
        await OidcClient(DISCOVERY, "id", "s", http=http).discover()


@pytest.mark.asyncio
async def test_post_auth_is_used_when_basic_is_not_offered() -> None:
    seen: list[httpx.Request] = []
    doc = {"issuer": ISSUER, "authorization_endpoint": f"{ISSUER}/a", "token_endpoint": f"{ISSUER}/t",
           "jwks_uri": f"{ISSUER}/j", "token_endpoint_auth_methods_supported": ["client_secret_post"]}

    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(200, json=doc)
        return httpx.Response(400, json={"error": "invalid_grant"})

    http = lambda: httpx.AsyncClient(transport=httpx.MockTransport(answer))  # noqa: E731
    with pytest.raises(OidcError):
        await OidcClient(DISCOVERY, "id", "sec", http=http).sign_in("c", REDIRECT, PendingLogin.new())
    token_request = seen[-1]
    assert "authorization" not in token_request.headers
    assert b"client_secret=sec" in token_request.content
```

- [ ] **Step 2: Write the failing Graph tests** (`tests/test_auth/test_graph.py`)

```python
"""Entra group overage: groups come from Graph, or not at all. Never from the token's URL."""

from typing import Any

import httpx
import pytest

from u2_mcp.auth.graph import GraphGroups

TID = "11111111-2222-3333-4444-555555555555"
OID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _graph(answer: Any, seen: list[httpx.Request]) -> GraphGroups:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return answer(request)

    return GraphGroups("client", "secret",
                       http=lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)))


def _ok(request: httpx.Request) -> httpx.Response:
    if request.url.host == "login.microsoftonline.com":
        return httpx.Response(200, json={"access_token": "graph-token"})
    return httpx.Response(200, json={"value": ["g-1", "g-2"]})


@pytest.mark.asyncio
async def test_groups_are_looked_up_for_the_tenant_and_user() -> None:
    seen: list[httpx.Request] = []
    groups = await _graph(_ok, seen)({"tid": TID, "oid": OID, "_claim_sources": {"src1": {
        "endpoint": "https://evil.example/steal"}}})
    assert groups == ["g-1", "g-2"]
    assert str(seen[0].url) == f"https://login.microsoftonline.com/{TID}/oauth2/v2.0/token"
    assert str(seen[1].url) == f"https://graph.microsoft.com/v1.0/users/{OID}/getMemberGroups"
    assert seen[1].headers["authorization"] == "Bearer graph-token"
    assert all(r.url.host != "evil.example" for r in seen)


@pytest.mark.asyncio
@pytest.mark.parametrize("claims", [{}, {"tid": "../x", "oid": OID}, {"tid": TID, "oid": "1/2"}])
async def test_missing_or_odd_ids_mean_no_lookup(claims: dict[str, str]) -> None:
    seen: list[httpx.Request] = []
    assert await _graph(_ok, seen)(claims) is None
    assert seen == []


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [400, 403, 500])
async def test_graph_failures_mean_no_groups(status: int) -> None:
    def failing(request: httpx.Request) -> httpx.Response:
        if request.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json={"access_token": "t"})
        return httpx.Response(status, json={"error": {"code": "Authorization_RequestDenied"}})

    assert await _graph(failing, [])({"tid": TID, "oid": OID}) is None


@pytest.mark.asyncio
async def test_a_network_error_means_no_groups() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    assert await _graph(refuse, [])({"tid": TID, "oid": OID}) is None
```

- [ ] **Step 3: Run them and confirm they fail**

Run: `.venv/Scripts/python -m pytest tests/test_auth/test_oidc_client.py tests/test_auth/test_graph.py -q`
Expected: FAIL, with `ModuleNotFoundError` for `u2_mcp.auth.oidc_client` and for `u2_mcp.auth.graph`.

- [ ] **Step 4: Implement `src/u2_mcp/auth/oidc_client.py`**

```python
"""OpenID Connect sign-in: authorization code with PKCE, state and nonce.

The identity provider is believed only through what it signs. The ID token's
signature is checked against the keys the provider publishes (JWKS, found through
discovery), and its issuer, audience, expiry and nonce are checked before any
claim is used. HTTP goes through an injected client factory, so tests can point
it at tests/mocks/oidc_provider.py without a network.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode

import httpx
import jwt

HttpFactory = Callable[[], httpx.AsyncClient]
ALGORITHMS = ["RS256"]
LEEWAY_SECONDS = 60
HTTP_TIMEOUT_SECONDS = 10.0
DISCOVERY_SUFFIX = "/.well-known/openid-configuration"


def default_http() -> httpx.AsyncClient:
    """The HTTP client used outside tests."""
    return httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS)


class OidcError(Exception):
    """Company sign-in failed. The message is safe to show an admin."""


@dataclass(frozen=True)
class Discovery:
    """The parts of a provider's discovery document this client uses."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    basic_auth: bool


@dataclass(frozen=True)
class PendingLogin:
    """What a sign-in carries from its start to its callback."""

    state: str
    nonce: str
    verifier: str

    @classmethod
    def new(cls) -> PendingLogin:
        """Fresh random state, nonce and PKCE verifier."""
        return cls(secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(48))

    @property
    def challenge(self) -> str:
        """The PKCE S256 code challenge for this verifier."""
        digest = hashlib.sha256(self.verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _error_text(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return f"HTTP {response.status_code}: {response.text[:200]}"
    if isinstance(body, dict):
        return str(body.get("error_description") or body.get("error") or response.status_code)
    return f"HTTP {response.status_code}"


class OidcClient:
    """One provider, as configured on the admin site.

    Args:
        discovery_url: The provider's /.well-known/openid-configuration URL
        client_id: This server's client (application) id at the provider
        client_secret: Its secret; None when none is saved
        http: Makes the HTTP client (replaced in tests)
        scopes: Scopes requested; openid is required for an ID token
    """

    def __init__(
        self,
        discovery_url: str,
        client_id: str,
        client_secret: str | None,
        *,
        http: HttpFactory = default_http,
        scopes: tuple[str, ...] = ("openid", "profile", "email"),
    ) -> None:
        self.discovery_url = discovery_url
        self.client_id = client_id
        self.client_secret = client_secret
        self._http = http
        self.scopes = scopes

    async def _get_json(self, client: httpx.AsyncClient, url: str) -> dict[str, Any]:
        try:
            response = await client.get(url)
        except httpx.HTTPError as exc:
            raise OidcError(f"Could not reach the identity provider at {url}: {exc}") from exc
        if response.status_code != 200:
            raise OidcError(f"The identity provider answered {response.status_code} for {url}")
        try:
            data = response.json()
        except ValueError as exc:
            raise OidcError(f"The identity provider sent something other than JSON from {url}") from exc
        if not isinstance(data, dict):
            raise OidcError(f"The identity provider sent an unexpected document from {url}")
        return data

    async def discover(self) -> Discovery:
        """Fetch and check the discovery document.

        Raises:
            OidcError: If it cannot be fetched, lacks an endpoint, or is a
                multi-tenant template (Entra's /common), whose issuer cannot be checked
        """
        async with self._http() as client:
            doc = await self._get_json(client, self.discovery_url)
        names = ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri")
        missing = [name for name in names if not isinstance(doc.get(name), str) or not doc[name]]
        if missing:
            raise OidcError(f"The discovery document lacks {', '.join(missing)}")
        if "{" in doc["issuer"]:
            raise OidcError(
                "The discovery document is a multi-tenant template (its issuer contains "
                "{tenantid}). Use your tenant's own discovery URL."
            )
        methods = doc.get("token_endpoint_auth_methods_supported") or ["client_secret_basic"]
        return Discovery(
            issuer=doc["issuer"],
            authorization_endpoint=doc["authorization_endpoint"],
            token_endpoint=doc["token_endpoint"],
            jwks_uri=doc["jwks_uri"],
            basic_auth="client_secret_basic" in methods,
        )

    async def authorization_url(self, redirect_uri: str, login: PendingLogin) -> str:
        """The provider URL that starts a sign-in (code flow, PKCE S256, state, nonce)."""
        discovery = await self.discover()
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(self.scopes),
            "state": login.state,
            "nonce": login.nonce,
            "code_challenge": login.challenge,
            "code_challenge_method": "S256",
        }
        separator = "&" if "?" in discovery.authorization_endpoint else "?"
        return f"{discovery.authorization_endpoint}{separator}{urlencode(params)}"

    async def sign_in(self, code: str, redirect_uri: str, login: PendingLogin) -> dict[str, Any]:
        """Exchange the callback's code and return the validated ID token's claims.

        Raises:
            OidcError: With the reason, safe to show an admin
        """
        discovery = await self.discover()
        id_token = await self._exchange(discovery, code, redirect_uri, login.verifier)
        return await self._validate(discovery, id_token, nonce=login.nonce)

    async def validate_id_token(self, id_token: str, *, nonce: str | None = None) -> dict[str, Any]:
        """Validate an ID token obtained elsewhere (the MCP OAuth bridge) and return its claims."""
        return await self._validate(await self.discover(), id_token, nonce=nonce)

    async def _exchange(
        self, discovery: Discovery, code: str, redirect_uri: str, verifier: str
    ) -> str:
        if not self.client_secret:
            raise OidcError("No client secret is saved for company sign-in.")
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        }
        auth: httpx.BasicAuth | None = None
        if discovery.basic_auth:
            # RFC 6749 2.3.1: form-encode the id and secret before Basic encoding.
            auth = httpx.BasicAuth(quote(self.client_id, safe=""), quote(self.client_secret, safe=""))
        else:
            data["client_id"] = self.client_id
            data["client_secret"] = self.client_secret
        async with self._http() as client:
            try:
                response = await client.post(discovery.token_endpoint, data=data, auth=auth)
            except httpx.HTTPError as exc:
                raise OidcError(f"Could not reach the identity provider's token endpoint: {exc}") from exc
        if response.status_code != 200:
            raise OidcError(f"The identity provider refused the code: {_error_text(response)}")
        try:
            body = response.json()
        except ValueError as exc:
            raise OidcError("The identity provider's token answer was not JSON") from exc
        id_token = body.get("id_token") if isinstance(body, dict) else None
        if not isinstance(id_token, str) or not id_token:
            raise OidcError("The identity provider sent no ID token. Check that the openid scope is allowed.")
        return id_token

    async def _validate(
        self, discovery: Discovery, id_token: str, *, nonce: str | None
    ) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as exc:
            raise OidcError(f"The ID token is malformed: {exc}") from exc
        if header.get("alg") not in ALGORITHMS:
            raise OidcError(f"The ID token is signed with {header.get('alg')}; only RS256 is accepted.")
        async with self._http() as client:
            published = await self._get_json(client, discovery.jwks_uri)
        try:
            key_set = jwt.PyJWKSet.from_dict(published)
        except jwt.PyJWTError as exc:
            raise OidcError(f"The identity provider's keys are unusable: {exc}") from exc
        kid = header.get("kid")
        keys = [key for key in key_set.keys if kid is None or key.key_id == kid]
        if not keys:
            raise OidcError("The ID token was signed with a key the identity provider does not publish.")
        try:
            claims: dict[str, Any] = jwt.decode(
                id_token,
                keys[0].key,
                algorithms=ALGORITHMS,
                audience=self.client_id,
                issuer=discovery.issuer,
                leeway=LEEWAY_SECONDS,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise OidcError(f"The ID token is not valid: {exc}") from exc
        if nonce is not None and not hmac.compare_digest(str(claims.get("nonce", "")), nonce):
            raise OidcError("The ID token's nonce does not match this sign-in.")
        audience = claims.get("aud")
        if isinstance(audience, list) and len(audience) > 1 and claims.get("azp") != self.client_id:
            raise OidcError("The ID token was issued to another client (azp).")
        if not isinstance(claims.get("sub"), str) or not claims["sub"]:
            raise OidcError("The ID token has no subject.")
        return claims
```

- [ ] **Step 5: Implement `src/u2_mcp/auth/graph.py`**

```python
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

import httpx

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
                answer = await client.post(
                    f"{self.graph_base}/v1.0/users/{object_id}/getMemberGroups",
                    json={"securityEnabledOnly": False},
                    headers={"Authorization": f"Bearer {access}"},
                )
                if answer.status_code != 200:
                    logger.warning(f"Group overage: Graph refused the lookup ({answer.status_code})")
                    return None
                values = answer.json().get("value")
        except (httpx.HTTPError, ValueError, AttributeError) as exc:
            logger.warning(f"Group overage: Graph lookup failed: {exc}")
            return None
        if not isinstance(values, list):
            return None
        return [str(value) for value in values]
```

- [ ] **Step 6: Run the tests and confirm they pass**

Run: `.venv/Scripts/python -m pytest tests/test_auth/test_oidc_client.py tests/test_auth/test_graph.py -q`
Expected: PASS. Then run the Global Constraints checks.

- [ ] **Step 7: Commit**

```bash
git add src/u2_mcp/auth/oidc_client.py src/u2_mcp/auth/graph.py tests/test_auth/test_oidc_client.py tests/test_auth/test_graph.py
git commit -m "feat(auth): OIDC client with PKCE, nonce and JWKS-checked ID tokens; Graph overage lookup

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
git push origin feature/phase3-sso-deploy
```

---

### Task 5: One sign-in recorder for the admin site and MCP, with ID-token claims

**Files:**
- Modify: `src/u2_mcp/team_auth.py`, `src/u2_mcp/auth/provider.py`, `tests/test_team_auth.py` (the four `TestSignIn` tests become async), `tests/test_auth/test_provider_identity.py`

**Interfaces:**
- **Produces, `team_auth.py`:**
  - `OverageResolver = Callable[[dict[str, Any]], Awaitable[list[str] | None]]`
  - `async groups_for_sign_in(claims: dict[str, Any], claim_name: str, resolver: OverageResolver | None) -> list[str] | None`
  - `record_sign_in(store: Store, info: TokenInfo, groups: list[str] | None, *, via: str) -> User`. It is synchronous: it links or creates the user, then calls `record_sso_login`, then writes the `sso_sign_in` audit row with `{"groups": n or None, "via": via}`.
  - `make_sign_in_handler(store, groups_claim, resolver: OverageResolver | None = None) -> Callable[[TokenInfo], Awaitable[None]]`. This is now a coroutine function, and it uses `via="mcp"`.
- **Produces, `U2OAuthProvider.__init__`:**
  - `on_sign_in` may now return an awaitable, and the provider awaits it.
  - New keyword argument `id_token_claims: Callable[[str], Awaitable[dict[str, Any]]] | None = None`. When it is set and the identity provider returned an `id_token`, its validated claims are merged over the userinfo claims. A different `sub` refuses the sign-in.

- [ ] **Step 1: Write the failing tests**

In `tests/test_team_auth.py`, replace the `TestSignIn` class with this version. The four old cases are kept, now awaited, and new ones are added. Add `from u2_mcp.team_auth import groups_for_sign_in, record_sign_in` to the imports.

```python
class TestSignIn:
    @pytest.mark.asyncio
    async def test_a_first_sign_in_creates_the_user_with_groups(self, store: Store) -> None:
        handler = make_sign_in_handler(store, "groups")
        await handler(
            TokenInfo(subject="s1", email="a@x.com", name="Alice", raw_claims={"groups": ["g-dev"]})
        )
        user = store.get_user_by_subject("s1")
        assert user is not None and user.display_name == "Alice"
        assert user.last_sso_login_at is not None
        assert len(store.group_ids_for_user(user.id)) == 1
        entry = store.recent_audit(1)[0]
        assert entry["action"] == "sso_sign_in"
        assert "mcp" in str(entry)

    @pytest.mark.asyncio
    async def test_an_email_imported_user_is_linked_not_duplicated(self, store: Store) -> None:
        pending = store.get_or_create_sso_user("pending:bob@corp.com", email="bob@corp.com")
        await make_sign_in_handler(store, "groups")(
            TokenInfo(subject="real-bob", email="Bob@Corp.com")
        )
        user = store.get_user_by_subject("real-bob")
        assert user is not None and user.id == pending.id

    @pytest.mark.asyncio
    async def test_an_unverified_email_does_not_inherit_an_imported_users_grants(
        self, store: Store
    ) -> None:
        pending = store.get_or_create_sso_user("pending:bob@corp.com", email="bob@corp.com")
        await make_sign_in_handler(store, "groups")(
            TokenInfo(subject="mallory", email="bob@corp.com", raw_claims={"email_verified": False})
        )
        user = store.get_user_by_subject("mallory")
        assert user is not None and user.id != pending.id
        still_pending = store.get_user_by_subject("pending:bob@corp.com")
        assert still_pending is not None and still_pending.id == pending.id

    @pytest.mark.asyncio
    async def test_groups_from_the_adapter_are_used_when_claims_lack_them(
        self, store: Store
    ) -> None:
        await make_sign_in_handler(store, "groups")(TokenInfo(subject="s2", groups=["g-ops"]))
        user = store.get_user_by_subject("s2")
        assert user is not None and len(store.group_ids_for_user(user.id)) == 1

    @pytest.mark.asyncio
    async def test_overage_groups_come_from_the_resolver(self, store: Store) -> None:
        async def resolver(claims: dict[str, Any]) -> list[str] | None:
            return ["g-from-graph"]

        handler = make_sign_in_handler(store, "groups", resolver)
        await handler(TokenInfo(subject="s3", raw_claims={"_claim_names": {"groups": "src1"}}))
        user = store.get_user_by_subject("s3")
        assert user is not None and not user.groups_unavailable
        assert [g.external_id for g in store.list_groups()] == ["g-from-graph"]

    @pytest.mark.asyncio
    async def test_a_failing_resolver_leaves_groups_unavailable(self, store: Store) -> None:
        async def resolver(claims: dict[str, Any]) -> list[str] | None:
            raise RuntimeError("graph down")

        await make_sign_in_handler(store, "groups", resolver)(
            TokenInfo(subject="s4", raw_claims={"_claim_names": {"groups": "src1"}})
        )
        user = store.get_user_by_subject("s4")
        assert user is not None and user.groups_unavailable


@pytest.mark.asyncio
async def test_the_resolver_is_not_asked_when_the_token_lists_groups() -> None:
    asked: list[dict[str, Any]] = []

    async def resolver(claims: dict[str, Any]) -> list[str] | None:
        asked.append(claims)
        return []

    assert await groups_for_sign_in({"groups": ["a"]}, "groups", resolver) == ["a"]
    assert asked == []


def test_record_sign_in_says_where_the_sign_in_came_from(store: Store) -> None:
    user = record_sign_in(store, TokenInfo(subject="s5", name="Sue"), ["g"], via="admin")
    assert user.last_sso_login_at is not None
    assert "admin" in str(store.recent_audit(1)[0])
```

Append to `tests/test_auth/test_provider_identity.py`:

```python
def _provider_with_id_token(id_claims: dict[str, Any], on_sign_in: Any) -> U2OAuthProvider:
    provider = _provider(on_sign_in=on_sign_in)
    provider.idp_adapter.exchange_code = AsyncMock(
        return_value=MagicMock(access_token="idp-access", id_token="id-token-1")
    )

    async def claims(token: str) -> dict[str, Any]:
        assert token == "id-token-1"
        return id_claims

    provider.id_token_claims = claims
    return provider


@pytest.mark.asyncio
async def test_id_token_groups_reach_the_settings_database(store: Store) -> None:
    provider = _provider_with_id_token(
        {"sub": "person-1", "groups": ["eng"]}, make_sign_in_handler(store, "groups")
    )
    await provider.handle_idp_callback("idp-code", "state-1")
    person = store.get_user_by_subject("person-1")
    assert person is not None
    assert [g.external_id for g in store.list_groups()] == ["eng"]


@pytest.mark.asyncio
async def test_an_id_token_for_someone_else_is_refused(store: Store) -> None:
    from mcp.server.auth.provider import AuthorizeError

    provider = _provider_with_id_token({"sub": "intruder"}, make_sign_in_handler(store, "groups"))
    with pytest.raises(AuthorizeError):
        await provider.handle_idp_callback("idp-code", "state-1")
    assert store.get_user_by_subject("person-1") is None
```

(`AuthorizeError` is what `provider.py` raises. If its import path differs, use the one `provider.py` imports.)

- [ ] **Step 2: Run them and confirm they fail**

Run: `.venv/Scripts/python -m pytest tests/test_team_auth.py tests/test_auth/test_provider_identity.py -q`

Expected:
- `ImportError` for `groups_for_sign_in`.
- The provider tests fail because `id_token_claims` is ignored.

- [ ] **Step 3: Implement the recorder** (`src/u2_mcp/team_auth.py`)

Replace `make_sign_in_handler` with the code below. Add these imports: `from collections.abc import Awaitable, Callable, Sequence` and `from .store.models import User`.

```python
OverageResolver = Callable[[dict[str, Any]], Awaitable[list[str] | None]]


async def groups_for_sign_in(
    claims: dict[str, Any], claim_name: str, resolver: OverageResolver | None
) -> list[str] | None:
    """The groups to record for a sign-in.

    The token's own claim wins. On an overage (None from groups_from_claims) the
    resolver, when configured, is asked. A failing resolver means "unknown", never
    a failed sign-in.
    """
    groups = groups_from_claims(claims, claim_name)
    if groups is None and resolver is not None:
        try:
            groups = await resolver(claims)
        except Exception as exc:  # noqa: BLE001 - a failed lookup must not block sign-in
            logger.warning(f"Looking up an overage user's groups failed: {exc}")
            groups = None
    return groups


def record_sign_in(store: Store, info: TokenInfo, groups: list[str] | None, *, via: str) -> User:
    """Record a completed company sign-in: the one place for the admin site and MCP.

    Creates the user on first sight (with no access), links a user imported by a
    verified email, replaces their groups (None flags them groups-unavailable) and
    restarts their token freshness window.

    Args:
        store: The settings database
        info: Who signed in, with the validated claims in raw_claims
        groups: From groups_for_sign_in
        via: "admin" (admin-site sign-in) or "mcp" (an MCP client's OAuth sign-in)
    """
    claims = info.raw_claims or {}
    if store.get_user_by_subject(info.subject) is None and info.email and _may_link_by_email(claims):
        store.link_pending_sso_user(info.email, info.subject)
    user = store.get_or_create_sso_user(info.subject, email=info.email, display_name=info.name)
    store.record_sso_login(user.id, groups)
    store.add_audit(
        kind="auth",
        action="sso_sign_in",
        outcome="ok",
        actor_user_id=user.id,
        actor_label=user.label,
        params={"groups": None if groups is None else len(groups), "via": via},
    )
    return store.get_user(user.id) or user


def make_sign_in_handler(
    store: Store, groups_claim: str, resolver: OverageResolver | None = None
) -> Callable[[TokenInfo], Awaitable[None]]:
    """Build the MCP OAuth provider's on_sign_in hook for team mode.

    Args:
        store: The settings database
        groups_claim: Name of the claim that lists groups
        resolver: Looks up groups on an Entra overage (Microsoft Graph), or None
    """

    async def on_sign_in(info: TokenInfo) -> None:
        claims = dict(info.raw_claims or {})
        if groups_claim not in claims and groups_claim == "groups" and info.groups is not None:
            claims["groups"] = info.groups
        groups = await groups_for_sign_in(claims, groups_claim, resolver)
        record_sign_in(store, info, groups, via="mcp")

    return on_sign_in
```

- [ ] **Step 4: Update the provider** (`src/u2_mcp/auth/provider.py`)

1. In `__init__`, change the `on_sign_in` annotation to `Callable[[TokenInfo], None | Awaitable[None]] | None` and add the keyword `id_token_claims: Callable[[str], Awaitable[dict[str, Any]]] | None = None`. Document it in the Args: "Validates the IdP's ID token and returns its claims. Team mode passes one, so groups that userinfo leaves out (Entra) are kept." Store it as `self.id_token_claims = id_token_claims`.

2. In `handle_idp_callback`, insert this block between the userinfo validation and the `on_sign_in` call (`import dataclasses` and `import inspect` at the top):

   ```python
           # Userinfo carries no groups at Entra; the signed ID token does. Its claims
           # are checked (signature, issuer, audience, expiry) before they are merged.
           if self.id_token_claims is not None and getattr(idp_tokens, "id_token", None):
               try:
                   id_claims = await self.id_token_claims(idp_tokens.id_token)
               except Exception as e:
                   logger.error(f"ID token validation failed: {e}")
                   raise AuthorizeError(
                       error="access_denied", error_description="Failed to validate identity"
                   ) from e
               if id_claims.get("sub") != user_info.subject:
                   logger.error("The ID token names a different subject than userinfo")
                   raise AuthorizeError(
                       error="access_denied", error_description="Failed to validate identity"
                   )
               user_info = dataclasses.replace(
                   user_info, raw_claims={**(user_info.raw_claims or {}), **id_claims}
               )
   ```

3. Change the `on_sign_in` call inside its `try` to:

   ```python
                   outcome = self.on_sign_in(user_info)
                   if inspect.isawaitable(outcome):
                       await outcome
   ```

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `.venv/Scripts/python -m pytest tests/test_team_auth.py tests/test_auth -q`
Expected: PASS. That includes the existing `seen.append` test, a plain function that is not awaited. Then run the Global Constraints checks.

- [ ] **Step 6: Commit**

```bash
git add src/u2_mcp/team_auth.py src/u2_mcp/auth/provider.py tests/test_team_auth.py tests/test_auth/test_provider_identity.py
git commit -m "feat(auth): one sign-in recorder with overage lookup; MCP sign-ins keep ID-token groups

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
git push origin feature/phase3-sso-deploy
```

---

### Task 6: Company sign-in settings: one form for the wizard's SSO step and Settings

**Files:**
- Create:
  - `src/u2_mcp/sso_config.py`
  - `src/u2_mcp/admin/sso_services.py`
  - `src/u2_mcp/admin/templates/partials/sso_form.html`
  - `src/u2_mcp/admin/templates/setup/sso.html`
  - `tests/test_admin/test_sso_settings.py`
- Modify:
  - `src/u2_mcp/setup_code.py`: `SETUP_STEPS`
  - `src/u2_mcp/store/bootstrap.py`: seeding
  - `src/u2_mcp/admin/routes_setup.py`: the SSO step, Settings save and clear, the Done page
  - `src/u2_mcp/admin/templates/settings.html`
  - `src/u2_mcp/admin/templates/partials/setup_checklist.html`
  - `tests/test_admin/test_route_table.py`
  - `tests/test_admin/test_routes_setup.py`
  - `tests/e2e/wizard.py`
  - `tests/e2e/test_setup_wizard.py`

**Interfaces:**
- **Produces, `sso_config.py`:**
  - Constants: `SSO_SETTING = "sso"`, `SSO_SECRET_SETTING = "sso_client_secret"`, `SSO_SEEDED_SETTING = "sso_seeded_from_environment"`, `ADMIN_CALLBACK_PATH = "/admin/sign-in/sso/callback"`, `MCP_CALLBACK_PATH = "/oauth/callback"`
  - `PROVIDERS: dict[str, str]`, which maps `"entra"` and `"oidc"` to their labels
  - `@dataclass(frozen=True) SsoSettings(provider, discovery_url, client_id, groups_claim, graph_overage)`, with the property `.provider_label`
  - `load_sso(store) -> SsoSettings | None`
  - `sso_client_secret(store) -> str | None`, which raises `SecretUnreadable`
  - `store_sso(store, settings, client_secret: str | None) -> None`. A `None` secret keeps the stored one.
  - `clear_sso(store) -> None`
  - `seed_sso_from_environment(store, config) -> bool`
- **Produces, `admin/sso_services.py`:**
  - The message constants from Global Constraints
  - `@dataclass SsoForm` with `from_form(data)`, `from_settings(settings, config)`, and `errors(*, stored, has_secret) -> dict[str, str]`
  - `save_sso(ctx, form, *, actor) -> SsoSettings`, which raises `ValidationFailed`
  - `remove_sso(ctx, *, actor) -> None`
  - `sso_context(ctx, *, action_url, form=None, errors=None) -> dict[str, Any]`. The template keys are `sso`, `sso_form`, `sso_errors`, `sso_providers`, `sso_secret_hint`, `sso_admin_callback`, `sso_mcp_callback`, `sso_action` and `sso_submit_label`.
- **Produces, `setup_code.SETUP_STEPS`:** `("admin", "connection", "server_address", "sso", "done")`.
- **Produces, routes:**
  - `GET` and `POST /admin/setup/sso`
  - `POST /admin/setup/sso/next`, which marks the step done (Continue or Skip)
  - `POST /admin/settings/sso`
  - `POST /admin/settings/sso/clear`
  - The server-address step now redirects to `/admin/setup/sso`.

- [ ] **Step 1: Write the failing tests** (`tests/test_admin/test_sso_settings.py`)

```python
"""Company sign-in settings: one validated save for the wizard and Settings."""

from typing import Any

import pytest

from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.services import ValidationFailed
from u2_mcp.admin.sso_services import (
    CLAIM_PROBLEM,
    CLIENT_ID_PROBLEM,
    DISCOVERY_HTTPS,
    DISCOVERY_PROBLEM,
    ENTRA_TENANT,
    PROVIDER_PROBLEM,
    SECRET_AGAIN,
    SECRET_NEEDED,
    SsoForm,
    remove_sso,
    save_sso,
)
from u2_mcp.config import U2Config
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import completed_step, finish_setup, mark_step_done
from u2_mcp.sso_config import (
    SSO_SECRET_SETTING,
    clear_sso,
    load_sso,
    seed_sso_from_environment,
    sso_client_secret,
)
from u2_mcp.store.models import User
from u2_mcp.store.repo import Store

from .helpers import PASSWORD, admin_client, csrf_from, sign_in

TENANT = "11111111-2222-3333-4444-555555555555"
GOOD: dict[str, Any] = {
    "provider": "entra",
    "discovery_url": f"https://login.microsoftonline.com/{TENANT}/v2.0/.well-known/openid-configuration",
    "client_id": "app-1",
    "client_secret": "s3cret",
    "groups_claim": "groups",
}


@pytest.mark.parametrize(
    ("changes", "field", "message"),
    [
        ({"provider": "saml"}, "provider", PROVIDER_PROBLEM),
        ({"discovery_url": "https://idp.example/"}, "discovery_url", DISCOVERY_PROBLEM),
        ({"discovery_url": "http://idp.example/.well-known/openid-configuration"},
         "discovery_url", DISCOVERY_HTTPS),
        ({"discovery_url": "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"},
         "discovery_url", ENTRA_TENANT),
        ({"client_id": ""}, "client_id", CLIENT_ID_PROBLEM),
        ({"client_secret": ""}, "client_secret", SECRET_NEEDED),
        ({"groups_claim": "has space"}, "groups_claim", CLAIM_PROBLEM),
    ],
)
def test_the_form_names_each_problem(changes: dict[str, str], field: str, message: str) -> None:
    form = SsoForm.from_form({**GOOD, **changes})
    assert form.errors(stored=None, has_secret=False)[field] == message


def test_loopback_http_discovery_is_allowed_for_local_test_providers() -> None:
    form = SsoForm.from_form(
        {**GOOD, "provider": "oidc",
         "discovery_url": "http://127.0.0.1:8901/.well-known/openid-configuration"}
    )
    assert form.errors(stored=None, has_secret=False) == {}


def test_saving_encrypts_the_secret_and_audits_without_it(ctx: AdminContext, admin: User) -> None:
    settings = save_sso(ctx, SsoForm.from_form(GOOD), actor=admin)
    assert load_sso(ctx.store) == settings
    assert sso_client_secret(ctx.store) == "s3cret"
    assert "s3cret" not in str(ctx.store.get_setting(SSO_SECRET_SETTING))
    entry = ctx.store.recent_audit(1)[0]
    assert entry["action"] == "settings.sso" and "s3cret" not in str(entry)


def test_a_blank_secret_keeps_the_saved_one_until_the_client_id_changes(
    ctx: AdminContext, admin: User
) -> None:
    save_sso(ctx, SsoForm.from_form(GOOD), actor=admin)
    save_sso(ctx, SsoForm.from_form({**GOOD, "client_secret": "", "groups_claim": "roles"}), actor=admin)
    saved = load_sso(ctx.store)
    assert sso_client_secret(ctx.store) == "s3cret" and saved is not None and saved.groups_claim == "roles"
    with pytest.raises(ValidationFailed) as failed:
        save_sso(ctx, SsoForm.from_form({**GOOD, "client_secret": "", "client_id": "app-2"}), actor=admin)
    assert failed.value.errors == {"client_secret": SECRET_AGAIN}


def test_the_graph_lookup_is_for_entra_only(ctx: AdminContext, admin: User) -> None:
    form = SsoForm.from_form({**GOOD, "provider": "oidc", "discovery_url":
                              "https://idp.example/.well-known/openid-configuration", "graph_overage": "on"})
    assert save_sso(ctx, form, actor=admin).graph_overage is False


def test_turning_it_off_forgets_the_secret(ctx: AdminContext, admin: User) -> None:
    save_sso(ctx, SsoForm.from_form(GOOD), actor=admin)
    remove_sso(ctx, actor=admin)
    assert load_sso(ctx.store) is None and sso_client_secret(ctx.store) is None
    assert ctx.store.recent_audit(1)[0]["action"] == "settings.sso_clear"


def test_u2_idp_variables_seed_the_settings_once(
    store: Store, mock_env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("U2_IDP_DISCOVERY_URL", GOOD["discovery_url"])
    monkeypatch.setenv("U2_IDP_CLIENT_ID", "app-1")
    monkeypatch.setenv("U2_IDP_CLIENT_SECRET", "env-secret")
    config = U2Config()
    assert seed_sso_from_environment(store, config) is True
    seeded = load_sso(store)
    assert seeded is not None and seeded.provider == "entra"
    assert sso_client_secret(store) == "env-secret"
    clear_sso(store)  # an admin turned it off: the environment does not bring it back
    assert seed_sso_from_environment(store, config) is False
    assert load_sso(store) is None


def _wizard_at_sso(ctx: AdminContext) -> None:
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    mark_step_done(ctx.store, "server_address")


def test_the_server_address_step_leads_to_company_sign_in(ctx: AdminContext) -> None:
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    mark_step_done(ctx.store, "connection")
    with admin_client(ctx) as client:
        sign_in(client)
        page = client.get("/admin/setup/server_address")
        response = client.post(
            "/admin/setup/server_address",
            data={"csrf_token": csrf_from(page.text), "public_url": "http://10.0.0.5:8080"},
            follow_redirects=False,
        )
    assert response.headers["location"] == "/admin/setup/sso"


def test_the_sso_step_can_be_skipped(ctx: AdminContext) -> None:
    _wizard_at_sso(ctx)
    with admin_client(ctx) as client:
        sign_in(client)
        page = client.get("/admin/setup/sso")
        assert "Skip this step" in page.text and "Company sign-in" in page.text
        response = client.post(
            "/admin/setup/sso/next", data={"csrf_token": csrf_from(page.text)}, follow_redirects=False
        )
    assert response.headers["location"] == "/admin/setup/done"
    assert completed_step(ctx.store) == "sso"


def test_the_sso_step_saves_and_waits_for_continue(ctx: AdminContext) -> None:
    _wizard_at_sso(ctx)
    with admin_client(ctx) as client:
        sign_in(client)
        token = csrf_from(client.get("/admin/setup/sso").text)
        saved = client.post("/admin/setup/sso", data={**GOOD, "csrf_token": token}, follow_redirects=False)
        assert saved.headers["location"] == "/admin/setup/sso?notice=saved"
        page = client.get("/admin/setup/sso")
        assert "Continue" in page.text and "A secret is saved" in page.text
        bad = client.post(
            "/admin/setup/sso", data={**GOOD, "client_id": "", "csrf_token": token}, follow_redirects=False
        )
    assert bad.status_code == 400 and CLIENT_ID_PROBLEM in bad.text
    assert completed_step(ctx.store) == "server_address"


def test_settings_saves_and_turns_off_company_sign_in(ctx: AdminContext) -> None:
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    finish_setup(ctx.store)
    with admin_client(ctx) as client:
        sign_in(client)
        token = csrf_from(client.get("/admin/settings").text)
        saved = client.post("/admin/settings/sso", data={**GOOD, "csrf_token": token}, follow_redirects=False)
        assert saved.status_code == 303
        page = client.get("/admin/settings")
        assert "Turn off company sign-in" in page.text
        assert "/admin/sign-in/sso/callback" in page.text and "/oauth/callback" in page.text
        client.post("/admin/settings/sso/clear", data={"csrf_token": token}, follow_redirects=False)
    assert load_sso(ctx.store) is None
```

- [ ] **Step 2: Run them and confirm they fail**

Run: `.venv/Scripts/python -m pytest tests/test_admin/test_sso_settings.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'u2_mcp.admin.sso_services'`.

- [ ] **Step 3: Implement `src/u2_mcp/sso_config.py`**

```python
"""Company sign-in (OIDC) settings, kept in the settings database.

The admin site edits them, and the admin site's sign-in reads them on every
sign-in. The MCP OAuth bridge reads them at startup. The client secret is
encrypted with U2_SECRET_KEY. On first start, U2_IDP_* seeds them once; after
that the saved settings win, even when an admin turns company sign-in off.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import U2Config
    from .store.repo import Store

SSO_SETTING = "sso"
SSO_SECRET_SETTING = "sso_client_secret"
SSO_SEEDED_SETTING = "sso_seeded_from_environment"
ADMIN_CALLBACK_PATH = "/admin/sign-in/sso/callback"
MCP_CALLBACK_PATH = "/oauth/callback"
PROVIDERS: dict[str, str] = {
    "entra": "Microsoft Entra ID",
    "oidc": "Other OpenID Connect provider (Okta, Google, Auth0, Duo, Keycloak)",
}


@dataclass(frozen=True)
class SsoSettings:
    """Company sign-in as configured (the secret is kept separately, encrypted)."""

    provider: str
    discovery_url: str
    client_id: str
    groups_claim: str
    graph_overage: bool

    @property
    def provider_label(self) -> str:
        """The provider's name as the pages show it."""
        return PROVIDERS.get(self.provider, self.provider)


def load_sso(store: Store) -> SsoSettings | None:
    """Return the saved company sign-in settings, or None when it is not set up."""
    value = store.get_setting(SSO_SETTING)
    if not isinstance(value, dict):
        return None
    try:
        return SsoSettings(
            provider=str(value["provider"]),
            discovery_url=str(value["discovery_url"]),
            client_id=str(value["client_id"]),
            groups_claim=str(value.get("groups_claim") or "groups"),
            graph_overage=bool(value.get("graph_overage", False)),
        )
    except KeyError:
        return None


def sso_client_secret(store: Store) -> str | None:
    """Return the decrypted client secret, or None.

    Raises:
        SecretUnreadable: If it was saved under a different U2_SECRET_KEY
    """
    return store.get_secret_setting(SSO_SECRET_SETTING)


def store_sso(store: Store, settings: SsoSettings, client_secret: str | None) -> None:
    """Save the settings; a None secret keeps the saved one."""
    store.set_setting(SSO_SETTING, asdict(settings))
    if client_secret is not None:
        store.set_secret_setting(SSO_SECRET_SETTING, client_secret)


def clear_sso(store: Store) -> None:
    """Turn company sign-in off and forget its secret."""
    store.delete_setting(SSO_SETTING)
    store.set_secret_setting(SSO_SECRET_SETTING, None)


def seed_sso_from_environment(store: Store, config: U2Config) -> bool:
    """Copy U2_IDP_* into the settings once, on first start.

    Returns:
        True when settings were seeded now
    """
    if store.get_setting(SSO_SEEDED_SETTING) or load_sso(store) is not None:
        return False
    if not (config.idp_discovery_url and config.idp_client_id):
        return False
    provider = "entra" if "login.microsoftonline.com" in config.idp_discovery_url else "oidc"
    settings = SsoSettings(
        provider=provider,
        discovery_url=config.idp_discovery_url,
        client_id=config.idp_client_id,
        groups_claim=config.sso_groups_claim,
        graph_overage=False,
    )
    store_sso(store, settings, config.idp_client_secret or None)
    store.set_setting(SSO_SEEDED_SETTING, True)
    store.add_audit(
        kind="admin",
        action="settings.sso",
        outcome="ok",
        actor_label="startup",
        params={"seeded_from": "U2_IDP_*", "provider": provider},
    )
    return True
```

Then in `store/bootstrap.py` `open_team_store`, just before `return store`:

```python
    # U2_IDP_* seeds company sign-in once; the admin site's settings win afterwards.
    seed_sso_from_environment(store, config)
```

Add the import `from ..sso_config import seed_sso_from_environment`. If it causes an import cycle, import inside the function instead.

- [ ] **Step 4: Implement `src/u2_mcp/admin/sso_services.py`**

```python
"""Saving company sign-in settings: one function for the wizard and Settings (spec rule 1)."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from ..config import U2Config
from ..store.crypto import SecretUnreadable
from ..store.models import User
from ..sso_config import (
    ADMIN_CALLBACK_PATH,
    MCP_CALLBACK_PATH,
    PROVIDERS,
    SsoSettings,
    clear_sso,
    load_sso,
    sso_client_secret,
    store_sso,
)
from .context import AdminContext
from .services import ValidationFailed, effective_public_url

DISCOVERY_SUFFIX = "/.well-known/openid-configuration"
PROVIDER_PROBLEM = "Choose a provider."
DISCOVERY_PROBLEM = "Enter the discovery URL, ending in /.well-known/openid-configuration."
DISCOVERY_HTTPS = "The discovery URL must be https."
ENTRA_TENANT = (
    "Use your tenant's own discovery URL (with your tenant ID), not /common or /organizations."
)
CLIENT_ID_PROBLEM = "Enter the client (application) ID."
SECRET_NEEDED = "Enter the client secret."
SECRET_AGAIN = "Enter the client secret again: the client ID changed."
CLAIM_PROBLEM = "Use up to 64 letters, digits, dots, dashes, underscores, colons or slashes."

_CLAIM = re.compile(r"[A-Za-z0-9_.:/-]{1,64}")
_LOOPBACK = ("localhost", "127.0.0.1", "::1")
_ENTRA_SHARED = re.compile(r"/(common|organizations|consumers)/")


@dataclass
class SsoForm:
    """The company sign-in form as submitted (the secret only when typed)."""

    provider: str = "entra"
    discovery_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    groups_claim: str = "groups"
    graph_overage: bool = False

    @classmethod
    def from_form(cls, data: Mapping[str, Any]) -> SsoForm:
        """Read a submitted form."""
        return cls(
            provider=str(data.get("provider", "")).strip(),
            discovery_url=str(data.get("discovery_url", "")).strip(),
            client_id=str(data.get("client_id", "")).strip(),
            client_secret=str(data.get("client_secret", "")),
            groups_claim=str(data.get("groups_claim", "")).strip() or "groups",
            graph_overage=data.get("graph_overage") == "on",
        )

    @classmethod
    def from_settings(cls, settings: SsoSettings | None, config: U2Config) -> SsoForm:
        """The form pre-filled from saved settings (never the secret)."""
        if settings is None:
            return cls(groups_claim=config.sso_groups_claim)
        return cls(
            provider=settings.provider,
            discovery_url=settings.discovery_url,
            client_id=settings.client_id,
            groups_claim=settings.groups_claim,
            graph_overage=settings.graph_overage,
        )

    def errors(self, *, stored: SsoSettings | None, has_secret: bool) -> dict[str, str]:
        """Each field's problem; empty when the form can be saved."""
        errors: dict[str, str] = {}
        if self.provider not in PROVIDERS:
            errors["provider"] = PROVIDER_PROBLEM
        parts = urlsplit(self.discovery_url)
        if (
            parts.scheme not in ("http", "https")
            or not parts.netloc
            or not parts.path.endswith(DISCOVERY_SUFFIX)
            or parts.query
            or parts.fragment
            or parts.username
            or parts.password
            or any(c.isspace() for c in self.discovery_url)
        ):
            errors["discovery_url"] = DISCOVERY_PROBLEM
        elif parts.scheme == "http" and parts.hostname not in _LOOPBACK:
            errors["discovery_url"] = DISCOVERY_HTTPS
        elif self.provider == "entra" and _ENTRA_SHARED.search(parts.path):
            errors["discovery_url"] = ENTRA_TENANT
        if not self.client_id or len(self.client_id) > 255 or any(c.isspace() for c in self.client_id):
            errors["client_id"] = CLIENT_ID_PROBLEM
        if not self.client_secret:
            if not has_secret:
                errors["client_secret"] = SECRET_NEEDED
            elif stored is not None and stored.client_id != self.client_id:
                errors["client_secret"] = SECRET_AGAIN
        if not _CLAIM.fullmatch(self.groups_claim):
            errors["groups_claim"] = CLAIM_PROBLEM
        return errors


def _has_secret(ctx: AdminContext) -> tuple[bool, bool]:
    """(a secret is saved and readable, a secret is saved but unreadable)."""
    try:
        return sso_client_secret(ctx.store) is not None, False
    except SecretUnreadable:
        return False, True


def save_sso(ctx: AdminContext, form: SsoForm, *, actor: User) -> SsoSettings:
    """Validate and save company sign-in settings.

    Raises:
        ValidationFailed: With each field's problem
    """
    stored = load_sso(ctx.store)
    has_secret, _unreadable = _has_secret(ctx)
    errors = form.errors(stored=stored, has_secret=has_secret)
    if errors:
        raise ValidationFailed(errors)
    settings = SsoSettings(
        provider=form.provider,
        discovery_url=form.discovery_url,
        client_id=form.client_id,
        groups_claim=form.groups_claim,
        graph_overage=form.graph_overage and form.provider == "entra",
    )
    store_sso(ctx.store, settings, form.client_secret or None)
    ctx.store.add_audit(
        kind="admin",
        action="settings.sso",
        outcome="ok",
        actor_user_id=actor.id,
        actor_label=actor.label,
        params={
            "provider": settings.provider,
            "discovery_url": settings.discovery_url,
            "client_id": settings.client_id,
            "groups_claim": settings.groups_claim,
            "graph_overage": settings.graph_overage,
            "secret_changed": bool(form.client_secret),
        },
    )
    return settings


def remove_sso(ctx: AdminContext, *, actor: User) -> None:
    """Turn company sign-in off (local admins can always still sign in)."""
    clear_sso(ctx.store)
    ctx.store.add_audit(
        kind="admin", action="settings.sso_clear", outcome="ok",
        actor_user_id=actor.id, actor_label=actor.label,
    )


def sso_context(
    ctx: AdminContext,
    *,
    action_url: str,
    form: SsoForm | None = None,
    errors: dict[str, str] | None = None,
) -> dict[str, Any]:
    """What partials/sso_form.html needs, for the wizard and Settings alike."""
    settings = load_sso(ctx.store)
    has_secret, unreadable = _has_secret(ctx)
    if unreadable:
        hint = "The saved secret can't be read with this U2_SECRET_KEY. Enter it again."
    elif has_secret:
        hint = "A secret is saved. Leave this blank to keep it."
    else:
        hint = "From your identity provider's app registration."
    public = effective_public_url(ctx)
    return {
        "sso": settings,
        "sso_form": form or SsoForm.from_settings(settings, ctx.config),
        "sso_errors": errors or {},
        "sso_providers": list(PROVIDERS.items()),
        "sso_secret_hint": hint,
        "sso_admin_callback": public + ADMIN_CALLBACK_PATH,
        "sso_mcp_callback": public + MCP_CALLBACK_PATH,
        "sso_action": action_url,
        "sso_submit_label": "Save company sign-in",
    }
```

- [ ] **Step 5: The templates**

`src/u2_mcp/admin/templates/partials/sso_form.html`:

```html
{% from "partials/fields.html" import checkbox, select, text %}
<form method="post" action="{{ sso_action }}">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  {{ select("provider", "Provider", sso_form.provider, sso_providers, sso_errors) }}
  {{ text("discovery_url", "Discovery URL", sso_form.discovery_url, sso_errors, type="url", hint="Ends in /.well-known/openid-configuration. Entra: https://login.microsoftonline.com/<tenant ID>/v2.0/.well-known/openid-configuration", required=true) }}
  {{ text("client_id", "Client ID", sso_form.client_id, sso_errors, required=true) }}
  {{ text("client_secret", "Client secret", "", sso_errors, type="password", autocomplete="new-password", hint=sso_secret_hint) }}
  {{ text("groups_claim", "Groups claim", sso_form.groups_claim, sso_errors, hint="The ID-token claim that lists a person's groups. Entra and Okta use groups.") }}
  {{ checkbox("graph_overage", "Entra only: look up groups through Microsoft Graph when someone is in too many groups to fit in the token", sso_form.graph_overage, hint="Needs the GroupMember.Read.All application permission, granted by an Entra admin. When off, such people sign in with no groups, and the Users page flags them.") }}
  <p class="hint">Register these redirect URIs with your identity provider: <code>{{ sso_admin_callback }}</code> (this admin site) and <code>{{ sso_mcp_callback }}</code> (VS Code and other MCP clients).</p>
  <div class="actions"><button type="submit">{{ sso_submit_label }}</button></div>
</form>
```

`src/u2_mcp/admin/templates/setup/sso.html`:

```html
{% extends "base.html" %}
{% block title %}Setup: company sign-in · u2-mcp admin{% endblock %}
{% block content %}
<h1>Set up u2-mcp</h1>
{% include "setup/_steps.html" %}
<h2>Company sign-in</h2>
<p>Optional. With company sign-in, people use their work account for this site and for VS Code. You can set it up later under Settings.</p>
{% include "partials/sso_form.html" %}
<form method="post" action="/admin/setup/sso/next" class="actions">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <button type="submit"{% if not sso %} class="secondary"{% endif %}>{{ "Continue" if sso else "Skip this step" }}</button>
</form>
{% endblock %}
```

In `settings.html`, insert a section after the Server address include:

```html
<h2 id="sign-in">Company sign-in</h2>
{% include "partials/sso_form.html" %}
{% if sso %}
<form method="post" action="/admin/settings/sso/clear" class="actions">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <button type="submit" class="danger">Turn off company sign-in</button>
</form>
{% endif %}
```

Replace `partials/setup_checklist.html`. The admin row no longer names the viewer (2b Minor 6), and SSO is real.

```html
<table>
  <tbody>
    <tr><th>Admin account</th><td>Created</td></tr>
    <tr><th>First connection</th><td>{% if connection %}{{ connection.name }} ({{ connection.host }}, {{ connection.account }}){% else %}Not set{% endif %}</td></tr>
    <tr><th>Server address</th><td>{{ public_url }}{% if warning %}<p class="warning">{{ warning }}</p>{% endif %}</td></tr>
    <tr><th>Company sign-in (SSO)</th><td>{% if sso %}{{ sso.provider_label }}: {{ sso.discovery_url }}{% else %}Not set up. Add it under Settings.{% endif %}</td></tr>
  </tbody>
</table>
```

- [ ] **Step 6: The step and the routes**

In `setup_code.py`, set `SETUP_STEPS = ("admin", "connection", "server_address", "sso", "done")`.

In `routes_setup.py`:

1. Add `"sso": "Company sign-in"` to `STEP_TITLES`, between `server_address` and `done`.
2. Import `from ..sso_config import load_sso` and `from .sso_services import SsoForm, remove_sso, save_sso, sso_context`.
3. In `setup_server_address`'s `on_saved`, redirect to `/admin/setup/sso` instead of `/admin/setup/done`.
4. In `setup_done_form`, add `sso=load_sso(ctx.store)` to the `_step_page` call.
5. Give `_settings_page` the SSO context. Its signature becomes `_settings_page(request, *, token_errors=None, sso_form=None, sso_errors=None)`. Add `**sso_context(ctx, action_url="/admin/settings/sso", form=sso_form, errors=sso_errors)` to the extras it passes to `_address_page`.
6. Add the handlers:

```python
# ----------------------------------------------------------------- sso step


def _sso_step_page(
    request: Request, *, form: SsoForm | None = None, errors: dict[str, str] | None = None,
    status_code: int = 200,
) -> Response:
    ctx = admin_context(request)
    return _step_page(
        request, "setup/sso.html", "sso", status_code=status_code,
        **sso_context(ctx, action_url="/admin/setup/sso", form=form, errors=errors),
    )


async def setup_sso_form(request: Request) -> Response:
    """Step 4 (optional): company sign-in, the same form as Settings."""
    return _guard(request, "sso") or _sso_step_page(request)


async def setup_sso(request: Request) -> Response:
    """Save company sign-in and stay on the step, so it can be tested."""
    blocked = _guard(request, "sso")
    if blocked is not None:
        return blocked
    ctx = admin_context(request)
    form = SsoForm.from_form(await read_form(request))
    try:
        save_sso(ctx, form, actor=request.state.user)
    except ValidationFailed as failed:
        return _sso_step_page(request, form=form, errors=failed.errors, status_code=400)
    return _redirect("/admin/setup/sso?notice=saved")


async def setup_sso_next(request: Request) -> Response:
    """Continue (or skip) past company sign-in."""
    blocked = _guard(request, "sso")
    if blocked is not None:
        return blocked
    await read_form(request)
    mark_step_done(admin_context(request).store, "sso")
    return _redirect("/admin/setup/done")


@admin_only
async def settings_sso(request: Request) -> Response:
    """Save company sign-in from Settings."""
    ctx = admin_context(request)
    form = SsoForm.from_form(await read_form(request))
    try:
        save_sso(ctx, form, actor=request.state.user)
    except ValidationFailed as failed:
        page = _settings_page(request, sso_form=form, sso_errors=failed.errors)
        return page(effective_public_url(ctx), {}, 400)
    return _redirect("/admin/settings?notice=saved#sign-in")


@admin_only
async def settings_sso_clear(request: Request) -> Response:
    """Turn company sign-in off."""
    await read_form(request)
    remove_sso(admin_context(request), actor=request.state.user)
    return _redirect("/admin/settings?notice=saved#sign-in")
```

7. Add these routes, keeping the setup routes in step order:

```python
    Route("/setup/sso", setup_sso_form, methods=["GET"]),
    Route("/setup/sso", setup_sso, methods=["POST"]),
    Route("/setup/sso/next", setup_sso_next, methods=["POST"]),
    Route("/settings/sso", settings_sso, methods=["POST"]),
    Route("/settings/sso/clear", settings_sso_clear, methods=["POST"]),
```

- [ ] **Step 7: Update the tests that walk the wizard**

1. `tests/test_admin/test_route_table.py`:
   - Rebuild `POSTS_REFUSED_BEFORE_THE_FORM` in step order: `/setup/admin`, `/setup/connection`, `/setup/server_address`, `/setup/sso`, `/setup/sso/next`, `/setup/done`. Every entry has the value `_SETUP_CLOSED`.
   - In `test_each_setup_step_refuses_a_post_without_the_csrf_token`, assert the same six-item list.
   - Make the loop:

   ```python
           for done, path in (
               ("admin", "/setup/connection"),
               ("connection", "/setup/server_address"),
               ("server_address", "/setup/sso"),
               ("server_address", "/setup/sso/next"),
               ("sso", "/setup/done"),
           ):
   ```

2. `tests/test_admin/test_routes_setup.py` (line numbers as of `main` at planning time):
   - Add this helper below `_post`. `_post` reads its CSRF token with a GET of the same URL, and `/setup/sso/next` has no GET, so it cannot be used for that step.

     ```python
     def _skip_sso(client: TestClient) -> object:
         """Press Skip on the company sign-in step."""
         token = csrf_from(client.get("/admin/setup/sso").text)
         return client.post(
             "/admin/setup/sso/next", data={"csrf_token": token}, follow_redirects=False
         )
     ```

   - Lines 271, 321 and 329: change `"/admin/setup/done"` to `"/admin/setup/sso"` in the `location` assertions that follow a server-address POST.
   - Insert `_skip_sso(client)` on its own line directly before each of these lines:
     - line 279: `page = client.get("/admin/setup/done").text`
     - line 336: `_post(client, "/admin/setup/done", {})`
     - line 359: `_post(client, "/admin/setup/done", {})`
     - line 420: `_post(client, "/admin/setup/done", {})`
   - In the parametrize list of `test_posting_a_step_after_finish_changes_nothing` (lines 408-413), add these two entries between the `server_address` and `done` entries. Each answers 303 to `/admin/` before reading the form, as that test asserts.

     ```python
                 ("sso", {"provider": "oidc"}),
                 ("sso/next", {}),
     ```

   - No test asserts the checklist text `Created: <name>` (a grep found none at planning time), so the checklist change needs no test edit.

3. `tests/e2e/wizard.py`. In `reach_done`, replace the last two lines with:

   ```python
       page.get_by_role("button", name="Save and continue").click()
       expect(page).to_have_url(re.compile(r"/admin/setup/sso$"))
       page.get_by_role("button", name="Skip this step").click()
       expect(page).to_have_url(re.compile(r"/admin/setup/done$"))
   ```

4. `tests/e2e/test_setup_wizard.py`:
   - In `test_the_whole_wizard_from_an_empty_data_directory`, after the confirmed https save (`page.get_by_role("button", name="Save and continue").click()` following `.check()`), add:

     ```python
         expect(page).to_have_url(re.compile(r"/admin/setup/sso$"))
         page.get_by_role("button", name="Skip this step").click()
     ```

   - In `test_refresh_and_back_at_every_step`, replace the block from the confirmed save down to the first `expect(page.get_by_label("Server address")).to_have_value(...)` with:

     ```python
         page.get_by_role("button", name="Save and continue").click()
         expect(page).to_have_url(re.compile(r"/admin/setup/sso$"))
         page.reload()
         expect(page).to_have_url(re.compile(r"/admin/setup/sso$"))
         page.get_by_role("button", name="Skip this step").click()
         expect(page).to_have_url(re.compile(r"/admin/setup/done$"))
         page.reload()
         expect(page).to_have_url(re.compile(r"/admin/setup/done$"))

         page.go_back()
         expect(page).to_have_url(re.compile(r"/admin/setup/sso$"))
         page.go_back()
         expect(page.get_by_label("Server address")).to_have_value("https://u2.example.com")
     ```

     Later in that test, `/admin/setup/done` is reached with `page.goto`. That keeps working, because the SSO step is already done.

- [ ] **Step 8: Run the tests and confirm they pass**

Run: `.venv/Scripts/python -m pytest tests/test_admin -q`, then `.venv/Scripts/python -m pytest -m e2e tests/e2e --browser chromium`.
Expected: PASS. Then run the Global Constraints checks.

- [ ] **Step 9: Commit**

```bash
git add src/u2_mcp/sso_config.py src/u2_mcp/admin/sso_services.py src/u2_mcp/setup_code.py src/u2_mcp/store/bootstrap.py src/u2_mcp/admin/routes_setup.py src/u2_mcp/admin/templates tests/test_admin/test_sso_settings.py tests/test_admin/test_route_table.py tests/test_admin/test_routes_setup.py tests/e2e/wizard.py tests/e2e/test_setup_wizard.py
git commit -m "feat(admin): company sign-in settings, shared by the wizard's SSO step and Settings

Seeded once from U2_IDP_*; the client secret is encrypted.

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
git push origin feature/phase3-sso-deploy
```

---

### Task 7: Company sign-in on the admin site, the Test button, and the overage warning

**Files:**
- Create: `src/u2_mcp/admin/routes_sso.py`, `src/u2_mcp/admin/templates/sso_test.html`, `tests/test_admin/test_sso_sign_in.py`
- Modify:
  - `src/u2_mcp/store/crypto.py`: `decrypt(..., ttl=None)`
  - `src/u2_mcp/store/repo.py`: `seal` and `unseal`
  - `src/u2_mcp/sso_config.py`: the client builders
  - `src/u2_mcp/admin/context.py`: `http`
  - `src/u2_mcp/admin/app.py`
  - `src/u2_mcp/admin/routes_auth.py`: `_sign_in_page` passes `sso_enabled`
  - `src/u2_mcp/admin/routes_audit.py`: dashboard
  - templates: `sign_in.html`, `partials/sso_form.html`, `dashboard.html`
  - `tests/test_admin/test_route_table.py`

**Interfaces:**
- **Consumes:**
  - `OidcClient`, `PendingLogin`, `OidcError`, `default_http`, `HttpFactory` (Task 4)
  - `GraphGroups` (Task 4)
  - `groups_for_sign_in`, `record_sign_in` (Task 5)
  - `load_sso`, `sso_client_secret`, `ADMIN_CALLBACK_PATH` (Task 6)
  - `cookie_name`, `cookie_path` (Task 2)
- **Produces:**
  - `SecretBox.decrypt(token, ttl: int | None = None)`
  - `Store.seal(plaintext: str) -> str`
  - `Store.unseal(sealed: str, *, max_age_seconds: int) -> str`, which raises `SecretUnreadable`
  - `sso_config.oidc_client(store, http) -> OidcClient | None`
  - `sso_config.overage_resolver(store, settings, http) -> GraphGroups | None`
  - `AdminContext.http: HttpFactory = default_http`
  - `routes_sso.SSO_COOKIE = "u2_admin_sso"` and `SSO_COOKIE_SECONDS = 600`
  - the messages `SSO_EXPIRED`, `SSO_FAILED`, `SSO_NOT_SET_UP` and `SSO_DISABLED`
  - routes: `POST /admin/sign-in/sso`, `GET /admin/sign-in/sso/callback`, `POST /admin/settings/sso/test`

- [ ] **Step 1: Write the failing tests** (`tests/test_admin/test_sso_sign_in.py`)

```python
"""Company sign-in on the admin site, against the mock provider (no network)."""

import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from starlette.testclient import TestClient

from tests.mocks.oidc_provider import MockIdP, Person, build_app
from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.routes_sso import SSO_DISABLED, SSO_EXPIRED, SSO_NOT_SET_UP
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import finish_setup
from u2_mcp.sso_config import SsoSettings, clear_sso, store_sso
from u2_mcp.store.crypto import SecretUnreadable
from u2_mcp.store.repo import Store

from .helpers import PASSWORD, admin_client, csrf_from, sign_in

ISSUER = "http://idp.test"


@pytest.fixture
def idp(ctx: AdminContext) -> MockIdP:
    provider = MockIdP(ISSUER, {"u2-mcp": "s3cret"})
    app = build_app(provider)
    ctx.http = lambda: httpx.AsyncClient(transport=httpx.ASGITransport(app=app))
    store_sso(
        ctx.store,
        SsoSettings("oidc", f"{ISSUER}/.well-known/openid-configuration", "u2-mcp", "groups", False),
        "s3cret",
    )
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    finish_setup(ctx.store)
    return provider


def _follow_idp(idp: MockIdP, location: str) -> str:
    """The browser's visit to the provider, which approves at once; returns the callback path."""
    parts = urlsplit(location)
    with TestClient(build_app(idp)) as browser:
        approved = browser.get(f"{parts.path}?{parts.query}", follow_redirects=False)
    callback = urlsplit(approved.headers["location"])
    return f"{callback.path}?{callback.query}"


def _start(client: TestClient, next_url: str = "") -> httpx.Response:
    page = client.get("/admin/sign-in")
    return client.post(
        "/admin/sign-in/sso",
        data={"csrf_token": csrf_from(page.text), "next": next_url},
        follow_redirects=False,
    )


def _sso_sign_in(client: TestClient, idp: MockIdP, next_url: str = "") -> httpx.Response:
    start = _start(client, next_url)
    assert start.status_code == 303, start.text
    return client.get(_follow_idp(idp, start.headers["location"]), follow_redirects=False)


def test_a_first_company_sign_in_creates_the_user_and_a_session(
    ctx: AdminContext, idp: MockIdP
) -> None:
    idp.next_user(Person(sub="sam", email="sam@x.com", name="Sam", groups=["eng"]))
    with admin_client(ctx) as client:
        response = _sso_sign_in(client, idp)
        assert response.status_code == 303 and response.headers["location"] == "/admin/"
        me = client.get("/admin/me")
    assert me.status_code == 200 and "Sam" in me.text
    user = ctx.store.get_user_by_subject("sam")
    assert user is not None and user.last_sso_login_at is not None and not user.is_admin
    assert [g.external_id for g in ctx.store.list_groups()] == ["eng"]
    assert [e["action"] for e in ctx.store.recent_audit(2)] == ["admin.sign_in", "sso_sign_in"]


def test_the_page_asked_for_is_where_sign_in_lands(ctx: AdminContext, idp: MockIdP) -> None:
    with admin_client(ctx) as client:
        response = _sso_sign_in(client, idp, next_url="/admin/me")
    assert response.headers["location"] == "/admin/me"


def test_each_sign_in_replaces_the_groups(ctx: AdminContext, idp: MockIdP) -> None:
    idp.next_user(Person(sub="sam", groups=["eng", "ops"]))
    idp.next_user(Person(sub="sam", groups=["ops"]))
    with admin_client(ctx) as client:
        _sso_sign_in(client, idp)
        _sso_sign_in(client, idp)
    sam = ctx.store.get_user_by_subject("sam")
    assert sam is not None
    names = {g.id: g.external_id for g in ctx.store.list_groups()}
    assert [names[i] for i in ctx.store.group_ids_for_user(sam.id)] == ["ops"]


def test_overage_people_are_flagged_and_the_dashboard_says_so(
    ctx: AdminContext, idp: MockIdP
) -> None:
    idp.next_user(Person(sub="olga", name="Olga", overage=True))
    with admin_client(ctx) as client:
        _sso_sign_in(client, idp)
    olga = ctx.store.get_user_by_subject("olga")
    assert olga is not None and olga.groups_unavailable
    with admin_client(ctx) as admin:
        sign_in(admin)
        dashboard = admin.get("/admin/dashboard").text
    assert "Groups were unavailable" in dashboard and "Olga" in dashboard


def test_a_callback_from_another_browser_is_refused(ctx: AdminContext, idp: MockIdP) -> None:
    with admin_client(ctx) as starter:
        callback = _follow_idp(idp, _start(starter).headers["location"])
    with admin_client(ctx) as other:
        response = other.get(callback, follow_redirects=False)
    assert response.status_code == 400 and SSO_EXPIRED in response.text
    assert ctx.store.get_user_by_subject("user-1") is None


def test_a_changed_state_or_a_replay_is_refused(ctx: AdminContext, idp: MockIdP) -> None:
    with admin_client(ctx) as client:
        callback = _follow_idp(idp, _start(client).headers["location"])
        forged = client.get(callback.replace("state=", "state=x"), follow_redirects=False)
        assert forged.status_code == 400
        callback = _follow_idp(idp, _start(client).headers["location"])
        assert client.get(callback, follow_redirects=False).status_code == 303
        replay = client.get(callback, follow_redirects=False)
    assert replay.status_code == 400 and SSO_EXPIRED in replay.text


def test_a_refusal_by_the_provider_is_shown(ctx: AdminContext, idp: MockIdP) -> None:
    with admin_client(ctx) as client:
        state = parse_qs(urlsplit(_start(client).headers["location"]).query)["state"][0]
        response = client.get(
            f"/admin/sign-in/sso/callback?error=access_denied&state={state}", follow_redirects=False
        )
    assert response.status_code == 400
    assert "Company sign-in failed: access_denied" in response.text
    assert ctx.store.recent_audit(1)[0]["outcome"] == "failed"


def test_a_disabled_person_gets_no_session(ctx: AdminContext, idp: MockIdP) -> None:
    sam = ctx.store.get_or_create_sso_user("sam")
    ctx.store.set_user_disabled(sam.id, True)
    idp.next_user(Person(sub="sam"))
    with admin_client(ctx) as client:
        response = _sso_sign_in(client, idp)
        after = client.get("/admin/me", follow_redirects=False)
    assert response.status_code == 403 and SSO_DISABLED in response.text
    assert after.status_code == 303  # still signed out


def test_the_settings_test_signs_nobody_in(ctx: AdminContext, idp: MockIdP) -> None:
    idp.next_user(Person(sub="tess", name="Tess", groups=["eng"]))
    users_before = len(ctx.store.list_users())
    with admin_client(ctx) as client:
        sign_in(client)
        token = csrf_from(client.get("/admin/settings").text)
        start = client.post("/admin/settings/sso/test", data={"csrf_token": token}, follow_redirects=False)
        result = client.get(_follow_idp(idp, start.headers["location"]))
        still_admin = client.get("/admin/dashboard", follow_redirects=False)
    assert "Company sign-in works" in result.text and "eng" in result.text and "Tess" in result.text
    assert len(ctx.store.list_users()) == users_before
    assert still_admin.status_code == 200
    assert ctx.store.recent_audit(1)[0]["action"] == "settings.sso_test"


def test_the_sign_in_page_offers_company_sign_in_only_when_set_up(
    ctx: AdminContext, idp: MockIdP
) -> None:
    with admin_client(ctx) as client:
        assert "Sign in with your company account" in client.get("/admin/sign-in").text
        clear_sso(ctx.store)
        assert "Sign in with your company account" not in client.get("/admin/sign-in").text
        assert _start(client).status_code == 400
        assert SSO_NOT_SET_UP in _start(client).text


def test_a_bad_discovery_url_is_reported_when_starting(ctx: AdminContext, idp: MockIdP) -> None:
    store_sso(
        ctx.store,
        SsoSettings("oidc", f"{ISSUER}/nowhere/.well-known/openid-configuration", "u2-mcp", "groups", False),
        None,
    )
    with admin_client(ctx) as client:
        response = _start(client)
    assert response.status_code == 400
    assert "Company sign-in failed: The identity provider answered 404" in response.text


def test_sealed_values_expire_and_resist_tampering(
    store: Store, monkeypatch: pytest.MonkeyPatch
) -> None:
    sealed = store.seal("hello")
    assert store.unseal(sealed, max_age_seconds=60) == "hello"
    with pytest.raises(SecretUnreadable):
        store.unseal(sealed[:-6] + "AAAAAA", max_age_seconds=60)
    later = time.time() + 3600
    monkeypatch.setattr(time, "time", lambda: later)
    with pytest.raises(SecretUnreadable):
        store.unseal(sealed, max_age_seconds=600)
```

In `tests/test_admin/test_route_table.py`, set `PUBLIC_GETS = {"/sign-in", "/sign-in/sso/callback"}`. Add `"/sign-in/sso/callback"` to `NON_ADMIN_GETS` and `"/sign-in/sso"` to `NON_ADMIN_POSTS`.

- [ ] **Step 2: Run them and confirm they fail**

Run: `.venv/Scripts/python -m pytest tests/test_admin/test_sso_sign_in.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'u2_mcp.admin.routes_sso'`.

- [ ] **Step 3: Sealing**

In `store/crypto.py`, change `decrypt`'s signature to `def decrypt(self, token: str, ttl: int | None = None) -> str:`. Document `ttl` as "Refuse tokens older than this many seconds", and call `self._fernet.decrypt(token.encode("ascii"), ttl=ttl)`.

In `store/repo.py`, add to the settings section:

```python
    def seal(self, plaintext: str) -> str:
        """Encrypt a short value for a cookie: confidential and tamper-evident."""
        return self._box.encrypt(plaintext)

    def unseal(self, sealed: str, *, max_age_seconds: int) -> str:
        """Open a value made by seal().

        Raises:
            SecretUnreadable: If it was changed, made under another key, or is too old
        """
        return self._box.decrypt(sealed, ttl=max_age_seconds)
```

- [ ] **Step 4: Client builders** (append to `src/u2_mcp/sso_config.py`)

```python
def oidc_client(store: Store, http: HttpFactory) -> OidcClient | None:
    """The OIDC client for the saved settings, or None when company sign-in is off.

    An unreadable secret yields a client with no secret: starting a sign-in still
    works, and the exchange then says that no client secret is saved.
    """
    settings = load_sso(store)
    if settings is None:
        return None
    try:
        secret = sso_client_secret(store)
    except SecretUnreadable:
        secret = None
    return OidcClient(settings.discovery_url, settings.client_id, secret, http=http)


def overage_resolver(store: Store, settings: SsoSettings, http: HttpFactory) -> GraphGroups | None:
    """The Microsoft Graph lookup when the admin turned it on, else None."""
    if not settings.graph_overage:
        return None
    try:
        secret = sso_client_secret(store)
    except SecretUnreadable:
        return None
    return GraphGroups(settings.client_id, secret, http=http) if secret else None
```

Imports at the top, outside `TYPE_CHECKING`:

```python
from .auth.graph import GraphGroups
from .auth.oidc_client import HttpFactory, OidcClient
from .store.crypto import SecretUnreadable
```

- [ ] **Step 5: `AdminContext.http`** (`src/u2_mcp/admin/context.py`)

Add the import `from ..auth.oidc_client import HttpFactory, default_http`. Add the field `http: HttpFactory = default_http` with the docstring line "http: Makes the HTTP client for identity providers; replaced in tests".

- [ ] **Step 6: Implement `src/u2_mcp/admin/routes_sso.py`**

```python
"""Company sign-in (OIDC) for the admin site: start, callback, and the Settings test.

The round trip is bound to the browser that started it. State, nonce and the
PKCE verifier travel in a sealed, short-lived cookie: SameSite=Lax, so it comes
back on the identity provider's redirect, and `__Host-` over https. The callback
deletes it whatever happens, so a code cannot be replayed.
"""

from __future__ import annotations

import hmac
import json
from typing import Any

from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from ..auth.idp.base import TokenInfo
from ..auth.oidc_client import OidcError, PendingLogin
from ..sso_config import ADMIN_CALLBACK_PATH, load_sso, oidc_client, overage_resolver
from ..store.crypto import SecretUnreadable
from ..store.models import User
from ..team_auth import groups_for_sign_in, record_sign_in
from .context import AdminContext
from .security import (
    admin_only,
    client_ip,
    cookie_name,
    cookie_path,
    is_secure,
    read_form,
    safe_next,
    set_session_cookie,
    start_session,
)
from .services import effective_public_url
from .templating import admin_context, render

SSO_COOKIE = "u2_admin_sso"
SSO_COOKIE_SECONDS = 600
SSO_EXPIRED = (
    "This sign-in expired or was started in another browser. Start again from the sign-in page."
)
SSO_FAILED = "Company sign-in failed: {reason}"
SSO_NOT_SET_UP = "Company sign-in is not set up."
SSO_DISABLED = "This account is disabled. Ask an admin."
_TITLE = "Company sign-in"
_PENDING_KEYS = ("state", "nonce", "verifier", "purpose", "next")


def _message(request: Request, text: str, status_code: int) -> Response:
    return render(request, "message.html", status_code=status_code, title=_TITLE, message=text)


def _redirect_uri(ctx: AdminContext) -> str:
    return effective_public_url(ctx) + ADMIN_CALLBACK_PATH


def _forget(response: Response, secure: bool) -> Response:
    response.delete_cookie(
        cookie_name(SSO_COOKIE, secure), path=cookie_path(secure), secure=secure,
        httponly=True, samesite="lax",
    )
    return response


def _audit(
    ctx: AdminContext, *, testing: bool, outcome: str, actor: User | None, params: dict[str, Any]
) -> None:
    ctx.store.add_audit(
        kind="admin" if testing else "auth",
        action="settings.sso_test" if testing else "admin.sign_in",
        outcome=outcome,
        actor_user_id=actor.id if actor else None,
        actor_label=actor.label if actor else None,
        params={"method": "sso", **params},
    )


async def _begin(request: Request, *, purpose: str, next_url: str) -> Response:
    ctx = admin_context(request)
    client = oidc_client(ctx.store, ctx.http)
    if client is None:
        return _message(request, SSO_NOT_SET_UP, 400)
    login = PendingLogin.new()
    try:
        url = await client.authorization_url(_redirect_uri(ctx), login)
    except OidcError as exc:
        return _message(request, SSO_FAILED.format(reason=exc), 400)
    pending = {"state": login.state, "nonce": login.nonce, "verifier": login.verifier,
               "purpose": purpose, "next": next_url}
    secure = is_secure(ctx)
    response = RedirectResponse(url, status_code=303)
    response.set_cookie(
        cookie_name(SSO_COOKIE, secure),
        ctx.store.seal(json.dumps(pending)),
        max_age=SSO_COOKIE_SECONDS,
        path=cookie_path(secure),
        httponly=True,
        samesite="lax",
        secure=secure,
    )
    return response


async def sign_in_start(request: Request) -> Response:
    """Start a company sign-in from the sign-in page (pre-session CSRF token)."""
    form = await read_form(request, presession=True)
    return await _begin(request, purpose="sign_in", next_url=safe_next(str(form.get("next", ""))))


@admin_only
async def test_start(request: Request) -> Response:
    """Settings and the wizard: a real round trip that signs nobody in."""
    await read_form(request)
    return await _begin(request, purpose="test", next_url="/admin/settings")


def _pending(ctx: AdminContext, raw: str | None) -> dict[str, str] | None:
    if not raw:
        return None
    try:
        data = json.loads(ctx.store.unseal(raw, max_age_seconds=SSO_COOKIE_SECONDS))
    except (SecretUnreadable, ValueError):
        return None
    if not isinstance(data, dict) or not all(isinstance(data.get(k), str) for k in _PENDING_KEYS):
        return None
    return {key: data[key] for key in _PENDING_KEYS}


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


async def callback(request: Request) -> Response:
    """The identity provider's redirect back: check, then sign in (or show the test)."""
    ctx = admin_context(request)
    secure = is_secure(ctx)
    pending = _pending(ctx, request.cookies.get(cookie_name(SSO_COOKIE, secure)))
    if pending is None or not hmac.compare_digest(
        pending["state"], request.query_params.get("state", "")
    ):
        return _forget(_message(request, SSO_EXPIRED, 400), secure)
    testing = pending["purpose"] == "test"
    ip = client_ip(request)
    viewer: User | None = request.state.user
    settings = load_sso(ctx.store)
    client = oidc_client(ctx.store, ctx.http)
    try:
        if "error" in request.query_params:
            raise OidcError(
                request.query_params.get("error_description") or request.query_params["error"]
            )
        if settings is None or client is None:
            raise OidcError(SSO_NOT_SET_UP)
        login = PendingLogin(pending["state"], pending["nonce"], pending["verifier"])
        claims = await client.sign_in(
            request.query_params.get("code", ""), _redirect_uri(ctx), login
        )
    except OidcError as exc:
        _audit(ctx, testing=testing, outcome="failed", actor=viewer if testing else None,
               params={"ip": ip, "reason": str(exc)[:200]})
        return _forget(_message(request, SSO_FAILED.format(reason=exc), 400), secure)

    groups = await groups_for_sign_in(
        claims, settings.groups_claim, overage_resolver(ctx.store, settings, ctx.http)
    )
    if testing:
        _audit(ctx, testing=True, outcome="ok", actor=viewer,
               params={"groups": None if groups is None else len(groups)})
        page = render(
            request, "sso_test.html", subject=claims["sub"], email=_text(claims.get("email")),
            name=_text(claims.get("name")), groups=groups, groups_claim=settings.groups_claim,
            graph_overage=settings.graph_overage,
        )
        return _forget(page, secure)

    info = TokenInfo(
        subject=claims["sub"], email=_text(claims.get("email")), name=_text(claims.get("name")),
        raw_claims=claims,
    )
    user = record_sign_in(ctx.store, info, groups, via="admin")
    if user.disabled:
        _audit(ctx, testing=False, outcome="refused", actor=user,
               params={"ip": ip, "reason": "disabled"})
        return _forget(_message(request, SSO_DISABLED, 403), secure)
    previous = request.state.session
    if previous is not None:
        ctx.store.delete_admin_session(previous.id_hash)  # one browser, one session
    raw_id, _ = start_session(ctx.store, user, ip)
    _audit(ctx, testing=False, outcome="ok", actor=user, params={"ip": ip})
    response = RedirectResponse(safe_next(pending["next"]), status_code=303)
    set_session_cookie(response, raw_id, secure=secure)
    return _forget(response, secure)


routes = [
    Route("/sign-in/sso", sign_in_start, methods=["POST"]),
    Route("/sign-in/sso/callback", callback, methods=["GET"]),
    Route("/settings/sso/test", test_start, methods=["POST"]),
]
```

In `admin/app.py`, import `routes_sso` and add `*routes_sso.routes,` after `*routes_auth.routes,`.

- [ ] **Step 7: Pages**

`templates/sso_test.html`:

```html
{% extends "base.html" %}
{% block title %}Company sign-in test · u2-mcp admin{% endblock %}
{% block content %}
<h1>Company sign-in works</h1>
<table><tbody>
  <tr><th>Subject</th><td>{{ subject }}</td></tr>
  <tr><th>Email</th><td>{{ email or "" }}</td></tr>
  <tr><th>Name</th><td>{{ name or "" }}</td></tr>
  <tr><th>Groups ({{ groups_claim }})</th><td>
    {% if groups is none %}<span class="warning">The token says this person is in too many groups to list.
      {% if graph_overage %}Microsoft Graph could not list them: check the GroupMember.Read.All permission.
      {% else %}Turn on the Microsoft Graph lookup, or configure Entra to send only the groups assigned to the application.{% endif %}</span>
    {% elif groups %}{{ groups | join(", ") }}{% else %}None{% endif %}</td></tr>
</tbody></table>
<p>Nothing was saved: this test signs nobody in. You can close this window.</p>
{% endblock %}
```

In `partials/sso_form.html`, append after the closing `</form>`:

```html
{% if sso %}
<form method="post" action="/admin/settings/sso/test" target="_blank" class="actions">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <button type="submit" class="secondary">Test sign-in</button>
</form>
{% endif %}
```

In `sign_in.html`, insert above the local form:

```html
{% if sso_enabled %}
<form method="post" action="/admin/sign-in/sso" class="actions">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <input type="hidden" name="next" value="{{ next_url }}">
  <button type="submit">Sign in with your company account</button>
</form>
<p class="hint">Or sign in with a local account:</p>
{% endif %}
```

In `routes_auth._sign_in_page`, pass `sso_enabled=load_sso(ctx.store) is not None` to `render` (import `from ..sso_config import load_sso`).

In `routes_audit.dashboard`, add this keyword to `render(...)`:

```python
        groups_unavailable=[u for u in store.list_users() if u.groups_unavailable and not u.disabled],
```

In `dashboard.html`, add after the `everyone` loop:

```html
{% if groups_unavailable %}
<p class="warning">Groups were unavailable at the last company sign-in of: {{ groups_unavailable | map(attribute="label") | join(", ") }}. Group grants do not apply to them until a sign-in carries their groups. <a href="/admin/settings#sign-in">Company sign-in settings</a></p>
{% endif %}
```

- [ ] **Step 8: Run the tests and confirm they pass**

Run: `.venv/Scripts/python -m pytest tests/test_admin -q`
Expected: PASS. That includes the route-table tests, with the callback treated as public and `/sign-in/sso` refusing a POST without CSRF.

Then run the Global Constraints checks and `pytest -m e2e tests/e2e --browser chromium`.

- [ ] **Step 9: Commit**

```bash
git add src/u2_mcp/store/crypto.py src/u2_mcp/store/repo.py src/u2_mcp/sso_config.py src/u2_mcp/admin tests/test_admin/test_sso_sign_in.py tests/test_admin/test_route_table.py
git commit -m "feat(admin): company sign-in (OIDC code + PKCE, state, nonce) and the Test button

Overage users are flagged on the dashboard; Graph lookup when configured.

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
git push origin feature/phase3-sso-deploy
```

---

### Task 8: VS Code sign-in from the stored settings, and the restart note

**Files:**
- Create: `tests/test_admin/test_mcp_sso.py`
- Modify:
  - `src/u2_mcp/server.py`: the OAuth bridge set-up, plus `_stored_sso_adapter`, `_team_sign_in` and `_id_token_claims`
  - `src/u2_mcp/admin/context.py`: `mcp_oauth`
  - `src/u2_mcp/admin/routes_me.py`
  - `src/u2_mcp/admin/templates/me.html`
  - `src/u2_mcp/admin/services.py`: `RESTART_NOTE`
  - `src/u2_mcp/admin/sso_services.py`: `sso_restart_note`
  - `src/u2_mcp/admin/templates/partials/sso_form.html`
  - `tests/test_admin/helpers.py`: `team_server(base_url=...)`
  - any test or doc that quotes the old `RESTART_NOTE`

**Interfaces:**
- **Consumes:**
  - `load_sso`, `sso_client_secret`, `overage_resolver` (Tasks 6 and 7)
  - `OidcClient`, `default_http` (Task 4)
  - `make_sign_in_handler(store, claim, resolver)` (Task 5)
  - `U2OAuthProvider(..., id_token_claims=...)` (Task 5)
- **Produces, `server.py`:**
  - `_stored_sso_adapter(store, public_url) -> GenericOIDCAdapter | None`
  - `_team_sign_in(store, config) -> Callable[[TokenInfo], Awaitable[None]]`
  - `_id_token_claims(adapter) -> Callable[[str], Awaitable[dict[str, Any]]] | None`
- **Produces:** `AdminContext.mcp_oauth: bool = False`, which is True when the OAuth bridge was built at startup.
- **Produces:** the new `RESTART_NOTE` text from Global Constraints.
- **Produces:** `team_server(..., base_url: str = "http://testserver", ...)`.

- [ ] **Step 1: Let `team_server` take a base URL**

In `tests/test_admin/helpers.py`, add `base_url: str = "http://testserver",` to `team_server`'s keyword-only parameters. Construct the client with `TestClient(app, client=client, base_url=base_url)`.

- [ ] **Step 2: Write the failing tests** (`tests/test_admin/test_mcp_sso.py`)

```python
"""Company sign-in saved on the admin site turns on VS Code's OAuth sign-in after a restart."""

from pathlib import Path

import pytest

from u2_mcp import server
from u2_mcp.admin.services import RESTART_NOTE
from u2_mcp.auth.idp.oidc import GenericOIDCAdapter
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import finish_setup
from u2_mcp.sso_config import SsoSettings, store_sso
from u2_mcp.store import get_store

from .helpers import PASSWORD, sign_in, team_server

HTTPS_URL = "https://u2.example.com"
METADATA = "/.well-known/oauth-authorization-server"
SNIPPET = "VS Code, signing in with your company account"


def _save_sso(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, secret: str | None = "s3cret", **env: str
) -> None:
    """A first start that saves company sign-in, as an admin would on the admin site."""
    with team_server(tmp_path, monkeypatch, **env):
        store_sso(
            get_store(),
            SsoSettings("oidc", "https://idp.example/.well-known/openid-configuration",
                        "u2-mcp", "groups", False),
            secret,
        )


def test_saved_company_sign_in_turns_on_oauth_after_a_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with team_server(tmp_path, monkeypatch, U2_PUBLIC_URL=HTTPS_URL) as client:
        assert client.get(METADATA).status_code != 200
    _save_sso(tmp_path, monkeypatch, U2_PUBLIC_URL=HTTPS_URL)
    with team_server(tmp_path, monkeypatch, U2_PUBLIC_URL=HTTPS_URL) as client:
        metadata = client.get(METADATA)
    assert metadata.status_code == 200
    assert metadata.json()["issuer"].rstrip("/") == HTTPS_URL


def test_an_http_address_keeps_vs_code_sign_in_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    address = "http://10.0.0.5:8080"
    _save_sso(tmp_path, monkeypatch, U2_PUBLIC_URL=address)
    with caplog.at_level("WARNING"), team_server(tmp_path, monkeypatch, U2_PUBLIC_URL=address) as client:
        assert client.get(METADATA).status_code != 200
    assert "needs an https server address" in caplog.text


def test_a_missing_secret_keeps_vs_code_sign_in_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _save_sso(tmp_path, monkeypatch, secret=None, U2_PUBLIC_URL=HTTPS_URL)
    with caplog.at_level("WARNING"), team_server(tmp_path, monkeypatch, U2_PUBLIC_URL=HTTPS_URL) as client:
        assert client.get(METADATA).status_code != 200
    assert "client secret is missing or unreadable" in caplog.text


def test_my_access_offers_the_oauth_snippet_only_when_the_bridge_is_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def my_access_page() -> str:
        with team_server(
            tmp_path, monkeypatch, base_url="https://testserver", U2_PUBLIC_URL=HTTPS_URL
        ) as client:
            store = get_store()
            if store.get_user_by_username("ann") is None:
                store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
                finish_setup(store)
            sign_in(client)
            return client.get("/admin/me").text

    assert SNIPPET not in my_access_page()
    _save_sso(tmp_path, monkeypatch, U2_PUBLIC_URL=HTTPS_URL)
    assert SNIPPET in my_access_page()


def test_id_tokens_are_checked_when_the_adapter_has_discovery() -> None:
    assert server._id_token_claims(GenericOIDCAdapter(None, "id", "s")) is None
    adapter = GenericOIDCAdapter("https://idp.example/.well-known/openid-configuration", "id", "s")
    assert server._id_token_claims(adapter) is not None


def test_the_restart_note_mentions_company_sign_in() -> None:
    assert "company sign-in" in RESTART_NOTE and "U2_AUTH_ISSUER_URL" in RESTART_NOTE
```

- [ ] **Step 3: Run them and confirm they fail**

Run: `.venv/Scripts/python -m pytest tests/test_admin/test_mcp_sso.py -q`

Expected: the restart test FAILS, because the metadata is still absent after saving. `_id_token_claims` FAILS with an `AttributeError`. The `RESTART_NOTE` test FAILS.

- [ ] **Step 4: Add the server helpers** (module level in `src/u2_mcp/server.py`)

```python
def _issuer_allowed(url: str) -> bool:
    """OAuth issuers must be https; the MCP SDK allows http only for localhost."""
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    return parts.scheme == "https" or parts.hostname in ("localhost", "127.0.0.1")


def _stored_sso_adapter(store: Any, public_url: str) -> Any | None:
    """The OAuth bridge's IdP adapter, built from the admin site's company sign-in.

    Returns None, with a warning naming the fix, when it cannot be used yet.
    """
    from .auth.idp import GenericOIDCAdapter
    from .sso_config import load_sso, sso_client_secret
    from .store.crypto import SecretUnreadable

    settings = load_sso(store)
    if settings is None:
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
    return GenericOIDCAdapter(
        discovery_url=settings.discovery_url,
        client_id=settings.client_id,
        client_secret=secret,
        scopes=["openid", "profile", "email"],
    )


def _team_sign_in(store: Any, config: U2Config) -> Any:
    """The OAuth bridge's on_sign_in in team mode, with the saved groups claim and Graph."""
    from .auth.oidc_client import default_http
    from .sso_config import load_sso, overage_resolver

    settings = load_sso(store)
    claim = settings.groups_claim if settings is not None else config.sso_groups_claim
    resolver = overage_resolver(store, settings, default_http) if settings is not None else None
    return make_sign_in_handler(store, claim, resolver)


def _id_token_claims(adapter: Any) -> Any | None:
    """Validate the IdP's ID token for the bridge, when the adapter has discovery."""
    from .auth.oidc_client import OidcClient

    if not getattr(adapter, "discovery_url", None) or not getattr(adapter, "client_id", None):
        return None
    client = OidcClient(adapter.discovery_url, adapter.client_id, adapter.client_secret)

    async def claims(id_token: str) -> dict[str, Any]:
        return await client.validate_id_token(id_token)

    return claims
```

- [ ] **Step 5: Use them in `build_streamable_http_app`**

1. Replace the part from the `pat_resource` comment down to just before `elif store is not None:` with the code below. The token-only branch after it stays as it is.

   ```python
       # Company sign-in saved on the admin site also drives VS Code's OAuth sign-in,
       # unless U2_AUTH_ENABLED configures the bridge from the environment. It is
       # read here, at startup: RESTART_NOTE tells admins to restart after changes.
       stored_adapter = (
           _stored_sso_adapter(store, public_url)
           if store is not None and not config.auth_enabled
           else None
       )
       oauth_issuer: str | None = (
           config.auth_issuer_url
           if config.auth_enabled
           else (public_url if stored_adapter is not None else None)
       )
       # A personal token must name the resource the SDK checks bearer tokens against:
       # the issuer URL when OAuth is on (resource_server_url below), otherwise ours.
       pat_resource = oauth_issuer or public_url
       pat_verifier = (
           PatVerifier(store, freshness_days=config.token_freshness_days, resource=pat_resource)
           if store is not None
           else None
       )

       auth_provider = None
       auth_settings = None
       token_verifier = None
       idp_adapter: Any = stored_adapter

       if config.auth_enabled:
           if not config.auth_issuer_url:
               raise ValueError("U2_AUTH_ISSUER_URL is required when auth is enabled")
           if not config.idp_discovery_url and not config.duo_api_host:
               raise ValueError(
                   "U2_IDP_DISCOVERY_URL (or U2_DUO_API_HOST for Duo) is required when auth is enabled"
               )
           idp_adapter = create_idp_adapter(config)

       if idp_adapter is not None and oauth_issuer:
           # In team mode it also accepts personal access tokens, validates the ID
           # token (Entra puts groups only there), and records each completed sign-in.
           auth_provider = U2OAuthProvider(
               idp_adapter=idp_adapter,
               issuer_url=oauth_issuer,
               token_expiry=config.token_expiry_seconds,
               refresh_token_expiry=config.refresh_token_expiry_seconds,
               storage=create_auth_storage(config.auth_storage, config.auth_storage_path),
               on_sign_in=_team_sign_in(store, config) if store is not None else None,
               id_token_claims=_id_token_claims(idp_adapter) if store is not None else None,
               pat_verifier=pat_verifier.verify_token if pat_verifier is not None else None,
           )
           issuer_url = AnyHttpUrl(oauth_issuer)
   ```

2. Keep the existing `auth_settings = AuthSettings(...)` block, the identity-resolver block and the two `logger.info` lines, now indented under this `if`. Change the first log line to:

   ```python
           source = config.idp_provider if config.auth_enabled else "the admin site's company sign-in"
           logger.info(f"OAuth enabled with {source}")
   ```

3. In the admin-site block, pass the bridge state: `AdminContext(store=store, config=config, registry=get_connection_registry, mcp_oauth=auth_provider is not None)`.

Behaviour without team mode is unchanged. `store` is None, so there is no stored adapter, no ID-token hook and no sign-in hook, and the env-configured bridge is built exactly as before.

- [ ] **Step 6: Admin context, My access, and the note**

1. `admin/context.py`: add the field `mcp_oauth: bool = False`, documented as "Whether VS Code's OAuth sign-in (the MCP OAuth bridge) was built at startup".
2. `routes_me.my_access`: `configs=client_configs(public_url, oauth=ctx.mcp_oauth)`.
3. `me.html`: replace the `{% else %}` hint with:

   ```html
   <p class="hint">Browser sign-in from VS Code works once company sign-in is set up and the server has restarted. Until then, use a token.</p>
   ```

4. `services.py`:

   ```python
   RESTART_NOTE = (
       "Restart the server after changing the address or company sign-in: VS Code sign-in "
       "and personal access tokens pick them up at startup. With U2_AUTH_ENABLED set, they "
       "use U2_AUTH_ISSUER_URL instead."
   )
   ```

5. `sso_services.sso_context`: add `"sso_restart_note": RESTART_NOTE` (import it from `.services`).
6. `partials/sso_form.html`: add `<p class="hint">{{ sso_restart_note }}</p>` just before the form's `<div class="actions">`.
7. Run `grep -rn "Restart the server for personal access tokens" src tests docs`. Replace every hit with the new text, or with a reference to `RESTART_NOTE`. This also closes the 2a item about the `set-public-url` CLI hint, because `cli.py` already prints `RESTART_NOTE`, which is now true with SSO.

- [ ] **Step 7: Run the tests and confirm they pass**

Run: `.venv/Scripts/python -m pytest tests/test_admin tests/test_auth tests/test_team_mode_e2e.py tests/test_cli.py -q`
Expected: PASS.

Then run the Global Constraints checks and the e2e suite. My access changed, so the e2e suite is required.

- [ ] **Step 8: Commit**

```bash
git add src/u2_mcp/server.py src/u2_mcp/admin tests/test_admin docs
git commit -m "feat: VS Code sign-in from the admin site's company sign-in (after restart)

The MCP OAuth bridge validates ID tokens and records sign-ins through the
shared recorder. RESTART_NOTE now covers company sign-in.

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
git push origin feature/phase3-sso-deploy
```

---

### Task 9: The 30-day freshness rule on the pages, and the personal U2 login hint

**Files:**
- Create: `tests/test_admin/test_freshness_ui.py`
- Modify:
  - `src/u2_mcp/tokens.py`: `is_fresh`, `fresh_until`
  - `src/u2_mcp/admin/services.py`: `TokenView`, `token_views`
  - `src/u2_mcp/access.py`: `needs_personal_login`
  - `src/u2_mcp/admin/routes_me.py`, `src/u2_mcp/admin/routes_users.py`
  - templates: `me.html`, `users/detail.html`, `users/access.html`

**Interfaces:**
- **Produces, `tokens.py`:**
  - `is_fresh(user: User, *, now: float, freshness_days: int) -> bool`: always True for local users
  - `fresh_until(user: User, *, freshness_days: int) -> float | None`
  - `verify_token` uses `is_fresh`. Its message is unchanged.
- **Produces, services:**
  - `TokenView.status` can now be `"Paused"`, for an owner who has not signed in recently.
  - `TokenView.revocable -> bool`: True when the status is `Active` or `Paused`.
- **Produces, `access.py`:** `VisibleConnection.needs_personal_login: bool = False` and `EffectiveAccess.needs_personal_login: bool = False`. Each is True on a `per_user` connection where the person has no user grant carrying both a U2 user and a password.

- [ ] **Step 1: Write the failing tests** (`tests/test_admin/test_freshness_ui.py`)

```python
"""Paused tokens and missing personal U2 logins are shown, not discovered by failure."""

from u2_mcp.access import effective_access, visible_connections
from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.security import SESSION_COOKIE, start_session
from u2_mcp.admin.services import token_views
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import finish_setup
from u2_mcp.store.repo import Store
from u2_mcp.tokens import create_token, fresh_until, is_fresh

from .helpers import PASSWORD, admin_client, sign_in

DAY = 86400.0


def _sso_user(store: Store, *, days_ago: float) -> int:
    user = store.get_or_create_sso_user("sam", display_name="Sam")
    store.record_sso_login(user.id, [])
    with store._tx() as conn:  # test-only: move the sign-in into the past
        conn.execute(
            "UPDATE users SET last_sso_login_at = ? WHERE id = ?",
            (store.clock() - days_ago * DAY, user.id),
        )
    return user.id


def test_is_fresh_counts_days_since_the_last_company_sign_in(store: Store) -> None:
    user_id = _sso_user(store, days_ago=29)
    user = store.get_user(user_id)
    assert user is not None
    now = store.clock()
    assert is_fresh(user, now=now, freshness_days=30)
    assert not is_fresh(user, now=now + 2 * DAY, freshness_days=30)
    until = fresh_until(user, freshness_days=30)
    assert until is not None and abs(until - (now + DAY)) < 5
    local = store.add_local_user("ann")
    assert is_fresh(local, now=now + 1000 * DAY, freshness_days=30)
    assert fresh_until(local, freshness_days=30) is None


def test_stale_owners_tokens_show_as_paused_and_stay_revocable(ctx: AdminContext) -> None:
    user_id = _sso_user(ctx.store, days_ago=31)
    create_token(ctx.store, user_id, "laptop")
    [view] = token_views(ctx, user_id)
    assert view.status == "Paused" and view.revocable


def test_the_users_page_explains_paused_tokens(ctx: AdminContext) -> None:
    user_id = _sso_user(ctx.store, days_ago=31)
    create_token(ctx.store, user_id, "laptop")
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    finish_setup(ctx.store)
    with admin_client(ctx) as client:
        sign_in(client)
        page = client.get(f"/admin/users/{user_id}").text
    assert "Paused" in page and "reactivate when the person signs in" in page
    assert "Revoke laptop" in page


def test_my_access_says_when_tokens_would_pause(ctx: AdminContext) -> None:
    user_id = _sso_user(ctx.store, days_ago=1)
    create_token(ctx.store, user_id, "laptop")
    with admin_client(ctx) as client:
        # A session made directly: the company sign-in round trip has its own tests.
        user = ctx.store.get_user(user_id)
        assert user is not None
        raw_id, _ = start_session(ctx.store, user, "10.0.0.1")
        client.cookies.set(SESSION_COOKIE, raw_id, domain="testserver", path="/admin")
        page = client.get("/admin/me").text
    assert "at least once every 30 days" in page


def test_group_access_on_a_per_person_connection_says_a_login_is_needed(store: Store) -> None:
    connection = store.add_connection(
        name="Prod", host="u2.example", port=31438, service="uvcs", account="PROD",
        login_mode="per_user",
    )
    viewer = store.get_role_by_name("Viewer")
    assert viewer is not None
    store.add_grant(connection_id=connection.id, subject_type="everyone", role_id=viewer.id)
    sam = store.get_or_create_sso_user("sam")
    [visible] = visible_connections(store, sam.id, global_read_only=False)
    assert visible.needs_personal_login
    [report] = effective_access(store, sam.id, global_read_only=False)
    assert report.needs_personal_login
    store.add_grant(
        connection_id=connection.id, subject_type="user", subject_id=sam.id, role_id=viewer.id,
        per_user_u2_user="sam", per_user_u2_password="pw",
    )
    [visible] = visible_connections(store, sam.id, global_read_only=False)
    assert not visible.needs_personal_login
```

If `add_connection` or `add_grant` use different keyword names for the login mode or the per-user login, use the names in `store/repo.py`; `add_grant` and `update_grant` are defined there. The intent of the test stays the same.

- [ ] **Step 2: Run them and confirm they fail**

Run: `.venv/Scripts/python -m pytest tests/test_admin/test_freshness_ui.py -q`
Expected: FAIL, with `ImportError` for `fresh_until` and `is_fresh`.

- [ ] **Step 3: Implement the freshness helpers** (`src/u2_mcp/tokens.py`)

```python
def is_fresh(user: User, *, now: float, freshness_days: int) -> bool:
    """Whether a user's tokens may be used now: always for local users; for SSO
    users, only within freshness_days of their last company sign-in."""
    if user.kind != "sso":
        return True
    last = user.last_sso_login_at
    return last is not None and now - last <= freshness_days * _DAY_SECONDS


def fresh_until(user: User, *, freshness_days: int) -> float | None:
    """When an SSO user's tokens pause without another sign-in; None for local users."""
    if user.kind != "sso" or user.last_sso_login_at is None:
        return None
    return user.last_sso_login_at + freshness_days * _DAY_SECONDS
```

In `verify_token`, replace the SSO block with:

```python
    if not is_fresh(user, now=now, freshness_days=freshness_days):
        raise TokenRejected("sign in to the admin site to reactivate your tokens")
```

- [ ] **Step 4: Paused tokens** (`src/u2_mcp/admin/services.py`)

```python
@dataclass(frozen=True)
class TokenView:
    """A token as a page lists it."""

    record: TokenRecord
    status: str  # "Active", "Paused", "Expired" or "Revoked"

    @property
    def revocable(self) -> bool:
        """Whether a Revoke button applies (it does to a paused token too)."""
        return self.status in ("Active", "Paused")


def token_views(ctx: AdminContext, user_id: int) -> list[TokenView]:
    """A user's tokens, newest first, with their status now."""
    now = ctx.store.clock()
    owner = ctx.store.get_user(user_id)
    fresh = owner is None or is_fresh(owner, now=now, freshness_days=ctx.config.token_freshness_days)
    views = []
    for record in ctx.store.list_tokens(user_id):
        if record.revoked_at is not None:
            status = "Revoked"
        elif now >= record.expires_at:
            status = "Expired"
        else:
            status = "Active" if fresh else "Paused"
        views.append(TokenView(record, status))
    return views
```

Import `is_fresh` from `..tokens`. In `me.html` and `users/detail.html`, change `{% if t.status == "Active" %}` to `{% if t.revocable %}`.

- [ ] **Step 5: The pages**

1. `routes_me.my_access`: add these to the render context:

   ```python
           freshness_days=ctx.config.token_freshness_days,
           fresh_until=fresh_until(user, freshness_days=ctx.config.token_freshness_days),
   ```

2. `me.html`: insert under `<h2>My tokens</h2>`:

   ```html
   {% if fresh_until %}<p class="hint">Your tokens work while you keep signing in here with your company account, at least once every {{ freshness_days }} days. Without a new sign-in they pause on {{ fresh_until | when }}. Signing in again reactivates them.</p>{% endif %}
   ```

3. `routes_users.user_detail`: add these to the render context (import `is_fresh` from `..tokens`):

   ```python
           paused=not is_fresh(user, now=ctx.store.clock(), freshness_days=ctx.config.token_freshness_days),
           freshness_days=ctx.config.token_freshness_days,
   ```

4. `users/detail.html`: insert under `<h2>Tokens</h2>`:

   ```html
   {% if paused %}<p class="warning">This person's tokens are paused: no company sign-in for over {{ freshness_days }} days. They reactivate when the person signs in to this site.</p>{% endif %}
   ```

5. `me.html`: in the connections table's third cell, replace `{{ v.permissions | sort | join(", ") }}` with:

   ```html
   {% if v.needs_personal_login %}<span class="warning">Nothing yet: an admin must add your own U2 login for this connection.</span>{% else %}{{ v.permissions | sort | join(", ") }}{% endif %}
   ```

6. `users/access.html`: insert just after `<h2>{{ entry.connection.name }}</h2>`:

   ```html
   {% if entry.needs_personal_login %}<p class="warning">No U2 login of their own is set on {{ entry.connection.name }}, so their calls there are refused. Add one on their user grant.</p>{% endif %}
   ```

- [ ] **Step 6: The personal login flag** (`src/u2_mcp/access.py`)

Add `needs_personal_login: bool = False` as the last field of `VisibleConnection` and of `EffectiveAccess`. In `visible_connections`, compute it and pass it in:

```python
        needs_login = connection.login_mode == "per_user" and not any(
            g.subject_type == "user"
            and g.subject_id == user_id
            and g.per_user_u2_user
            and g.has_per_user_password
            for g in mine
        )
```

Add `needs_personal_login=needs_login` to the `VisibleConnection(...)` call. In `effective_access`, pass `needs_personal_login=visible.needs_personal_login` to `EffectiveAccess(...)`.

- [ ] **Step 7: Run the tests and confirm they pass**

Run: `.venv/Scripts/python -m pytest tests/test_admin tests/test_tokens.py tests/test_access.py -q`
Expected: PASS. Then run the Global Constraints checks and the e2e suite.

- [ ] **Step 8: Commit**

```bash
git add src/u2_mcp/tokens.py src/u2_mcp/access.py src/u2_mcp/admin tests/test_admin/test_freshness_ui.py
git commit -m "feat(admin): show paused tokens and the 30-day rule; flag missing personal U2 logins

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
git push origin feature/phase3-sso-deploy
```

---

### Task 10: Docker image, compose, proxy examples, TLS, and the browser suite against the image in CI

**Files:**
- Create:
  - `Dockerfile`, `.dockerignore`, `docker-compose.yml`
  - `deploy/caddy/Caddyfile`, `deploy/caddy/docker-compose.yml`
  - `deploy/nginx/default.conf`, `deploy/nginx/docker-compose.yml`
- Modify:
  - `src/u2_mcp/config.py`: `U2_TLS_CERT` and `U2_TLS_KEY`
  - `src/u2_mcp/server.py`: TLS passed to uvicorn
  - `tests/e2e/conftest.py`: process or container
  - `tests/e2e/test_everyday_pages.py`: `server.python`
  - `.github/workflows/ci.yml`
  - `tests/test_admin/test_proxy_headers.py`: the TLS tests

**Interfaces:**
- **Produces, config:** `U2Config.tls_cert: str | None` and `U2Config.tls_key: str | None`. Setting only one of them is a `ValueError`.
- **Produces, `tests/e2e/conftest.py`:**
  - `Server(base_url, data_dir, env, container=None)`, with methods `.url(path)`, `.admin_cli(*args) -> str`, `.python(code) -> str` and `.setup_code() -> str`
  - `launch_server(data_dir) -> tuple[_Process | _Container, Server]`
  - `E2E_IMAGE`, read from `U2_E2E_IMAGE`
  - `_free_port()` and `_stop()`, unchanged
- **Produces, images:** the `release` target runs `u2-mcp --streamable-http` as user `u2mcp`, on `0.0.0.0:8000`, with `/data` as a volume. The `test` target adds `tests/mocks` and `U2_DRIVER=tests.mocks.sim_driver`.

- [ ] **Step 1: Write the failing TLS tests** (append to `tests/test_admin/test_proxy_headers.py`)

```python
def test_tls_files_are_handed_to_uvicorn(
    monkeypatch: pytest.MonkeyPatch, mock_env: dict[str, str]
) -> None:
    seen: dict[str, object] = {}
    for key, value in {"U2_WATCHDOG_ENABLED": "false", "U2_AUDIT_ENABLED": "false",
                       "U2_TLS_CERT": "/certs/cert.pem", "U2_TLS_KEY": "/certs/key.pem"}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: seen.update(kwargs))
    server.run_streamable_http_server()
    assert seen["ssl_certfile"] == "/certs/cert.pem" and seen["ssl_keyfile"] == "/certs/key.pem"


def test_a_certificate_without_its_key_is_refused(
    monkeypatch: pytest.MonkeyPatch, mock_env: dict[str, str]
) -> None:
    from u2_mcp.config import U2Config

    monkeypatch.setenv("U2_TLS_CERT", "/certs/cert.pem")
    with pytest.raises(ValueError, match="U2_TLS_CERT and U2_TLS_KEY"):
        U2Config()
```

Run: `.venv/Scripts/python -m pytest tests/test_admin/test_proxy_headers.py -q`
Expected: the two new tests FAIL with a `KeyError` on `ssl_certfile`, and with no error raised.

- [ ] **Step 2: Implement TLS**

In `config.py`, add these after `trusted_proxies`:

```python
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

    @model_validator(mode="after")
    def _tls_pair(self) -> "U2Config":
        """A certificate is useless without its key, and the reverse."""
        if bool(self.tls_cert) != bool(self.tls_key):
            raise ValueError("Set both U2_TLS_CERT and U2_TLS_KEY, or neither.")
        return self
```

In `server.run_streamable_http_server`, build this before `uvicorn.run`:

```python
    tls: dict[str, str] = (
        {"ssl_certfile": config.tls_cert, "ssl_keyfile": config.tls_key}
        if config.tls_cert and config.tls_key
        else {}
    )
```

Then call `uvicorn.run(app, host=config.http_host, port=config.http_port, log_level="info", proxy_headers=False, **tls)`. Re-run the step 1 command and expect PASS.

- [ ] **Step 3: The image** (`Dockerfile`)

```dockerfile
# syntax=docker/dockerfile:1
# u2-mcp in team mode. Two targets:
#   release - what you deploy (no test code)
#   test    - adds the scripted U2 driver and the mock identity provider, for CI's
#             browser tests (U2_E2E_IMAGE); never deploy it.
FROM python:3.12-slim AS release

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
# uopy (Rocket's driver) is on PyPI, so this installs everything the server needs.
RUN pip install . \
    && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin u2mcp \
    && mkdir -p /data \
    && chown u2mcp /data

ENV U2_DATA_DIR=/data \
    U2_HTTP_HOST=0.0.0.0 \
    U2_HTTP_PORT=8000
VOLUME ["/data"]
EXPOSE 8000
USER u2mcp

# slim has no curl: ask /health with Python. https when U2_TLS_CERT is set.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os, ssl, urllib.request; s = 'https' if os.environ.get('U2_TLS_CERT') else 'http'; p = os.environ.get('U2_HTTP_PORT', '8000'); urllib.request.urlopen(s + '://127.0.0.1:' + p + '/health', timeout=4, context=ssl._create_unverified_context())"

ENTRYPOINT ["u2-mcp"]
CMD ["--streamable-http"]

FROM release AS test
USER root
COPY tests/__init__.py /app/tests/__init__.py
COPY tests/mocks /app/tests/mocks
ENV PYTHONPATH=/app \
    U2_DRIVER=tests.mocks.sim_driver
USER u2mcp
```

`.dockerignore`:

```
.git
.venv
.superpowers
**/__pycache__
.pytest_cache
.mypy_cache
.ruff_cache
logs
evidence
dist
build
```

`docker-compose.yml`:

```yaml
# u2-mcp in team mode.
# 1. Put U2_SECRET_KEY (32+ random characters; keep a copy in your vault) in a .env
#    file next to this one.
# 2. docker compose up -d
# 3. Open http://<this host>:8000/admin/ and enter the setup code from:
#      docker compose exec u2-mcp u2-mcp admin show-setup-code
# Behind a reverse proxy, see deploy/caddy or deploy/nginx instead.
services:
  u2-mcp:
    image: ${U2_IMAGE:-u2-mcp:local}
    build:
      context: .
      target: release
    restart: unless-stopped
    ports:
      - "8000:8000"
    environment:
      U2_SECRET_KEY: ${U2_SECRET_KEY:?Set U2_SECRET_KEY in .env (32+ random characters)}
      U2_PUBLIC_URL: ${U2_PUBLIC_URL:-}
      U2_TRUSTED_PROXIES: ${U2_TRUSTED_PROXIES:-}
      U2_ADMIN_ALLOWED_IPS: ${U2_ADMIN_ALLOWED_IPS:-}
    volumes:
      - u2-data:/data

volumes:
  u2-data:
```

- [ ] **Step 4: The proxy examples**

`deploy/caddy/Caddyfile`:

```
# Caddy terminates TLS (automatic certificates) and forwards to u2-mcp.
# Set U2_SITE_ADDRESS to the host name people use, e.g. u2-mcp.example.com.
# Caddy replaces any X-Forwarded-For the client sent, and sets X-Forwarded-Proto.
{$U2_SITE_ADDRESS:u2-mcp.example.com} {
	reverse_proxy u2-mcp:8000 {
		# Streamable HTTP keeps responses open: pass bytes on as they arrive.
		flush_interval -1
	}
}
```

`deploy/caddy/docker-compose.yml`:

```yaml
# u2-mcp behind Caddy. From the repository root:
#   U2_SECRET_KEY=... U2_SITE_ADDRESS=u2-mcp.example.com \
#     docker compose -f deploy/caddy/docker-compose.yml up -d
# u2-mcp is not published: only Caddy reaches it, from a fixed address, and that
# address is the only one whose X-Forwarded-* headers u2-mcp believes.
services:
  u2-mcp:
    image: ${U2_IMAGE:-u2-mcp:local}
    build:
      context: ../..
      target: release
    restart: unless-stopped
    environment:
      U2_SECRET_KEY: ${U2_SECRET_KEY:?Set U2_SECRET_KEY (32+ random characters)}
      U2_PUBLIC_URL: ${U2_PUBLIC_URL:-}
      U2_TRUSTED_PROXIES: 172.31.250.2
      U2_ADMIN_ALLOWED_IPS: ${U2_ADMIN_ALLOWED_IPS:-}
    volumes:
      - u2-data:/data
    networks:
      edge:
        ipv4_address: 172.31.250.3

  caddy:
    image: caddy:2.8
    restart: unless-stopped
    depends_on: [u2-mcp]
    ports:
      - "80:80"
      - "443:443"
    environment:
      U2_SITE_ADDRESS: ${U2_SITE_ADDRESS:-u2-mcp.example.com}
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy-data:/data
    networks:
      edge:
        ipv4_address: 172.31.250.2

networks:
  edge:
    ipam:
      config:
        - subnet: 172.31.250.0/24

volumes:
  u2-data:
  caddy-data:
```

`deploy/nginx/default.conf`:

```nginx
# nginx in front of u2-mcp. This example listens on port 80 so it runs as is;
# for production, use the TLS server block at the end instead.
server {
    listen 80;
    server_name _;
    client_max_body_size 10m;

    location / {
        proxy_pass http://u2-mcp:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        # Replace, never append to, what the client sent: u2-mcp believes only this proxy.
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        # Streamable HTTP (MCP) streams responses: no buffering, long reads.
        proxy_buffering off;
        proxy_read_timeout 3600s;
    }
}

# server {
#     listen 443 ssl;
#     server_name u2-mcp.example.com;
#     ssl_certificate     /etc/nginx/certs/fullchain.pem;
#     ssl_certificate_key /etc/nginx/certs/privkey.pem;
#     client_max_body_size 10m;
#
#     location / {
#         proxy_pass http://u2-mcp:8000;
#         proxy_http_version 1.1;
#         proxy_set_header Host $host;
#         proxy_set_header X-Forwarded-For $remote_addr;
#         proxy_set_header X-Forwarded-Proto $scheme;
#         proxy_buffering off;
#         proxy_read_timeout 3600s;
#     }
# }
```

`deploy/nginx/docker-compose.yml`:

```yaml
# u2-mcp behind nginx. From the repository root:
#   U2_SECRET_KEY=... docker compose -f deploy/nginx/docker-compose.yml up -d
# u2-mcp is not published: only nginx reaches it, from a fixed address, and that
# address is the only one whose X-Forwarded-* headers u2-mcp believes.
services:
  u2-mcp:
    image: ${U2_IMAGE:-u2-mcp:local}
    build:
      context: ../..
      target: release
    restart: unless-stopped
    environment:
      U2_SECRET_KEY: ${U2_SECRET_KEY:?Set U2_SECRET_KEY (32+ random characters)}
      U2_PUBLIC_URL: ${U2_PUBLIC_URL:-}
      U2_TRUSTED_PROXIES: 172.31.250.2
      U2_ADMIN_ALLOWED_IPS: ${U2_ADMIN_ALLOWED_IPS:-}
    volumes:
      - u2-data:/data
    networks:
      edge:
        ipv4_address: 172.31.250.3

  nginx:
    image: nginx:1.27-alpine
    restart: unless-stopped
    depends_on: [u2-mcp]
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./default.conf:/etc/nginx/conf.d/default.conf:ro
    networks:
      edge:
        ipv4_address: 172.31.250.2

networks:
  edge:
    ipam:
      config:
        - subnet: 172.31.250.0/24

volumes:
  u2-data:
```

- [ ] **Step 5: The e2e launcher learns containers** (replace `tests/e2e/conftest.py`)

```python
"""Browser tests: a real server, a real browser, the scripted U2 driver.

Run with: pytest -m e2e tests/e2e
Plain `pytest` deselects these (see addopts), so it never needs a browser.

The server is a local process by default. With U2_E2E_IMAGE set (CI sets it to
the image's test target), each test runs that image instead: a fresh container
and volume per test, on the host network, so the browser and the server reach
the mock identity provider at the same address. Nothing here needs Docker
unless U2_E2E_IMAGE is set.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
from playwright.sync_api import Browser, Page

REPO_ROOT = Path(__file__).resolve().parents[2]
SECRET_KEY = "e2e-secret-key-" + "k" * 32
START_TIMEOUT_SECONDS = 60.0
E2E_IMAGE = os.environ.get("U2_E2E_IMAGE", "")


@dataclass
class Server:
    """A running server under test: a local process, or a container when `container` is set."""

    base_url: str
    data_dir: Path
    env: dict[str, str]
    container: str | None = None

    def url(self, path: str) -> str:
        """Return an absolute URL on this server."""
        return f"{self.base_url}{path}"

    def _run(self, argv: list[str]) -> str:
        if self.container:
            argv = ["docker", "exec", self.container, *argv]
        completed = subprocess.run(  # noqa: S603 - fixed argv, test-only
            argv,
            env=None if self.container else self.env,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
        return completed.stdout

    def admin_cli(self, *args: str) -> str:
        """Run `u2-mcp admin ...` where the server runs, as an operator would."""
        if self.container:
            return self._run(["u2-mcp", "admin", *args])
        return self._run([sys.executable, "-m", "u2_mcp", "admin", *args])

    def python(self, code: str) -> str:
        """Run Python where the server runs, with the server's environment."""
        return self._run(["python" if self.container else sys.executable, "-c", code])

    def setup_code(self) -> str:
        """Read the setup code the way an operator would: from the CLI."""
        return self.admin_cli("show-setup-code").strip()


class _Process:
    def __init__(self, process: subprocess.Popen[bytes], log_path: Path) -> None:
        self.process = process
        self.log_path = log_path

    def alive(self) -> bool:
        return self.process.poll() is None

    def log(self) -> str:
        return _read_log(self.log_path)

    def stop(self) -> None:
        _stop(self.process)


class _Container:
    def __init__(self, container_id: str, volume: str, log_path: Path) -> None:
        self.id = container_id
        self.volume = volume
        self.log_path = log_path

    def alive(self) -> bool:
        state = subprocess.run(  # noqa: S603, S607 - fixed argv, test-only
            ["docker", "inspect", "-f", "{{.State.Running}}", self.id],
            capture_output=True, text=True,
        )
        return state.stdout.strip() == "true"

    def log(self) -> str:
        logs = subprocess.run(  # noqa: S603, S607 - fixed argv, test-only
            ["docker", "logs", self.id], capture_output=True, text=True
        )
        return logs.stdout + logs.stderr

    def stop(self) -> None:
        self.log_path.write_text(self.log(), encoding="utf-8")
        subprocess.run(["docker", "rm", "-f", self.id], capture_output=True)  # noqa: S603, S607
        subprocess.run(["docker", "volume", "rm", "-f", self.volume], capture_output=True)  # noqa: S603, S607


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _start_process(data_dir: Path, port: int, settings: dict[str, str]) -> tuple[_Process, Server]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("U2_")}
    env.update(settings)
    env.update(
        {
            "U2_DATA_DIR": str(data_dir),
            "U2_DRIVER": "tests.mocks.sim_driver",
            "PYTHONPATH": str(REPO_ROOT),
            "PYTHONUNBUFFERED": "1",
        }
    )
    log_path = data_dir / "server.log"
    with log_path.open("wb") as log:
        process = subprocess.Popen(  # noqa: S603 - fixed argv, test-only
            [sys.executable, "-m", "u2_mcp", "--streamable-http"],
            env=env,
            cwd=REPO_ROOT,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    return _Process(process, log_path), Server(f"http://127.0.0.1:{port}", data_dir, env)


def _start_container(
    data_dir: Path, port: int, settings: dict[str, str]
) -> tuple[_Container, Server]:
    volume = f"u2-e2e-{uuid.uuid4().hex[:12]}"
    subprocess.run(["docker", "volume", "create", volume], check=True, capture_output=True)  # noqa: S603, S607
    env_args = [arg for key, value in settings.items() for arg in ("-e", f"{key}={value}")]
    started = subprocess.run(  # noqa: S603, S607 - fixed argv, test-only
        ["docker", "run", "-d", "--network", "host", "-v", f"{volume}:/data", *env_args, E2E_IMAGE],
        check=True, capture_output=True, text=True,
    )
    container_id = started.stdout.strip()
    handle = _Container(container_id, volume, data_dir / "server.log")
    return handle, Server(f"http://127.0.0.1:{port}", data_dir, dict(settings), container_id)


def launch_server(data_dir: Path) -> tuple[_Process | _Container, Server]:
    """Start a server on empty data and wait until /health answers.

    This is the only place that knows how the server is started: a local process,
    or (U2_E2E_IMAGE) the Docker image.
    """
    port = _free_port()
    settings = {
        "U2_SECRET_KEY": SECRET_KEY,
        "U2_HTTP_HOST": "127.0.0.1",
        "U2_HTTP_PORT": str(port),
        # The watchdog stays at its default (on): a fresh server must run with it.
        "U2_AUDIT_ENABLED": "false",
    }
    starter = _start_container if E2E_IMAGE else _start_process
    handle, server = starter(data_dir, port, settings)
    try:
        deadline = time.monotonic() + START_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if not handle.alive():
                raise RuntimeError(f"The server exited early:\n{handle.log()}")
            try:
                if httpx.get(server.url("/health"), timeout=1.0).status_code == 200:
                    return handle, server
            except httpx.HTTPError:
                pass
            time.sleep(0.2)
        raise RuntimeError(f"The server did not answer /health:\n{handle.log()}")
    except BaseException:
        # Never leave a server running behind a failed start (or Ctrl+C).
        handle.stop()
        raise


def _read_log(log_path: Path) -> str:
    return log_path.read_text(encoding="utf-8", errors="replace")


def _stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


@pytest.fixture
def server(tmp_path: Path) -> Iterator[Server]:
    """A fresh server with an empty data directory."""
    handle, running = launch_server(tmp_path)
    try:
        yield running
    finally:
        handle.stop()


@pytest.fixture
def other_page(browser: Browser) -> Iterator[Page]:
    """A page in a second, separate browser context (another person or browser)."""
    context = browser.new_context()
    try:
        yield context.new_page()
    finally:
        context.close()
```

In `tests/e2e/test_everyday_pages.py`, make `_seed_group` call `server.python(_SEED_GROUP)`. Remove the `subprocess`, `sys` and `REPO_ROOT` imports if nothing else uses them.

- [ ] **Step 6: Check locally (no Docker)**

1. Run `.venv/Scripts/python -m pytest -m e2e tests/e2e --browser chromium`. Expected: PASS, with the same tests as before. `U2_E2E_IMAGE` is unset, so local processes are used.
2. If PyYAML is installed (check with `.venv/Scripts/python -c "import yaml"`), parse the YAML:

   ```bash
   .venv/Scripts/python -c "import sys, yaml; [yaml.safe_load(open(f)) for f in sys.argv[1:]]" docker-compose.yml deploy/caddy/docker-compose.yml deploy/nginx/docker-compose.yml .github/workflows/ci.yml
   ```

3. The Docker steps run only in CI. Say so in the report.

- [ ] **Step 7: The CI job** (`.github/workflows/ci.yml`)

1. Add `workflow_dispatch:` under `on:`, so maintainers can run CI by hand after this merges. GitHub offers the button only once the trigger is on the default branch, so on this branch CI (the docker job included) first runs on a pull request into `main`. The controller asks the user to open a draft PR right after this task lands.
2. Change `build.needs` to `[security, lint, test, e2e, docker]`. This also closes 2a review M-4.
3. Add this job:

```yaml
  # The image people deploy: built, started with compose, proven healthy, shown to
  # hold no test code, and run behind both proxy examples. Then the whole browser
  # suite runs against the image's test target, one container per test.
  docker:
    runs-on: ubuntu-latest
    env:
      U2_SECRET_KEY: ci-only-secret-key-0123456789abcdefghijklmnop
    steps:
      - uses: actions/checkout@v4

      - name: Build the release and test images
        run: |
          docker build --target release -t u2-mcp:ci .
          docker build --target test -t u2-mcp:ci-test .

      - name: The release image holds no test code
        run: >
          docker run --rm --entrypoint python u2-mcp:ci -c
          "import importlib.util, sys; sys.exit(importlib.util.find_spec('tests.mocks') is not None)"

      - name: docker compose starts a healthy server
        env:
          U2_IMAGE: u2-mcp:ci
        run: |
          docker compose up -d --wait --wait-timeout 120
          curl -fsS http://127.0.0.1:8000/health
          docker compose exec -T u2-mcp u2-mcp admin show-setup-code
          docker compose down -v

      - name: The Caddy and nginx examples serve the admin site
        env:
          U2_IMAGE: u2-mcp:ci
          U2_SITE_ADDRESS: ":80"
        run: |
          for proxy in caddy nginx; do
            docker compose -f deploy/$proxy/docker-compose.yml up -d --wait --wait-timeout 120
            curl -fsS http://127.0.0.1/health
            test "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1/admin/sign-in)" = "303"
            docker compose -f deploy/$proxy/docker-compose.yml down -v
          done

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install test dependencies and Chromium
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[dev]"
          python -m playwright install --with-deps chromium

      - name: Browser tests against the image
        env:
          U2_E2E_IMAGE: u2-mcp:ci-test
        run: pytest -m e2e tests/e2e --browser chromium

      - name: Keep server logs when they fail
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: docker-e2e-server-logs
          path: /tmp/pytest-of-*/**/*.log
          if-no-files-found: ignore
```

4. In the existing `e2e` job, widen the log artifact path to `/tmp/pytest-of-*/**/*.log`, so the identity provider's log from Task 11 is kept too.

- [ ] **Step 8: Run the checks**

Run the Global Constraints checks and the e2e suite again.

- [ ] **Step 9: Commit**

```bash
git add Dockerfile .dockerignore docker-compose.yml deploy src/u2_mcp/config.py src/u2_mcp/server.py tests/e2e/conftest.py tests/e2e/test_everyday_pages.py tests/test_admin/test_proxy_headers.py .github/workflows/ci.yml
git commit -m "build: Docker image and compose, Caddy and nginx examples, TLS files; CI runs the browser suite against the image

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
git push origin feature/phase3-sso-deploy
```

---

### Task 11: SSO browser tests against the mock provider

**Files:**
- Create: `tests/e2e/test_sso.py`
- Modify: `tests/e2e/conftest.py` (the `idp` fixture), `tests/e2e/wizard.py` (`set_up_sso`, `reach_done` and `finish_wizard` take `idp`)

**Interfaces:**
- **Consumes:**
  - the whole SSO stack (Tasks 6 to 9)
  - `launch_server` and `Server.python` (Task 10)
  - `python -m tests.mocks.oidc_provider` (Task 3)
- **Produces, `conftest.py`:**
  - `@dataclass Idp(issuer, client_id="u2-mcp", client_secret="e2e-client-secret")`, with the property `.discovery_url` and the method `.next_user(**person)`
  - the `idp` fixture, a function-scoped local process
- **Produces, `wizard.py`:**
  - `set_up_sso(page, idp) -> None`
  - `reach_done(page, server, *, public_url=None, idp=None)`
  - `finish_wizard(page, server, *, public_url=None, idp=None)`
  - `sso_sign_in(page, server) -> None`

- [ ] **Step 1: The provider fixture** (append to `tests/e2e/conftest.py`)

```python
@dataclass
class Idp:
    """The mock identity provider, running as a local process."""

    issuer: str
    client_id: str = "u2-mcp"
    client_secret: str = "e2e-client-secret"

    @property
    def discovery_url(self) -> str:
        return f"{self.issuer}/.well-known/openid-configuration"

    def next_user(self, **person: object) -> None:
        """Queue who signs in next: sub, email, name, groups, overage, extra."""
        httpx.post(f"{self.issuer}/_control/next-user", json=person, timeout=5).raise_for_status()


@pytest.fixture
def idp(tmp_path: Path) -> Iterator[Idp]:
    """A fresh mock OIDC provider on 127.0.0.1 (reachable from a host-network container too)."""
    port = _free_port()
    running = Idp(f"http://127.0.0.1:{port}")
    log_path = tmp_path / "idp.log"
    with log_path.open("wb") as log:
        process = subprocess.Popen(  # noqa: S603 - fixed argv, test-only
            [sys.executable, "-m", "tests.mocks.oidc_provider", "--port", str(port),
             "--client-id", running.client_id, "--client-secret", running.client_secret],
            cwd=REPO_ROOT, stdout=log, stderr=subprocess.STDOUT,
        )
    try:
        deadline = time.monotonic() + START_TIMEOUT_SECONDS
        while True:
            if process.poll() is not None:
                raise RuntimeError(f"The mock provider exited early:\n{_read_log(log_path)}")
            try:
                if httpx.get(running.discovery_url, timeout=1.0).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if time.monotonic() > deadline:
                raise RuntimeError(f"The mock provider did not start:\n{_read_log(log_path)}")
            time.sleep(0.2)
        yield running
    finally:
        _stop(process)
```

- [ ] **Step 2: The wizard helpers** (`tests/e2e/wizard.py`)

Add `from .conftest import Idp, Server`. Then add `set_up_sso` and `sso_sign_in`, and give `reach_done` and `finish_wizard` an `idp` keyword:

```python
OTHER_OIDC = "Other OpenID Connect provider (Okta, Google, Auth0, Duo, Keycloak)"


def set_up_sso(page: Page, idp: Idp, *, discovery_url: str | None = None) -> None:
    """Fill and save the company sign-in form (wizard or Settings: the same form)."""
    page.get_by_label("Provider").select_option(label=OTHER_OIDC)
    page.get_by_label("Discovery URL").fill(discovery_url or idp.discovery_url)
    page.get_by_label("Client ID").fill(idp.client_id)
    page.get_by_label("Client secret").fill(idp.client_secret)
    page.get_by_role("button", name="Save company sign-in").click()
    expect(page.locator(".notice")).to_have_text("Saved.")


def sso_sign_in(page: Page, server: Server) -> None:
    """Sign in with the company account (the mock provider approves at once)."""
    page.goto(server.url("/admin/sign-in"))
    page.get_by_role("button", name="Sign in with your company account").click()


def finish_wizard(
    page: Page, server: Server, *, public_url: str | None = None, idp: Idp | None = None
) -> None:
    """Run the whole wizard with good values (company sign-in too when idp is given).

    The server address defaults to the test server's own http URL: an https
    address would make later sign-ins set Secure cookies the browser drops over
    plain http.
    """
    reach_done(page, server, public_url=public_url, idp=idp)
    page.get_by_role("button", name="Finish setup").click()
    expect(page).to_have_url(re.compile(r"/admin/connections\?notice=setup_done$"))


def reach_done(
    page: Page, server: Server, *, public_url: str | None = None, idp: Idp | None = None
) -> None:
    """Run the wizard with good values up to, not including, Finish setup."""
    create_admin(page, server)
    fill_connection(page)
    page.get_by_role("button", name="Save and continue").click()
    expect(page).to_have_url(re.compile(r"/admin/setup/server_address$"))
    page.get_by_label("Server address").fill(public_url or server.base_url)
    page.get_by_role("button", name="Save and continue").click()
    expect(page).to_have_url(re.compile(r"/admin/setup/sso$"))
    if idp is None:
        page.get_by_role("button", name="Skip this step").click()
    else:
        set_up_sso(page, idp)
        page.get_by_role("button", name="Continue").click()
    expect(page).to_have_url(re.compile(r"/admin/setup/done$"))
```

- [ ] **Step 3: Write the browser tests** (`tests/e2e/test_sso.py`)

```python
"""Company sign-in in a real browser, against the mock identity provider (spec Testing 7)."""

from __future__ import annotations

import re

import httpx
import pytest
from playwright.sync_api import Page, expect

from .conftest import Idp, Server, _free_port
from .wizard import create_admin, create_token, fill_connection, finish_wizard, set_up_sso, sso_sign_in

pytestmark = pytest.mark.e2e

_AGE_SIGN_IN = (
    "import time\n"
    "from u2_mcp.config import U2Config\n"
    "from u2_mcp.store.bootstrap import open_store_for_cli\n"
    "store = open_store_for_cli(U2Config())\n"
    "user = store.get_user_by_subject('tom')\n"
    "with store._tx() as conn:\n"
    "    conn.execute('UPDATE users SET last_sso_login_at = ? WHERE id = ?',\n"
    "                 (time.time() - 31 * 86400, user.id))\n"
)


def _initialize_status(url: str, token: str) -> int:
    """The HTTP status an MCP client gets for its first request with this token."""
    response = httpx.post(
        url,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json, text/event-stream"},
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                         "clientInfo": {"name": "e2e", "version": "1"}}},
        timeout=30,
    )
    return response.status_code


def _to_sso_step(page: Page, server: Server) -> None:
    create_admin(page, server)
    fill_connection(page)
    page.get_by_role("button", name="Save and continue").click()
    page.get_by_label("Server address").fill(server.base_url)
    page.get_by_role("button", name="Save and continue").click()
    expect(page).to_have_url(re.compile(r"/admin/setup/sso$"))


def test_the_sso_step_tests_a_real_sign_in_and_signs_nobody_in(
    page: Page, server: Server, idp: Idp
) -> None:
    _to_sso_step(page, server)
    set_up_sso(page, idp)
    idp.next_user(sub="tess", email="tess@example.com", name="Tess Ter", groups=["eng-team"])
    with page.expect_popup() as popup_info:
        page.get_by_role("button", name="Test sign-in").click()
    popup = popup_info.value
    expect(popup.get_by_role("heading", name="Company sign-in works")).to_be_visible()
    expect(popup.get_by_text("eng-team")).to_be_visible()
    popup.close()

    page.get_by_role("button", name="Continue").click()
    expect(page.get_by_text("Other OpenID Connect provider")).to_be_visible()  # the checklist
    page.get_by_role("button", name="Finish setup").click()
    page.goto(server.url("/admin/users"))
    expect(page.get_by_text("Tess Ter")).to_have_count(0)


def test_bad_sso_settings_show_the_error_text(page: Page, server: Server, idp: Idp) -> None:
    _to_sso_step(page, server)
    nowhere = f"http://127.0.0.1:{_free_port()}/.well-known/openid-configuration"
    set_up_sso(page, idp, discovery_url=nowhere)
    with page.expect_popup() as popup_info:
        page.get_by_role("button", name="Test sign-in").click()
    expect(popup_info.value.get_by_text("Company sign-in failed: Could not reach the identity provider")).to_be_visible()


def test_group_grants_follow_company_sign_in(
    page: Page, other_page: Page, server: Server, idp: Idp
) -> None:
    finish_wizard(page, server, idp=idp)
    idp.next_user(sub="sam", email="sam@example.com", name="Sam", groups=["eng-team"])
    sso_sign_in(other_page, server)
    expect(other_page).to_have_url(re.compile(r"/admin/me$"))
    expect(other_page.get_by_text("You can't use any connection yet.")).to_be_visible()

    page.goto(server.url("/admin/groups"))
    page.get_by_role("link", name="eng-team").click()
    page.get_by_label("Connection").select_option(label="Prod")
    page.get_by_role("button", name="Add grant").click()
    expect(page.locator(".notice")).to_have_text("Saved.")

    other_page.reload()
    expect(other_page.get_by_role("cell", name="Prod")).to_be_visible()

    idp.next_user(sub="sam", email="sam@example.com", name="Sam", groups=[])
    sso_sign_in(other_page, server)  # the next sign-in no longer carries the group
    expect(other_page.get_by_text("You can't use any connection yet.")).to_be_visible()


def test_an_overage_sign_in_is_flagged_for_admins(
    page: Page, other_page: Page, server: Server, idp: Idp
) -> None:
    finish_wizard(page, server, idp=idp)
    idp.next_user(sub="olga", email="olga@example.com", name="Olga", overage=True)
    sso_sign_in(other_page, server)
    expect(other_page).to_have_url(re.compile(r"/admin/me$"))

    page.goto(server.url("/admin/dashboard"))
    expect(page.locator(".warning", has_text="Olga")).to_be_visible()
    page.goto(server.url("/admin/users"))
    expect(page.get_by_text("(groups unavailable)")).to_be_visible()


def test_tokens_pause_without_company_sign_in_and_come_back_with_it(
    page: Page, other_page: Page, server: Server, idp: Idp
) -> None:
    finish_wizard(page, server, idp=idp)
    idp.next_user(sub="tom", email="tom@example.com", name="Tom")
    sso_sign_in(other_page, server)
    token = create_token(other_page, server)
    expect(other_page.get_by_text("at least once every 30 days")).to_be_visible()
    mcp_url = server.url("/")
    assert _initialize_status(mcp_url, token) == 200

    server.python(_AGE_SIGN_IN)
    assert _initialize_status(mcp_url, token) == 401
    page.goto(server.url("/admin/users"))
    page.get_by_role("link", name="Tom").click()
    expect(page.get_by_text("This person's tokens are paused")).to_be_visible()

    idp.next_user(sub="tom", email="tom@example.com", name="Tom")
    sso_sign_in(other_page, server)
    assert _initialize_status(mcp_url, token) == 200
```

- [ ] **Step 4: Run them**

Run: `.venv/Scripts/python -m pytest -m e2e tests/e2e --browser chromium`
Expected: every test PASSES, the new SSO tests included.

If a selector does not match the real page (for example, the users list links people by another label), fix the selector, not the product, and record it. A real product bug found here is fixed in the product code, with a unit test, in this task's commit.

- [ ] **Step 5: Run the checks and commit**

Run the Global Constraints checks.

```bash
git add tests/e2e
git commit -m "test(e2e): company sign-in, group grants, overage and token freshness in a real browser

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
git push origin feature/phase3-sso-deploy
```

---

### Task 12: The admin guide, configuration reference, CHANGELOG and roadmap

**Files:**
- Create: `docs/admin.md`
- Modify: `docs/configuration.md`, `docs/oauth.md`, `CHANGELOG.md`, `docs/superpowers/plans/2026-10-30-admin-ui-roadmap.md`

**Interfaces:** documentation only. Every name, message, path and command it gives must match Tasks 1 to 11. Check each one against the code before you commit.

- [ ] **Step 1: Write `docs/admin.md`** (complete text)

````markdown
# Running u2-mcp for a team

This guide is for the person who installs and looks after u2-mcp: Docker, the
setup wizard, company sign-in (SSO), a reverse proxy, backups and recovery. For
every environment variable, see [Configuration](configuration.md).

In team mode one server serves several U2 connections to many people. Each
person signs in, and an admin decides per connection who may do what. Servers,
accounts and U2 logins are added on the admin site, not in environment
variables.

## 1. Install with Docker

You need Docker with the compose plugin, and a host that can reach your U2
servers (UniRPC, port 31438 by default).

```bash
git clone https://github.com/cmc0619/u2-mcp-hub.git && cd u2-mcp-hub
python -c "import secrets; print('U2_SECRET_KEY=' + secrets.token_urlsafe(48))" > .env
docker compose up -d
```

`U2_SECRET_KEY` turns team mode on and encrypts the U2 passwords and the SSO
client secret stored in the settings database. **Keep a copy in your password
vault.** Without it, a restored database cannot decrypt its secrets. Once a
database exists, the server refuses to start without its key.

The settings database lives in the `u2-data` volume at `/data/u2-mcp.db`. The
image runs as an unprivileged user, and answers `GET /health` for the container
health check.

Run one replica. Sign-in rate limits and new-token display are held in memory.

## 2. First start: the setup wizard

1. Get the one-time setup code:
   `docker compose exec u2-mcp u2-mcp admin show-setup-code`.
   It is also in the log: `docker compose logs u2-mcp`.
2. Open `http://<host>:8000/admin/` (or your proxy's https address).
3. Work through the steps. Each one saves when you submit it, so Refresh, Back
   and a closed browser all resume where you were.
   - **Admin account**: the setup code, then a local admin. This account is your
     way back in if company sign-in ever fails, so keep it.
   - **First connection**: host, account, service and the U2 login. **Test
     connection** really connects and runs `COUNT VOC`, and shows the driver's
     error text if it fails.
   - **Server address**: the URL people use, such as
     `https://u2-mcp.example.com`. Use https.
   - **Company sign-in** (optional): see section 3. You can skip it and add it
     later under **Settings**.
   - **Done**: a checklist, and the Copilot configuration.
4. Give people access. Open the connection and add grants under **Access**:
   - a role for a person;
   - a role for an SSO group;
   - a role for everyone (shown with a warning).

   Admins need a grant too: being an admin gives no data access.

If `U2_HOST`, `U2_USER`, `U2_PASSWORD` and `U2_ACCOUNT` are set at first start,
they are imported as a connection named `default`, with the access the server
gave before team mode. See [Configuration](configuration.md#first-start).

## 3. Company sign-in (SSO)

Company sign-in works for this admin site at once. For VS Code's browser
sign-in it works after a restart (`docker compose restart u2-mcp`), and only
with an https server address. Register **two redirect URIs** with your identity
provider. The Settings page shows both, with your address filled in:

- `https://<your address>/admin/sign-in/sso/callback` (this admin site)
- `https://<your address>/oauth/callback` (VS Code and other MCP clients)

### Microsoft Entra ID

1. Entra admin center → **App registrations** → **New registration**. Choose
   *Accounts in this organizational directory only*, and add the two redirect
   URIs as type **Web**.
2. **Certificates & secrets** → **New client secret**. Copy the value, not the
   ID.
3. **Token configuration** → **Add groups claim** → **Security groups**. For the
   ID token, choose **Group ID**.
4. Recommended: **Enterprise applications** → your app → **Properties** →
   *Assignment required* = Yes. Then assign the groups that should use u2-mcp.
   Back in **Token configuration**, edit the groups claim and choose **Groups
   assigned to the application**. A person who is in more than about 200 groups
   would otherwise get no groups in the token at all (Entra's "group overage").
5. In u2-mcp, go to **Settings → Company sign-in** (or the wizard step):
   - **Provider**: Microsoft Entra ID.
   - **Discovery URL**:
     `https://login.microsoftonline.com/<tenant ID>/v2.0/.well-known/openid-configuration`.
     Use your tenant ID. `/common` and `/organizations` are refused, because
     their issuer cannot be checked.
   - **Client ID**: the Application (client) ID. **Client secret**: from step 2.
   - **Groups claim**: `groups`.
6. **Group overage.** If you cannot limit the groups as in step 4, tick *look up
   groups through Microsoft Graph*. Then give the app the **Microsoft Graph →
   Application permission → GroupMember.Read.All**, and grant admin consent.
   Without it, an overage person signs in with no groups. Group grants do not
   apply to them, and the Dashboard and Users pages flag them.
7. Click **Test sign-in**. A new window signs you in for real and shows your
   subject, email and groups. The test saves nothing.

Groups appear in u2-mcp under the IDs Entra sends. Give them readable labels on
the **Groups** page.

### Okta

1. **Applications** → **Create App Integration** → *OIDC* → *Web Application*.
   Add the two redirect URIs as **Sign-in redirect URIs**.
2. **Sign On** → **OpenID Connect ID Token** → **Groups claim**. Set the type to
   *Filter*, name `groups`, *Matches regex* `.*` (or a narrower filter).
3. In u2-mcp: **Provider**: *Other OpenID Connect provider*.
   **Discovery URL**: `https://<your-okta-domain>/.well-known/openid-configuration`
   (or `/oauth2/default/.well-known/openid-configuration` for a custom
   authorization server). Then the client ID and secret, and **Groups claim**:
   `groups`.

### Google Workspace

1. Google Cloud console → **APIs & Services** → **Credentials** → **OAuth client
   ID** → *Web application*. Add the two redirect URIs.
2. In u2-mcp: **Discovery URL**:
   `https://accounts.google.com/.well-known/openid-configuration`, plus the
   client ID and secret.
3. Google ID tokens carry no groups, so use grants to people (or to everyone)
   rather than to groups.

### Other providers (Auth0, Duo, Keycloak)

Any OpenID Connect provider with a discovery document works:
- authorization code flow with PKCE;
- ID tokens signed with RS256;
- a groups claim, if you want group grants. Name it in **Groups claim**.

### Personal access tokens and the 30-day rule

Editors without browser sign-in use personal access tokens. People create them
on **My access**. A token belonging to an SSO user works only while that person
signs in to the admin site with their company account at least once every 30
days (`U2_TOKEN_FRESHNESS_DAYS`). After that the token is **Paused** and calls
are refused until they sign in again. That way someone removed from the
company, or from a group, loses access through their tokens too. Tokens of
local accounts do not pause.

### Local accounts

**Settings → Local accounts** can turn off local sign-in for people who are not
admins. Local admins can always sign in. This is your break-glass path. The
switch affects new sign-ins only: existing sessions run out (at most 8 hours),
and existing tokens keep working until they expire or you revoke them.

## 4. Behind a reverse proxy (https)

Put u2-mcp behind a proxy that terminates TLS. There are two ready examples:

- **Caddy** (automatic certificates):
  `U2_SECRET_KEY=... U2_SITE_ADDRESS=u2-mcp.example.com docker compose -f deploy/caddy/docker-compose.yml up -d`
- **nginx**: `deploy/nginx/`. Add your certificate in the TLS server block of
  `default.conf`.

In both examples u2-mcp is not published on the host. Only the proxy reaches it,
from a fixed address that `U2_TRUSTED_PROXIES` names. Only then does u2-mcp
believe the proxy's `X-Forwarded-For` and `X-Forwarded-Proto`. The sign-in rate
limit, `U2_ADMIN_ALLOWED_IPS`, the audit log and the https check then see the
real client, not the proxy. Never list an address that clients can reach
directly. With your own proxy:

- set `U2_TRUSTED_PROXIES` to the proxy's address or network;
- make the proxy **replace** `X-Forwarded-For` (nginx:
  `proxy_set_header X-Forwarded-For $remote_addr;`) and set
  `X-Forwarded-Proto`;
- turn off response buffering. MCP's Streamable HTTP streams its responses.

Without a proxy, mount a certificate and key and set `U2_TLS_CERT` and
`U2_TLS_KEY` to their paths in the container.

`U2_ADMIN_ALLOWED_IPS` (addresses or CIDRs) limits who can reach `/admin`. The
MCP endpoint is not affected.

## 5. Backups

Back up two things, and keep them apart:

1. The volume's `/data` (`u2-mcp.db` and per-connection knowledge notes). Use
   SQLite's online backup, so a copy taken while the server runs is consistent:

   ```bash
   docker compose exec u2-mcp python -c "import sqlite3; s = sqlite3.connect('/data/u2-mcp.db'); d = sqlite3.connect('/data/backup.db'); s.backup(d); d.close()"
   docker compose cp u2-mcp:/data/backup.db ./u2-mcp-$(date +%F).db
   ```

2. `U2_SECRET_KEY`, in your password vault. Without it, a restored database
   still has its users, grants and audit log, but every stored U2 password and
   the SSO client secret must be entered again. The pages mark them "secret
   unreadable, re-enter".

Before each schema upgrade the server copies the database to
`/data/u2-mcp.db.bak-<version>-<timestamp>`.

To restore: stop the server, put the backup back as `/data/u2-mcp.db`, and start
it again with the same `U2_SECRET_KEY`.

## 6. Recovery commands

Run these on the server (`docker compose exec u2-mcp ...`):

| Command | Use |
|---|---|
| `u2-mcp admin show-setup-code` | Print the setup code while setup is unfinished |
| `u2-mcp admin reset-password <user>` | Give a local user a one-time password (they choose a new one at sign-in) and re-enable them |
| `u2-mcp admin reset-password <user> --admin` | The same, and make them an admin: the way back in when no admin is left |
| `u2-mcp admin set-public-url <url>` | Fix the server address, for example after saving an https address while still on http |
| `u2-mcp admin set-public-url --clear` | Forget the saved address (`U2_PUBLIC_URL`, or host and port, applies) |

Restart after changing the address or company sign-in. VS Code sign-in and
personal access tokens pick them up at startup.

## 7. Connecting GitHub Copilot

Each person opens **My access**, which shows copy-ready configuration with your
address filled in:

- **VS Code, company sign-in**: add the server to `.vscode/mcp.json` or the user
  MCP configuration. VS Code opens a browser to sign in. This needs SSO, an
  https address and a restart after SSO was set up.
- **VS Code, token**: VS Code asks for the token once, and keeps it out of the
  file.
- **Visual Studio**: `%USERPROFILE%\.mcp.json` with the token. Never commit it.
- **JetBrains IDEs**: Copilot Chat → Agent mode → tools → *Add MCP Tools*.

Organisations on Copilot Business or Enterprise must allow MCP servers. In
GitHub, open the organisation (or enterprise) → **Settings** → **Copilot** →
**Policies**, and enable **MCP servers in Copilot**.

A person sees only the connections they have a grant on. `list_connections`
shows their role and permissions on each.

## 8. Before each release: manual acceptance against real U2

Rocket U2 cannot run in CI, so before each release check these by hand against a
real UniVerse or UniData server:

1. `python scripts/try-it-here.py`, with the `U2_*` variables for a test
   account, completes.
2. On a fresh `docker compose up`, the wizard's **Test connection** passes
   against the real server, and shows the real error for a wrong password.
3. A grant plus a token from My access lets VS Code list files and read a
   record.
4. Company sign-in against your real identity provider: **Test sign-in** shows
   the expected groups, and a group grant applies.
5. The Visual Studio snippet from My access (`type`, `url`, `headers`) works in
   a current Visual Studio.
````

- [ ] **Step 2: Update `docs/configuration.md`**

1. In the Team mode variables table, add these rows:

   ```markdown
   | `U2_TRUSTED_PROXIES` | (unset) | Addresses or CIDR networks of reverse proxies whose `X-Forwarded-For` and `X-Forwarded-Proto` are believed. Unset trusts none. See [admin.md](admin.md#4-behind-a-reverse-proxy-https). |
   | `U2_TLS_CERT`, `U2_TLS_KEY` | (unset) | Certificate and key files (PEM) to serve https without a proxy. Set both or neither. |
   ```

2. Add this subsection at the end of the "Team mode" part, after "Personal access tokens":

   ```markdown
   ### Company sign-in (SSO)

   Company sign-in is set up on the admin site, in the wizard's optional step or
   under **Settings → Company sign-in**. It is stored in the settings database, with
   the client secret encrypted under `U2_SECRET_KEY`.

   `U2_IDP_DISCOVERY_URL`, `U2_IDP_CLIENT_ID`, `U2_IDP_CLIENT_SECRET` and
   `U2_SSO_GROUPS_CLAIM` seed it once, on the first start of a new database. After
   that the admin site's settings win, even when an admin turns company sign-in off.

   The admin site uses the saved settings at once. VS Code's browser sign-in (the
   MCP OAuth bridge) uses them after a restart, and only when the server address is
   https. Without that, personal access tokens still work. `U2_AUTH_ENABLED=true`
   still configures the bridge from the environment instead, as before.

   Provider set-up for Entra ID, Okta and Google is in
   [admin.md](admin.md#3-company-sign-in-sso).
   ```

3. Run `grep -n "Restart the server for personal access tokens" docs/configuration.md` and replace each hit with the new `RESTART_NOTE` text.

- [ ] **Step 3: Update `docs/oauth.md`**

Insert under `## Overview`, as its first paragraph:

```markdown
> **Team mode:** with `U2_SECRET_KEY` set, set up company sign-in on the admin site instead (see [admin.md](admin.md#3-company-sign-in-sso)). It serves the admin site and, after a restart, VS Code and other MCP clients. The environment variables below remain for deployments without team mode, and seed the admin site's settings on first start.
```

- [ ] **Step 4: Update the CHANGELOG** (under `## [Unreleased]`, in a new `### Added` list and the existing `### Changed` list)

```markdown
### Added

- Company sign-in (OIDC) for the admin site: authorization code with PKCE, state and nonce, ID tokens checked against the provider's keys. It is set up in the wizard's new optional step or under Settings, with a real **Test sign-in**.
- SSO groups from the ID token, with Entra group-overage handling: optional Microsoft Graph lookup, otherwise the person is flagged and the Dashboard warns.
- VS Code browser sign-in from the admin site's company sign-in, after a restart, with an https address.
- `U2_TRUSTED_PROXIES`: behind a reverse proxy, the sign-in rate limit, `U2_ADMIN_ALLOWED_IPS`, audit and https detection see the real client.
- `U2_TLS_CERT` and `U2_TLS_KEY` to serve https without a proxy.
- `Dockerfile`, `docker-compose.yml`, and Caddy and nginx examples under `deploy/`. CI builds the image and runs the browser suite against it.
- `docs/admin.md`: install, setup, SSO for Entra, Okta and Google, proxies, backups, recovery and Copilot set-up.

### Changed

- Personal access tokens of SSO users show as **Paused** after 30 days without a company sign-in. My access says when they would pause.
- My access and Effective access say when a per-person connection still needs the person's own U2 login.
- The pre-sign-in CSRF cookie is `__Host-` prefixed over https. Password checks run off the event loop. CORS no longer applies to `/admin`.
- Uvicorn no longer believes `X-Forwarded-*` from 127.0.0.1 by itself. Only `U2_TRUSTED_PROXIES` is believed.
- The restart note now covers company sign-in.
```

- [ ] **Step 5: Update the roadmap** (`docs/superpowers/plans/2026-10-30-admin-ui-roadmap.md`)

Skip this step if the planning commit already made the change.

- In row 3, change the Plan cell to `` `2026-10-31-admin-ui-phase3-sso-deploy.md` ``.
- Change the sentence under the table to: "Phase 3 also handles trusted reverse-proxy headers (`U2_TRUSTED_PROXIES`), so the sign-in rate limit and `U2_ADMIN_ALLOWED_IPS` see the real client address behind a proxy."

- [ ] **Step 6: Check, then commit**

1. Check every command in `admin.md` against `cli.py` and every variable against `config.py`.
2. Check the Okta, Google and Entra steps against the providers' current consoles. If a menu name has changed, use the current one and say so in the report.
3. Run the Global Constraints checks.
4. Commit:

```bash
git add docs/admin.md docs/configuration.md docs/oauth.md CHANGELOG.md docs/superpowers/plans/2026-10-30-admin-ui-roadmap.md
git commit -m "docs: admin guide (Docker, wizard, SSO, proxies, backups, recovery, Copilot); configuration and CHANGELOG

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
git push origin feature/phase3-sso-deploy
```

---

### Task 13: README for team mode

The coordinator added this requirement. The README leads with Docker and the setup wizard. Servers, accounts and U2 logins are added on the admin web page, not in environment variables. Startup needs only `U2_SECRET_KEY`, plus the deployment variables if wanted. The `U2_HOST`, `U2_USER`, `U2_PASSWORD` and `U2_ACCOUNT` material moves into one short section. The Claude Desktop examples get the same treatment. Acknowledgments stay exactly as they are.

**Files:**
- Modify: `README.md` (full replacement)

**Interfaces:** documentation only. Every name must match the code after Tasks 1 to 12.

- [ ] **Step 1: Check the facts it states**

1. `config.py`: team mode needs only `U2_SECRET_KEY`, and in team mode `U2_HOST` is optional.
2. The compose file publishes 8000.
3. The tool names are those in `src/u2_mcp/tools/*.py` and `server.py`. In particular, check `list_connections` and `list_sessions`.
4. `docs/configuration.md` has a `#first-start` anchor (the heading "### First start"). If not, link to `docs/configuration.md` without the anchor.

- [ ] **Step 2: Replace `README.md` with this text**

The Acknowledgments section is copied verbatim from the current README.

````markdown
# u2-mcp

[![PyPI version](https://img.shields.io/pypi/v/u2-mcp.svg)](https://pypi.org/project/u2-mcp/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![MCP](https://img.shields.io/badge/MCP-Registry-green.svg)](https://registry.modelcontextprotocol.io)

<!-- mcp-name: io.github.bpamiri/u2-mcp -->

**Let your team ask Rocket Universe and UniData questions in plain English, from GitHub Copilot, Claude or any MCP client.**

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
 Copilot / Claude ──►  u2-mcp  ──►  U2 Prod
 (each person signs in)  │     ──►  U2 Test
                         │     ──►  U2 Training
 Browser (admins) ──► /admin: connections, people, groups, roles, audit
```

1. You ask your assistant a question.
2. It calls a u2-mcp tool on a connection you have access to.
3. u2-mcp checks your permissions, then queries that U2 server with the connection's login (or your own U2 login).
4. The answer comes back in plain language. The admin site's audit log records the call.

**New to MCP?** See [What is MCP?](docs/what-is-mcp.md).

## Quick start (Docker)

You need Docker with the compose plugin, on a host that can reach your U2 servers.

```bash
git clone https://github.com/cmc0619/u2-mcp-hub.git && cd u2-mcp-hub
python -c "import secrets; print('U2_SECRET_KEY=' + secrets.token_urlsafe(48))" > .env
docker compose up -d
docker compose exec u2-mcp u2-mcp admin show-setup-code
```

Open `http://<host>:8000/admin/` and follow the setup wizard:

1. **Admin account**: enter the setup code, then create the first (local) admin.
2. **First connection**: host, account, service and the U2 user and password. **Test connection** really connects.
3. **Server address**: the URL people use, ideally https behind a proxy.
4. **Company sign-in** (optional): Microsoft Entra ID, Okta, Google or any OpenID Connect provider, with a real **Test sign-in**.
5. **Done**: then give people access on the connection's **Access** section.

U2 servers, accounts, logins, people and permissions all live in the admin site. The settings database encrypts every stored password with `U2_SECRET_KEY`. **Keep that key in your password vault.** Without it, stored passwords cannot be read.

Startup needs only `U2_SECRET_KEY`. These deployment settings are optional:

| Variable | Use |
|---|---|
| `U2_PUBLIC_URL` | The address people use (the wizard can set it instead) |
| `U2_TRUSTED_PROXIES` | Your reverse proxy's address, so the real client address is seen behind it |
| `U2_ADMIN_ALLOWED_IPS` | Addresses or networks allowed to reach `/admin` |
| `U2_TLS_CERT`, `U2_TLS_KEY` | Serve https without a proxy |

The [admin guide](docs/admin.md) covers https with Caddy or nginx, SSO set-up for Entra, Okta and Google, backups and recovery.

## Connect your editor

Each person opens **My access** on the admin site. It shows their connections and copy-ready configuration:

- **VS Code (GitHub Copilot)** signs in through the browser when company sign-in is set up, or uses a personal access token that VS Code asks for once.
- **Visual Studio** and **JetBrains IDEs** use a personal access token.
- **Claude Desktop**: add the server under *Settings → Connectors* with its URL, or use a token through `mcp-remote`:

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

- **Several connections, per-person access**: grants give a role on a connection to a person, an SSO group or everyone. Roles are sets of granular permissions (schema, records, queries, writes, deletes, TCL, subroutines, knowledge).
- **Sign-in**: company SSO (OIDC, with groups) and local accounts. Personal access tokens are available for editors without browser sign-in. An SSO user's tokens pause after 30 days without a company sign-in.
- **Admin site**: a setup wizard, connections with live tests, users with effective access, groups, roles, audit with CSV export, and a dashboard.
- **MultiValue-native tools**: read, write and delete records with multivalues and subvalues intact. RetrieVe/UniQuery queries, dictionaries, BASIC subroutine calls and transactions.
- **Safety**: global and per-connection read-only switches, a TCL command blocklist, query timeouts and record limits.
- **Knowledge notes**: what the assistant learns about a connection's files is saved per connection.

## Available tools

Every tool except `list_connections` takes an optional `connection` argument. When you can see exactly one connection, it is used.

- **Connections**: `list_connections` (yours, with your role and permissions), `connect`, `disconnect`, `list_sessions`, `watchdog_status`
- **Files**: `list_files`, `get_file_info`, `read_record`, `read_records`, `write_record`, `update_value`, `delete_record`
- **Queries**: `execute_query`, `get_select_list`, `validate_query`, `execute_tcl`
- **Dictionary**: `list_dictionary`, `get_field_definition`, `describe_file`, `analyze_file_structure`, `get_account_info`
- **Export**: `export_to_json`, `export_to_csv`
- **BASIC**: `call_subroutine`, `list_catalog`
- **Transactions**: `begin_transaction`, `commit_transaction`, `rollback_transaction`, `get_transaction_status`
- **Knowledge**: `save_knowledge`, `list_knowledge`, `get_all_knowledge`, `get_knowledge_topic`, `search_knowledge`, `delete_knowledge`

See the [tools reference](docs/tools.md).

## Single-user (stdio) mode and first-start import

Without `U2_SECRET_KEY`, u2-mcp runs as before: one person, one U2 login from environment variables, launched by a desktop client over stdio. There is no admin site, and the caller has full rights within that login, subject to `U2_READ_ONLY` and the command blocklist.

```json
{
  "mcpServers": {
    "u2": {
      "command": "uvx",
      "args": ["u2-mcp"],
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

In team mode the same `U2_HOST`, `U2_USER`, `U2_PASSWORD` and `U2_ACCOUNT` are optional. If they are set on the very first start, they are imported once as a connection named `default`, with the access the server gave before. After that, connections are managed on the admin site. See [Configuration](docs/configuration.md#first-start) for every variable and for the import rules.

## Documentation

| Guide | Description |
|---|---|
| [Admin guide](docs/admin.md) | Docker, the setup wizard, SSO, reverse proxies, backups, recovery, Copilot |
| [Configuration](docs/configuration.md) | Every setting, team mode and stdio |
| [Tools reference](docs/tools.md) | Each tool in detail |
| [Usage examples](docs/examples.md) | Common usage patterns |
| [What is MCP?](docs/what-is-mcp.md) | MCP, and how u2-mcp fits |
| [Installation](docs/installation.md) and [Quickstart](docs/quickstart.md) | Installing from PyPI, and single-user set-up |
| [OAuth](docs/oauth.md) | The environment-configured OAuth bridge (without team mode) |
| [Hardening](docs/hardening.md) | Security notes and the proven fixes |

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
````

- [ ] **Step 3: Check the result**

1. Run `git diff README.md` and confirm the Acknowledgments block is byte-identical to the old one.
2. Check the tool list against the registered tools:

   ```bash
   grep -rh -A2 "@mcp.tool()" src/u2_mcp | grep -oE "def [a-z_]+" | sed 's/def //' | sort -u
   ```

   Expected: the same 35 names the README lists (35 at planning time). If they differ, fix the README, not the code.
3. Confirm that every link target exists.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: README leads with Docker and the setup wizard (team mode); stdio in its own section

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
git push origin feature/phase3-sso-deploy
```

---

## Self-review (done while planning)

- **Spec coverage:**
  - Sign-in / SSO users: Tasks 5 and 7.
  - Groups and overage: Tasks 4, 5 and 7.
  - Personal access tokens and the 30-day rule: Task 9 (rule unchanged in `tokens.py`, now shown).
  - Admin site security:
    - Secure cookies, the allowlist and rate limits behind a proxy: Task 1;
    - `__Host-` and CORS: Task 2.
  - Setup wizard SSO step with a real Test sign-in in a pop-up: Tasks 6 and 7.
  - "SSO settings entered in the UI take precedence over U2_IDP_*, which seed them": Task 6.
  - Deployment:
    - Dockerfile (non-root), compose (volume, env, health check, port 8000), Caddy and nginx examples, and `U2_TLS_CERT`/`U2_TLS_KEY`: Task 10;
    - `docs/admin.md` (deployment, Entra, Okta and Google, Entra groups claim, Copilot org policy, backups of `/data` and the key): Task 12.
  - Testing:
    - item 6, browser end-to-end against the built image: Task 10's CI job;
    - item 7, a containerised OIDC provider, replaced by an in-repo process as decided: Tasks 3 and 11;
    - item 8, the manual checklist: Task 12, section 8.
- **Deferred items:** each appears in "Deferred", with a reason.
- **Type consistency:**
  - `OidcClient`, `PendingLogin`, `OidcError`, `HttpFactory` and `default_http` are defined in Task 4 and used in Tasks 7 and 8.
  - `groups_for_sign_in`, `record_sign_in` and `make_sign_in_handler(store, claim, resolver)` are defined in Task 5 and used in Tasks 7 and 8.
  - `SsoSettings`, `load_sso`, `store_sso`, `clear_sso`, `sso_client_secret` and `seed_sso_from_environment` are defined in Task 6. `oidc_client` and `overage_resolver` are added in Task 7.
  - `cookie_name` and `cookie_path` are defined in Task 2 and used in Task 7.
  - `team_server` is defined in Task 1. Task 8 adds `base_url` to it.
  - `AdminContext.http` comes from Task 7, and `AdminContext.mcp_oauth` from Task 8.
  - `Server.python` and `Server.admin_cli` come from Task 10 and are used in Task 11.
