# Admin UI roadmap

Spec: `docs/superpowers/specs/2026-10-30-admin-ui-design.md`

The spec is built in three phases. Each phase leaves the server working and fully tested, and each has its own plan.

| Phase | Plan | Delivers | Visible to users? |
|---|---|---|---|
| 1. Access core | `2026-10-30-admin-ui-phase1-access-core.md` | Settings database, permissions and roles, the access decision, personal access tokens, multiple connections, a `connection` argument on every tool, and import of today's configuration. Configured in code and tests. No web pages yet. | Barely. Existing deployments behave as before, and tokens work. |
| 2a. Setup and connections | `2026-10-30-admin-ui-phase2a-setup-and-connections.md` | Local sign-in, database sessions, CSRF, sign-in rate limits, the address allowlist, the setup wizard (admin, connection, server address, done), the Connections pages, the Settings page's server address, `u2-mcp admin reset-password` and `show-setup-code`, and Playwright tests against a real server process. | Yes. |
| 2b. Everyday pages | `2026-10-31-admin-ui-phase2b-everyday-pages.md` | Dashboard, Users (with effective access), Groups, Roles, grants editor, Audit with CSV export, the rest of Settings (token policy, local accounts), My access with tokens and Copilot configuration, and the remaining browser tests. | Yes. |
| 3. SSO and deployment | `2026-10-31-admin-ui-phase3-sso-deploy.md` | SSO sign-in to the admin site, ID-token groups and Entra overage handling, the 30-day token freshness rule in the UI, a containerised OIDC test provider, Dockerfile, docker-compose, reverse-proxy examples, and `docs/admin.md`, the setup wizard's SSO step, and running the browser suite against the Docker image (`launch_server` in `tests/e2e/conftest.py`). | Yes. |

Phase 3 also handles trusted reverse-proxy headers (`U2_TRUSTED_PROXIES`), so the sign-in rate limit and `U2_ADMIN_ALLOWED_IPS` see the real client address behind a proxy.

Phases 2 and 3 are planned after the previous phase lands, so that each plan is written against the real code rather than guesses about it.

Project 2 (BASIC tools) follows phase 3 and has its own spec.
