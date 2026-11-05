# Admin UI phase 2b: grants, My access and the everyday pages — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a team-mode server usable from Copilot right after the wizard: grant access, create a token, call a tool. Then add the remaining everyday pages: Users with effective access, Groups, Roles, Audit with CSV, Dashboard, and the rest of Settings.

**Architecture:** This plan keeps 2a's shape.
- **Writes:** every write is a function in `admin/services.py` that validates, saves through `Store`, evicts registry slots when U2 logins change (commit first, evict second) and writes an `audit` row of kind `admin`.
- **The grants editor:** one Jinja partial plus one route set (`/admin/grants…`). The connection, user and group pages all include it. A hidden `return_to` field, checked by `safe_next`, sends each post back to the page it came from.
- **Errors on redirect:** after POST-redirect-GET, errors travel as fixed codes in the query string (`?problem=<code>`). Free text never does.
- **My access:** every signed-in user can open it. A new token is shown exactly once through a one-shot, in-process reveal, so the page still follows POST-redirect-GET.

**Tech Stack:** Python 3.10+, Starlette, Jinja2 (autoescape), htmx 2.0.4 (vendored), SQLite through `store/repo.py`, pytest, pytest-playwright (Chromium), and the `mcp` client SDK for the end-to-end tool call.

Spec: `docs/superpowers/specs/2026-10-30-admin-ui-design.md`. The relevant sections are "Data model", "Permissions and roles", "Access decision", "Personal access tokens", "Admin site > Everyday pages" and "Testing" item 6.
Roadmap: `docs/superpowers/plans/2026-10-30-admin-ui-roadmap.md` (row 2b).
Follow-ups folded in: `.superpowers/sdd/final-2a-review.md` (the "Phase 2b" triage, M-1, M-2, M-3, M-6) and the ledger in `.superpowers/sdd/progress.md`.

## Global Constraints

Everything in 2a's Global Constraints still holds: Python 3.10; `ruff==0.16.5` (line length 100, `E,F,I,UP,B,SIM`); `ruff format`; `mypy src/`; Google docstrings; type hints; no CDN; autoescape on and never `|safe` on user text; POST-redirect-GET; the CSRF field `csrf_token` or header `X-CSRF-Token`; `admin_only`/`signed_in`; and 2a's exact messages. In addition:

- **Every task ends with:**

  ```
  pytest -q
  ruff check . && ruff format --check .
  mypy src/ --ignore-missing-imports
  bandit -r src/ --severity-level medium --confidence-level medium
  ```

  Tasks that touch pages also run `pytest -m e2e tests/e2e`. All must pass, with no new warnings.

- **Code blocks are compacted.** Some blocks here put several arguments on one line. Run `ruff format .` after pasting code, and before the checks.
- **No schema migration.** The schema stays at version 2. Version 2 already has `roles.version`.
- **New settings keys:**
  - `token_max_lifetime_days`: an int, or absent for no cap.
  - `last_connection_id`: the high-water mark for connection ids.
  - `last_check:<connection id>`: `{"ok": bool, "message": str, "at": float}`.
  - `local_accounts_enabled` already exists.
- **Audit actions, all `kind="admin"`:** `grant.create`, `grant.update`, `grant.delete`, `token.create`, `token.revoke`, `user.flags`, `group.label`, `role.create`, `role.update`, `role.delete`, `settings.token_policy`, `settings.local_accounts`. The sign-in follow-up adds `kind="auth"` actions: `admin.sign_in` with outcome `refused` (local sign-in off), and `admin.password_check` with outcome `failed`.
- **New user-visible messages.** They are fixed in `admin/problems.py` (`PROBLEMS`) or named below. Use them exactly:
  - `grant_duplicate`: `That person or group already has a grant on this connection. Change its role instead.`
  - `grant_u2_login`: `Enter this person's U2 user and password for this connection.`
  - `grant_u2_password`: `Enter the password again: the U2 user changed.`
  - `gone`: `That item no longer exists. Reload the page.`
  - `token_name`: `Give the token a name of up to 64 characters.`
  - `token_days`: `Choose a lifetime from 1 day up to the maximum shown.`
  - `user_self`: `You can't remove your own admin access or disable yourself.`
  - `last_admin`: `Keep at least one enabled local admin. It is the way back in if company sign-in fails.`
  - `role_builtin`: `Built-in roles can't be changed. Clone one to make your own.`
  - `role_in_use`: `This role is used by a grant. Change those grants first.`
  - `per_user_check`: `Per-person connections are tested on the connection page, with a U2 login.`
  - `EVERYONE_WARNING`: `Everyone who can sign in gets this role on this connection.`
  - Stale role edit (a `StaleEdit` message): `Someone else changed this role since you opened it. Reload to see their changes.`
  - New token, shown above it: `Copy this token now. It is shown only once.`
  - Notices (codes in `NOTICES`): `revoked` → `Token revoked.`; `token_created` → `Token created.`
- **The current `RESTART_NOTE`**, copied from `routes_setup.py`, reads `Restart the server for personal access tokens to use a changed address. With OAuth sign-in on, sign-in and tokens use U2_AUTH_ISSUER_URL instead.` The 2a plan quotes an older text that is no longer accurate.
- **Revoking a token:** a non-admin may revoke only their own tokens, so My access checks that the token's `user_id` matches the signed-in user. Admins revoke other people's tokens from the Users page.
- **`is_admin`** grants no data access. An admin who wants to call tools gives themselves a grant like anyone else.
- `.superpowers/` is git-ignored scratch. Never `git add -f`.

## Decisions taken while planning

| Question | Decision |
|---|---|
| Task order | The coordinator asked that the server be usable from Copilot first. The order is therefore: the grants editor on the connection page (1), then My access and tokens with the non-admin landing (2), then a browser test of wizard, grant, token and a real MCP call (3). After that come Users (4), Groups and Roles (5), Audit and Dashboard (6), Settings and the ledger follow-ups (7), and docs (8). |
| "Shown once" vs POST-redirect-GET | `POST /admin/me/tokens` stores the new token in `OneTimeReveal`, an in-process map keyed by the session-id hash with a 5-minute TTL. It then redirects to `/admin/me?reveal=<id>`, and that GET pops the token. Refresh shows nothing again. The server is one process: the limiter and the registry already assume this. The token is never written to disk. |
| Errors after a redirect | The grants, tokens, users, roles and groups forms redirect back with `?problem=<code>`. `render()` looks the code up in `PROBLEMS`, so a link cannot put its own words on the page (the same rule as `NOTICES`). Form-field errors on the full-page forms (new user, role edit, settings) re-render with status 400, as in 2a. |
| Per-user U2 passwords when a connection's server changes | This is the I-2 leak again. Saving a `per_user` connection whose host, port, service, ssl or account changed clears every per-user password on its grants in the same transaction (`Store.update_connection(..., clear_grant_u2_passwords=True)`), so no tool call can pair the new host with an old password. The audit row records how many were cleared, and the grants table then shows "password needed". |
| Registry eviction on grant changes | Changing or removing a user grant's U2 login on a `per_user` connection evicts that connection's slots, after the commit. Role changes need no eviction, because `decide` reads current data on every call. |
| VS Code OAuth snippet | It is shown only when `config.auth_enabled` (SSO is configured). Otherwise My access says that browser sign-in arrives with company sign-in and shows the token variants. The VS Code token variant uses an `inputs` entry with `"password": true`, so the token is never written into `.vscode/mcp.json`. |
| Visual Studio and JetBrains formats | Visual Studio: `.mcp.json` in the solution folder or `%USERPROFILE%`, with `servers.u2.type = "http"`, `url` and `headers`. JetBrains (Copilot plugin `mcp.json`): `servers.u2.url` and `requestInit.headers`, as GitHub's MCP install guide shows. |
| Dashboard health | Nothing contacts U2 on page load, because `COUNT VOC` can take up to 10 seconds per connection. The dashboard shows the stored last check result (`last_check:<id>`). Every Test, on the connection page or the dashboard, saves its result. A "Check now" htmx button tests a shared connection with its saved password. Per-user connections link to their page. The dashboard also shows live U2 sessions (deduplicated logins) and active admin-site sessions. |
| The "imported everyone grant" warning | The dashboard warns about every `everyone` grant, not only the imported one, and adds "(imported at first start)" when the role is `Imported access`. Any `everyone` grant is just as wide, and the spec labels admin-made ones with a warning too. |
| Connection ids are reused (review M-2) | No migration. `add_connection` inserts an explicit id: `max(MAX(id), setting last_connection_id) + 1`. It writes the setting in the same transaction, so a deleted connection's audit history and registry slots never pass to a new connection. |
| Last local admin | Disabling or demoting yourself is refused (`user_self`). So is anything that would leave no enabled local admin (`last_admin`). |
| Landing pages | `/admin/` goes to `/admin/me` for non-admins and to `/admin/dashboard` for admins, once Task 6 lands (until then, `/admin/connections`). `admin_only` sends a non-admin's GET to `/admin/me` (303). A non-admin's POST still gets 403 `Only admins can use this page.`. Finish setup keeps redirecting to `/admin/connections?notice=setup_done`, so `tests/e2e/wizard.py` is unchanged. |
| Groups in browser tests | Without SSO no groups exist. The Groups browser test seeds one through `open_store_for_cli` with the server's environment and `record_sso_login`. That is the same data an SSO sign-in writes. |
| Settings: SSO and the setup checklist | SSO settings stay in phase 3. The setup checklist moves into a partial shared by the Done page and Settings. |
| Ledger items deferred to phase 3 | These are test-hygiene items with no behaviour change: `filterwarnings` on the base `Warning` category, docstrings on 2a's config tests, the no-op `.replace` in the wrong-code test, and deriving the migration tests from `SCHEMA_VERSION`. Phase 3 has its own phase 3 items in the review. |

## File structure

Create:

| File | Responsibility |
|---|---|
| `src/u2_mcp/admin/problems.py` | `PROBLEMS`, `Refused(code)`, `with_query(url, **params)` |
| `src/u2_mcp/admin/reveal.py` | `OneTimeReveal`: show a new token once, across a redirect |
| `src/u2_mcp/admin/routes_grants.py` | `grant_editor(...)` context, and the routes `POST /grants`, `/grants/{id}`, `/grants/{id}/delete` |
| `src/u2_mcp/admin/routes_me.py` | My access: connections, tokens, client configuration |
| `src/u2_mcp/admin/routes_users.py` | Users list, new user, user page, flags, token revoke, effective access |
| `src/u2_mcp/admin/routes_roles.py` | Groups list and label, Roles list, clone, edit and delete |
| `src/u2_mcp/admin/routes_audit.py` | Audit page, CSV export, Dashboard, Check now |
| `src/u2_mcp/admin/templates/partials/grants_editor.html` | The one grants component |
| `src/u2_mcp/admin/templates/partials/check_cell.html`, `partials/audit_rows.html` | The Dashboard's check cell, and the audit rows the Dashboard and Audit share |
| `src/u2_mcp/admin/templates/partials/setup_checklist.html` | Shared by the Done page and Settings |
| `src/u2_mcp/admin/templates/me.html`, `users/list.html`, `users/new.html`, `users/detail.html`, `users/access.html`, `groups/list.html`, `groups/detail.html`, `roles/list.html`, `roles/edit.html`, `audit.html`, `dashboard.html` | Pages |
| `tests/test_store/test_repo_2b.py` | Store additions |
| `tests/test_admin/test_grants.py`, `test_me.py`, `test_users.py`, `test_roles_groups.py`, `test_audit_dashboard.py`, `test_settings_2b.py`, `test_sign_in_followups.py`, `test_route_table.py` | Services and HTTP tests |
| `tests/e2e/test_copilot_journey.py`, `tests/e2e/test_everyday_pages.py` | Browser tests |

Modify: `src/u2_mcp/store/repo.py`, `src/u2_mcp/registry.py`, `src/u2_mcp/admin/app.py`, `services.py`, `security.py`, `templating.py`, `routes_connections.py`, `routes_setup.py`, `routes_auth.py`, `src/u2_mcp/cli.py`, `templates/base.html`, `connections/edit.html`, `partials/connection_form.html`, `setup/done.html`, `settings.html`, `static/styles.css`, `tests/test_admin/conftest.py`, `tests/test_admin/test_routes_auth.py`, `tests/test_admin/test_routes_setup.py`, `docs/configuration.md`, `CHANGELOG.md`, `docs/superpowers/plans/2026-10-30-admin-ui-roadmap.md`.

---

### Task 1: The grants editor, on the connection page

**Files:**
- Create: `src/u2_mcp/admin/problems.py`, `src/u2_mcp/admin/routes_grants.py`, `src/u2_mcp/admin/templates/partials/grants_editor.html`
- Modify: `src/u2_mcp/store/repo.py` (grants, roles and users section), `src/u2_mcp/admin/services.py`, `src/u2_mcp/admin/templating.py`, `src/u2_mcp/admin/app.py`, `src/u2_mcp/admin/routes_connections.py` (`_edit_page`), `src/u2_mcp/admin/templates/base.html`, `src/u2_mcp/admin/templates/connections/edit.html`, `src/u2_mcp/admin/static/styles.css`
- Test: `tests/test_store/test_repo_2b.py`, `tests/test_admin/test_grants.py`, `tests/test_admin/test_route_table.py`

**Interfaces:**
- **Produces, Store:**
  - `list_roles() -> list[Role]`: built-in roles first, then by name.
  - `list_users(*, search: str = "", is_admin: bool | None = None, disabled: bool | None = None) -> list[User]`: ordered by label.
  - `get_grant(grant_id: int) -> Grant | None`
  - `update_grant(grant_id: int, *, role_id: int, per_user_u2_user: str | None, per_user_u2_password: str | None = None) -> Grant`: `None` for the password keeps the stored one. A `None` user clears both. Raises `StoreError` when the grant is gone.
  - `delete_grant(grant_id: int) -> bool`
  - `grants_for_subject(subject_type: str, subject_id: int | None) -> list[Grant]`
  - `everyone_grants() -> list[Grant]`
  - `update_connection(..., clear_grant_u2_passwords: bool = False)`: a new keyword. When it is True, every per-user password on that connection's grants is forgotten in the same transaction.
- **Produces, `admin/problems.py`:** `PROBLEMS: dict[str, str]`; `class Refused(Exception)` with `.code`; `with_query(url: str, **params: str) -> str`.
- **Produces, services:**
  - `EVERYONE_WARNING: str`
  - `@dataclass(frozen=True) GrantRow(grant: Grant, connection: Connection, subject_label: str, role: Role)`
  - `grant_rows(ctx, *, connection_id: int | None = None, subject_type: str | None = None, subject_id: int | None = None) -> list[GrantRow]`
  - `save_grant(ctx, *, connection_id: int, subject_type: str, subject_id: int | None, role_id: int, u2_user: str, u2_password: str, actor: User) -> Grant`
  - `update_grant(ctx, grant_id: int, *, role_id: int, u2_user: str, u2_password: str, actor: User) -> Grant`
  - `delete_grant(ctx, grant_id: int, *, actor: User) -> None`
  - All three raise `Refused`.
- **Produces, routes:**
  - `routes_grants.grant_editor(ctx, *, return_to: str, connection: Connection | None = None, subject_type: str | None = None, subject_id: int | None = None) -> dict[str, Any]`: the template context keys `grants`, `editor` and `everyone_warning`.
  - Routes `POST /admin/grants`, `POST /admin/grants/{id:int}` and `POST /admin/grants/{id:int}/delete`. Form fields: `return_to`, `connection_id`, `subject_type` (`user`, `group` or `everyone`), `user_id`, `group_id`, `role_id`, `u2_user`, `u2_password`.
- **Produces, `render()`:** a `problem` value, from `PROBLEMS.get(query "problem")`.

- [ ] **Step 1: Write the failing store tests**

Create `tests/test_store/test_repo_2b.py`:

```python
"""Store additions for phase 2b: grants, roles, users, tokens, groups and audit."""

import pytest

from u2_mcp.store.repo import Store, StoreError


def _per_user(store: Store, name: str = "Dev") -> int:
    return store.add_connection(
        name=name, host="u2.example", port=31438, service="uvcs", account="DEV",
        login_mode="per_user",
    ).id


def _viewer(store: Store) -> int:
    role = store.get_role_by_name("Viewer")
    assert role is not None
    return role.id


class TestGrants:
    def test_update_changes_role_and_keeps_a_blank_password(self, store: Store) -> None:
        connection_id = _per_user(store)
        ann = store.add_local_user("ann")
        grant = store.add_grant(
            connection_id=connection_id, subject_type="user", subject_id=ann.id,
            role_id=_viewer(store), per_user_u2_user="ann", per_user_u2_password="pw1",
        )
        analyst = store.get_role_by_name("Analyst")
        assert analyst is not None

        updated = store.update_grant(grant.id, role_id=analyst.id, per_user_u2_user="ann")

        assert updated.role_id == analyst.id
        assert store.grant_u2_password(grant.id) == "pw1"

    def test_update_replaces_the_password_and_none_user_clears_both(self, store: Store) -> None:
        connection_id = _per_user(store)
        ann = store.add_local_user("ann")
        grant = store.add_grant(
            connection_id=connection_id, subject_type="user", subject_id=ann.id,
            role_id=_viewer(store), per_user_u2_user="ann", per_user_u2_password="pw1",
        )
        store.update_grant(grant.id, role_id=_viewer(store), per_user_u2_user="ann",
                           per_user_u2_password="pw2")
        assert store.grant_u2_password(grant.id) == "pw2"

        cleared = store.update_grant(grant.id, role_id=_viewer(store), per_user_u2_user=None)

        assert cleared.per_user_u2_user is None and not cleared.has_per_user_password

    def test_update_of_a_missing_grant_is_refused(self, store: Store) -> None:
        with pytest.raises(StoreError):
            store.update_grant(999, role_id=_viewer(store), per_user_u2_user=None)

    def test_delete_and_lookups(self, store: Store) -> None:
        connection_id = _per_user(store)
        everyone = store.add_grant(
            connection_id=connection_id, subject_type="everyone", role_id=_viewer(store)
        )

        assert store.get_grant(everyone.id) == everyone
        assert store.everyone_grants() == [everyone]
        assert store.grants_for_subject("everyone", None) == [everyone]
        assert store.delete_grant(everyone.id) is True
        assert store.delete_grant(everyone.id) is False
        assert store.get_grant(everyone.id) is None

    def test_moving_a_connection_can_forget_its_u2_passwords_atomically(
        self, store: Store
    ) -> None:
        connection_id = _per_user(store)
        other_id = _per_user(store, "Other")
        ann = store.add_local_user("ann")
        mine = store.add_grant(
            connection_id=connection_id, subject_type="user", subject_id=ann.id,
            role_id=_viewer(store), per_user_u2_user="ann", per_user_u2_password="pw",
        )
        theirs = store.add_grant(
            connection_id=other_id, subject_type="user", subject_id=ann.id,
            role_id=_viewer(store), per_user_u2_user="ann", per_user_u2_password="pw",
        )

        store.update_connection(
            connection_id, expected_version=1, name="Dev", host="elsewhere.example",
            port=31438, service="uvcs", account="DEV", ssl=False, login_mode="per_user",
            shared_user=None, clear_shared_password=True, clear_grant_u2_passwords=True,
            read_only=True, enabled=True, actor=None,
        )

        assert store.grant_u2_password(mine.id) is None
        assert store.grant_u2_password(theirs.id) == "pw"
        assert store.get_grant(mine.id).per_user_u2_user == "ann"  # type: ignore[union-attr]


class TestListing:
    def test_roles_list_builtins_first(self, store: Store) -> None:
        store.add_role("Auditor", ["schema.read"])

        names = [role.name for role in store.list_roles()]

        assert names[:4] == ["Analyst", "Developer", "Owner", "Viewer"]
        assert names[-1] == "Auditor"

    def test_users_filter_by_text_and_flags(self, store: Store) -> None:
        store.add_local_user("ann", display_name="Ann Admin", is_admin=True)
        bob = store.add_local_user("bob", email="bob@example.com")
        store.set_user_disabled(bob.id, True)

        assert [u.username for u in store.list_users()] == ["ann", "bob"]
        assert [u.username for u in store.list_users(search="EXAMPLE")] == ["bob"]
        assert [u.username for u in store.list_users(is_admin=True)] == ["ann"]
        assert [u.username for u in store.list_users(disabled=True)] == ["bob"]
        assert store.list_users(search="%") == []
```

Run: `pytest tests/test_store/test_repo_2b.py -v`
Expected: FAIL with `AttributeError: 'Store' object has no attribute 'update_grant'` (and similar for the others).

- [ ] **Step 2: Implement the store methods**

In `src/u2_mcp/store/repo.py`, add to the users section, after `get_user_by_username`:

```python
    def list_users(
        self, *, search: str = "", is_admin: bool | None = None, disabled: bool | None = None
    ) -> list[User]:
        """Return users matching a text search and flags, ordered by label.

        Args:
            search: Matched, case-insensitively, against username, email, display
                name and SSO subject. LIKE wildcards in it are taken literally.
            is_admin: Only admins (True) or only non-admins (False)
            disabled: Only disabled (True) or only enabled (False) users
        """
        sql = "SELECT * FROM users WHERE 1 = 1"
        params: list[Any] = []
        if search:
            escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            pattern = f"%{escaped}%"
            sql += (
                " AND (username LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\' "
                "OR display_name LIKE ? ESCAPE '\\' OR sso_subject LIKE ? ESCAPE '\\')"
            )
            params += [pattern] * 4
        if is_admin is not None:
            sql += " AND is_admin = ?"
            params.append(int(is_admin))
        if disabled is not None:
            sql += " AND disabled = ?"
            params.append(int(disabled))
        users = [self._user(row) for row in self._all(sql, params)]
        return sorted(users, key=lambda user: (user.label.casefold(), user.id))
```

Add to the roles section, after `get_role_by_name`:

```python
    def list_roles(self) -> list[Role]:
        """Return every role: built-in roles first, then custom roles, each by name."""
        rows = self._all("SELECT * FROM roles ORDER BY builtin DESC, name")
        return [self._role(row) for row in rows]
```

Add to the grants section, after `grants_on_connection`:

```python
    def get_grant(self, grant_id: int) -> Grant | None:
        """Return a grant by id, or None."""
        row = self._one("SELECT * FROM grants WHERE id = ?", (grant_id,))
        return self._grant(row) if row else None

    def grants_for_subject(self, subject_type: str, subject_id: int | None) -> list[Grant]:
        """Return one user's, one group's, or everyone's own grants (not inherited ones)."""
        if subject_type == "everyone":
            return self.everyone_grants()
        rows = self._all(
            "SELECT * FROM grants WHERE subject_type = ? AND subject_id = ? ORDER BY id",
            (subject_type, subject_id),
        )
        return [self._grant(row) for row in rows]

    def everyone_grants(self) -> list[Grant]:
        """Return every grant whose subject is everyone."""
        rows = self._all("SELECT * FROM grants WHERE subject_type = 'everyone' ORDER BY id")
        return [self._grant(row) for row in rows]

    def update_grant(
        self,
        grant_id: int,
        *,
        role_id: int,
        per_user_u2_user: str | None,
        per_user_u2_password: str | None = None,
    ) -> Grant:
        """Change a grant's role and per-user U2 login.

        Args:
            grant_id: The grant
            role_id: Its new role
            per_user_u2_user: The U2 user; None removes the login and its password
            per_user_u2_password: A new password, or None to keep the stored one

        Raises:
            StoreError: If the grant no longer exists or a value breaks a schema rule
        """
        try:
            with self._tx() as conn:
                cursor = conn.execute(
                    "UPDATE grants SET role_id = ?, per_user_u2_user = ? WHERE id = ?",
                    (role_id, per_user_u2_user, grant_id),
                )
                if cursor.rowcount == 0:
                    raise StoreError("That grant no longer exists.")
                if per_user_u2_user is None:
                    conn.execute(
                        "UPDATE grants SET per_user_u2_password_enc = NULL WHERE id = ?",
                        (grant_id,),
                    )
                elif per_user_u2_password is not None:
                    conn.execute(
                        "UPDATE grants SET per_user_u2_password_enc = ? WHERE id = ?",
                        (self._encrypt(per_user_u2_password), grant_id),
                    )
        except sqlite3.IntegrityError as exc:
            raise StoreError(f"Invalid grant: {exc}") from exc
        updated = self.get_grant(grant_id)
        if updated is None:
            raise StoreError("That grant no longer exists.")
        return updated

    def delete_grant(self, grant_id: int) -> bool:
        """Delete a grant. Returns whether one was deleted."""
        with self._tx() as conn:
            return conn.execute("DELETE FROM grants WHERE id = ?", (grant_id,)).rowcount > 0

```

In `update_connection`:
- Add the keyword `clear_grant_u2_passwords: bool = False` after `clear_shared_password`.
- Document it in the docstring: "Forget every per-user U2 password on this connection's grants, in the same transaction (the server changed)".
- Inside the `with self._tx() as conn:` block, after the shared-password `if`/`elif`, add:

```python
                if clear_grant_u2_passwords:
                    # Same transaction as the host change: no call can pair the new
                    # server with a password that was given for the old one.
                    conn.execute(
                        "UPDATE grants SET per_user_u2_password_enc = NULL "
                        "WHERE connection_id = ?",
                        (connection_id,),
                    )
```

Run: `pytest tests/test_store/test_repo_2b.py -v`
Expected: PASS.

- [ ] **Step 3: Write the failing services tests**

Create `tests/test_admin/test_grants.py`:

```python
"""The grants service and the grants routes."""

from collections.abc import Iterator

import pytest
from starlette.testclient import TestClient

from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.problems import Refused, with_query
from u2_mcp.admin.services import (
    ConnectionForm,
    delete_grant,
    grant_rows,
    save_connection,
    save_grant,
    update_grant,
)
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import finish_setup
from u2_mcp.store.models import User

from .conftest import FakeRegistry
from .helpers import PASSWORD, admin_client, csrf_from, sign_in


def _role(ctx: AdminContext, name: str) -> int:
    role = ctx.store.get_role_by_name(name)
    assert role is not None
    return role.id


def _connection(ctx: AdminContext, *, per_user: bool = False) -> int:
    return ctx.store.add_connection(
        name="Dev" if per_user else "Prod", host="u2.example", port=31438, service="uvcs",
        account="DEV", login_mode="per_user" if per_user else "shared",
        shared_user=None if per_user else "svc", shared_password=None if per_user else "pw",
    ).id


class TestService:
    def test_a_user_grant_is_saved_and_audited(self, ctx: AdminContext, admin: User) -> None:
        connection_id = _connection(ctx)

        grant = save_grant(
            ctx, connection_id=connection_id, subject_type="user", subject_id=admin.id,
            role_id=_role(ctx, "Viewer"), u2_user="ignored", u2_password="ignored", actor=admin,
        )

        assert grant.per_user_u2_user is None  # shared connection: no personal login
        entry = ctx.store.recent_audit(1)[0]
        assert (entry["action"], entry["connection_id"]) == ("grant.create", connection_id)
        assert entry["params"]["role"] == "Viewer"

    def test_a_second_grant_for_the_same_subject_is_refused(
        self, ctx: AdminContext, admin: User
    ) -> None:
        connection_id = _connection(ctx)
        values = dict(connection_id=connection_id, subject_type="everyone", subject_id=None,
                      role_id=_role(ctx, "Viewer"), u2_user="", u2_password="", actor=admin)
        save_grant(ctx, **values)  # type: ignore[arg-type]

        with pytest.raises(Refused) as refused:
            save_grant(ctx, **values)  # type: ignore[arg-type]

        assert refused.value.code == "grant_duplicate"

    def test_per_user_connections_need_a_login_on_user_grants(
        self, ctx: AdminContext, admin: User
    ) -> None:
        connection_id = _connection(ctx, per_user=True)

        with pytest.raises(Refused) as refused:
            save_grant(ctx, connection_id=connection_id, subject_type="user",
                       subject_id=admin.id, role_id=_role(ctx, "Viewer"), u2_user="root",
                       u2_password="", actor=admin)

        assert refused.value.code == "grant_u2_login"

    def test_changing_the_u2_user_needs_the_password_and_evicts(
        self, ctx: AdminContext, admin: User, registry: FakeRegistry
    ) -> None:
        connection_id = _connection(ctx, per_user=True)
        grant = save_grant(ctx, connection_id=connection_id, subject_type="user",
                           subject_id=admin.id, role_id=_role(ctx, "Viewer"), u2_user="root",
                           u2_password="pw", actor=admin)

        with pytest.raises(Refused) as refused:
            update_grant(ctx, grant.id, role_id=grant.role_id, u2_user="other",
                         u2_password="", actor=admin)
        assert refused.value.code == "grant_u2_password"
        assert registry.evicted == []

        update_grant(ctx, grant.id, role_id=grant.role_id, u2_user="other", u2_password="pw2",
                     actor=admin)
        assert ctx.store.grant_u2_password(grant.id) == "pw2"
        assert registry.evicted == [connection_id]

    def test_delete_and_rows(self, ctx: AdminContext, admin: User) -> None:
        connection_id = _connection(ctx)
        grant = save_grant(ctx, connection_id=connection_id, subject_type="everyone",
                           subject_id=None, role_id=_role(ctx, "Viewer"), u2_user="",
                           u2_password="", actor=admin)

        rows = grant_rows(ctx, connection_id=connection_id)
        assert [(r.subject_label, r.role.name) for r in rows] == [("Everyone", "Viewer")]

        delete_grant(ctx, grant.id, actor=admin)
        assert grant_rows(ctx, connection_id=connection_id) == []
        assert ctx.store.recent_audit(1)[0]["action"] == "grant.delete"
        with pytest.raises(Refused) as refused:
            delete_grant(ctx, grant.id, actor=admin)
        assert refused.value.code == "gone"

    def test_moving_a_per_user_connection_forgets_its_u2_passwords(
        self, ctx: AdminContext, admin: User
    ) -> None:
        connection_id = _connection(ctx, per_user=True)
        grant = save_grant(ctx, connection_id=connection_id, subject_type="user",
                           subject_id=admin.id, role_id=_role(ctx, "Viewer"), u2_user="root",
                           u2_password="pw", actor=admin)
        saved = ctx.store.get_connection(connection_id)
        assert saved is not None
        form = ConnectionForm.from_connection(saved)
        form.host = "elsewhere.example"

        save_connection(ctx, form, actor=admin, connection_id=connection_id)

        assert ctx.store.grant_u2_password(grant.id) is None
        assert ctx.store.recent_audit(1)[0]["params"]["u2_passwords_cleared"] == 1


def test_with_query_appends_safely() -> None:
    assert with_query("/admin/users/3", problem="gone") == "/admin/users/3?problem=gone"
    assert with_query("/admin/x?a=1", notice="saved") == "/admin/x?a=1&notice=saved"


@pytest.fixture
def client(ctx: AdminContext) -> Iterator[TestClient]:
    finish_setup(ctx.store)
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    with admin_client(ctx) as test_client:
        sign_in(test_client)
        yield test_client


class TestRoutes:
    def test_the_connection_page_adds_a_grant(self, client: TestClient, ctx: AdminContext) -> None:
        connection_id = _connection(ctx)
        page = client.get(f"/admin/connections/{connection_id}").text
        assert "Add grant" in page

        ann = ctx.store.get_user_by_username("ann")
        assert ann is not None
        response = client.post(
            "/admin/grants",
            data={
                "csrf_token": csrf_from(page),
                "return_to": f"/admin/connections/{connection_id}",
                "connection_id": str(connection_id),
                "subject_type": "user",
                "user_id": str(ann.id),
                "role_id": str(_role(ctx, "Viewer")),
            },
            follow_redirects=False,
        )

        assert response.headers["location"] == f"/admin/connections/{connection_id}?notice=saved"
        [grant] = ctx.store.grants_on_connection(connection_id)
        assert (grant.subject_type, grant.subject_id, grant.role_id) == (
            "user", ann.id, _role(ctx, "Viewer"),
        )
        assert "Remove" in client.get(response.headers["location"]).text

    def test_a_refusal_comes_back_as_a_fixed_problem(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        connection_id = _connection(ctx)
        page = client.get(f"/admin/connections/{connection_id}").text
        data = {
            "csrf_token": csrf_from(page),
            "return_to": f"/admin/connections/{connection_id}",
            "connection_id": str(connection_id),
            "subject_type": "everyone",
            "role_id": str(_role(ctx, "Viewer")),
        }
        client.post("/admin/grants", data=data)

        again = client.post("/admin/grants", data=data, follow_redirects=False)

        assert again.headers["location"].endswith("?problem=grant_duplicate")
        shown = client.get(again.headers["location"]).text
        assert "already has a grant on this connection" in shown

    def test_return_to_outside_the_admin_site_is_ignored(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        connection_id = _connection(ctx)
        page = client.get(f"/admin/connections/{connection_id}").text
        response = client.post(
            "/admin/grants",
            data={"csrf_token": csrf_from(page), "return_to": "https://evil.example/",
                  "connection_id": str(connection_id), "subject_type": "everyone",
                  "role_id": str(_role(ctx, "Viewer"))},
            follow_redirects=False,
        )

        assert response.headers["location"] == "/admin/?notice=saved"
```

Run: `pytest tests/test_admin/test_grants.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'u2_mcp.admin.problems'`.

- [ ] **Step 4: Add `admin/problems.py`**

```python
"""Fixed messages that travel across a redirect as a short code.

A code in the query string selects one of these texts, so a link can never put
words of its own on an admin page (the same rule as NOTICES in templating.py).
"""

from __future__ import annotations

from urllib.parse import urlencode

PROBLEMS: dict[str, str] = {
    "grant_duplicate": (
        "That person or group already has a grant on this connection. Change its role instead."
    ),
    "grant_u2_login": "Enter this person's U2 user and password for this connection.",
    "grant_u2_password": "Enter the password again: the U2 user changed.",
    "gone": "That item no longer exists. Reload the page.",
    "token_name": "Give the token a name of up to 64 characters.",
    "token_days": "Choose a lifetime from 1 day up to the maximum shown.",
    "user_self": "You can't remove your own admin access or disable yourself.",
    "last_admin": (
        "Keep at least one enabled local admin. It is the way back in if company sign-in fails."
    ),
    "role_builtin": "Built-in roles can't be changed. Clone one to make your own.",
    "role_in_use": "This role is used by a grant. Change those grants first.",
    "per_user_check": "Per-person connections are tested on the connection page, with a U2 login.",
}


class Refused(Exception):
    """A change was refused for a reason with a fixed message.

    Attributes:
        code: Key into PROBLEMS
    """

    def __init__(self, code: str) -> None:
        super().__init__(PROBLEMS[code])
        self.code = code


def with_query(url: str, **params: str) -> str:
    """Append query parameters to a server-chosen admin URL."""
    joiner = "&" if "?" in url else "?"
    return f"{url}{joiner}{urlencode(params)}"
```

In `src/u2_mcp/admin/templating.py`, add `from .problems import PROBLEMS`. In `render`'s `values`, after `"notice"`, add:

```python
        "problem": PROBLEMS.get(request.query_params.get("problem", "")),
```

In `src/u2_mcp/admin/templates/base.html`, after the notice line in `<main>`, add:

```html
    {% if problem %}<p class="alert" role="alert">{{ problem }}</p>{% endif %}
```

- [ ] **Step 5: Add the grants services**

In `src/u2_mcp/admin/services.py`:
- Add `from .problems import Refused`.
- Change the models import to `from ..store.models import Connection, Grant, Role, User`.
- Append:

```python
EVERYONE_WARNING = "Everyone who can sign in gets this role on this connection."
_SUBJECT_TYPES = ("user", "group", "everyone")


@dataclass(frozen=True)
class GrantRow:
    """A grant with the names a page shows beside it."""

    grant: Grant
    connection: Connection
    subject_label: str
    role: Role


def _subject_label(ctx: AdminContext, subject_type: str, subject_id: int | None) -> str | None:
    """A subject's name, or None when it does not exist."""
    if subject_type == "everyone":
        return "Everyone"
    if subject_type == "user" and subject_id is not None:
        user = ctx.store.get_user(subject_id)
        return user.label if user else None
    if subject_type == "group" and subject_id is not None:
        group = next((g for g in ctx.store.list_groups() if g.id == subject_id), None)
        return (group.label or group.external_id) if group else None
    return None


def grant_rows(
    ctx: AdminContext,
    *,
    connection_id: int | None = None,
    subject_type: str | None = None,
    subject_id: int | None = None,
) -> list[GrantRow]:
    """The grants on one connection, or held by one subject, ready to show."""
    if connection_id is not None:
        grants = ctx.store.grants_on_connection(connection_id)
    elif subject_type is not None:
        grants = ctx.store.grants_for_subject(subject_type, subject_id)
    else:
        grants = []
    rows = []
    for grant in grants:
        connection = ctx.store.get_connection(grant.connection_id)
        role = ctx.store.get_role(grant.role_id)
        label = _subject_label(ctx, grant.subject_type, grant.subject_id)
        if connection is not None and role is not None and label is not None:
            rows.append(GrantRow(grant, connection, label, role))
    return sorted(rows, key=lambda r: (r.connection.name.casefold(), r.subject_label.casefold()))


def _personal_login(connection: Connection, subject_type: str) -> bool:
    """Whether a grant carries a U2 login: user grants on per-user connections only."""
    return connection.login_mode == "per_user" and subject_type == "user"


def save_grant(
    ctx: AdminContext,
    *,
    connection_id: int,
    subject_type: str,
    subject_id: int | None,
    role_id: int,
    u2_user: str,
    u2_password: str,
    actor: User,
) -> Grant:
    """Give a user, a group or everyone a role on a connection.

    Raises:
        Refused: grant_duplicate, grant_u2_login or gone
    """
    connection = ctx.store.get_connection(connection_id)
    role = ctx.store.get_role(role_id)
    if subject_type == "everyone":
        subject_id = None
    if (
        connection is None
        or role is None
        or subject_type not in _SUBJECT_TYPES
        or _subject_label(ctx, subject_type, subject_id) is None
    ):
        raise Refused("gone")
    personal = _personal_login(connection, subject_type)
    u2_user = u2_user.strip()
    if personal and (not u2_user or not u2_password):
        raise Refused("grant_u2_login")
    try:
        grant = ctx.store.add_grant(
            connection_id=connection_id,
            subject_type=subject_type,
            subject_id=subject_id,
            role_id=role_id,
            per_user_u2_user=u2_user if personal else None,
            per_user_u2_password=u2_password if personal else None,
        )
    except StoreError as exc:
        raise Refused("grant_duplicate" if "already has" in str(exc) else "gone") from exc
    _audit(
        ctx,
        actor,
        "grant.create",
        connection_id=connection_id,
        params={
            "subject_type": subject_type,
            "subject_id": subject_id,
            "role": role.name,
            "u2_user": u2_user if personal else None,
        },
    )
    return grant


def update_grant(
    ctx: AdminContext, grant_id: int, *, role_id: int, u2_user: str, u2_password: str, actor: User
) -> Grant:
    """Change a grant's role, and on per-user connections the person's U2 login.

    A blank password keeps the stored one only while the U2 user is unchanged.
    A changed login closes the connection's live sessions, after saving.

    Raises:
        Refused: grant_u2_login, grant_u2_password or gone
    """
    grant = ctx.store.get_grant(grant_id)
    connection = ctx.store.get_connection(grant.connection_id) if grant else None
    role = ctx.store.get_role(role_id)
    if grant is None or connection is None or role is None:
        raise Refused("gone")
    personal = _personal_login(connection, grant.subject_type)
    u2_user = u2_user.strip()
    login_changed = False
    if personal:
        if not u2_user:
            raise Refused("grant_u2_login")
        if u2_user != (grant.per_user_u2_user or "") and not u2_password:
            raise Refused("grant_u2_password")
        if not u2_password and not grant.has_per_user_password:
            raise Refused("grant_u2_login")
        login_changed = u2_user != grant.per_user_u2_user or bool(u2_password)
    try:
        updated = ctx.store.update_grant(
            grant_id,
            role_id=role_id,
            per_user_u2_user=u2_user if personal else None,
            per_user_u2_password=(u2_password or None) if personal else None,
        )
    except StoreError as exc:
        raise Refused("gone") from exc
    if login_changed:
        ctx.registry().evict_connection(connection.id)
    _audit(
        ctx,
        actor,
        "grant.update",
        connection_id=connection.id,
        params={"grant_id": grant_id, "role": role.name, "login_changed": login_changed},
    )
    return updated


def delete_grant(ctx: AdminContext, grant_id: int, *, actor: User) -> None:
    """Remove a grant. Removing a personal U2 login closes the connection's sessions.

    Raises:
        Refused: gone
    """
    grant = ctx.store.get_grant(grant_id)
    if grant is None or not ctx.store.delete_grant(grant_id):
        raise Refused("gone")
    if grant.per_user_u2_user is not None:
        ctx.registry().evict_connection(grant.connection_id)
    _audit(
        ctx,
        actor,
        "grant.delete",
        connection_id=grant.connection_id,
        params={"subject_type": grant.subject_type, "subject_id": grant.subject_id},
    )
```

In `save_connection`, just before `try:`, add:

```python
    # Personal U2 passwords were given for the old server: never send them on.
    forget = (
        existing is not None
        and existing.login_mode == "per_user"
        and not form.targets_connection(existing)
    )
    cleared = (
        sum(1 for g in ctx.store.grants_on_connection(existing.id) if g.has_per_user_password)
        if forget and existing is not None
        else 0
    )
```

In the `ctx.store.update_connection(...)` call, add `clear_grant_u2_passwords=forget,` after `clear_shared_password=not shared,`. Then replace the final audit call with:

```python
    params = form.described()
    if cleared:
        params["u2_passwords_cleared"] = cleared
    _audit(ctx, actor, action, connection_id=saved.id, params=params)
    return saved
```

- [ ] **Step 6: Add the grants routes and the editor partial**

Create `src/u2_mcp/admin/routes_grants.py`:

```python
"""The grants editor: one component on the connection, user and group pages."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from starlette.datastructures import FormData
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from ..store.models import Connection, Group, Role, User
from .context import AdminContext
from .problems import Refused, with_query
from .security import admin_only, read_form, safe_next
from .services import EVERYONE_WARNING, delete_grant, grant_rows, save_grant, update_grant
from .templating import admin_context


@dataclass(frozen=True)
class GrantEditor:
    """What the grants partial needs besides the rows.

    A fixed connection hides the connection picker; a fixed subject hides the
    "who" pickers. return_to is where every form on the editor comes back to.
    """

    return_to: str
    connection: Connection | None
    subject_type: str | None
    subject_id: int | None
    roles: list[Role]
    users: list[User]
    groups: list[Group]
    connections: list[Connection]

    @property
    def asks_for_login(self) -> bool:
        """Whether the add form shows U2 user and password boxes."""
        if self.subject_type in ("group", "everyone"):
            return False
        if self.connection is not None:
            return self.connection.login_mode == "per_user"
        return any(c.login_mode == "per_user" for c in self.connections)


def grant_editor(
    ctx: AdminContext,
    *,
    return_to: str,
    connection: Connection | None = None,
    subject_type: str | None = None,
    subject_id: int | None = None,
) -> dict[str, Any]:
    """Template values for partials/grants_editor.html."""
    rows = (
        grant_rows(ctx, connection_id=connection.id)
        if connection is not None
        else grant_rows(ctx, subject_type=subject_type, subject_id=subject_id)
    )
    editor = GrantEditor(
        return_to=return_to,
        connection=connection,
        subject_type=subject_type,
        subject_id=subject_id,
        roles=ctx.store.list_roles(),
        users=ctx.store.list_users(disabled=False),
        groups=ctx.store.list_groups(),
        connections=ctx.store.list_connections(),
    )
    return {"grants": rows, "editor": editor, "everyone_warning": EVERYONE_WARNING}


def form_int(value: object) -> int | None:
    """A submitted id as an int, or None."""
    text = str(value or "")
    return int(text) if text.isascii() and text.isdecimal() else None


def _back(data: FormData) -> str:
    return safe_next(str(data.get("return_to", "")))


def _done(back: str, refused: Refused | None = None) -> Response:
    target = with_query(back, problem=refused.code) if refused else with_query(back, notice="saved")
    return RedirectResponse(target, status_code=303)


@admin_only
async def add(request: Request) -> Response:
    """Create a grant from the editor's add form."""
    data = await read_form(request)
    subject_type = str(data.get("subject_type", ""))
    subject_id = form_int({"user": data.get("user_id"), "group": data.get("group_id")}.get(
        subject_type
    ))
    try:
        save_grant(
            admin_context(request),
            connection_id=form_int(data.get("connection_id")) or 0,
            subject_type=subject_type,
            subject_id=subject_id,
            role_id=form_int(data.get("role_id")) or 0,
            u2_user=str(data.get("u2_user", "")),
            u2_password=str(data.get("u2_password", "")),
            actor=request.state.user,
        )
    except Refused as refused:
        return _done(_back(data), refused)
    return _done(_back(data))


@admin_only
async def change(request: Request) -> Response:
    """Change one grant's role or U2 login."""
    data = await read_form(request)
    try:
        update_grant(
            admin_context(request),
            request.path_params["id"],
            role_id=form_int(data.get("role_id")) or 0,
            u2_user=str(data.get("u2_user", "")),
            u2_password=str(data.get("u2_password", "")),
            actor=request.state.user,
        )
    except Refused as refused:
        return _done(_back(data), refused)
    return _done(_back(data))


@admin_only
async def remove(request: Request) -> Response:
    """Remove one grant."""
    data = await read_form(request)
    try:
        delete_grant(admin_context(request), request.path_params["id"], actor=request.state.user)
    except Refused as refused:
        return _done(_back(data), refused)
    return _done(_back(data))


routes = [
    Route("/grants", add, methods=["POST"]),
    Route("/grants/{id:int}", change, methods=["POST"]),
    Route("/grants/{id:int}/delete", remove, methods=["POST"]),
]
```

In `src/u2_mcp/admin/app.py`, import `routes_grants` and add `*routes_grants.routes,` after `*routes_connections.routes,`.

Create `src/u2_mcp/admin/templates/partials/grants_editor.html`:

```html
<section id="grants">
<h2>Access</h2>
{% if grants %}
<table>
  <thead><tr>
    {% if not editor.connection %}<th>Connection</th>{% endif %}
    {% if not editor.subject_type %}<th>Who</th>{% endif %}
    <th>Role and U2 login</th><th></th>
  </tr></thead>
  <tbody>
  {% for row in grants %}
  <tr>
    {% if not editor.connection %}<td><a href="/admin/connections/{{ row.connection.id }}">{{ row.connection.name }}</a></td>{% endif %}
    {% if not editor.subject_type %}<td>{{ row.subject_label }}{% if row.grant.subject_type == "everyone" %}<p class="warning">{{ everyone_warning }}</p>{% endif %}</td>{% endif %}
    <td>
      <form method="post" action="/admin/grants/{{ row.grant.id }}" class="inline">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <input type="hidden" name="return_to" value="{{ editor.return_to }}">
        <select name="role_id" aria-label="Role for {{ row.subject_label }} on {{ row.connection.name }}">
          {% for role in editor.roles %}<option value="{{ role.id }}" {% if role.id == row.grant.role_id %}selected{% endif %}>{{ role.name }}</option>{% endfor %}
        </select>
        {% if row.connection.login_mode == "per_user" and row.grant.subject_type == "user" %}
        <input type="text" name="u2_user" value="{{ row.grant.per_user_u2_user or '' }}" aria-label="U2 user" autocomplete="off">
        <input type="password" name="u2_password" aria-label="U2 password" autocomplete="new-password"
               placeholder="{{ 'Leave blank to keep' if row.grant.has_per_user_password else 'Password needed' }}">
        {% endif %}
        <button type="submit" class="secondary">Save</button>
      </form>
    </td>
    <td>
      <form method="post" action="/admin/grants/{{ row.grant.id }}/delete" class="inline">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <input type="hidden" name="return_to" value="{{ editor.return_to }}">
        <button type="submit" class="danger">Remove</button>
      </form>
    </td>
  </tr>
  {% endfor %}
  </tbody>
</table>
{% else %}
<p>No grants yet. Nobody can use this from Copilot until one is added.</p>
{% endif %}
<h3>Add a grant</h3>
<form method="post" action="/admin/grants" class="grant-add">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <input type="hidden" name="return_to" value="{{ editor.return_to }}">
  {% if editor.connection %}
  <input type="hidden" name="connection_id" value="{{ editor.connection.id }}">
  {% else %}
  <div class="field"><label for="g-connection">Connection</label>
    <select id="g-connection" name="connection_id">
      {% for c in editor.connections %}<option value="{{ c.id }}">{{ c.name }}{{ " (per person)" if c.login_mode == "per_user" else "" }}</option>{% endfor %}
    </select></div>
  {% endif %}
  {% if editor.subject_type %}
  <input type="hidden" name="subject_type" value="{{ editor.subject_type }}">
  {% if editor.subject_type == "user" %}<input type="hidden" name="user_id" value="{{ editor.subject_id }}">{% endif %}
  {% if editor.subject_type == "group" %}<input type="hidden" name="group_id" value="{{ editor.subject_id }}">{% endif %}
  {% else %}
  <div class="field"><label for="g-who">Who</label>
    <select id="g-who" name="subject_type">
      <option value="user">A person</option>
      <option value="group">A group</option>
      <option value="everyone">Everyone</option>
    </select>
    <p class="hint">Everyone: {{ everyone_warning }}</p></div>
  <div class="field"><label for="g-user">Person</label>
    <select id="g-user" name="user_id">
      {% for u in editor.users %}<option value="{{ u.id }}">{{ u.label }}</option>{% endfor %}
    </select></div>
  {% if editor.groups %}
  <div class="field"><label for="g-group">Group</label>
    <select id="g-group" name="group_id">
      {% for g in editor.groups %}<option value="{{ g.id }}">{{ g.label or g.external_id }}</option>{% endfor %}
    </select></div>
  {% endif %}
  {% endif %}
  <div class="field"><label for="g-role">Role</label>
    <select id="g-role" name="role_id">
      {% for role in editor.roles %}<option value="{{ role.id }}">{{ role.name }}</option>{% endfor %}
    </select></div>
  {% if editor.asks_for_login %}
  <fieldset>
    <legend>Personal U2 login</legend>
    <p class="hint">Only for a person on a per-person connection. Stored encrypted.</p>
    <div class="field"><label for="g-u2-user">U2 user</label><input id="g-u2-user" type="text" name="u2_user" autocomplete="off"></div>
    <div class="field"><label for="g-u2-password">U2 password</label><input id="g-u2-password" type="password" name="u2_password" autocomplete="new-password"></div>
  </fieldset>
  {% endif %}
  <div class="actions"><button type="submit">Add grant</button></div>
</form>
</section>
```

In `src/u2_mcp/admin/routes_connections.py`, add `from .routes_grants import grant_editor`. In `_edit_page`'s `page`, build:

```python
        grants = (
            grant_editor(ctx, return_to=f"/admin/connections/{connection.id}",
                         connection=connection)
            if connection
            else {}
        )
```

Then pass `**grants` to `render(...)`. In `templates/connections/edit.html`, add `{% include "partials/grants_editor.html" %}` after the Live sessions block, inside `{% if connection %}`. Append to `styles.css`:

```css
#grants form.inline select, #grants form.inline input { max-width: 12rem; }
fieldset { border: 1px solid var(--line); border-radius: 6px; margin: 0 0 1rem; }
```

Run: `pytest tests/test_admin/test_grants.py -v`
Expected: PASS.

- [ ] **Step 7: Add the route-table test (review M-6)**

Create `tests/test_admin/test_route_table.py`. It walks every route, so each later task's routes are covered automatically:

```python
"""Every admin route: sign-in required, CSRF on POST, never cached (review M-6)."""

import re

from starlette.routing import Route

from u2_mcp.admin.app import build_admin_app
from u2_mcp.admin.context import AdminContext
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import finish_setup

from .helpers import PASSWORD, admin_client, sign_in

PUBLIC_GETS = {"/sign-in"}


def _routes(ctx: AdminContext) -> list[tuple[str, str]]:
    found = []
    for route in build_admin_app(ctx).routes:
        if isinstance(route, Route):
            path = re.sub(r"\{[^}]+\}", "1", route.path)
            found += [(method, path) for method in sorted(route.methods or ()) if method != "HEAD"]
    return found


def test_every_page_needs_sign_in_and_is_never_cached(ctx: AdminContext) -> None:
    finish_setup(ctx.store)
    with admin_client(ctx) as anonymous:
        for method, path in _routes(ctx):
            if method != "GET" or path in PUBLIC_GETS:
                continue
            response = anonymous.get(f"/admin{path}", follow_redirects=False)
            assert response.status_code == 303, path
            assert response.headers["cache-control"] == "no-store", path


def test_no_post_changes_anything_without_the_csrf_token(ctx: AdminContext) -> None:
    finish_setup(ctx.store)
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    with admin_client(ctx) as client:
        sign_in(client)
        before = len(ctx.store.recent_audit(1000))
        for method, path in _routes(ctx):
            if method != "POST":
                continue
            response = client.post(f"/admin{path}", data={}, follow_redirects=False)
            assert response.status_code in (303, 403, 404), path
            assert response.headers["cache-control"] == "no-store", path
        assert len(ctx.store.recent_audit(1000)) == before
```

Run: `pytest tests/test_admin/test_route_table.py -v`
Expected: PASS. If a POST answers 200 or writes audit, that route reads the form without `read_form`: fix the route, not the test.

- [ ] **Step 8: Run all checks**

Run the four Global Constraints commands, then `pytest -m e2e tests/e2e`.
Expected: all pass.

- [ ] **Step 9: Commit**

```bash
git add src/u2_mcp/store/repo.py src/u2_mcp/admin tests/test_store/test_repo_2b.py tests/test_admin/test_grants.py tests/test_admin/test_route_table.py
git commit -m "feat(admin): grants editor on the connection page"
```

---

### Task 2: My access, personal tokens and the non-admin landing

**Files:**
- Create: `src/u2_mcp/admin/reveal.py`, `src/u2_mcp/admin/routes_me.py`, `src/u2_mcp/admin/templates/me.html`
- Modify: `src/u2_mcp/store/repo.py` (`get_token`), `src/u2_mcp/admin/services.py`, `src/u2_mcp/admin/security.py` (`admin_only`), `src/u2_mcp/admin/routes_setup.py` (`_home`, `_guard`), `src/u2_mcp/admin/templating.py` (notices, the `when` filter), `src/u2_mcp/admin/app.py`, `templates/base.html` (nav), `templates/setup/done.html`
- Test: `tests/test_admin/test_me.py`; update `test_a_non_admin_sees_the_refusal` in `tests/test_admin/test_routes_auth.py`

**Interfaces:**
- **Consumes:** `Refused`, `with_query` and `PROBLEMS` (Task 1); `tokens.create_token`, `tokens.revoke`, `tokens.DEFAULT_LIFETIME_DAYS`; `access.visible_connections`.
- **Produces, Store:** `get_token(token_id: int) -> TokenRecord | None`.
- **Produces, services:**
  - `TOKEN_MAX_LIFETIME_SETTING = "token_max_lifetime_days"`
  - `token_max_lifetime(ctx) -> int | None`
  - `default_token_days(ctx) -> int`
  - `@dataclass(frozen=True) TokenView(record: TokenRecord, status: str)`, where `status` is `"Active"`, `"Expired"` or `"Revoked"`
  - `token_views(ctx, user_id: int) -> list[TokenView]`
  - `create_personal_token(ctx, user: User, *, name: str, days: str) -> tuple[str, TokenRecord]`, which raises `Refused("token_name" | "token_days")`
  - `revoke_personal_token(ctx, token_id: int, *, owner_id: int, actor: User) -> None`, which raises `Refused("gone")` when the token is missing or not `owner_id`'s
  - `client_configs(public_url: str, *, oauth: bool) -> dict[str, str]`, with keys `vscode_oauth` (only when `oauth`), `vscode_token`, `visual_studio` and `jetbrains`
- **Produces, `admin/reveal.py`:** `OneTimeReveal(*, ttl_seconds: float = 300.0, clock: Callable[[], float] = time.monotonic)` with `.put(owner: str, value: str) -> str` and `.take(owner: str, reveal_id: str) -> str | None`.
- **Produces, routes:** `GET /admin/me`, `POST /admin/me/tokens` (fields `name`, `days`) and `POST /admin/me/tokens/{id:int}/revoke`. The new token is rendered in `<pre id="new-token">`. Each revoke button is named `Revoke <token name>`.
- **Produces, templating:** a Jinja filter `when(value: float | None) -> str`, formatted `YYYY-MM-DD HH:MM UTC` (or `""`).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_admin/test_me.py`:

```python
"""My access: connections, tokens shown once, client configuration, non-admin landing."""

import json
import re
from collections.abc import Iterator

import pytest
from starlette.testclient import TestClient

from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.problems import Refused
from u2_mcp.admin.reveal import OneTimeReveal
from u2_mcp.admin.services import (
    TOKEN_MAX_LIFETIME_SETTING,
    client_configs,
    create_personal_token,
    revoke_personal_token,
)
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import finish_setup, mark_step_done
from u2_mcp.store.models import User
from u2_mcp.tokens import hash_token

from .helpers import PASSWORD, admin_client, csrf_from, sign_in


class TestReveal:
    def test_a_value_is_taken_once_and_only_by_its_owner(self) -> None:
        reveal = OneTimeReveal()
        reveal_id = reveal.put("session-a", "u2pat_x")

        assert reveal.take("session-b", reveal_id) is None
        assert reveal.take("session-a", reveal_id) == "u2pat_x"
        assert reveal.take("session-a", reveal_id) is None

    def test_values_expire(self) -> None:
        now = [0.0]
        reveal = OneTimeReveal(ttl_seconds=10, clock=lambda: now[0])
        reveal_id = reveal.put("s", "v")
        now[0] = 11.0

        assert reveal.take("s", reveal_id) is None


class TestTokenService:
    def test_creating_stores_only_the_hash_and_audits_without_the_token(
        self, ctx: AdminContext, admin: User
    ) -> None:
        token, record = create_personal_token(ctx, admin, name=" laptop ", days="30")

        assert record.token_hash == hash_token(token) and record.name == "laptop"
        entry = ctx.store.recent_audit(1)[0]
        assert entry["action"] == "token.create"
        assert token not in json.dumps(entry)

    @pytest.mark.parametrize(
        ("name", "days", "code"),
        [
            ("", "30", "token_name"),
            ("x" * 65, "30", "token_name"),
            ("ok", "0", "token_days"),
            ("ok", "abc", "token_days"),
            ("ok", "31", "token_days"),
        ],
    )
    def test_bad_values_are_refused(
        self, ctx: AdminContext, admin: User, name: str, days: str, code: str
    ) -> None:
        ctx.store.set_setting(TOKEN_MAX_LIFETIME_SETTING, 30)

        with pytest.raises(Refused) as refused:
            create_personal_token(ctx, admin, name=name, days=days)

        assert refused.value.code == code

    def test_nobody_revokes_another_persons_token_here(
        self, ctx: AdminContext, admin: User
    ) -> None:
        bob = ctx.store.add_local_user("bob")
        _token, record = create_personal_token(ctx, bob, name="bob's", days="30")

        with pytest.raises(Refused):
            revoke_personal_token(ctx, record.id, owner_id=admin.id, actor=admin)

        stored = ctx.store.get_token(record.id)
        assert stored is not None and stored.revoked_at is None


def test_client_configs_keep_the_token_out_of_vscode_files() -> None:
    configs = client_configs("https://u2.example.com/", oauth=False)

    assert "vscode_oauth" not in configs
    vscode = json.loads(configs["vscode_token"])
    assert vscode["inputs"][0]["password"] is True
    assert vscode["servers"]["u2"]["url"] == "https://u2.example.com/"
    assert vscode["servers"]["u2"]["headers"]["Authorization"] == "Bearer ${input:u2-mcp-token}"
    jetbrains = json.loads(configs["jetbrains"])
    assert "Authorization" in jetbrains["servers"]["u2"]["requestInit"]["headers"]
    assert json.loads(configs["visual_studio"])["servers"]["u2"]["type"] == "http"
    assert "vscode_oauth" in client_configs("https://u2.example.com", oauth=True)


@pytest.fixture
def bob_client(ctx: AdminContext) -> Iterator[TestClient]:
    finish_setup(ctx.store)
    ctx.store.add_local_user("bob", password_hash=hash_password(PASSWORD))
    with admin_client(ctx) as client:
        sign_in(client, username="bob")
        yield client


def _location(client: TestClient, path: str) -> str:
    return str(client.get(path, follow_redirects=False).headers["location"])


class TestPages:
    def test_a_non_admin_lands_on_my_access(self, bob_client: TestClient) -> None:
        assert _location(bob_client, "/admin/") == "/admin/me"
        assert _location(bob_client, "/admin/connections") == "/admin/me"
        page = bob_client.get("/admin/me")
        assert page.status_code == 200 and "My access" in page.text

    def test_a_non_admin_post_to_an_admin_page_is_refused(self, bob_client: TestClient) -> None:
        token = csrf_from(bob_client.get("/admin/me").text)

        response = bob_client.post("/admin/connections/new", data={"csrf_token": token})

        assert response.status_code == 403
        assert "Only admins can use this page." in response.text

    def test_my_connections_show_role_and_permissions(
        self, bob_client: TestClient, ctx: AdminContext
    ) -> None:
        connection = ctx.store.add_connection(
            name="Prod", host="h", port=1, service="uvcs", account="A",
            shared_user="s", shared_password="p",
        )
        bob = ctx.store.get_user_by_username("bob")
        viewer = ctx.store.get_role_by_name("Viewer")
        assert bob is not None and viewer is not None
        ctx.store.add_grant(
            connection_id=connection.id, subject_type="user", subject_id=bob.id,
            role_id=viewer.id,
        )

        page = bob_client.get("/admin/me").text

        assert "Prod" in page and "Viewer" in page and "records.read" in page

    def test_a_new_token_is_shown_exactly_once(
        self, bob_client: TestClient, ctx: AdminContext
    ) -> None:
        token = csrf_from(bob_client.get("/admin/me").text)
        created = bob_client.post(
            "/admin/me/tokens",
            data={"csrf_token": token, "name": "laptop", "days": "90"},
            follow_redirects=False,
        )
        location = created.headers["location"]
        assert location.startswith("/admin/me?notice=token_created&reveal=")

        first = bob_client.get(location).text
        shown = re.search(r'<pre id="new-token">(u2pat_[^<]+)</pre>', first)
        assert shown and "It is shown only once." in first
        assert ctx.store.get_token_by_hash(hash_token(shown.group(1))) is not None
        assert "u2pat_" not in bob_client.get(location).text

    def test_revoking_my_token(self, bob_client: TestClient, ctx: AdminContext) -> None:
        bob = ctx.store.get_user_by_username("bob")
        assert bob is not None
        _value, record = create_personal_token(ctx, bob, name="old", days="5")
        token = csrf_from(bob_client.get("/admin/me").text)

        response = bob_client.post(
            f"/admin/me/tokens/{record.id}/revoke",
            data={"csrf_token": token},
            follow_redirects=False,
        )

        assert response.headers["location"] == "/admin/me?notice=revoked"
        stored = ctx.store.get_token(record.id)
        assert stored is not None and stored.revoked_at is not None
        assert "Revoked" in bob_client.get("/admin/me").text


def test_the_wizard_sends_a_forced_password_change_first(ctx: AdminContext) -> None:
    """Review M-1: the wizard's own guard honours must_change_password."""
    root = ctx.store.add_local_user("root", password_hash=hash_password(PASSWORD), is_admin=True)
    mark_step_done(ctx.store, "admin")
    with admin_client(ctx) as client:
        sign_in(client, username="root")
        ctx.store.set_password_hash(root.id, hash_password(PASSWORD), must_change=True)

        location = _location(client, "/admin/setup/connection")

    assert location == "/admin/account/password"


def test_the_done_page_no_longer_says_grants_are_coming(ctx: AdminContext) -> None:
    ctx.store.add_local_user("root", password_hash=hash_password(PASSWORD), is_admin=True)
    for step in ("admin", "connection", "server_address"):
        mark_step_done(ctx.store, step)
    with admin_client(ctx) as client:
        sign_in(client, username="root")
        page = client.get("/admin/setup/done").text

    assert "next version" not in page
    assert "add one under Access" in page
```

In `tests/test_admin/test_routes_auth.py`, replace `test_a_non_admin_sees_the_refusal` with:

```python
    def test_a_non_admin_goes_to_my_access(self, ctx: AdminContext, client: TestClient) -> None:
        ctx.store.add_local_user("bob", password_hash=hash_password(PASSWORD))
        sign_in(client, username="bob")

        response = client.get("/admin/", follow_redirects=False)

        assert response.headers["location"] == "/admin/me"
```

Run: `pytest tests/test_admin/test_me.py tests/test_admin/test_routes_auth.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'u2_mcp.admin.reveal'`.

- [ ] **Step 2: Add `get_token`, `reveal.py` and the token services**

In `src/u2_mcp/store/repo.py`, after `get_token_by_hash`:

```python
    def get_token(self, token_id: int) -> TokenRecord | None:
        """Return a token record by id, or None."""
        row = self._one("SELECT * FROM tokens WHERE id = ?", (token_id,))
        return self._token(row) if row else None
```

Create `src/u2_mcp/admin/reveal.py`:

```python
"""Show a newly created token exactly once, across a POST-redirect-GET.

The token is held in memory only, for a few minutes, keyed by the session
that created it. The redirected page takes it out; a refresh finds nothing.
"""

from __future__ import annotations

import hmac
import secrets
import threading
import time
from collections.abc import Callable


class OneTimeReveal:
    """A short-lived, take-once store of values, each tied to one owner.

    Args:
        ttl_seconds: How long a value waits to be taken
        clock: Monotonic time source, replaceable in tests
    """

    def __init__(
        self, *, ttl_seconds: float = 300.0, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._ttl = ttl_seconds
        self._clock = clock
        self._items: dict[str, tuple[str, str, float]] = {}
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        for key in [k for k, (_o, _v, expires) in self._items.items() if expires <= now]:
            del self._items[key]

    def put(self, owner: str, value: str) -> str:
        """Hold a value for its owner and return the id that takes it."""
        reveal_id = secrets.token_urlsafe(16)
        with self._lock:
            now = self._clock()
            self._prune(now)
            self._items[reveal_id] = (owner, value, now + self._ttl)
        return reveal_id

    def take(self, owner: str, reveal_id: str) -> str | None:
        """Return the value once, to its owner only; None otherwise."""
        with self._lock:
            self._prune(self._clock())
            item = self._items.get(reveal_id)
            if item is None or not hmac.compare_digest(item[0], owner):
                return None
            del self._items[reveal_id]
            return item[1]
```

In `src/u2_mcp/admin/services.py`:
- Add `import json`.
- Add `from ..tokens import DEFAULT_LIFETIME_DAYS, create_token, revoke`.
- Change the models import to `Connection, Grant, Role, TokenRecord, User`.
- Append:

```python
TOKEN_MAX_LIFETIME_SETTING = "token_max_lifetime_days"


@dataclass(frozen=True)
class TokenView:
    """A token as a page lists it."""

    record: TokenRecord
    status: str  # "Active", "Expired" or "Revoked"


def token_max_lifetime(ctx: AdminContext) -> int | None:
    """The admin's cap on token lifetime in days, or None for no cap."""
    value = ctx.store.get_setting(TOKEN_MAX_LIFETIME_SETTING)
    return int(value) if value else None


def default_token_days(ctx: AdminContext) -> int:
    """The lifetime the create form suggests: 90 days, or the cap if lower."""
    cap = token_max_lifetime(ctx)
    return min(DEFAULT_LIFETIME_DAYS, cap) if cap else DEFAULT_LIFETIME_DAYS


def token_views(ctx: AdminContext, user_id: int) -> list[TokenView]:
    """A user's tokens, newest first, with their status now."""
    now = ctx.store.clock()
    views = []
    for record in ctx.store.list_tokens(user_id):
        if record.revoked_at is not None:
            status = "Revoked"
        elif now >= record.expires_at:
            status = "Expired"
        else:
            status = "Active"
        views.append(TokenView(record, status))
    return views


def create_personal_token(
    ctx: AdminContext, user: User, *, name: str, days: str
) -> tuple[str, TokenRecord]:
    """Create a token for the signed-in user. The token itself is returned once.

    Raises:
        Refused: token_name or token_days
    """
    name = name.strip()
    if not name or len(name) > 64:
        raise Refused("token_name")
    if not (days.isascii() and days.isdecimal()):
        raise Refused("token_days")
    try:
        token, record = create_token(
            ctx.store,
            user.id,
            name,
            lifetime_days=int(days),
            max_lifetime_days=token_max_lifetime(ctx),
        )
    except ValueError as exc:
        raise Refused("token_days") from exc
    # Key names containing "token" are redacted by the audit table, so use plain ones.
    _audit(ctx, user, "token.create", params={"id": record.id, "label": name, "days": int(days)})
    return token, record


def revoke_personal_token(
    ctx: AdminContext, token_id: int, *, owner_id: int, actor: User
) -> None:
    """Revoke one of owner_id's tokens.

    My access passes the signed-in user as owner, so nobody revokes another
    person's token there. The Users page passes the user being viewed.

    Raises:
        Refused: gone, when the token is missing or not owner_id's
    """
    record = ctx.store.get_token(token_id)
    if record is None or record.user_id != owner_id:
        raise Refused("gone")
    revoke(ctx.store, token_id)
    _audit(ctx, actor, "token.revoke", params={"id": token_id, "owner_id": owner_id})


def client_configs(public_url: str, *, oauth: bool) -> dict[str, str]:
    """Copy-ready MCP client configuration for this server.

    VS Code prompts for the token through an input marked password, so it is
    never written into .vscode/mcp.json. The OAuth variant exists only when
    company sign-in is configured.
    """
    url = public_url.rstrip("/") + "/"
    placeholder = "Bearer <paste your token>"
    configs: dict[str, object] = {}
    if oauth:
        configs["vscode_oauth"] = {"servers": {"u2": {"type": "http", "url": url}}}
    configs["vscode_token"] = {
        "inputs": [
            {
                "type": "promptString",
                "id": "u2-mcp-token",
                "description": "u2-mcp personal access token",
                "password": True,
            }
        ],
        "servers": {
            "u2": {
                "type": "http",
                "url": url,
                "headers": {"Authorization": "Bearer ${input:u2-mcp-token}"},
            }
        },
    }
    configs["visual_studio"] = {
        "servers": {"u2": {"type": "http", "url": url, "headers": {"Authorization": placeholder}}}
    }
    configs["jetbrains"] = {
        "servers": {"u2": {"url": url, "requestInit": {"headers": {"Authorization": placeholder}}}}
    }
    return {key: json.dumps(value, indent=2) for key, value in configs.items()}
```

- [ ] **Step 3: Add the My access routes and page**

Create `src/u2_mcp/admin/routes_me.py`:

```python
"""My access: every signed-in person's connections, tokens and editor setup."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from ..access import visible_connections
from .problems import Refused, with_query
from .reveal import OneTimeReveal
from .security import read_form, signed_in
from .services import (
    client_configs,
    create_personal_token,
    default_token_days,
    effective_public_url,
    revoke_personal_token,
    token_max_lifetime,
    token_views,
)
from .templating import admin_context, render

_reveals = OneTimeReveal()


def _back(code: str) -> RedirectResponse:
    return RedirectResponse(with_query("/admin/me", problem=code), status_code=303)


@signed_in
async def my_access(request: Request) -> Response:
    """The signed-in person's connections, tokens and client configuration."""
    ctx = admin_context(request)
    user = request.state.user
    new_token = None
    reveal_id = request.query_params.get("reveal")
    if reveal_id and request.state.session is not None:
        new_token = _reveals.take(request.state.session.id_hash, reveal_id)
    public_url = effective_public_url(ctx)
    return render(
        request,
        "me.html",
        connections=visible_connections(ctx.store, user.id, global_read_only=ctx.config.read_only),
        tokens=token_views(ctx, user.id),
        new_token=new_token,
        configs=client_configs(public_url, oauth=ctx.config.auth_enabled),
        max_days=token_max_lifetime(ctx),
        default_days=default_token_days(ctx),
    )


@signed_in
async def create(request: Request) -> Response:
    """Create a token and send the browser to see it once."""
    ctx = admin_context(request)
    data = await read_form(request)
    try:
        token, _record = create_personal_token(
            ctx,
            request.state.user,
            name=str(data.get("name", "")),
            days=str(data.get("days", "")).strip(),
        )
    except Refused as refused:
        return _back(refused.code)
    reveal_id = _reveals.put(request.state.session.id_hash, token)
    return RedirectResponse(
        with_query("/admin/me", notice="token_created", reveal=reveal_id), status_code=303
    )


@signed_in
async def revoke(request: Request) -> Response:
    """Revoke one of the signed-in person's own tokens."""
    await read_form(request)
    user = request.state.user
    try:
        revoke_personal_token(
            admin_context(request), request.path_params["id"], owner_id=user.id, actor=user
        )
    except Refused as refused:
        return _back(refused.code)
    return RedirectResponse("/admin/me?notice=revoked", status_code=303)


routes = [
    Route("/me", my_access, methods=["GET"]),
    Route("/me/tokens", create, methods=["POST"]),
    Route("/me/tokens/{id:int}/revoke", revoke, methods=["POST"]),
]
```

In `app.py`, import `routes_me` and add `*routes_me.routes,`.

Create `src/u2_mcp/admin/templates/me.html`:

```html
{% extends "base.html" %}
{% block title %}My access · u2-mcp admin{% endblock %}
{% block content %}
<h1>My access</h1>
<h2>My connections</h2>
{% if connections %}
<table>
  <thead><tr><th>Connection</th><th>Role</th><th>What you can do now</th></tr></thead>
  <tbody>
  {% for v in connections %}
    <tr><td>{{ v.connection.name }}{% if v.connection.read_only %} (read-only){% endif %}</td>
        <td>{{ v.roles | join(", ") }}</td>
        <td>{{ v.permissions | sort | join(", ") }}</td></tr>
  {% endfor %}
  </tbody>
</table>
{% else %}
<p>You can't use any connection yet. Ask an admin to give you a grant.</p>
{% endif %}

<h2>My tokens</h2>
{% if new_token %}
<div class="notice" role="status">
  <p>Copy this token now. It is shown only once.</p>
  <pre id="new-token">{{ new_token }}</pre>
</div>
{% endif %}
{% if tokens %}
<table>
  <thead><tr><th>Name</th><th>Created</th><th>Expires</th><th>Last used</th><th>Status</th><th></th></tr></thead>
  <tbody>
  {% for t in tokens %}
    <tr><td>{{ t.record.name }}</td><td>{{ t.record.created_at | when }}</td>
        <td>{{ t.record.expires_at | when }}</td>
        <td>{{ t.record.last_used_at | when }}{% if t.record.last_used_ip %} from {{ t.record.last_used_ip }}{% endif %}</td>
        <td>{{ t.status }}</td>
        <td>{% if t.status == "Active" %}
          <form method="post" action="/admin/me/tokens/{{ t.record.id }}/revoke" class="inline">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <button type="submit" class="danger">Revoke {{ t.record.name }}</button>
          </form>{% endif %}</td></tr>
  {% endfor %}
  </tbody>
</table>
{% endif %}
<form method="post" action="/admin/me/tokens">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <div class="field"><label for="t-name">Token name</label>
    <input id="t-name" type="text" name="name" maxlength="64" required placeholder="work laptop"></div>
  <div class="field"><label for="t-days">Lifetime in days</label>
    <input id="t-days" type="number" name="days" min="1" {% if max_days %}max="{{ max_days }}"{% endif %} value="{{ default_days }}">
    {% if max_days %}<p class="hint">At most {{ max_days }} days on this server.</p>{% endif %}</div>
  <div class="actions"><button type="submit">Create token</button></div>
</form>

<h2>Connect your editor</h2>
{% if configs.vscode_oauth %}
<h3>VS Code, signing in with your company account</h3>
<p>Add this to <code>.vscode/mcp.json</code> or your user MCP configuration:</p>
<pre>{{ configs.vscode_oauth }}</pre>
{% else %}
<p class="hint">Browser sign-in from VS Code arrives with company sign-in (SSO). Until then, use a token.</p>
{% endif %}
<h3>VS Code, with a token</h3>
<p>Add this to <code>.vscode/mcp.json</code>. VS Code asks for the token once and keeps it out of the file.</p>
<pre>{{ configs.vscode_token }}</pre>
<h3>Visual Studio</h3>
<p>Save as <code>.mcp.json</code> in your solution folder or in <code>%USERPROFILE%</code>, and paste your token:</p>
<pre>{{ configs.visual_studio }}</pre>
<h3>JetBrains IDEs</h3>
<p>From the GitHub Copilot status bar icon, open Edit Settings, Model Context Protocol, Configure, and add:</p>
<pre>{{ configs.jetbrains }}</pre>
{% endblock %}
```

- [ ] **Step 4: Landing, nav, notices, the M-1 guard and the Done page**

In `src/u2_mcp/admin/security.py`, replace the inner `if not request.state.user.is_admin:` block of `admin_only` with:

```python
        if not request.state.user.is_admin:
            if request.method == "GET":
                return RedirectResponse("/admin/me", status_code=303)
            from .templating import render

            return render(
                request,
                "message.html",
                status_code=403,
                title="Not available",
                message="Only admins can use this page.",
            )
```

In `src/u2_mcp/admin/routes_setup.py`, import `signed_in` from `.security` and replace `_home` with:

```python
@signed_in
async def _home(request: Request) -> Response:
    if not request.state.user.is_admin:
        return _redirect("/admin/me")
    return _redirect("/admin/connections")
```

In `_guard`, replace the final `return None` with:

```python
    if user is not None and user.must_change_password:
        # Review M-1: a one-time password from reset-password must be changed first.
        return _redirect("/admin/account/password")
    return None
```

In `templating.py`:
- Add `from datetime import datetime, timezone`.
- Add these entries to `NOTICES`: `"revoked": "Token revoked."` and `"token_created": "Token created."`.
- Add:

```python
def when(value: float | None) -> str:
    """Format a stored timestamp for a page: YYYY-MM-DD HH:MM UTC, or blank."""
    if value is None:
        return ""
    return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
```

Then change `_environment()` to:

```python
@lru_cache(maxsize=1)
def _environment() -> Environment:
    env = Environment(
        loader=PackageLoader("u2_mcp.admin", "templates"),
        autoescape=select_autoescape(["html"], default_for_string=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["when"] = when
    return env
```

In `base.html`, replace the `<nav>` block with:

```html
    {% if user and setup_complete %}
    <nav>
      {% if user.is_admin %}
      <a href="/admin/connections">Connections</a>
      <a href="/admin/settings">Settings</a>
      {% endif %}
      <a href="/admin/me">My access</a>
    </nav>
    {% endif %}
```

In `templates/setup/done.html`, replace the `<p class="warning">Nobody can use…</p>` paragraph with:

```html
<p class="warning">Nobody can use this connection from Copilot until it has a grant. After you finish, open the connection and add one under Access. Admins need a grant too: being an admin gives no data access. Each person then creates a personal access token on My access, which also shows the configuration for their editor. (A connection imported from U2_HOST at first start keeps the access it had before.)</p>
```

Run: `pytest tests/test_admin -v`
Expected: PASS.

- [ ] **Step 5: Run all checks**

Run the four Global Constraints commands, then `pytest -m e2e tests/e2e`.
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/u2_mcp tests/test_admin
git commit -m "feat(admin): My access with personal tokens; non-admins land there"
```

---

### Task 3: Browser test — wizard, grant, token, a real MCP tool call

**Files:**
- Create: `tests/e2e/test_copilot_journey.py`
- Modify: `tests/e2e/wizard.py` (two helpers)

**Interfaces:**
- **Consumes:** the grants editor labels (`Who`, `Person`, `Role`, `Add grant`, Task 1); My access (`Token name`, `Create token`, `#new-token`, `Revoke <name>`, Task 2); `Server.url` and `finish_wizard` (2a); `list_connections` returning `{"connections": [{"name": ...}]}` (`server.py`).
- **Produces:**
  - `wizard.grant_on(page, server, *, connection: str = "Prod", who: str = "A person", person: str | None = ADMIN_USER, role: str = "Viewer") -> None`
  - `wizard.create_token(page, server, name: str = "laptop") -> str`
  - `test_copilot_journey.call_tool(url: str, token: str, tool: str, arguments: dict[str, Any]) -> str`, which runs the MCP client in a worker thread so it never shares Playwright's event loop.

- [ ] **Step 1: Add the helpers to `tests/e2e/wizard.py`**

```python
def grant_on(
    page: Page,
    server: Server,
    *,
    connection: str = "Prod",
    who: str = "A person",
    person: str | None = ADMIN_USER,
    role: str = "Viewer",
) -> None:
    """Give a person (by default the admin) a role on a connection, from its page."""
    page.goto(server.url("/admin/connections"))
    page.get_by_role("link", name=connection, exact=True).click()
    page.get_by_label("Who").select_option(label=who)
    if person is not None:
        page.get_by_label("Person").select_option(label=person)
    page.get_by_label("Role", exact=True).select_option(label=role)
    page.get_by_role("button", name="Add grant").click()
    expect(page.locator(".notice")).to_have_text("Saved.")


def create_token(page: Page, server: Server, name: str = "laptop") -> str:
    """Create a personal access token on My access and return it."""
    page.goto(server.url("/admin/me"))
    page.get_by_label("Token name").fill(name)
    page.get_by_role("button", name="Create token").click()
    expect(page.locator("#new-token")).to_be_visible()
    return page.locator("#new-token").inner_text().strip()
```

- [ ] **Step 2: Write the browser test**

Create `tests/e2e/test_copilot_journey.py`:

```python
"""From an empty server to a Copilot-style tool call, the way an admin would do it."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import anyio
import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from playwright.sync_api import Page, expect

from .conftest import Server
from .wizard import create_token, finish_wizard, grant_on

pytestmark = pytest.mark.e2e


async def _call(url: str, token: str, tool: str, arguments: dict[str, Any]) -> str:
    http_client = httpx.AsyncClient(headers={"Authorization": f"Bearer {token}"})
    try:
        async with (
            streamable_http_client(url, http_client=http_client) as (read, write, _),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            result = await session.call_tool(tool, arguments)
    finally:
        await http_client.aclose()
    return "\n".join(getattr(block, "text", "") for block in result.content)


def call_tool(url: str, token: str, tool: str, arguments: dict[str, Any]) -> str:
    """Call an MCP tool as an editor would, off Playwright's event loop."""
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(anyio.run, _call, url, token, tool, arguments).result(timeout=60)


def test_wizard_grant_token_and_a_tool_call(page: Page, server: Server) -> None:
    finish_wizard(page, server)
    mcp_url = server.url("/")

    # Being an admin gives no data access: before a grant the token sees nothing.
    early = create_token(page, server, name="before-grant")
    assert json.loads(call_tool(mcp_url, early, "list_connections", {}))["connections"] == []

    grant_on(page, server)
    expect(page.get_by_role("cell", name="admin", exact=True)).to_be_visible()

    token = create_token(page, server)
    page.reload()
    expect(page.locator("#new-token")).to_have_count(0)  # shown once only

    listed = json.loads(call_tool(mcp_url, token, "list_connections", {}))
    assert [c["name"] for c in listed["connections"]] == ["Prod"]

    # No connection argument: the only connection this person can see is used.
    assert "CUSTOMERS" in call_tool(mcp_url, token, "list_files", {})

    page.get_by_role("button", name="Revoke laptop").click()
    expect(page.locator(".notice")).to_have_text("Token revoked.")
    refused = httpx.post(
        mcp_url,
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream",
        },
        timeout=10,
    )
    assert refused.status_code == 401
```

Run: `pytest -m e2e tests/e2e/test_copilot_journey.py -v`
Expected: PASS. A failure here is a product bug in Task 1 or 2: fix it there, not by weakening the test.

- [ ] **Step 3: Run all checks**

Run the four Global Constraints commands, then `pytest -m e2e tests/e2e`.
Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add tests/e2e
git commit -m "test(e2e): wizard, grant, token and a real MCP tool call"
```

---

### Task 4: Users, with tokens, grants and effective access

**Files:**
- Create: `src/u2_mcp/admin/routes_users.py`, `templates/users/list.html`, `templates/users/new.html`, `templates/users/detail.html`, `templates/users/access.html`
- Modify: `src/u2_mcp/store/repo.py` (`set_user_admin`, `set_user_disabled`), `src/u2_mcp/admin/services.py`, `src/u2_mcp/admin/app.py`, `templates/partials/local_user_form.html`, `templates/base.html` (nav)
- Test: `tests/test_store/test_repo_2b.py` (append), `tests/test_admin/test_users.py`, `tests/e2e/test_everyday_pages.py`

**Interfaces:**
- **Consumes:** `grant_editor` (Task 1); `token_views` and `revoke_personal_token` (Task 2); `create_local_user` (2a); `access.effective_access`.
- **Produces, Store:** `set_user_admin` and `set_user_disabled` raise `StoreError("That user no longer exists.")` for an unknown id (ledger, Task 3 of 2a).
- **Produces, services:**
  - `set_user_flags(ctx, user_id: int, *, is_admin: bool | None = None, disabled: bool | None = None, actor: User) -> User`, which raises `Refused("user_self" | "last_admin" | "gone")`
  - `user_groups(ctx, user_id: int) -> list[Group]`
- **Produces, routes:**
  - `GET /admin/users` (query `q`, `admin` = `yes`/`no`, `status` = `enabled`/`disabled`)
  - `GET`/`POST /admin/users/new`
  - `GET /admin/users/{id}`
  - `POST /admin/users/{id}/flags` (fields `is_admin` and `disabled`, each `on`/`off`)
  - `POST /admin/users/{id}/tokens/{token_id}/revoke`
  - `GET /admin/users/{id}/access`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_store/test_repo_2b.py`:

```python
class TestUserFlags:
    def test_flags_on_an_unknown_user_are_refused(self, store: Store) -> None:
        with pytest.raises(StoreError):
            store.set_user_admin(999, True)
        with pytest.raises(StoreError):
            store.set_user_disabled(999, True)

    def test_re_enabling_keeps_the_user_signed_out(self, store: Store) -> None:
        ann = store.add_local_user("ann")
        store.add_admin_session(id_hash="h", user_id=ann.id, csrf_token="c", ip=None)
        store.set_user_disabled(ann.id, True)
        store.set_user_disabled(ann.id, False)

        assert store.get_admin_session("h") is None
```

Create `tests/test_admin/test_users.py`:

```python
"""Users: list, create, flags, tokens, grants and effective access."""

from collections.abc import Iterator

import pytest
from starlette.testclient import TestClient

from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.problems import Refused
from u2_mcp.admin.services import create_personal_token, set_user_flags
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import finish_setup
from u2_mcp.store.models import User

from .helpers import PASSWORD, admin_client, csrf_from, sign_in


class TestFlags:
    def test_you_cannot_demote_or_disable_yourself(self, ctx: AdminContext, admin: User) -> None:
        for change in ({"is_admin": False}, {"disabled": True}):
            with pytest.raises(Refused) as refused:
                set_user_flags(ctx, admin.id, actor=admin, **change)  # type: ignore[arg-type]
            assert refused.value.code == "user_self"

    def test_the_last_enabled_local_admin_stays(self, ctx: AdminContext, admin: User) -> None:
        sso_admin = ctx.store.get_or_create_sso_user("sub-1")
        ctx.store.set_user_admin(sso_admin.id, True)
        acting = ctx.store.get_user(sso_admin.id)
        assert acting is not None

        with pytest.raises(Refused) as refused:
            set_user_flags(ctx, admin.id, disabled=True, actor=acting)

        assert refused.value.code == "last_admin"

    def test_disabling_ends_sessions_and_is_audited(self, ctx: AdminContext, admin: User) -> None:
        bob = ctx.store.add_local_user("bob")
        ctx.store.add_admin_session(id_hash="b", user_id=bob.id, csrf_token="c", ip=None)

        set_user_flags(ctx, bob.id, disabled=True, actor=admin)

        assert ctx.store.get_admin_session("b") is None
        entry = ctx.store.recent_audit(1)[0]
        assert entry["action"] == "user.flags" and entry["params"] == {
            "user_id": bob.id, "disabled": True,
        }


@pytest.fixture
def client(ctx: AdminContext) -> Iterator[TestClient]:
    finish_setup(ctx.store)
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    with admin_client(ctx) as test_client:
        sign_in(test_client)
        yield test_client


class TestPages:
    def test_the_list_filters_and_escapes(self, client: TestClient, ctx: AdminContext) -> None:
        ctx.store.add_local_user("bob", display_name="<b>Bob</b>")
        ctx.store.add_local_user("cy")

        page = client.get("/admin/users?q=bob").text

        assert "&lt;b&gt;Bob&lt;/b&gt;" in page and "<b>Bob</b>" not in page
        assert ">cy<" not in page
        assert "&lt;b&gt;Bob" not in client.get("/admin/users?admin=yes").text

    def test_creating_a_local_user(self, client: TestClient, ctx: AdminContext) -> None:
        token = csrf_from(client.get("/admin/users/new").text)
        response = client.post(
            "/admin/users/new",
            data={"csrf_token": token, "username": "dee", "password": "long enough pass",
                  "password_again": "long enough pass"},
            follow_redirects=False,
        )

        dee = ctx.store.get_user_by_username("dee")
        assert dee is not None and not dee.is_admin
        assert response.headers["location"] == f"/admin/users/{dee.id}?notice=saved"

    def test_problems_stay_on_the_form(self, client: TestClient) -> None:
        token = csrf_from(client.get("/admin/users/new").text)
        response = client.post(
            "/admin/users/new",
            data={"csrf_token": token, "username": "dee", "password": "short",
                  "password_again": "short"},
        )

        assert response.status_code == 400 and "Use at least 12 characters." in response.text

    def test_an_admin_revokes_someone_elses_token(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        bob = ctx.store.add_local_user("bob")
        _value, record = create_personal_token(ctx, bob, name="bobs-laptop", days="9")
        page = client.get(f"/admin/users/{bob.id}").text
        assert "bobs-laptop" in page

        client.post(f"/admin/users/{bob.id}/tokens/{record.id}/revoke",
                    data={"csrf_token": csrf_from(page)})

        stored = ctx.store.get_token(record.id)
        assert stored is not None and stored.revoked_at is not None

    def test_effective_access_names_each_source(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        connection = ctx.store.add_connection(
            name="Prod", host="h", port=1, service="uvcs", account="A",
            shared_user="s", shared_password="p",
        )
        sso = ctx.store.get_or_create_sso_user("sub-9", display_name="Sue")
        ctx.store.record_sso_login(sso.id, ["eng"])
        group = ctx.store.list_groups()[0]
        viewer = ctx.store.get_role_by_name("Viewer")
        analyst = ctx.store.get_role_by_name("Analyst")
        assert viewer is not None and analyst is not None
        ctx.store.add_grant(connection_id=connection.id, subject_type="user",
                            subject_id=sso.id, role_id=viewer.id)
        ctx.store.add_grant(connection_id=connection.id, subject_type="group",
                            subject_id=group.id, role_id=analyst.id)

        page = client.get(f"/admin/users/{sso.id}/access").text

        assert "user grant (Viewer)" in page and "group eng (Analyst)" in page
        assert "query.run" in page
        assert "Add grant" in client.get(f"/admin/users/{sso.id}").text
```

Run: `pytest tests/test_store/test_repo_2b.py tests/test_admin/test_users.py -v`
Expected: FAIL (`set_user_admin` does not raise; `set_user_flags` cannot be imported).

- [ ] **Step 2: Store and services**

In `src/u2_mcp/store/repo.py`, replace `set_user_admin` and `set_user_disabled` with:

```python
    def set_user_admin(self, user_id: int, is_admin: bool) -> None:
        """Grant or remove admin-site access. This never grants data access.

        Raises:
            StoreError: If the user does not exist
        """
        with self._tx() as conn:
            cursor = conn.execute(
                "UPDATE users SET is_admin = ? WHERE id = ?", (int(is_admin), user_id)
            )
            if cursor.rowcount == 0:
                raise StoreError("That user no longer exists.")

    def set_user_disabled(self, user_id: int, disabled: bool) -> None:
        """Disable or re-enable a user. Disabling ends their admin-site sessions.

        Raises:
            StoreError: If the user does not exist
        """
        with self._tx() as conn:
            cursor = conn.execute(
                "UPDATE users SET disabled = ? WHERE id = ?", (int(disabled), user_id)
            )
            if cursor.rowcount == 0:
                raise StoreError("That user no longer exists.")
            if disabled:
                conn.execute("DELETE FROM admin_sessions WHERE user_id = ?", (user_id,))
```

In `src/u2_mcp/admin/services.py`, add `Group` to the models import and append:

```python
def set_user_flags(
    ctx: AdminContext,
    user_id: int,
    *,
    is_admin: bool | None = None,
    disabled: bool | None = None,
    actor: User,
) -> User:
    """Turn a user's admin flag or disabled flag on or off.

    Nobody demotes or disables themselves, and the last enabled local admin
    stays: it is the way back in when company sign-in fails.

    Raises:
        Refused: user_self, last_admin or gone
    """
    target = ctx.store.get_user(user_id)
    if target is None:
        raise Refused("gone")
    loses_admin = is_admin is False or disabled is True
    if user_id == actor.id and loses_admin:
        raise Refused("user_self")
    if loses_admin and target.kind == "local" and target.is_admin and not target.disabled:
        others = [
            u
            for u in ctx.store.list_users(is_admin=True, disabled=False)
            if u.kind == "local" and u.id != user_id
        ]
        if not others:
            raise Refused("last_admin")
    try:
        if is_admin is not None:
            ctx.store.set_user_admin(user_id, is_admin)
        if disabled is not None:
            ctx.store.set_user_disabled(user_id, disabled)
    except StoreError as exc:
        raise Refused("gone") from exc
    params: dict[str, Any] = {"user_id": user_id}
    params.update({k: v for k, v in (("is_admin", is_admin), ("disabled", disabled)) if v is not None})
    _audit(ctx, actor, "user.flags", params=params)
    updated = ctx.store.get_user(user_id)
    if updated is None:
        raise Refused("gone")
    return updated


def user_groups(ctx: AdminContext, user_id: int) -> list[Group]:
    """The groups recorded at a user's last SSO sign-in."""
    mine = set(ctx.store.group_ids_for_user(user_id))
    return [group for group in ctx.store.list_groups() if group.id in mine]
```

- [ ] **Step 3: Routes and templates**

Create `src/u2_mcp/admin/routes_users.py`:

```python
"""Users: list with filters, create a local user, flags, tokens, grants, effective access."""

from __future__ import annotations

from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from ..access import effective_access
from ..store.models import User
from .problems import Refused, with_query
from .routes_grants import grant_editor
from .security import admin_only, read_form
from .services import (
    ValidationFailed,
    create_local_user,
    revoke_personal_token,
    set_user_flags,
    token_views,
    user_groups,
)
from .templating import admin_context, render

_YES_NO = {"yes": True, "no": False}
_STATUS = {"disabled": True, "enabled": False}


def _user_or_404(request: Request) -> User:
    user = admin_context(request).store.get_user(request.path_params["id"])
    if user is None:
        raise HTTPException(404, "There is no such user.")
    return user


@admin_only
async def list_users(request: Request) -> Response:
    """Every user, filtered by text, admin flag and status."""
    query = request.query_params
    users = admin_context(request).store.list_users(
        search=query.get("q", "").strip(),
        is_admin=_YES_NO.get(query.get("admin", "")),
        disabled=_STATUS.get(query.get("status", "")),
    )
    return render(request, "users/list.html", users=users, filters=dict(query))


def _new_page(request: Request, values: dict[str, str], errors: dict[str, str], status: int
              ) -> Response:
    return render(request, "users/new.html", status_code=status, values=values, errors=errors,
                  action_url="/admin/users/new", submit_label="Create user",
                  show_setup_code=False, show_admin_flag=True)


@admin_only
async def new_user_form(request: Request) -> Response:
    """An empty new-user form."""
    return _new_page(request, {}, {}, 200)


@admin_only
async def new_user(request: Request) -> Response:
    """Create a local user."""
    data = await read_form(request)
    values = {key: str(value) for key, value in data.items() if "password" not in key}
    try:
        user = create_local_user(
            admin_context(request),
            username=str(data.get("username", "")),
            password=str(data.get("password", "")),
            password_again=str(data.get("password_again", "")),
            display_name=str(data.get("display_name", "")),
            is_admin=data.get("is_admin") == "on",
            actor=request.state.user,
        )
    except ValidationFailed as failed:
        return _new_page(request, values, failed.errors, 400)
    return RedirectResponse(f"/admin/users/{user.id}?notice=saved", status_code=303)


@admin_only
async def user_detail(request: Request) -> Response:
    """One user's flags, groups, tokens and grants."""
    ctx = admin_context(request)
    user = _user_or_404(request)
    return render(
        request,
        "users/detail.html",
        person=user,
        groups=user_groups(ctx, user.id),
        tokens=token_views(ctx, user.id),
        **grant_editor(ctx, return_to=f"/admin/users/{user.id}", subject_type="user",
                       subject_id=user.id),
    )


@admin_only
async def flags(request: Request) -> Response:
    """Turn admin or disabled on or off."""
    user = _user_or_404(request)
    data = await read_form(request)

    def flag(name: str) -> bool | None:
        return {"on": True, "off": False}.get(str(data.get(name)))

    target = f"/admin/users/{user.id}"
    try:
        set_user_flags(admin_context(request), user.id, is_admin=flag("is_admin"),
                       disabled=flag("disabled"), actor=request.state.user)
    except Refused as refused:
        return RedirectResponse(with_query(target, problem=refused.code), status_code=303)
    return RedirectResponse(with_query(target, notice="saved"), status_code=303)


@admin_only
async def revoke_token(request: Request) -> Response:
    """Revoke one of this user's tokens."""
    user = _user_or_404(request)
    await read_form(request)
    target = f"/admin/users/{user.id}"
    try:
        revoke_personal_token(admin_context(request), request.path_params["token_id"],
                              owner_id=user.id, actor=request.state.user)
    except Refused as refused:
        return RedirectResponse(with_query(target, problem=refused.code), status_code=303)
    return RedirectResponse(with_query(target, notice="revoked"), status_code=303)


@admin_only
async def access(request: Request) -> Response:
    """For every connection: each permission and the grant or group that gives it."""
    ctx = admin_context(request)
    user = _user_or_404(request)
    report = effective_access(ctx.store, user.id, global_read_only=ctx.config.read_only)
    return render(request, "users/access.html", person=user, report=report,
                  groups=user_groups(ctx, user.id))


routes = [
    Route("/users", list_users, methods=["GET"]),
    Route("/users/new", new_user_form, methods=["GET"]),
    Route("/users/new", new_user, methods=["POST"]),
    Route("/users/{id:int}", user_detail, methods=["GET"]),
    Route("/users/{id:int}/flags", flags, methods=["POST"]),
    Route("/users/{id:int}/tokens/{token_id:int}/revoke", revoke_token, methods=["POST"]),
    Route("/users/{id:int}/access", access, methods=["GET"]),
]
```

In `app.py`, import `routes_users` and add `*routes_users.routes,`. In `base.html`'s admin links, add `<a href="/admin/users">Users</a>` after Connections.

The template context uses `person`, not `user`, because `user` is always the signed-in user.

In `templates/partials/local_user_form.html`, change the import to `{% from "partials/fields.html" import text, checkbox %}` and add this line before the actions `<div>`:

```html
  {% if show_admin_flag %}{{ checkbox("is_admin", "Admin: can use this admin site (gives no data access)", values.get("is_admin") == "on") }}{% endif %}
```

Create `templates/users/list.html`:

```html
{% extends "base.html" %}
{% block title %}Users · u2-mcp admin{% endblock %}
{% block content %}
<h1>Users</h1>
<p><a class="button" href="/admin/users/new">Create a local user</a></p>
<form method="get" action="/admin/users" class="actions"
      hx-get="/admin/users" hx-target="#users" hx-select="#users" hx-swap="outerHTML"
      hx-trigger="input changed delay:300ms from:#f-q, change">
  <label for="f-q">Search</label>
  <input id="f-q" type="text" name="q" value="{{ filters.get('q', '') }}">
  <label for="f-admin">Admin</label>
  <select id="f-admin" name="admin">
    {% for v, l in [("", "Any"), ("yes", "Admins"), ("no", "Not admins")] %}<option value="{{ v }}" {% if filters.get('admin', '') == v %}selected{% endif %}>{{ l }}</option>{% endfor %}
  </select>
  <label for="f-status">Status</label>
  <select id="f-status" name="status">
    {% for v, l in [("", "Any"), ("enabled", "Enabled"), ("disabled", "Disabled")] %}<option value="{{ v }}" {% if filters.get('status', '') == v %}selected{% endif %}>{{ l }}</option>{% endfor %}
  </select>
  <button type="submit" class="secondary">Filter</button>
</form>
<div id="users">
{% if users %}
<table>
  <thead><tr><th>Name</th><th>Sign-in</th><th>Admin</th><th>Status</th><th>Last SSO sign-in</th></tr></thead>
  <tbody>
  {% for u in users %}
  <tr><td><a href="/admin/users/{{ u.id }}">{{ u.label }}</a></td>
      <td>{{ "Local" if u.kind == "local" else "Company (SSO)" }}</td>
      <td>{{ "Admin" if u.is_admin else "" }}</td>
      <td>{{ "Disabled" if u.disabled else "Enabled" }}{% if u.groups_unavailable %} (groups unavailable){% endif %}</td>
      <td>{{ u.last_sso_login_at | when }}</td></tr>
  {% endfor %}
  </tbody>
</table>
{% else %}<p>No users match.</p>{% endif %}
</div>
{% endblock %}
```

Create `templates/users/new.html`:

```html
{% extends "base.html" %}
{% block title %}Create a local user · u2-mcp admin{% endblock %}
{% block content %}
<p><a href="/admin/users">All users</a></p>
<h1>Create a local user</h1>
{% include "partials/local_user_form.html" %}
{% endblock %}
```

Create `templates/users/detail.html`:

```html
{% extends "base.html" %}
{% block title %}{{ person.label }} · u2-mcp admin{% endblock %}
{% block content %}
<p><a href="/admin/users">All users</a></p>
<h1>{{ person.label }}</h1>
<table><tbody>
  <tr><th>Sign-in</th><td>{{ "Local: " ~ person.username if person.kind == "local" else "Company (SSO): " ~ person.sso_subject }}</td></tr>
  <tr><th>Email</th><td>{{ person.email or "" }}</td></tr>
  <tr><th>Groups</th><td>{% if person.groups_unavailable %}<span class="warning">Groups unavailable at the last sign-in: group grants do not apply until a sign-in carries them.</span>{% else %}{{ groups | map(attribute="external_id") | join(", ") }}{% endif %}</td></tr>
</tbody></table>
<form method="post" action="/admin/users/{{ person.id }}/flags" class="actions">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  {% if person.is_admin %}<button type="submit" name="is_admin" value="off" class="secondary">Remove admin</button>
  {% else %}<button type="submit" name="is_admin" value="on" class="secondary">Make admin</button>{% endif %}
  {% if person.disabled %}<button type="submit" name="disabled" value="off" class="secondary">Enable</button>
  {% else %}<button type="submit" name="disabled" value="on" class="danger">Disable</button>{% endif %}
</form>
<p><a href="/admin/users/{{ person.id }}/access">Effective access</a></p>
<h2>Tokens</h2>
{% if tokens %}
<table>
  <thead><tr><th>Name</th><th>Expires</th><th>Last used</th><th>Status</th><th></th></tr></thead>
  <tbody>
  {% for t in tokens %}
  <tr><td>{{ t.record.name }}</td><td>{{ t.record.expires_at | when }}</td>
      <td>{{ t.record.last_used_at | when }}</td><td>{{ t.status }}</td>
      <td>{% if t.status == "Active" %}<form method="post" action="/admin/users/{{ person.id }}/tokens/{{ t.record.id }}/revoke" class="inline">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <button type="submit" class="danger">Revoke {{ t.record.name }}</button></form>{% endif %}</td></tr>
  {% endfor %}
  </tbody>
</table>
{% else %}<p>No tokens.</p>{% endif %}
{% include "partials/grants_editor.html" %}
{% endblock %}
```

Create `templates/users/access.html`:

```html
{% extends "base.html" %}
{% block title %}Effective access: {{ person.label }} · u2-mcp admin{% endblock %}
{% block content %}
<p><a href="/admin/users/{{ person.id }}">{{ person.label }}</a></p>
<h1>Effective access: {{ person.label }}</h1>
{% if person.disabled %}<p class="warning">This user is disabled and can use nothing.</p>{% endif %}
{% if person.groups_unavailable %}<p class="warning">Groups were unavailable at the last sign-in, so group grants do not apply.</p>{% endif %}
{% for entry in report %}
<h2>{{ entry.connection.name }}</h2>
<table>
  <thead><tr><th>Permission</th><th>Given by</th></tr></thead>
  <tbody>
  {% for permission, origins in entry.sources.items() %}
  <tr><td>{{ permission }}{% if permission in entry.blocked_by_read_only %} (blocked: read-only){% endif %}</td>
      <td>{{ origins | join("; ") }}</td></tr>
  {% endfor %}
  </tbody>
</table>
{% else %}
<p>No access to any connection.</p>
{% endfor %}
{% endblock %}
```

Run: `pytest tests/test_store/test_repo_2b.py tests/test_admin/test_users.py tests/test_admin/test_route_table.py -v`
Expected: PASS.

- [ ] **Step 4: Browser test for Users**

Create `tests/e2e/test_everyday_pages.py`:

```python
"""The everyday admin pages' main paths in a real browser."""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import Page, expect

from .conftest import Server
from .wizard import finish_wizard

pytestmark = pytest.mark.e2e


def test_users_create_grant_and_effective_access(page: Page, server: Server) -> None:
    finish_wizard(page, server)
    page.get_by_role("link", name="Users").click()
    page.get_by_role("link", name="Create a local user").click()
    page.get_by_label("Username").fill("dana")
    page.get_by_label("Password", exact=True).fill("dana's long passphrase")
    page.get_by_label("Password again").fill("dana's long passphrase")
    page.get_by_role("button", name="Create user").click()
    expect(page).to_have_url(re.compile(r"/admin/users/\d+\?notice=saved$"))

    page.get_by_label("Connection").select_option(label="Prod")
    page.get_by_label("Role", exact=True).select_option(label="Analyst")
    page.get_by_role("button", name="Add grant").click()
    expect(page.locator(".notice")).to_have_text("Saved.")

    page.get_by_role("link", name="Effective access").click()
    expect(page.get_by_text("user grant (Analyst)").first).to_be_visible()

    page.go_back()
    page.get_by_role("button", name="Disable").click()
    expect(page.get_by_role("button", name="Enable")).to_be_visible()
```

Run: `pytest -m e2e tests/e2e/test_everyday_pages.py -v`
Expected: PASS.

- [ ] **Step 5: Run all checks**

Run the four Global Constraints commands, then `pytest -m e2e tests/e2e`.
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/u2_mcp tests
git commit -m "feat(admin): Users pages with tokens, grants and effective access"
```

---

### Task 5: Groups and Roles

**Files:**
- Create: `src/u2_mcp/admin/routes_roles.py`, `templates/groups/list.html`, `templates/groups/detail.html`, `templates/roles/list.html`, `templates/roles/edit.html`
- Modify: `src/u2_mcp/store/repo.py` (groups and roles), `src/u2_mcp/admin/services.py`, `src/u2_mcp/admin/app.py`, `templates/base.html` (nav)
- Test: `tests/test_store/test_repo_2b.py` (append), `tests/test_admin/test_roles_groups.py`, `tests/e2e/test_everyday_pages.py` (append)

**Interfaces:**
- **Produces, Store:**
  - `STALE_ROLE_MESSAGE` (the exact text in Global Constraints)
  - `get_group(group_id: int) -> Group | None`
  - `set_group_label(group_id: int, label: str | None) -> None`, which raises `StoreError` when the group is gone
  - `role_in_use(role_id: int) -> int`: how many grants use it
  - `update_role(role_id: int, *, expected_version: int, name: str, permissions: Iterable[str]) -> Role`, which raises `StaleEdit` or `StoreError` (built-in, gone, name taken, unknown permission)
  - `delete_role(role_id: int) -> None`, which raises `StoreError` for a built-in or in-use role
- **Produces, services:**
  - `clone_role(ctx, role_id: int, *, actor: User) -> Role`
  - `save_role(ctx, role_id: int, *, name: str, permissions: list[str], version: int, actor: User) -> Role`, which raises `ValidationFailed({"name": ...})`, `Refused("role_builtin" | "gone")` or `StaleEdit`
  - `remove_role(ctx, role_id: int, *, actor: User) -> None`, which raises `Refused("role_builtin" | "role_in_use" | "gone")`
  - `set_group_label(ctx, group_id: int, label: str, *, actor: User) -> None`, which raises `ValidationFailed({"label": ...})` or `Refused("gone")`
- **Produces, routes:**
  - Groups: `GET /admin/groups`, `GET /admin/groups/{id}` and `POST /admin/groups/{id}` (field `label`).
  - Roles: `GET /admin/roles`, `GET /admin/roles/{id}`, `POST /admin/roles/{id}` (fields `name`, `permissions` repeated, `version`), `POST /admin/roles/{id}/clone` and `POST /admin/roles/{id}/delete`.

- [ ] **Step 1: Write the failing tests**

In `tests/test_store/test_repo_2b.py`, change the repo import to `from u2_mcp.store.repo import STALE_ROLE_MESSAGE, StaleEdit, Store, StoreError` and append:

```python
class TestRolesAndGroups:
    def test_editing_a_custom_role_bumps_its_version(self, store: Store) -> None:
        role = store.add_role("Auditor", ["schema.read"])

        edited = store.update_role(role.id, expected_version=role.version, name="Auditors",
                                   permissions=["schema.read", "records.read"])

        assert edited.version == role.version + 1
        assert edited.permissions == {"schema.read", "records.read"}
        with pytest.raises(StaleEdit, match=STALE_ROLE_MESSAGE):
            store.update_role(role.id, expected_version=role.version, name="X", permissions=[])

    def test_builtin_roles_cannot_be_edited_or_deleted(self, store: Store) -> None:
        viewer = store.get_role_by_name("Viewer")
        assert viewer is not None
        with pytest.raises(StoreError):
            store.update_role(viewer.id, expected_version=viewer.version, name="Viewer",
                              permissions=[])
        with pytest.raises(StoreError):
            store.delete_role(viewer.id)

    def test_a_role_in_use_cannot_be_deleted(self, store: Store) -> None:
        role = store.add_role("Auditor", ["schema.read"])
        store.add_grant(connection_id=_per_user(store), subject_type="everyone", role_id=role.id)

        assert store.role_in_use(role.id) == 1
        with pytest.raises(StoreError):
            store.delete_role(role.id)

    def test_group_labels(self, store: Store) -> None:
        user = store.get_or_create_sso_user("s")
        store.record_sso_login(user.id, ["eng"])
        group = store.list_groups()[0]

        store.set_group_label(group.id, "Engineering")

        assert store.get_group(group.id).label == "Engineering"  # type: ignore[union-attr]
        with pytest.raises(StoreError):
            store.set_group_label(999, "x")
```

Create `tests/test_admin/test_roles_groups.py`:

```python
"""Roles (clone, edit, delete) and Groups (labels, grants)."""

from collections.abc import Iterator

import pytest
from starlette.testclient import TestClient

from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.problems import Refused
from u2_mcp.admin.services import clone_role, remove_role, save_role
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import finish_setup
from u2_mcp.store.models import User

from .helpers import PASSWORD, admin_client, csrf_from, sign_in


def _viewer_id(ctx: AdminContext) -> int:
    role = ctx.store.get_role_by_name("Viewer")
    assert role is not None
    return role.id


class TestRoleService:
    def test_cloning_names_the_copy_and_audits(self, ctx: AdminContext, admin: User) -> None:
        first = clone_role(ctx, _viewer_id(ctx), actor=admin)
        second = clone_role(ctx, _viewer_id(ctx), actor=admin)

        assert (first.name, second.name) == ("Copy of Viewer", "Copy of Viewer 2")
        assert not first.builtin and ctx.store.recent_audit(1)[0]["action"] == "role.create"

    def test_builtin_roles_are_refused(self, ctx: AdminContext, admin: User) -> None:
        with pytest.raises(Refused) as refused:
            save_role(ctx, _viewer_id(ctx), name="Viewer", permissions=[], version=1,
                      actor=admin)
        assert refused.value.code == "role_builtin"

    def test_a_role_in_use_stays(self, ctx: AdminContext, admin: User) -> None:
        role = clone_role(ctx, _viewer_id(ctx), actor=admin)
        connection = ctx.store.add_connection(name="P", host="h", port=1, service="uvcs",
                                              account="A", shared_user="s", shared_password="p")
        ctx.store.add_grant(connection_id=connection.id, subject_type="everyone",
                            role_id=role.id)

        with pytest.raises(Refused) as refused:
            remove_role(ctx, role.id, actor=admin)
        assert refused.value.code == "role_in_use"


@pytest.fixture
def client(ctx: AdminContext) -> Iterator[TestClient]:
    finish_setup(ctx.store)
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    with admin_client(ctx) as test_client:
        sign_in(test_client)
        yield test_client


class TestPages:
    def test_two_admins_editing_one_role(
        self, client: TestClient, ctx: AdminContext, admin: User
    ) -> None:
        role = clone_role(ctx, _viewer_id(ctx), actor=admin)
        page = client.get(f"/admin/roles/{role.id}").text
        data = {"csrf_token": csrf_from(page), "name": "Readers", "version": str(role.version),
                "permissions": ["schema.read"]}
        assert client.post(f"/admin/roles/{role.id}", data=data,
                           follow_redirects=False).status_code == 303

        stale = client.post(f"/admin/roles/{role.id}", data={**data, "name": "Late"})

        assert stale.status_code == 409
        assert "Someone else changed this role since you opened it." in stale.text

    def test_the_group_page_edits_the_label_and_offers_grants(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        user = ctx.store.get_or_create_sso_user("s")
        ctx.store.record_sso_login(user.id, ["eng"])
        group = ctx.store.list_groups()[0]
        page = client.get(f"/admin/groups/{group.id}").text
        assert "Add grant" in page

        client.post(f"/admin/groups/{group.id}",
                    data={"csrf_token": csrf_from(page), "label": "Engineering"})

        assert "Engineering" in client.get("/admin/groups").text
```

Run: `pytest tests/test_store/test_repo_2b.py tests/test_admin/test_roles_groups.py -v`
Expected: FAIL (`ImportError: cannot import name 'STALE_ROLE_MESSAGE'`).

- [ ] **Step 2: Store**

In `src/u2_mcp/store/repo.py`, after `STALE_CONNECTION_MESSAGE`:

```python
STALE_ROLE_MESSAGE = (
    "Someone else changed this role since you opened it. Reload to see their changes."
)
```

Add to the groups section:

```python
    def get_group(self, group_id: int) -> Group | None:
        """Return a group by id, or None."""
        row = self._one("SELECT id, external_id, label FROM groups WHERE id = ?", (group_id,))
        return Group(id=row["id"], external_id=row["external_id"], label=row["label"]) if row else None

    def set_group_label(self, group_id: int, label: str | None) -> None:
        """Set the name admins see for a group; None shows its claim value.

        Raises:
            StoreError: If the group does not exist
        """
        with self._tx() as conn:
            cursor = conn.execute("UPDATE groups SET label = ? WHERE id = ?", (label, group_id))
            if cursor.rowcount == 0:
                raise StoreError("That group no longer exists.")
```

Add to the roles section:

```python
    def role_in_use(self, role_id: int) -> int:
        """Return how many grants use a role."""
        row = self._one("SELECT COUNT(*) FROM grants WHERE role_id = ?", (role_id,))
        return int(row[0]) if row else 0

    def update_role(
        self, role_id: int, *, expected_version: int, name: str, permissions: Iterable[str]
    ) -> Role:
        """Save an edited custom role, unless someone else saved it first.

        Raises:
            StaleEdit: If the role was saved since expected_version
            StoreError: If it is built-in, gone, the name is taken or a permission unknown
        """
        wanted = list(dict.fromkeys(permissions))
        unknown = [p for p in wanted if p not in PERMISSIONS]
        if unknown:
            raise StoreError(f"unknown permission(s): {', '.join(unknown)}")
        try:
            with self._tx() as conn:
                row = conn.execute(
                    "SELECT builtin, version FROM roles WHERE id = ?", (role_id,)
                ).fetchone()
                if row is None:
                    raise StoreError("That role no longer exists.")
                if row["builtin"]:
                    raise StoreError("Built-in roles can't be changed.")
                if row["version"] != expected_version:
                    raise StaleEdit(STALE_ROLE_MESSAGE)
                conn.execute(
                    "UPDATE roles SET name = ?, permissions = ?, version = version + 1 "
                    "WHERE id = ?",
                    (name, json.dumps(wanted), role_id),
                )
        except sqlite3.IntegrityError as exc:
            raise StoreError(f"A role named '{name}' already exists") from exc
        role = self.get_role(role_id)
        if role is None:
            raise StoreError("That role no longer exists.")
        return role

    def delete_role(self, role_id: int) -> None:
        """Delete a custom role that no grant uses.

        Raises:
            StoreError: If it is built-in, in use or gone
        """
        with self._tx() as conn:
            row = conn.execute("SELECT builtin FROM roles WHERE id = ?", (role_id,)).fetchone()
            if row is None:
                raise StoreError("That role no longer exists.")
            if row["builtin"]:
                raise StoreError("Built-in roles can't be changed.")
            used = conn.execute(
                "SELECT COUNT(*) FROM grants WHERE role_id = ?", (role_id,)
            ).fetchone()[0]
            if used:
                raise StoreError("That role is in use.")
            conn.execute("DELETE FROM roles WHERE id = ?", (role_id,))
```

- [ ] **Step 3: Services**

Append to `src/u2_mcp/admin/services.py`:

```python
_ROLE_NAME_PROBLEM = (
    "Use letters, digits, spaces, dots, dashes or underscores (up to 64), "
    "starting with a letter or digit."
)


def _custom_role(ctx: AdminContext, role_id: int) -> Role:
    role = ctx.store.get_role(role_id)
    if role is None:
        raise Refused("gone")
    if role.builtin:
        raise Refused("role_builtin")
    return role


def clone_role(ctx: AdminContext, role_id: int, *, actor: User) -> Role:
    """Copy a role, built-in or custom, into a new editable custom role.

    Raises:
        Refused: gone
    """
    source = ctx.store.get_role(role_id)
    if source is None:
        raise Refused("gone")
    base = f"Copy of {source.name}"[:64]
    name, number = base, 1
    while ctx.store.get_role_by_name(name) is not None:
        number += 1
        name = f"{base[:60]} {number}"
    role = ctx.store.add_role(name, sorted(source.permissions))
    _audit(ctx, actor, "role.create", params={"name": name, "from": source.name})
    return role


def save_role(
    ctx: AdminContext,
    role_id: int,
    *,
    name: str,
    permissions: list[str],
    version: int,
    actor: User,
) -> Role:
    """Save a custom role's name and permissions.

    Raises:
        ValidationFailed: For a bad or taken name
        Refused: role_builtin or gone
        StaleEdit: If someone saved the role since this form was opened
    """
    _custom_role(ctx, role_id)
    name = name.strip()
    if not _NAME.fullmatch(name):
        raise ValidationFailed({"name": _ROLE_NAME_PROBLEM})
    try:
        role = ctx.store.update_role(
            role_id, expected_version=version, name=name, permissions=permissions
        )
    except StaleEdit:
        raise
    except StoreError as exc:
        if "already exists" in str(exc):
            raise ValidationFailed({"name": str(exc)}) from exc
        raise Refused("gone") from exc
    _audit(ctx, actor, "role.update", params={"name": name, "permissions": sorted(permissions)})
    return role


def remove_role(ctx: AdminContext, role_id: int, *, actor: User) -> None:
    """Delete a custom role that no grant uses.

    Raises:
        Refused: role_builtin, role_in_use or gone
    """
    role = _custom_role(ctx, role_id)
    if ctx.store.role_in_use(role_id):
        raise Refused("role_in_use")
    try:
        ctx.store.delete_role(role_id)
    except StoreError as exc:
        raise Refused("role_in_use" if "in use" in str(exc) else "gone") from exc
    _audit(ctx, actor, "role.delete", params={"name": role.name})


def set_group_label(ctx: AdminContext, group_id: int, label: str, *, actor: User) -> None:
    """Name a group for admins; blank shows the identity provider's value.

    Raises:
        ValidationFailed: For a label over 64 characters
        Refused: gone
    """
    label = label.strip()
    if len(label) > 64:
        raise ValidationFailed({"label": "Use up to 64 characters."})
    try:
        ctx.store.set_group_label(group_id, label or None)
    except StoreError as exc:
        raise Refused("gone") from exc
    _audit(ctx, actor, "group.label", params={"group_id": group_id, "label": label or None})
```

Add `StaleEdit` to the `..store.repo` import in services.

- [ ] **Step 4: Routes and templates**

Create `src/u2_mcp/admin/routes_roles.py`:

```python
"""Groups (labels and grants) and Roles (built-in read-only; clone, edit, delete)."""

from __future__ import annotations

from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from ..permissions import PERMISSIONS, TOOL_PERMISSIONS, WRITE_PERMISSIONS
from ..store.models import Group, Role
from ..store.repo import StaleEdit
from .problems import Refused, with_query
from .routes_grants import form_int, grant_editor
from .security import admin_only, read_form
from .services import ValidationFailed, clone_role, remove_role, save_role, set_group_label
from .templating import admin_context, render

TOOLS_BY_PERMISSION = {
    p: sorted(tool for tool, needed in TOOL_PERMISSIONS.items() if needed == p)
    for p in PERMISSIONS
}


def _group_or_404(request: Request) -> Group:
    group = admin_context(request).store.get_group(request.path_params["id"])
    if group is None:
        raise HTTPException(404, "There is no such group.")
    return group


def _role_or_404(request: Request) -> Role:
    role = admin_context(request).store.get_role(request.path_params["id"])
    if role is None:
        raise HTTPException(404, "There is no such role.")
    return role


def _redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


@admin_only
async def list_groups(request: Request) -> Response:
    """Groups seen at sign-in."""
    return render(request, "groups/list.html", groups=admin_context(request).store.list_groups())


def _group_page(request: Request, group: Group, errors: dict[str, str], status: int) -> Response:
    ctx = admin_context(request)
    return render(request, "groups/detail.html", status_code=status, group=group, errors=errors,
                  **grant_editor(ctx, return_to=f"/admin/groups/{group.id}",
                                 subject_type="group", subject_id=group.id))


@admin_only
async def group_detail(request: Request) -> Response:
    """A group's label and grants."""
    return _group_page(request, _group_or_404(request), {}, 200)


@admin_only
async def group_save(request: Request) -> Response:
    """Save a group's label."""
    group = _group_or_404(request)
    data = await read_form(request)
    try:
        set_group_label(admin_context(request), group.id, str(data.get("label", "")),
                        actor=request.state.user)
    except ValidationFailed as failed:
        return _group_page(request, group, failed.errors, 400)
    except Refused as refused:
        return _redirect(with_query("/admin/groups", problem=refused.code))
    return _redirect(f"/admin/groups/{group.id}?notice=saved")


@admin_only
async def list_roles(request: Request) -> Response:
    """Every role, with how many grants use each."""
    store = admin_context(request).store
    roles = store.list_roles()
    return render(request, "roles/list.html", roles=roles,
                  in_use={r.id: store.role_in_use(r.id) for r in roles})


def _role_page(request: Request, role: Role, *, name: str, chosen: set[str], version: int,
               errors: dict[str, str], status: int) -> Response:
    return render(request, "roles/edit.html", status_code=status, role=role, name=name,
                  chosen=chosen, version=version, errors=errors, permissions=PERMISSIONS,
                  tools=TOOLS_BY_PERMISSION, writes=WRITE_PERMISSIONS,
                  in_use=admin_context(request).store.role_in_use(role.id))


@admin_only
async def role_detail(request: Request) -> Response:
    """A role: read-only when built-in, editable otherwise."""
    role = _role_or_404(request)
    return _role_page(request, role, name=role.name, chosen=set(role.permissions),
                      version=role.version, errors={}, status=200)


@admin_only
async def role_save(request: Request) -> Response:
    """Save a custom role."""
    role = _role_or_404(request)
    data = await read_form(request)
    name = str(data.get("name", ""))
    chosen = [str(p) for p in data.getlist("permissions")]
    version = form_int(data.get("version")) or 0
    try:
        save_role(admin_context(request), role.id, name=name, permissions=chosen,
                  version=version, actor=request.state.user)
    except ValidationFailed as failed:
        return _role_page(request, role, name=name, chosen=set(chosen), version=version,
                          errors=failed.errors, status=400)
    except StaleEdit as stale:
        return _role_page(request, role, name=name, chosen=set(chosen), version=version,
                          errors={"_stale": str(stale)}, status=409)
    except Refused as refused:
        return _redirect(with_query(f"/admin/roles/{role.id}", problem=refused.code))
    return _redirect(f"/admin/roles/{role.id}?notice=saved")


@admin_only
async def role_clone(request: Request) -> Response:
    """Copy a role into a new custom role and open it."""
    role = _role_or_404(request)
    await read_form(request)
    copy = clone_role(admin_context(request), role.id, actor=request.state.user)
    return _redirect(f"/admin/roles/{copy.id}?notice=saved")


@admin_only
async def role_delete(request: Request) -> Response:
    """Delete a custom role nobody uses."""
    role = _role_or_404(request)
    await read_form(request)
    try:
        remove_role(admin_context(request), role.id, actor=request.state.user)
    except Refused as refused:
        return _redirect(with_query(f"/admin/roles/{role.id}", problem=refused.code))
    return _redirect("/admin/roles?notice=deleted")


routes = [
    Route("/groups", list_groups, methods=["GET"]),
    Route("/groups/{id:int}", group_detail, methods=["GET"]),
    Route("/groups/{id:int}", group_save, methods=["POST"]),
    Route("/roles", list_roles, methods=["GET"]),
    Route("/roles/{id:int}", role_detail, methods=["GET"]),
    Route("/roles/{id:int}", role_save, methods=["POST"]),
    Route("/roles/{id:int}/clone", role_clone, methods=["POST"]),
    Route("/roles/{id:int}/delete", role_delete, methods=["POST"]),
]
```

In `app.py`, import `routes_roles` and add `*routes_roles.routes,`. In `base.html`'s admin links, add `<a href="/admin/groups">Groups</a> <a href="/admin/roles">Roles</a>` after Users.

Create `templates/groups/list.html`:

```html
{% extends "base.html" %}
{% block title %}Groups · u2-mcp admin{% endblock %}
{% block content %}
<h1>Groups</h1>
<p class="hint">Groups appear here the first time someone signs in through company sign-in with them.</p>
{% if groups %}
<table>
  <thead><tr><th>Label</th><th>Value from the identity provider</th></tr></thead>
  <tbody>{% for g in groups %}<tr><td><a href="/admin/groups/{{ g.id }}">{{ g.label or g.external_id }}</a></td><td><code>{{ g.external_id }}</code></td></tr>{% endfor %}</tbody>
</table>
{% else %}<p>No groups seen yet.</p>{% endif %}
{% endblock %}
```

Create `templates/groups/detail.html`:

```html
{% extends "base.html" %}
{% from "partials/fields.html" import text %}
{% block title %}{{ group.label or group.external_id }} · u2-mcp admin{% endblock %}
{% block content %}
<p><a href="/admin/groups">All groups</a></p>
<h1>{{ group.label or group.external_id }}</h1>
<p>Identity provider value: <code>{{ group.external_id }}</code></p>
<form method="post" action="/admin/groups/{{ group.id }}">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  {{ text("label", "Label", group.label or "", errors, hint="What admins see. Leave blank to show the value above.") }}
  <div class="actions"><button type="submit">Save label</button></div>
</form>
{% include "partials/grants_editor.html" %}
{% endblock %}
```

Create `templates/roles/list.html`:

```html
{% extends "base.html" %}
{% block title %}Roles · u2-mcp admin{% endblock %}
{% block content %}
<h1>Roles</h1>
<table>
  <thead><tr><th>Role</th><th>Kind</th><th>Permissions</th><th>Grants using it</th></tr></thead>
  <tbody>
  {% for r in roles %}
  <tr><td><a href="/admin/roles/{{ r.id }}">{{ r.name }}</a></td>
      <td>{{ "Built-in" if r.builtin else "Custom" }}</td>
      <td>{{ r.permissions | sort | join(", ") }}</td><td>{{ in_use[r.id] }}</td></tr>
  {% endfor %}
  </tbody>
</table>
{% endblock %}
```

Create `templates/roles/edit.html`:

```html
{% extends "base.html" %}
{% from "partials/fields.html" import text %}
{% block title %}{{ role.name }} · u2-mcp admin{% endblock %}
{% block content %}
<p><a href="/admin/roles">All roles</a></p>
<h1>{{ role.name }}</h1>
{% if errors.get("_stale") %}<p class="alert" role="alert">{{ errors["_stale"] }} <a href="/admin/roles/{{ role.id }}">Reload</a></p>{% endif %}
{% if role.builtin %}<p class="hint">Built-in roles can't be changed. Clone one to make your own.</p>{% endif %}
<form method="post" action="/admin/roles/{{ role.id }}">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <input type="hidden" name="version" value="{{ version }}">
  {% if not role.builtin %}{{ text("name", "Name", name, errors, required=true) }}{% endif %}
  <table>
    <thead><tr><th>Permission</th><th>Tools</th></tr></thead>
    <tbody>
    {% for p in permissions %}
    <tr><td><label><input type="checkbox" name="permissions" value="{{ p }}" {% if p in chosen %}checked{% endif %} {% if role.builtin %}disabled{% endif %}> {{ p }}</label>{% if p in writes %} <span class="hint">(write)</span>{% endif %}</td>
        <td>{{ tools[p] | join(", ") or "Reserved for BASIC tools" }}</td></tr>
    {% endfor %}
    </tbody>
  </table>
  {% if not role.builtin %}<div class="actions"><button type="submit">Save role</button></div>{% endif %}
</form>
<form method="post" action="/admin/roles/{{ role.id }}/clone" class="actions">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <button type="submit" class="secondary">Clone {{ role.name }}</button>
</form>
{% if not role.builtin %}
<form method="post" action="/admin/roles/{{ role.id }}/delete" class="actions">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <button type="submit" class="danger" {% if in_use %}disabled title="Used by {{ in_use }} grant(s)"{% endif %}>Delete role</button>
</form>
{% endif %}
{% endblock %}
```

Run: `pytest tests/test_store/test_repo_2b.py tests/test_admin/test_roles_groups.py tests/test_admin/test_route_table.py -v`
Expected: PASS.

- [ ] **Step 5: Browser tests for Roles and Groups**

In `tests/e2e/test_everyday_pages.py`, add `import subprocess` and `import sys` to the imports, change the conftest import to `from .conftest import REPO_ROOT, Server`, and append:

```python
_SEED_GROUP = (
    "from u2_mcp.config import U2Config\n"
    "from u2_mcp.store.bootstrap import open_store_for_cli\n"
    "store = open_store_for_cli(U2Config())\n"
    "user = store.get_or_create_sso_user('sub-e2e', display_name='Sam')\n"
    "store.record_sso_login(user.id, ['eng-team'])\n"
)


def _seed_group(server: Server) -> None:
    """Write what a company sign-in would: a user and their group."""
    subprocess.run(  # noqa: S603 - fixed argv, test-only
        [sys.executable, "-c", _SEED_GROUP], env=server.env, cwd=REPO_ROOT, check=True,
        timeout=30,
    )


def test_roles_clone_edit_and_delete(page: Page, server: Server) -> None:
    finish_wizard(page, server)
    page.get_by_role("link", name="Roles").click()
    page.get_by_role("link", name="Viewer", exact=True).click()
    page.get_by_role("button", name="Clone Viewer").click()
    expect(page.get_by_label("Name")).to_have_value("Copy of Viewer")

    page.get_by_label("Name").fill("Readers")
    page.get_by_label("query.run").uncheck()
    page.get_by_role("button", name="Save role").click()
    expect(page.locator(".notice")).to_have_text("Saved.")
    expect(page.get_by_label("query.run")).not_to_be_checked()

    page.get_by_role("button", name="Delete role").click()
    expect(page.locator(".notice")).to_have_text("Deleted.")
    expect(page.get_by_role("link", name="Readers")).to_have_count(0)


def test_groups_label_and_grant(page: Page, server: Server) -> None:
    finish_wizard(page, server)
    _seed_group(server)
    page.get_by_role("link", name="Groups").click()
    page.get_by_role("link", name="eng-team").click()
    page.get_by_label("Label").fill("Engineering")
    page.get_by_role("button", name="Save label").click()
    expect(page.get_by_role("heading", name="Engineering")).to_be_visible()

    page.get_by_label("Connection").select_option(label="Prod")
    page.get_by_role("button", name="Add grant").click()
    expect(page.locator(".notice")).to_have_text("Saved.")
    expect(page.get_by_role("link", name="Prod")).to_be_visible()
```

Run: `pytest -m e2e tests/e2e/test_everyday_pages.py -v`
Expected: PASS.

- [ ] **Step 6: Run all checks, then commit**

Run the four Global Constraints commands, then `pytest -m e2e tests/e2e`. Expected: all pass.

```bash
git add src/u2_mcp tests
git commit -m "feat(admin): Groups and Roles pages"
```

---

### Task 6: Audit with CSV export, the Dashboard, and connection ids that are never reused

**Files:**
- Create: `src/u2_mcp/admin/routes_audit.py`, `templates/audit.html`, `templates/dashboard.html`, `templates/partials/check_cell.html`
- Modify: `src/u2_mcp/store/repo.py` (`add_connection`, audit, sessions), `src/u2_mcp/admin/services.py` (checks, audit), `src/u2_mcp/admin/routes_setup.py` (`_home`), `src/u2_mcp/admin/app.py`, `templates/base.html` (nav), `tests/test_admin/test_routes_setup.py` (one assertion)
- Test: `tests/test_store/test_repo_2b.py` (append), `tests/test_admin/test_audit_dashboard.py`, `tests/e2e/test_everyday_pages.py` (append)

**Interfaces:**
- **Produces, Store:**
  - `CONNECTION_ID_SETTING = "last_connection_id"`; `add_connection` never reuses an id (review M-2).
  - `query_audit(*, actor_user_id: int | None = None, connection_id: int | None = None, kind: str | None = None, action: str = "", since: float | None = None, until: float | None = None, limit: int | None = 200) -> list[dict[str, Any]]`: newest first, params decoded. `action` is a prefix match.
  - `count_admin_sessions(*, seen_since: float) -> int`
- **Produces, services:**
  - `record_check(ctx, connection_id: int, result: CheckResult) -> None`
  - `last_check(ctx, connection_id: int) -> dict[str, Any] | None`
  - `check_saved_connection(ctx, connection_id: int) -> CheckResult`, which raises `Refused("gone" | "per_user_check")`
  - `check_connection_form` now also records its result when `connection_id` is given.
  - `@dataclass(frozen=True) AuditFilters(user_id, connection_id, kind, action, date_from, date_to)` with `.from_query(Mapping[str, str])`, `.since` and `.until`
  - `audit_entries(ctx, filters: AuditFilters, *, limit: int | None = 200) -> list[dict[str, Any]]`
  - `audit_csv(ctx, filters: AuditFilters) -> str`
- **Produces, routes:**
  - `GET /admin/audit` (query `user`, `connection`, `kind`, `action`, `from`, `to`, with dates as `YYYY-MM-DD` UTC) and `GET /admin/audit.csv`, which takes the same query.
  - `GET /admin/dashboard` and `POST /admin/dashboard/check/{id:int}`. The POST returns the `partials/check_cell.html` fragment to htmx and redirects without it.
  - Admins' `/admin/` now goes to `/admin/dashboard`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_store/test_repo_2b.py`:

```python
class TestAuditAndIds:
    def test_a_deleted_connections_id_is_never_given_out_again(self, store: Store) -> None:
        first = _per_user(store, "A")
        second = _per_user(store, "B")
        store.delete_connection(second)

        third = _per_user(store, "C")

        assert third > second > first

    def test_audit_filters(self, store: Store) -> None:
        store.add_audit(kind="admin", action="grant.create", outcome="ok", actor_user_id=1,
                        connection_id=7)
        store.add_audit(kind="tool", action="read_record", outcome="ok", actor_user_id=2)
        store.add_audit(kind="admin", action="grant_x", outcome="ok")

        assert [e["action"] for e in store.query_audit(kind="admin")] == ["grant_x",
                                                                         "grant.create"]
        assert [e["action"] for e in store.query_audit(action="grant.")] == ["grant.create"]
        assert [e["action"] for e in store.query_audit(actor_user_id=2)] == ["read_record"]
        assert [e["action"] for e in store.query_audit(connection_id=7)] == ["grant.create"]
        assert store.query_audit(since=store.clock() + 60) == []
        assert len(store.query_audit(limit=None)) == 3

    def test_counting_active_admin_sessions(self, store: Store) -> None:
        ann = store.add_local_user("ann")
        store.add_admin_session(id_hash="a", user_id=ann.id, csrf_token="c", ip=None)

        assert store.count_admin_sessions(seen_since=store.clock() - 60) == 1
        assert store.count_admin_sessions(seen_since=store.clock() + 60) == 0
```

Create `tests/test_admin/test_audit_dashboard.py`:

```python
"""Audit (filters, CSV) and the Dashboard (health, sessions, everyone warning)."""

import csv
import io
from collections.abc import Iterator

import pytest
from starlette.testclient import TestClient

from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.problems import Refused
from u2_mcp.admin.services import (
    AuditFilters,
    audit_csv,
    check_saved_connection,
    last_check,
)
from u2_mcp.connection_check import CheckResult
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import finish_setup

from .conftest import FakeCheck
from .helpers import PASSWORD, admin_client, csrf_from, sign_in


def _shared(ctx: AdminContext) -> int:
    return ctx.store.add_connection(name="Prod", host="h", port=1, service="uvcs", account="A",
                                    shared_user="svc", shared_password="pw").id


class TestServices:
    def test_csv_has_a_header_and_defuses_formulas(self, ctx: AdminContext) -> None:
        ctx.store.add_audit(kind="admin", action="=HYPERLINK(1)", outcome="ok",
                            actor_label="@evil")

        rows = list(csv.reader(io.StringIO(audit_csv(ctx, AuditFilters()))))

        assert rows[0] == ["at", "actor", "kind", "connection", "action", "outcome",
                           "duration_ms", "params"]
        assert rows[1][1] == "'@evil" and rows[1][4] == "'=HYPERLINK(1)"

    def test_dates_bound_the_range(self) -> None:
        filters = AuditFilters.from_query({"from": "2026-10-01", "to": "2026-10-01",
                                           "kind": "nonsense", "user": "x"})

        assert filters.until is not None and filters.since is not None
        assert filters.until - filters.since == 86400
        assert filters.kind is None and filters.user_id is None

    def test_checking_a_saved_connection_records_the_result(
        self, ctx: AdminContext, check: FakeCheck
    ) -> None:
        connection_id = _shared(ctx)
        check.result = CheckResult(False, "Login refused", 3.0)

        result = check_saved_connection(ctx, connection_id)

        assert result.ok is False
        assert check.calls[0][1].password == "pw"
        saved = last_check(ctx, connection_id)
        assert saved is not None and saved["message"] == "Login refused"

    def test_per_user_connections_are_checked_on_their_page(self, ctx: AdminContext) -> None:
        connection_id = ctx.store.add_connection(name="Dev", host="h", port=1, service="uvcs",
                                                 account="A", login_mode="per_user").id
        with pytest.raises(Refused) as refused:
            check_saved_connection(ctx, connection_id)
        assert refused.value.code == "per_user_check"


@pytest.fixture
def client(ctx: AdminContext) -> Iterator[TestClient]:
    finish_setup(ctx.store)
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    with admin_client(ctx) as test_client:
        sign_in(test_client)
        yield test_client


class TestPages:
    def test_admins_land_on_the_dashboard(self, client: TestClient) -> None:
        response = client.get("/admin/", follow_redirects=False)
        assert response.headers["location"] == "/admin/dashboard"

    def test_the_dashboard_warns_about_everyone_grants(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        connection_id = _shared(ctx)
        role = ctx.store.add_role("Imported access", ["schema.read"])
        ctx.store.add_grant(connection_id=connection_id, subject_type="everyone",
                            role_id=role.id)

        page = client.get("/admin/dashboard").text

        assert "Everyone who can sign in can use Prod" in page
        assert "(imported at first start)" in page
        assert "Not checked yet" in page and "admin.sign_in" in page

    def test_check_now_returns_the_cell_to_htmx(
        self, client: TestClient, ctx: AdminContext
    ) -> None:
        connection_id = _shared(ctx)
        token = csrf_from(client.get("/admin/dashboard").text)

        cell = client.post(f"/admin/dashboard/check/{connection_id}",
                           data={"csrf_token": token}, headers={"HX-Request": "true"})

        assert cell.status_code == 200 and "Responding" in cell.text
        assert "<html" not in cell.text

    def test_audit_filters_and_csv(self, client: TestClient) -> None:
        page = client.get("/admin/audit?kind=auth").text
        assert "admin.sign_in" in page

        export = client.get("/admin/audit.csv?kind=auth")

        assert export.headers["content-type"].startswith("text/csv")
        assert "attachment" in export.headers["content-disposition"]
        assert "admin.sign_in" in export.text
```

In `tests/test_admin/test_routes_setup.py::test_done_lists_everything_and_finishes`, change the final expected location from `"/admin/connections"` to `"/admin/dashboard"`.

Run: `pytest tests/test_store/test_repo_2b.py tests/test_admin/test_audit_dashboard.py -v`
Expected: FAIL (`AttributeError: 'Store' object has no attribute 'query_audit'`; `AuditFilters` cannot be imported).

- [ ] **Step 2: Store**

In `src/u2_mcp/store/repo.py`, below `STALE_ROLE_MESSAGE`, add `CONNECTION_ID_SETTING = "last_connection_id"`. In `add_connection`, replace the whole `with self._tx() as conn:` block with:

```python
            with self._tx() as conn:
                # Ids are never reused: audit rows and registry slots name a connection by
                # id, so a new connection must not inherit a deleted one's (review M-2).
                highest = conn.execute("SELECT COALESCE(MAX(id), 0) FROM connections").fetchone()
                mark = conn.execute(
                    "SELECT value FROM settings WHERE key = ?", (CONNECTION_ID_SETTING,)
                ).fetchone()
                new_id = max(int(highest[0]), int(json.loads(mark[0])) if mark else 0) + 1
                conn.execute(
                    "INSERT INTO connections (id, name, host, port, service, account, ssl, "
                    "login_mode, shared_user, shared_password_enc, read_only, enabled, "
                    "created_at, created_by, updated_at, updated_by) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        new_id,
                        name,
                        host,
                        port,
                        service,
                        account,
                        int(ssl),
                        login_mode,
                        shared_user,
                        self._encrypt(shared_password),
                        int(read_only),
                        int(enabled),
                        now,
                        actor,
                        now,
                        actor,
                    ),
                )
                conn.execute(
                    "INSERT INTO settings (key, value) VALUES (?, ?) "
                    "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                    (CONNECTION_ID_SETTING, json.dumps(new_id)),
                )
```

Replace `recent_audit` with:

```python
    @staticmethod
    def _audit_entries(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
        entries = []
        for row in rows:
            entry = dict(row)
            entry["params"] = json.loads(entry["params"]) if entry["params"] else None
            entries.append(entry)
        return entries

    def recent_audit(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return the newest audit rows, newest first, with params decoded."""
        rows = self._all("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))
        return self._audit_entries(rows)

    def query_audit(
        self,
        *,
        actor_user_id: int | None = None,
        connection_id: int | None = None,
        kind: str | None = None,
        action: str = "",
        since: float | None = None,
        until: float | None = None,
        limit: int | None = 200,
    ) -> list[dict[str, Any]]:
        """Return matching audit rows, newest first, with params decoded.

        Args:
            action: A prefix: "grant." matches every grant action. LIKE
                wildcards in it are taken literally.
            since: Only rows at or after this time
            until: Only rows before this time
            limit: At most this many rows; None for all
        """
        sql = "SELECT * FROM audit WHERE 1 = 1"
        params: list[Any] = []
        if actor_user_id is not None:
            sql += " AND actor_user_id = ?"
            params.append(actor_user_id)
        if connection_id is not None:
            sql += " AND connection_id = ?"
            params.append(connection_id)
        if kind is not None:
            sql += " AND kind = ?"
            params.append(kind)
        if action:
            escaped = action.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            sql += " AND action LIKE ? ESCAPE '\\'"
            params.append(escaped + "%")
        if since is not None:
            sql += " AND at >= ?"
            params.append(since)
        if until is not None:
            sql += " AND at < ?"
            params.append(until)
        sql += " ORDER BY id DESC"
        if limit is not None:
            sql += " LIMIT ?"
            params.append(limit)
        return self._audit_entries(self._all(sql, params))
```

After `purge_admin_sessions`, add:

```python
    def count_admin_sessions(self, *, seen_since: float) -> int:
        """Return how many admin-site sessions were active since a time."""
        row = self._one(
            "SELECT COUNT(*) FROM admin_sessions WHERE last_seen_at >= ?", (seen_since,)
        )
        return int(row[0]) if row else 0
```

- [ ] **Step 3: Services**

In `src/u2_mcp/admin/services.py`:
- Add `import csv`, `import io` and `from datetime import datetime, timedelta, timezone`.
- At the end of `check_connection_form`, replace `return ctx.check(ctx.config, transient, login)` with:

```python
    result = ctx.check(ctx.config, transient, login)
    if connection_id is not None:
        record_check(ctx, connection_id, result)
    return result
```

Then append:

```python
LAST_CHECK_PREFIX = "last_check:"
_CSV_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def record_check(ctx: AdminContext, connection_id: int, result: CheckResult) -> None:
    """Keep a connection's latest test result for the dashboard."""
    ctx.store.set_setting(
        f"{LAST_CHECK_PREFIX}{connection_id}",
        {"ok": result.ok, "message": result.message, "at": ctx.store.clock()},
    )


def last_check(ctx: AdminContext, connection_id: int) -> dict[str, Any] | None:
    """A connection's latest test result, or None if it was never tested."""
    value = ctx.store.get_setting(f"{LAST_CHECK_PREFIX}{connection_id}")
    return value if isinstance(value, dict) else None


def check_saved_connection(ctx: AdminContext, connection_id: int) -> CheckResult:
    """Test a saved shared connection with its saved login, and record the result.

    This blocks for up to 10 seconds: call it off the event loop.

    Raises:
        Refused: gone, or per_user_check (those need a person's U2 login)
    """
    connection = ctx.store.get_connection(connection_id)
    if connection is None:
        raise Refused("gone")
    if connection.login_mode != "shared":
        raise Refused("per_user_check")
    try:
        password = ctx.store.shared_password(connection_id) or ""
    except SecretUnreadable:
        result = CheckResult(
            False,
            "The stored password can't be read; U2_SECRET_KEY may have changed. "
            "Type the password again.",
            0.0,
        )
    else:
        login = U2Credentials(
            user=connection.shared_user or "",
            password=password,
            account=connection.account,
            is_shared=True,
        )
        result = ctx.check(ctx.config, connection, login)
    record_check(ctx, connection_id, result)
    return result


def _date(value: str) -> str:
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return ""
    return value


def _day_start(value: str) -> float:
    day = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return day.timestamp()


@dataclass(frozen=True)
class AuditFilters:
    """The Audit page's filters, read safely from a query string. Dates are UTC days."""

    user_id: int | None = None
    connection_id: int | None = None
    kind: str | None = None
    action: str = ""
    date_from: str = ""
    date_to: str = ""

    @classmethod
    def from_query(cls, query: Mapping[str, str]) -> AuditFilters:
        """Read filters; anything malformed is ignored rather than refused."""

        def number(key: str) -> int | None:
            value = query.get(key, "")
            return int(value) if value.isascii() and value.isdecimal() else None

        kind = query.get("kind", "")
        return cls(
            user_id=number("user"),
            connection_id=number("connection"),
            kind=kind if kind in ("tool", "admin", "auth") else None,
            action=query.get("action", "").strip()[:64],
            date_from=_date(query.get("from", "")),
            date_to=_date(query.get("to", "")),
        )

    @property
    def since(self) -> float | None:
        """Start of the first day, or None."""
        return _day_start(self.date_from) if self.date_from else None

    @property
    def until(self) -> float | None:
        """End of the last day (start of the next), or None."""
        if not self.date_to:
            return None
        return _day_start(self.date_to) + timedelta(days=1).total_seconds()


def audit_entries(
    ctx: AdminContext, filters: AuditFilters, *, limit: int | None = 200
) -> list[dict[str, Any]]:
    """Audit rows matching the filters, newest first."""
    return ctx.store.query_audit(
        actor_user_id=filters.user_id,
        connection_id=filters.connection_id,
        kind=filters.kind,
        action=filters.action,
        since=filters.since,
        until=filters.until,
        limit=limit,
    )


def _csv_cell(value: Any) -> str:
    """A CSV cell that a spreadsheet will not run as a formula."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_CSV_FORMULA_START) else text


def audit_csv(ctx: AdminContext, filters: AuditFilters) -> str:
    """Every audit row matching the filters, as CSV text."""
    names = {c.id: c.name for c in ctx.store.list_connections()}
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        ["at", "actor", "kind", "connection", "action", "outcome", "duration_ms", "params"]
    )
    for entry in audit_entries(ctx, filters, limit=None):
        at = datetime.fromtimestamp(entry["at"], tz=timezone.utc).isoformat()
        connection = names.get(entry["connection_id"], entry["connection_id"])
        params = json.dumps(entry["params"]) if entry["params"] is not None else ""
        writer.writerow(
            [
                _csv_cell(value)
                for value in (
                    at,
                    entry["actor_label"],
                    entry["kind"],
                    connection,
                    entry["action"],
                    entry["outcome"],
                    entry["duration_ms"],
                    params,
                )
            ]
        )
    return out.getvalue()
```

- [ ] **Step 4: Routes and templates**

Create `src/u2_mcp/admin/routes_audit.py`:

```python
"""Audit (filters and CSV export) and the Dashboard."""

from __future__ import annotations

import anyio
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from ..store.bootstrap import IMPORT_ROLE
from .problems import Refused, with_query
from .security import SESSION_IDLE_SECONDS, admin_only, read_form
from .services import AuditFilters, audit_csv, audit_entries, check_saved_connection, last_check
from .templating import admin_context, render


@admin_only
async def audit(request: Request) -> Response:
    """The audit trail, filtered; the newest 200 rows."""
    ctx = admin_context(request)
    filters = AuditFilters.from_query(request.query_params)
    return render(
        request,
        "audit.html",
        entries=audit_entries(ctx, filters),
        filters=filters,
        query=request.url.query,
        users=ctx.store.list_users(),
        connections=ctx.store.list_connections(),
        names={c.id: c.name for c in ctx.store.list_connections()},
    )


@admin_only
async def audit_export(request: Request) -> Response:
    """Every matching audit row as a CSV download."""
    ctx = admin_context(request)
    filters = AuditFilters.from_query(request.query_params)
    body = await anyio.to_thread.run_sync(lambda: audit_csv(ctx, filters))
    return Response(
        body,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="u2-mcp-audit.csv"'},
    )


@admin_only
async def dashboard(request: Request) -> Response:
    """Connection health, sessions, everyone grants and the latest audit rows."""
    ctx = admin_context(request)
    store = ctx.store
    registry = ctx.registry()
    rows = [
        {
            "connection": c,
            "sessions": len(set(registry.sessions_for_connection(c.id))),
            "check": last_check(ctx, c.id),
        }
        for c in store.list_connections()
    ]
    everyone = []
    for grant in store.everyone_grants():
        connection = store.get_connection(grant.connection_id)
        role = store.get_role(grant.role_id)
        if connection is not None and role is not None:
            everyone.append({"connection": connection, "role": role,
                             "imported": role.name == IMPORT_ROLE})
    return render(
        request,
        "dashboard.html",
        rows=rows,
        everyone=everyone,
        admin_sessions=store.count_admin_sessions(seen_since=store.clock() - SESSION_IDLE_SECONDS),
        recent=store.recent_audit(20),
        names={c.id: c.name for c in store.list_connections()},
    )


@admin_only
async def check_now(request: Request) -> Response:
    """Test a shared connection now; htmx gets the refreshed cell."""
    ctx = admin_context(request)
    await read_form(request)
    connection_id = request.path_params["id"]
    try:
        await anyio.to_thread.run_sync(lambda: check_saved_connection(ctx, connection_id))
    except Refused as refused:
        return RedirectResponse(with_query("/admin/dashboard", problem=refused.code),
                                status_code=303)
    if request.headers.get("HX-Request"):
        return render(request, "partials/check_cell.html", check=last_check(ctx, connection_id))
    return RedirectResponse("/admin/dashboard", status_code=303)


routes = [
    Route("/audit", audit, methods=["GET"]),
    Route("/audit.csv", audit_export, methods=["GET"]),
    Route("/dashboard", dashboard, methods=["GET"]),
    Route("/dashboard/check/{id:int}", check_now, methods=["POST"]),
]
```

In `app.py`, import `routes_audit` and add `*routes_audit.routes,`. In `routes_setup._home`, change `return _redirect("/admin/connections")` to `return _redirect("/admin/dashboard")`. In `base.html`, make the admin links read Dashboard, Connections, Users, Groups, Roles, Audit, Settings (add `<a href="/admin/dashboard">Dashboard</a>` first and `<a href="/admin/audit">Audit</a>` before Settings).

Create `templates/partials/check_cell.html`:

```html
{% if check %}{{ "Responding" if check.ok else "Failed" }}: {{ check.message }} <span class="hint">({{ check.at | when }})</span>{% else %}Not checked yet{% endif %}
```

Create `templates/dashboard.html`:

```html
{% extends "base.html" %}
{% block title %}Dashboard · u2-mcp admin{% endblock %}
{% block content %}
<h1>Dashboard</h1>
{% for e in everyone %}
<p class="warning">Everyone who can sign in can use {{ e.connection.name }}, with the {{ e.role.name }} role{% if e.imported %} (imported at first start){% endif %}. <a href="/admin/connections/{{ e.connection.id }}#grants">Review its grants</a></p>
{% endfor %}
<h2>Connections</h2>
<table>
  <thead><tr><th>Connection</th><th>State</th><th>Live sessions</th><th>Last check</th><th></th></tr></thead>
  <tbody>
  {% for r in rows %}
  <tr><td><a href="/admin/connections/{{ r.connection.id }}">{{ r.connection.name }}</a></td>
      <td>{{ "Enabled" if r.connection.enabled else "Disabled" }}{{ ", read-only" if r.connection.read_only else "" }}</td>
      <td>{{ r.sessions }}</td>
      <td id="check-{{ r.connection.id }}" aria-live="polite">{% with check = r.check %}{% include "partials/check_cell.html" %}{% endwith %}</td>
      <td>{% if r.connection.login_mode == "shared" %}
        <form method="post" action="/admin/dashboard/check/{{ r.connection.id }}" class="inline"
              hx-post="/admin/dashboard/check/{{ r.connection.id }}" hx-target="#check-{{ r.connection.id }}">
          <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
          <button type="submit" class="secondary">Check now</button>
        </form>{% else %}<a href="/admin/connections/{{ r.connection.id }}">Test with a login</a>{% endif %}</td></tr>
  {% else %}
  <tr><td colspan="5">No connections yet. <a href="/admin/connections/new">Add one</a>.</td></tr>
  {% endfor %}
  </tbody>
</table>
<p>Admin-site sessions active in the last 30 minutes: {{ admin_sessions }}</p>
<h2>Latest activity</h2>
{% include "partials/audit_rows.html" %}
<p><a href="/admin/audit">All activity</a></p>
{% endblock %}
```

Both pages show audit rows, so create `templates/partials/audit_rows.html` (it takes `recent` and `names`):

```html
<table id="audit-rows">
  <thead><tr><th>When</th><th>Who</th><th>Kind</th><th>Connection</th><th>Action</th><th>Outcome</th></tr></thead>
  <tbody>
  {% for e in recent %}
  <tr><td>{{ e.at | when }}</td><td>{{ e.actor_label or "" }}</td><td>{{ e.kind }}</td>
      <td>{{ names.get(e.connection_id, e.connection_id or "") }}</td><td>{{ e.action }}</td><td>{{ e.outcome }}</td></tr>
  {% else %}
  <tr><td colspan="6">Nothing yet.</td></tr>
  {% endfor %}
  </tbody>
</table>
```

Create `templates/audit.html`:

```html
{% extends "base.html" %}
{% block title %}Audit · u2-mcp admin{% endblock %}
{% block content %}
<h1>Audit</h1>
<form method="get" action="/admin/audit" class="actions"
      hx-get="/admin/audit" hx-target="#audit-results" hx-select="#audit-results" hx-swap="outerHTML"
      hx-trigger="change, input changed delay:300ms from:#a-action" hx-push-url="true">
  <label for="a-user">Who</label>
  <select id="a-user" name="user"><option value="">Anyone</option>
    {% for u in users %}<option value="{{ u.id }}" {% if filters.user_id == u.id %}selected{% endif %}>{{ u.label }}</option>{% endfor %}</select>
  <label for="a-connection">Connection</label>
  <select id="a-connection" name="connection"><option value="">Any</option>
    {% for c in connections %}<option value="{{ c.id }}" {% if filters.connection_id == c.id %}selected{% endif %}>{{ c.name }}</option>{% endfor %}</select>
  <label for="a-kind">Kind</label>
  <select id="a-kind" name="kind">
    {% for v, l in [("", "Any"), ("tool", "Tool calls"), ("admin", "Admin changes"), ("auth", "Sign-ins")] %}<option value="{{ v }}" {% if (filters.kind or "") == v %}selected{% endif %}>{{ l }}</option>{% endfor %}</select>
  <label for="a-action">Action starts with</label>
  <input id="a-action" type="text" name="action" value="{{ filters.action }}">
  <label for="a-from">From (UTC)</label><input id="a-from" type="date" name="from" value="{{ filters.date_from }}">
  <label for="a-to">To (UTC)</label><input id="a-to" type="date" name="to" value="{{ filters.date_to }}">
  <button type="submit" class="secondary">Filter</button>
</form>
<div id="audit-results">
<p><a href="/admin/audit.csv{{ '?' ~ query if query else '' }}">Export CSV</a> <span class="hint">All matching rows. The page shows the newest 200.</span></p>
{% with recent = entries %}{% include "partials/audit_rows.html" %}{% endwith %}
</div>
{% endblock %}
```

Run: `pytest tests/test_store tests/test_admin -v`
Expected: PASS.

- [ ] **Step 5: Browser test for the Dashboard and Audit**

In `tests/e2e/test_everyday_pages.py`, add `import csv`, `import io` and `from pathlib import Path` to the imports and append:

```python
def test_dashboard_check_now_and_audit_export(page: Page, server: Server) -> None:
    finish_wizard(page, server)
    page.get_by_role("link", name="Dashboard").click()
    cell = page.locator("td[id^='check-']").first
    expect(cell).to_have_text("Not checked yet")
    page.get_by_role("button", name="Check now").click()
    expect(cell).to_contain_text("Responding")

    page.get_by_role("link", name="Audit").click()
    page.get_by_label("Kind").select_option(label="Admin changes")
    expect(page).to_have_url(re.compile(r"kind=admin"))  # the htmx swap has landed
    expect(page.locator("#audit-rows")).to_contain_text("setup.finish")
    expect(page.get_by_role("link", name="Export CSV")).to_have_attribute(
        "href", re.compile(r"kind=admin")
    )
    with page.expect_download() as download:
        page.get_by_role("link", name="Export CSV").click()
    text = Path(download.value.path()).read_text(encoding="utf-8")
    rows = list(csv.reader(io.StringIO(text)))
    assert rows[0][2] == "kind" and len(rows) > 1
    assert {row[2] for row in rows[1:]} == {"admin"}
    assert "setup.finish" in {row[4] for row in rows[1:]}
```

Run: `pytest -m e2e tests/e2e/test_everyday_pages.py -v`
Expected: PASS.

- [ ] **Step 6: Run all checks, then commit**

Run the four Global Constraints commands, then `pytest -m e2e tests/e2e`. Expected: all pass.

```bash
git add src/u2_mcp tests
git commit -m "feat(admin): Dashboard, Audit with CSV export; connection ids never reused"
```

---

### Task 7: The rest of Settings

**Files:**
- Create: `templates/partials/setup_checklist.html`
- Modify: `src/u2_mcp/admin/services.py`, `src/u2_mcp/admin/routes_setup.py` (Settings routes, `_address_page`, `RESTART_NOTE`), `src/u2_mcp/cli.py` (the set-public-url hint), `templates/settings.html`, `templates/setup/done.html`
- Test: `tests/test_admin/test_settings_2b.py`, `tests/e2e/test_everyday_pages.py` (append)

**Interfaces:**
- **Consumes:** `TOKEN_MAX_LIFETIME_SETTING` and `token_max_lifetime` (Task 2); `LOCAL_ACCOUNTS_SETTING` and `local_accounts_enabled` (2a).
- **Produces, services:**
  - `RESTART_NOTE`, moved here from `routes_setup.py`, which re-imports it
  - `TOKEN_POLICY_PROBLEM = "Enter a whole number of days from 1 to 3650, or leave it blank for no limit."`
  - `save_token_policy(ctx, value: str, *, actor: User) -> int | None`, which raises `ValidationFailed({"token_max_days": TOKEN_POLICY_PROBLEM})`
  - `set_local_accounts(ctx, enabled: bool, *, actor: User) -> None`
  - `clean_public_url` refuses a user name or password in the URL (review M-3).
- **Produces, routes:** `POST /admin/settings/tokens` (field `token_max_days`) and `POST /admin/settings/local-accounts` (field `enabled` = `on`/`off`).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_admin/test_settings_2b.py`:

```python
"""Settings: token policy, local accounts, the setup checklist, and URL hygiene."""

from collections.abc import Iterator

import pytest
from starlette.testclient import TestClient

from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.services import (
    TOKEN_POLICY_PROBLEM,
    ValidationFailed,
    clean_public_url,
    local_accounts_enabled,
    save_token_policy,
    set_local_accounts,
    token_max_lifetime,
)
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import finish_setup
from u2_mcp.store.models import User

from .helpers import PASSWORD, admin_client, csrf_from, sign_in


class TestServices:
    def test_token_policy_saves_clears_and_validates(self, ctx: AdminContext, admin: User) -> None:
        assert save_token_policy(ctx, "30", actor=admin) == 30
        assert token_max_lifetime(ctx) == 30
        assert ctx.store.recent_audit(1)[0]["action"] == "settings.token_policy"
        assert save_token_policy(ctx, " ", actor=admin) is None
        assert token_max_lifetime(ctx) is None
        for bad in ("0", "3651", "ten"):
            with pytest.raises(ValidationFailed, match=TOKEN_POLICY_PROBLEM):
                save_token_policy(ctx, bad, actor=admin)

    def test_local_accounts_switch(self, ctx: AdminContext, admin: User) -> None:
        set_local_accounts(ctx, False, actor=admin)

        assert local_accounts_enabled(ctx) is False
        assert ctx.store.recent_audit(1)[0]["params"] == {"enabled": False}

    def test_a_public_url_with_a_password_is_refused(self) -> None:
        """Review M-3."""
        with pytest.raises(ValidationFailed):
            clean_public_url("https://user:secret@u2.example.com")


@pytest.fixture
def client(ctx: AdminContext) -> Iterator[TestClient]:
    finish_setup(ctx.store)
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    with admin_client(ctx) as test_client:
        sign_in(test_client)
        yield test_client


def test_the_settings_page_saves_each_section(client: TestClient, ctx: AdminContext) -> None:
    page = client.get("/admin/settings").text
    assert "Token policy" in page and "Local accounts" in page and "Admin account" in page
    token = csrf_from(page)

    saved = client.post("/admin/settings/tokens", data={"csrf_token": token,
                                                        "token_max_days": "60"},
                        follow_redirects=False)
    refused = client.post("/admin/settings/tokens", data={"csrf_token": token,
                                                          "token_max_days": "-1"})
    client.post("/admin/settings/local-accounts", data={"csrf_token": token, "enabled": "off"})

    assert saved.headers["location"] == "/admin/settings?notice=saved"
    assert refused.status_code == 400 and TOKEN_POLICY_PROBLEM in refused.text
    assert token_max_lifetime(ctx) == 60
    assert local_accounts_enabled(ctx) is False
```

Run: `pytest tests/test_admin/test_settings_2b.py -v`
Expected: FAIL (`ImportError: cannot import name 'TOKEN_POLICY_PROBLEM'`).

- [ ] **Step 2: Services**

In `src/u2_mcp/admin/services.py`, add the restart note, which moves from `routes_setup.py` with its text unchanged:

```python
RESTART_NOTE = (
    "Restart the server for personal access tokens to use a changed address. "
    "With OAuth sign-in on, sign-in and tokens use U2_AUTH_ISSUER_URL instead."
)
```

In `clean_public_url`, change the condition to also refuse credentials in the URL:

```python
    if (
        parts.scheme not in ("http", "https")
        or not parts.netloc
        or parts.query
        or parts.fragment
        or parts.username
        or parts.password
    ):
```

Append:

```python
TOKEN_POLICY_PROBLEM = "Enter a whole number of days from 1 to 3650, or leave it blank for no limit."


def save_token_policy(ctx: AdminContext, value: str, *, actor: User) -> int | None:
    """Set the longest lifetime a new token may have; blank removes the cap.

    Existing tokens keep their expiry.

    Raises:
        ValidationFailed: Unless blank or a whole number from 1 to 3650
    """
    text = value.strip()
    if not text:
        ctx.store.delete_setting(TOKEN_MAX_LIFETIME_SETTING)
        days = None
    elif text.isascii() and text.isdecimal() and 1 <= int(text) <= 3650:
        days = int(text)
        ctx.store.set_setting(TOKEN_MAX_LIFETIME_SETTING, days)
    else:
        raise ValidationFailed({"token_max_days": TOKEN_POLICY_PROBLEM})
    _audit(ctx, actor, "settings.token_policy", params={"max_days": days})
    return days


def set_local_accounts(ctx: AdminContext, enabled: bool, *, actor: User) -> None:
    """Allow or stop local sign-in for non-admins (local admins always may)."""
    ctx.store.set_setting(LOCAL_ACCOUNTS_SETTING, enabled)
    _audit(ctx, actor, "settings.local_accounts", params={"enabled": enabled})
```

In `src/u2_mcp/cli.py`, import `RESTART_NOTE` from `.admin.services` and replace the `print("Sign-in cookies use it at once. Restart the server for personal access tokens.")` line with:

```python
    print(f"Sign-in cookies use it at once. {RESTART_NOTE}")
```

- [ ] **Step 3: Routes and templates**

In `src/u2_mcp/admin/routes_setup.py`:
- Delete the local `RESTART_NOTE`, and import `RESTART_NOTE`, `local_accounts_enabled`, `save_token_policy`, `set_local_accounts` and `token_max_lifetime` from `.services`.
- Give `_address_page` an `**extra: object` parameter after `submit_label`, and in `page()` call `context.update(extra)` before rendering.
- Replace the Settings section with:

```python
def _settings_page(
    request: Request, *, token_errors: dict[str, str] | None = None
) -> Callable[[str, dict[str, str], int], Response]:
    ctx = admin_context(request)
    return _address_page(
        request,
        "settings.html",
        None,
        "/admin/settings",
        "Save",
        token_max_days=token_max_lifetime(ctx) or "",
        token_errors=token_errors or {},
        local_accounts=local_accounts_enabled(ctx),
        connection=_first_connection(request),
    )


@admin_only
async def settings_form(request: Request) -> Response:
    """Settings: server address, token policy, local accounts and the setup checklist."""
    return _settings_page(request)(effective_public_url(admin_context(request)), {}, 200)


@admin_only
async def settings_save(request: Request) -> Response:
    """Save the server address from the Settings page."""
    return await server_address_submission(
        request,
        page=_settings_page(request),
        on_saved=lambda _url: _redirect("/admin/settings?notice=saved"),
    )


@admin_only
async def settings_tokens(request: Request) -> Response:
    """Save the token policy."""
    ctx = admin_context(request)
    data = await read_form(request)
    try:
        save_token_policy(ctx, str(data.get("token_max_days", "")), actor=request.state.user)
    except ValidationFailed as failed:
        page = _settings_page(request, token_errors=failed.errors)
        return page(effective_public_url(ctx), {}, 400)
    return _redirect("/admin/settings?notice=saved")


@admin_only
async def settings_local_accounts(request: Request) -> Response:
    """Turn local sign-in for non-admins on or off."""
    data = await read_form(request)
    enabled = {"on": True, "off": False}.get(str(data.get("enabled")))
    if enabled is not None:
        set_local_accounts(admin_context(request), enabled, actor=request.state.user)
    return _redirect("/admin/settings?notice=saved")
```

Add these routes to `routes`:

```python
    Route("/settings/tokens", settings_tokens, methods=["POST"]),
    Route("/settings/local-accounts", settings_local_accounts, methods=["POST"]),
```

Create `templates/partials/setup_checklist.html` from the `<table>…</table>` in `setup/done.html`:

```html
<table>
  <tbody>
    <tr><th>Admin account</th><td>Created{% if user %}: {{ user.label }}{% endif %}</td></tr>
    <tr><th>First connection</th><td>{% if connection %}{{ connection.name }} ({{ connection.host }}, {{ connection.account }}){% else %}Not set{% endif %}</td></tr>
    <tr><th>Server address</th><td>{{ public_url }}{% if warning %}<p class="warning">{{ warning }}</p>{% endif %}</td></tr>
    <tr><th>Company sign-in (SSO)</th><td>Not available yet. It arrives in a later version of u2-mcp.</td></tr>
  </tbody>
</table>
```

In `setup/done.html`, replace that table with `{% include "partials/setup_checklist.html" %}`.

Replace `templates/settings.html` with:

```html
{% extends "base.html" %}
{% from "partials/fields.html" import text %}
{% block title %}Settings · u2-mcp admin{% endblock %}
{% block content %}
<h1>Settings</h1>
<h2>Server address</h2>
{% include "partials/server_address_form.html" %}

<h2>Token policy</h2>
<form method="post" action="/admin/settings/tokens">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  {{ text("token_max_days", "Longest token lifetime, in days", token_max_days, token_errors, type="number", hint="Blank means no limit. New tokens default to 90 days, or this limit if lower. Existing tokens keep their expiry.") }}
  <div class="actions"><button type="submit">Save token policy</button></div>
</form>

<h2>Local accounts</h2>
<p>Local sign-in for people who are not admins is <strong>{{ "on" if local_accounts else "off" }}</strong>. Local admins can always sign in, so there is a way back in if company sign-in fails.</p>
<form method="post" action="/admin/settings/local-accounts" class="actions">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  {% if local_accounts %}<button type="submit" name="enabled" value="off" class="secondary">Turn off local sign-in for non-admins</button>
  {% else %}<button type="submit" name="enabled" value="on" class="secondary">Turn on local sign-in for non-admins</button>{% endif %}
</form>

<h2>Setup</h2>
{% include "partials/setup_checklist.html" %}
{% endblock %}
```

Run: `pytest tests/test_admin tests/test_cli.py -v`
Expected: PASS. If a 2a test asserted the old CLI hint text, update it to the `RESTART_NOTE` wording.

- [ ] **Step 4: Browser test for Settings**

Append to `tests/e2e/test_everyday_pages.py`:

```python
def test_settings_token_policy_caps_new_tokens(page: Page, server: Server) -> None:
    finish_wizard(page, server)
    page.get_by_role("link", name="Settings").click()
    page.get_by_label("Longest token lifetime, in days").fill("30")
    page.get_by_role("button", name="Save token policy").click()
    expect(page.locator(".notice")).to_have_text("Saved.")
    page.get_by_role("button", name="Turn off local sign-in for non-admins").click()
    expect(page.get_by_role("button", name="Turn on local sign-in for non-admins")).to_be_visible()

    page.get_by_role("link", name="My access").click()
    expect(page.get_by_label("Lifetime in days")).to_have_value("30")
    expect(page.get_by_text("At most 30 days on this server.")).to_be_visible()
```

Run: `pytest -m e2e tests/e2e -v`
Expected: PASS.

- [ ] **Step 5: Run all checks, then commit**

Run the four Global Constraints commands, then `pytest -m e2e tests/e2e`. Expected: all pass.

```bash
git add src/u2_mcp tests
git commit -m "feat(admin): token policy, local accounts switch and setup checklist in Settings"
```

---

### Task 8: Sign-in and connection follow-ups from the 2a review, docs and CHANGELOG

**Files:**
- Modify: `src/u2_mcp/admin/routes_auth.py`, `src/u2_mcp/admin/security.py` (`signed_in`), `src/u2_mcp/admin/services.py` (`change_password`, `check_connection_form`), `src/u2_mcp/passwords.py`, `src/u2_mcp/store/repo.py` (`update_connection`, `set_password_hash`), `templates/partials/connection_form.html`, `docs/configuration.md`, `CHANGELOG.md`
- Test: `tests/test_admin/test_sign_in_followups.py`, `tests/test_store/test_repo_2b.py` (append)

**Interfaces:**
- **Produces:** `passwords.needs_rehash(password_hash: str) -> bool`.
- **Behaviour:**
  - The current-password check is rate-limited (5 per minute per user) and each failure is audited as `admin.password_check`.
  - Signing out without a live session redirects instead of answering 403.
  - The `next=` link keeps the query string.
  - The local-sign-in-off refusal is audited (`admin.sign_in`, outcome `refused`).
  - A failed sign-in's audited username is capped at 64 characters.
  - Hashes are upgraded on sign-in when the argon2 parameters change.
  - `change_password` reports every field's problem.
  - A per-user Test needs a password.
  - The stale-edit Reload link names its URL.
  - `update_connection` refuses a new password together with clearing it.
  - `set_password_hash` refuses an unknown user.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_store/test_repo_2b.py`:

```python
class TestFollowUps:
    def test_a_new_password_and_clearing_it_are_not_both_allowed(self, store: Store) -> None:
        connection = store.add_connection(name="P", host="h", port=1, service="uvcs",
                                          account="A", shared_user="s", shared_password="p")
        with pytest.raises(StoreError):
            store.update_connection(
                connection.id, expected_version=connection.version, name="P", host="h",
                port=1, service="uvcs", account="A", ssl=False, login_mode="shared",
                shared_user="s", shared_password="new", clear_shared_password=True,
                read_only=True, enabled=True, actor=None,
            )

    def test_setting_a_password_for_nobody_is_refused(self, store: Store) -> None:
        with pytest.raises(StoreError):
            store.set_password_hash(999, "h", must_change=False)
```

Create `tests/test_admin/test_sign_in_followups.py`:

```python
"""Follow-ups from the phase 2a review: sign-in, password change, Test and next=."""

from collections.abc import Iterator

import pytest
from argon2 import PasswordHasher
from starlette.testclient import TestClient

from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.routes_auth import RATE_LIMITED
from u2_mcp.admin.services import (
    LOCAL_ACCOUNTS_SETTING,
    ConnectionForm,
    ValidationFailed,
    change_password,
    check_connection_form,
)
from u2_mcp.passwords import hash_password, needs_rehash
from u2_mcp.setup_code import finish_setup

from .helpers import PASSWORD, admin_client, csrf_from, sign_in


@pytest.fixture
def client(ctx: AdminContext) -> Iterator[TestClient]:
    finish_setup(ctx.store)
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    with admin_client(ctx) as test_client:
        yield test_client


def _password_post(client: TestClient, current: str) -> object:
    token = csrf_from(client.get("/admin/account/password").text)
    return client.post("/admin/account/password", data={
        "csrf_token": token, "current_password": current,
        "new_password": "another long passphrase", "new_password_again": "another long passphrase",
    })


def test_wrong_current_passwords_are_audited_and_limited(
    client: TestClient, ctx: AdminContext
) -> None:
    sign_in(client)
    for _ in range(5):
        _password_post(client, "wrong")
    sixth = _password_post(client, "wrong")

    assert sixth.status_code == 429 and RATE_LIMITED in sixth.text  # type: ignore[attr-defined]
    actions = [e["action"] for e in ctx.store.recent_audit(10)]
    assert actions.count("admin.password_check") == 5


def test_change_password_reports_every_problem(ctx: AdminContext) -> None:
    bob = ctx.store.add_local_user("bob", password_hash=hash_password(PASSWORD))
    with pytest.raises(ValidationFailed) as failed:
        change_password(ctx, bob, current="wrong", new="short", new_again="short")
    assert set(failed.value.errors) == {"current_password", "new_password"}


def test_signing_out_without_a_session_redirects(client: TestClient) -> None:
    response = client.post("/admin/sign-out", data={}, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/admin/sign-in"


def test_next_keeps_the_query_string(client: TestClient) -> None:
    response = client.get("/admin/users?q=ann", follow_redirects=False)
    assert response.headers["location"] == "/admin/sign-in?next=/admin/users%3Fq%3Dann"


def test_the_local_sign_in_off_refusal_is_audited(client: TestClient, ctx: AdminContext) -> None:
    ctx.store.add_local_user("bob", password_hash=hash_password(PASSWORD))
    ctx.store.set_setting(LOCAL_ACCOUNTS_SETTING, False)

    sign_in(client, username="bob")

    entry = ctx.store.recent_audit(1)[0]
    assert (entry["action"], entry["outcome"]) == ("admin.sign_in", "refused")


def test_a_long_failed_username_is_capped(client: TestClient, ctx: AdminContext) -> None:
    sign_in(client, username="x" * 500, password="nope")
    assert len(ctx.store.recent_audit(1)[0]["actor_label"]) == 64


def test_an_old_hash_is_upgraded_at_sign_in(client: TestClient, ctx: AdminContext) -> None:
    weak = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(PASSWORD)
    bob = ctx.store.add_local_user("bob", password_hash=weak, is_admin=True)
    assert needs_rehash(weak)

    sign_in(client, username="bob")

    upgraded = ctx.store.password_hash(bob.id)
    assert upgraded != weak and upgraded is not None and not needs_rehash(upgraded)


def test_a_per_user_test_needs_a_password(ctx: AdminContext) -> None:
    form = ConnectionForm(name="Dev", host="h", account="A", login_mode="per_user",
                          login_user="me")
    with pytest.raises(ValidationFailed) as failed:
        check_connection_form(ctx, form)
    assert "login_password" in failed.value.errors


def test_the_stale_edit_reload_link_names_the_page(client: TestClient, ctx: AdminContext) -> None:
    sign_in(client)
    connection = ctx.store.add_connection(name="P", host="h", port=1, service="uvcs",
                                          account="A", shared_user="s", shared_password="p")
    token = csrf_from(client.get(f"/admin/connections/{connection.id}").text)
    form = {"csrf_token": token, "name": "P", "host": "h", "port": "1", "service": "uvcs",
            "account": "A", "login_mode": "shared", "login_user": "s", "version": "0",
            "read_only": "on", "enabled": "on"}

    stale = client.post(f"/admin/connections/{connection.id}", data=form)

    assert stale.status_code == 409
    assert f'<a href="/admin/connections/{connection.id}">Reload</a>' in stale.text
```

Run: `pytest tests/test_admin/test_sign_in_followups.py tests/test_store/test_repo_2b.py -v`
Expected: FAIL (`ImportError: cannot import name 'needs_rehash'`).

- [ ] **Step 2: Implement**

In `src/u2_mcp/passwords.py`, add:

```python
def needs_rehash(password_hash: str) -> bool:
    """Whether a stored hash used older argon2 parameters than today's defaults."""
    return _hasher.check_needs_rehash(password_hash)
```

In `src/u2_mcp/store/repo.py`:
- At the top of `update_connection`'s body, add:

```python
        if clear_shared_password and shared_password is not None:
            raise StoreError("Give a new password or clear it, not both.")
```

- Replace `set_password_hash`'s body with:

```python
        with self._tx() as conn:
            cursor = conn.execute(
                "UPDATE users SET password_hash = ?, must_change_password = ? WHERE id = ?",
                (password_hash, int(must_change), user_id),
            )
            if cursor.rowcount == 0:
                raise StoreError("That user no longer exists.")
```

In `src/u2_mcp/admin/services.py`, replace `change_password`'s checks, everything before `ctx.store.set_password_hash`, with:

```python
    errors: dict[str, str] = {}
    if not verify_password(ctx.store.password_hash(user.id), current):
        errors["current_password"] = "That is not your current password."
    problem = password_problem(new, username=user.username or "")
    if problem:
        errors["new_password"] = problem
    elif new != new_again:
        errors["new_password_again"] = "The two passwords don't match."
    if errors:
        raise ValidationFailed(errors)
```

In `check_connection_form`, after the existing `if form.login_mode == "per_user" and not form.login_user:` block, add:

```python
    if form.login_mode == "per_user" and not form.login_password:
        errors["login_password"] = "Enter the password for that U2 login to test with."
```

In `src/u2_mcp/admin/security.py`, in `signed_in`, replace the GET redirect line with:

```python
            if request.method == "GET":
                target = path + (f"?{request.url.query}" if request.url.query else "")
                return RedirectResponse(f"/admin/sign-in?next={quote(target)}", status_code=303)
```

In `src/u2_mcp/admin/routes_auth.py`:
- Import `hash_password` and `needs_rehash` from `..passwords`.
- In the failed sign-in audit, use `actor_label=username[:64] or None`.
- Right after the successful `verify_password` branch (before the local-accounts check), add:

```python
    if stored_hash and needs_rehash(stored_hash):
        ctx.store.set_password_hash(
            user.id, hash_password(password), must_change=user.must_change_password
        )
```

- Before the `LOCAL_SIGN_IN_OFF` return, add:

```python
        ctx.store.add_audit(
            kind="auth",
            action="admin.sign_in",
            outcome="refused",
            actor_user_id=user.id,
            actor_label=user.label,
            params={"ip": ip, "reason": "local sign-in off"},
        )
```

- In `sign_out`, replace `await read_form(request)` and the `session = request.state.session` line with:

```python
    session = request.state.session
    if session is None:
        # Already signed out or expired: nothing to end, so no form to check.
        gone = RedirectResponse("/admin/sign-in", status_code=303)
        clear_session_cookie(gone, secure=is_secure(ctx))
        return gone
    await read_form(request)
```

  Then drop the now-redundant `if session is not None:` check, keeping its body.

- In `password_save`, after `user = request.state.user`, add:

```python
    if not _limiter.allow(f"password:{user.id}"):
        return render(
            request,
            "change_password.html",
            status_code=429,
            errors={"current_password": RATE_LIMITED},
        )
```

  In its `except ValidationFailed as failed:` branch, add before the `return`:

```python
        if "current_password" in failed.errors:
            ctx.store.add_audit(
                kind="auth",
                action="admin.password_check",
                outcome="failed",
                actor_user_id=user.id,
                actor_label=user.label,
                params={"ip": client_ip(request)},
            )
```

In `templates/partials/connection_form.html`, change `<a href="">Reload</a>` to `<a href="{{ action_url }}">Reload</a>`.

Run: `pytest tests/test_admin tests/test_store tests/test_passwords.py -v`
Expected: PASS. Two 2a tests may need adjusting:
- A test that tested a per-user connection with no password: add a password.
- A test that expected only the first `change_password` error: assert the key is present instead.

- [ ] **Step 3: Documentation**

In `docs/configuration.md`, replace the body of `### Personal access tokens` (the Python snippet included) with:

```markdown
In team mode, clients that cannot do a browser sign-in authenticate with a
personal access token: `Authorization: Bearer u2pat_...`. Every signed-in person
creates and revokes their own on **My access** (`/admin/me`), which also shows
copy-ready configuration for VS Code, Visual Studio and JetBrains. A token is
shown once. It lasts 90 days by default; an admin can set a lower maximum under
Settings, Token policy. Admins can revoke anyone's token from their Users page.

A token proves who is calling, not what they may do: nobody, admins included,
can use a connection until a grant gives them a role on it.
```

After `### Choosing a connection`, add:

```markdown
### Everyday admin pages

- **Dashboard**: each connection's state, live sessions and last Test result
  (Check now tests a shared connection; nothing contacts U2 on page load), active
  admin sessions, the latest 20 audit rows, and a warning for every `everyone` grant.
- **Connections**: as before, plus **Access**, the grants editor. Grants on a
  per-person connection carry that person's U2 login, stored encrypted. Changing
  a per-person connection's server forgets those passwords, so they are never sent
  to a new host.
- **Users**: filter, create local users, admin and disabled flags (you cannot
  demote or disable yourself, or the last enabled local admin), tokens, grants,
  and **Effective access**: each permission and the grant or group giving it.
- **Groups**: groups seen at company sign-in, with labels and grants.
- **Roles**: built-in roles are read-only; clone them into custom roles you can edit
  and delete (a role used by a grant cannot be deleted). Two admins editing the same
  role: the second save is refused.
- **Audit**: filter by person, connection, kind, action prefix and UTC dates; Export
  CSV downloads every matching row.
- **Settings**: server address, token policy, local sign-in for non-admins, and the
  setup checklist.
- **My access**: for everyone. People who are not admins land here.
```

In `CHANGELOG.md`, under `## [Unreleased]` → `### Added`, add:

```markdown
- Admin site, phase 2b: a grants editor on the connection, user and group pages; My access with personal access tokens (shown once) and copy-ready VS Code, Visual Studio and JetBrains configuration; Dashboard, Users with effective access, Groups, Roles (clone, edit, delete with optimistic locking), Audit with CSV export, and Settings for token policy and local sign-in. People who are not admins land on My access.
```

Under `### Changed` (create it if missing), add:

```markdown
- Connection ids are never reused, so a new connection never inherits a deleted one's audit history.
- Changing a per-person connection's server forgets the personal U2 passwords stored for it.
- `set-public-url` and the Settings page refuse an address that contains a user name or password.
```

- [ ] **Step 4: Run all checks, then commit**

Run the four Global Constraints commands, then `pytest -m e2e tests/e2e`. Expected: all pass.

```bash
git add src/u2_mcp tests docs/configuration.md CHANGELOG.md
git commit -m "fix(admin): 2a review follow-ups for sign-in and Test; document the everyday pages"
```

---

## Self-review against the spec

| Spec item | Task |
|---|---|
| Dashboard: health, active sessions, last 20 audit, `everyone` warning | 6 |
| Users: list and filters, create local, admin flag, disable, tokens, grants, Effective access | 4 |
| Groups: seen at sign-in, labels, grants | 5 |
| Roles: built-in read-only; clone, edit (version lock), delete (not in use) | 5 |
| Grants editor on the connection, user and group pages; user, group or everyone plus a role; per-user U2 login on per_user connections; `everyone` warning | 1 (component), 4 and 5 (reuse) |
| Audit: user, connection, kind, action and date filters; CSV export | 6 |
| Settings: token policy, local accounts on/off, setup checklist (SSO is phase 3) | 7 |
| My access: connections with role and permissions; tokens created (shown once) and revoked; VS Code (OAuth and token), Visual Studio, JetBrains | 2 |
| Non-admins land on My access | 2 |
| Testing item 6: every everyday page's main path; create a token and use it from an MCP client | 3, 4, 5, 6, 7 |
| Ledger and review: Done-page text (2); connection health (6); M-1 (2); M-2 (6); M-3 (7); M-6 route-table test (1); RESTART_NOTE and CLI hint (7); password-check rate limit and audit, sign-out redirect, `next=` query, local-off audit, username cap, rehash, `change_password` errors, per-user Test, Reload link, `update_connection`, unknown-id setters (4, 8) | as listed |
