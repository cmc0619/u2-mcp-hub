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
from ..sso_config import load_sso
from ..store.models import Connection
from .routes_connections import Page, connection_submission, password_hint
from .security import (
    admin_only,
    client_ip,
    is_secure,
    presession_token,
    read_form,
    set_presession_cookie,
    set_session_cookie,
    signed_in,
    start_session,
)
from .services import (
    RESTART_NOTE,
    ConnectionForm,
    ValidationFailed,
    clean_public_url,
    create_local_user,
    effective_public_url,
    non_admin_sign_in_enabled,
    public_url_warning,
    save_public_url,
    save_token_policy,
    set_non_admin_sign_in,
    token_max_lifetime,
)
from .sso_services import SsoForm, remove_sso, save_sso, sso_context
from .templating import admin_context, render

STEP_TITLES: dict[str, str] = {
    "admin": "Admin account",
    "connection": "First connection",
    "server_address": "Server address",
    "sso": "Company sign-in",
    "done": "Done",
}

CONFIRM_HTTPS_LABEL = "I will reach the admin site over https from now on"
HTTPS_OVER_HTTP = (
    "You are on http now. After saving an https address you must reach this site over "
    "https, or sign-in will fail. Tick the box to confirm."
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
    if user is not None and user.must_change_password:
        # Review M-1: a one-time password from reset-password must be changed first.
        return _redirect("/admin/account/password")
    return None


def _step_page(
    request: Request, template: str, step: str, *, status_code: int = 200, **context: object
) -> Response:
    store = admin_context(request).store
    done = completed_step(store)
    done_index = SETUP_STEPS.index(done) if done else -1
    return render(
        request,
        template,
        status_code=status_code,
        step=step,
        steps=[
            (name, STEP_TITLES[name], SETUP_STEPS.index(name) <= done_index + 1)
            for name in SETUP_STEPS
        ],
        **context,
    )


async def index(request: Request) -> Response:
    """The admin home: the wizard until setup is finished, then Connections."""
    if not is_setup_complete(admin_context(request).store):
        return _redirect("/admin/setup")
    return await _home(request)


@signed_in
async def _home(request: Request) -> Response:
    if not request.state.user.is_admin:
        return _redirect("/admin/me")
    return _redirect("/admin/connections")


async def setup_start(request: Request) -> Response:
    """Resume at the first unfinished step."""
    store = admin_context(request).store
    if is_setup_complete(store):
        return _redirect("/admin/")
    return _redirect(f"/admin/setup/{next_step(store)}")


# ------------------------------------------------------------------ admin step


def _admin_page(
    request: Request, *, values: dict[str, str], errors: dict[str, str], status_code: int = 200
) -> Response:
    ctx = admin_context(request)
    created = completed_step(ctx.store) is not None
    token = request.state.csrf_token or presession_token(request, secure=is_secure(ctx))
    response = _step_page(
        request,
        "setup/admin.html",
        "admin",
        status_code=status_code,
        created=created,
        values=values,
        errors=errors,
        csrf_token=token,
        action_url="/admin/setup/admin",
        submit_label="Create admin and continue",
        show_setup_code=True,
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
    # Shown before sign-in, so the pre-session (double-submit) token is accepted here.
    form = await read_form(request, presession=True)
    # Another browser may have finished this step while the form was read. Nothing
    # below awaits (argon2 and SQLite are synchronous), so this check is enough.
    if completed_step(ctx.store) is not None:
        return _redirect("/admin/setup/connection")
    values = {key: str(form.get(key, "")) for key in ("username", "display_name")}
    if not check_setup_code(ctx.store, str(form.get("setup_code", ""))):
        return _admin_page(
            request, values=values, errors={"setup_code": WRONG_SETUP_CODE_MESSAGE}, status_code=400
        )
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
    previous = request.state.session
    if previous is not None:
        # One browser, one session, as on the sign-in page.
        ctx.store.delete_admin_session(previous.id_hash)
    raw_id, _ = start_session(ctx.store, user, client_ip(request))
    response = _redirect("/admin/setup/connection")
    set_session_cookie(response, raw_id, secure=is_secure(ctx))
    return response


# ------------------------------------------------------------- connection step


def _first_connection(request: Request) -> Connection | None:
    connections = admin_context(request).store.list_connections()
    return min(connections, key=lambda c: c.id) if connections else None


def _connection_page(request: Request, connection: Connection | None) -> Page:
    def page(
        form: ConnectionForm, errors: dict[str, str], result: CheckResult | None, status: int
    ) -> Response:
        return _step_page(
            request,
            "setup/connection.html",
            "connection",
            status_code=status,
            form=form,
            errors=errors,
            result=result,
            test_errors=[],
            action_url="/admin/setup/connection",
            submit_label="Save and continue",
            password_hint=password_hint(connection),
        )

    return page


async def setup_connection_form(request: Request) -> Response:
    """Step 2: the first connection."""
    blocked = _guard(request, "connection")
    if blocked is not None:
        return blocked
    connection = _first_connection(request)
    form = ConnectionForm.from_connection(connection) if connection else ConnectionForm()
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
    """Handle a server-address form POST for the wizard and the Settings page.

    An https address saved while this request is plain http makes the sign-in
    cookies Secure, which the browser then drops over http, so every later
    sign-in would fail. That needs the confirm_https box ticked.
    """
    ctx = admin_context(request)
    form = await read_form(request)
    typed = str(form.get("public_url", ""))
    try:
        cleaned = clean_public_url(typed)
        if (
            _on_http(request)
            and cleaned.lower().startswith("https://")
            and form.get("confirm_https") != "on"
        ):
            raise ValidationFailed({"public_url": HTTPS_OVER_HTTP})
        saved = save_public_url(ctx, cleaned, actor=request.state.user)
    except ValidationFailed as failed:
        return page(typed, failed.errors, 400)
    return on_saved(saved)


def _on_http(request: Request) -> bool:
    return request.url.scheme == "http"


def _address_page(
    request: Request,
    template: str,
    step: str | None,
    action_url: str,
    submit_label: str,
    **extra: object,
) -> Callable[[str, dict[str, str], int], Response]:
    def page(public_url: str, errors: dict[str, str], status: int) -> Response:
        context: dict[str, object] = {
            "public_url": public_url,
            "warning": public_url_warning(public_url),
            "errors": errors,
            "action_url": action_url,
            "submit_label": submit_label,
            "restart_note": RESTART_NOTE,
            "confirm_https_label": CONFIRM_HTTPS_LABEL if _on_http(request) else "",
        }
        context.update(extra)
        if step is None:
            return render(request, template, status_code=status, **context)
        return _step_page(request, template, step, status_code=status, **context)

    return page


async def setup_server_address_form(request: Request) -> Response:
    """Step 3: the address people use to reach this server."""
    blocked = _guard(request, "server_address")
    if blocked is not None:
        return blocked
    page = _address_page(
        request,
        "setup/server_address.html",
        "server_address",
        "/admin/setup/server_address",
        "Save and continue",
    )
    return page(effective_public_url(admin_context(request)), {}, 200)


async def setup_server_address(request: Request) -> Response:
    """Save the address and continue."""
    blocked = _guard(request, "server_address")
    if blocked is not None:
        return blocked
    ctx = admin_context(request)

    def on_saved(_url: str) -> Response:
        mark_step_done(ctx.store, "server_address")
        return _redirect("/admin/setup/sso")

    return await server_address_submission(
        request,
        page=_address_page(
            request,
            "setup/server_address.html",
            "server_address",
            "/admin/setup/server_address",
            "Save and continue",
        ),
        on_saved=on_saved,
    )


# ----------------------------------------------------------------- sso step


def _sso_step_page(
    request: Request,
    *,
    form: SsoForm | None = None,
    errors: dict[str, str] | None = None,
    status_code: int = 200,
) -> Response:
    ctx = admin_context(request)
    return _step_page(
        request,
        "setup/sso.html",
        "sso",
        status_code=status_code,
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


# ------------------------------------------------------------------- done step


async def setup_done_form(request: Request) -> Response:
    """Step 5: what is set up, what is not yet, and the MCP client configuration."""
    blocked = _guard(request, "done")
    if blocked is not None:
        return blocked
    ctx = admin_context(request)
    public_url = effective_public_url(ctx)
    return _step_page(
        request,
        "setup/done.html",
        "done",
        connection=_first_connection(request),
        public_url=public_url,
        warning=public_url_warning(public_url),
        sso=load_sso(ctx.store),
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
    ctx.store.add_audit(
        kind="admin",
        action="setup.finish",
        outcome="ok",
        actor_user_id=user.id,
        actor_label=user.label,
    )
    return _redirect("/admin/connections?notice=setup_done")


# ----------------------------------------------------------------- settings


def _settings_page(
    request: Request,
    *,
    token_errors: dict[str, str] | None = None,
    sso_form: SsoForm | None = None,
    sso_errors: dict[str, str] | None = None,
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
        non_admin_sign_in=non_admin_sign_in_enabled(ctx.store),
        connection=_first_connection(request),
        **sso_context(ctx, action_url="/admin/settings/sso", form=sso_form, errors=sso_errors),
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
async def settings_non_admin_sign_in(request: Request) -> Response:
    """Turn admin-site sign-in for people who are not admins on or off."""
    data = await read_form(request)
    enabled = {"on": True, "off": False}.get(str(data.get("enabled")))
    if enabled is None:
        return _redirect("/admin/settings")
    set_non_admin_sign_in(admin_context(request), enabled, actor=request.state.user)
    return _redirect("/admin/settings?notice=saved")


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


routes = [
    Route("/", index, methods=["GET"]),
    Route("/setup", setup_start, methods=["GET"]),
    Route("/setup/admin", setup_admin_form, methods=["GET"]),
    Route("/setup/admin", setup_admin, methods=["POST"]),
    Route("/setup/connection", setup_connection_form, methods=["GET"]),
    Route("/setup/connection", setup_connection, methods=["POST"]),
    Route("/setup/server_address", setup_server_address_form, methods=["GET"]),
    Route("/setup/server_address", setup_server_address, methods=["POST"]),
    Route("/setup/sso", setup_sso_form, methods=["GET"]),
    Route("/setup/sso", setup_sso, methods=["POST"]),
    Route("/setup/sso/next", setup_sso_next, methods=["POST"]),
    Route("/setup/done", setup_done_form, methods=["GET"]),
    Route("/setup/done", setup_done, methods=["POST"]),
    Route("/settings", settings_form, methods=["GET"]),
    Route("/settings", settings_save, methods=["POST"]),
    Route("/settings/tokens", settings_tokens, methods=["POST"]),
    Route("/settings/non-admin-sign-in", settings_non_admin_sign_in, methods=["POST"]),
    Route("/settings/sso", settings_sso, methods=["POST"]),
    Route("/settings/sso/clear", settings_sso_clear, methods=["POST"]),
]
