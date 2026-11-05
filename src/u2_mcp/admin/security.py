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

from starlette.datastructures import FormData, MutableHeaders
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse, Response

from ..store.models import AdminSession, User
from ..store.repo import Store
from .context import AdminContext
from .services import effective_public_url, kept_off_this_site

SESSION_COOKIE = "u2_admin_session"
PRESESSION_COOKIE = "u2_admin_presession"
SESSION_ABSOLUTE_SECONDS = 8 * 60 * 60
SESSION_IDLE_SECONDS = 30 * 60
CSRF_FIELD = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"
SIGN_IN_LIMIT = 5
SIGN_IN_WINDOW_SECONDS = 60.0
RATE_LIMIT_MAX_KEYS = 10_000

_TOUCH_SECONDS = 60.0
_COOKIE_PATH = "/admin"
HOST_PREFIX = "__Host-"

Handler = Callable[[Request], Awaitable[Response]]


class RateLimiter:
    """At most `limit` attempts per `window` seconds for each key.

    Keys with no attempts inside the window are dropped, and the whole table is
    swept once it reaches `max_keys`, so random usernames cannot grow it forever.
    """

    def __init__(
        self,
        limit: int = SIGN_IN_LIMIT,
        window: float = SIGN_IN_WINDOW_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = RATE_LIMIT_MAX_KEYS,
    ) -> None:
        self._limit = limit
        self._window = window
        self._clock = clock
        self._max_keys = max_keys
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> deque[float] | None:
        """Forget attempts older than the window; drop the key if none remain."""
        hits = self._hits.get(key)
        if hits is None:
            return None
        while hits and now - hits[0] >= self._window:
            hits.popleft()
        if not hits:
            del self._hits[key]
            return None
        return hits

    def allow(self, *keys: str) -> bool:
        """Record an attempt against every key, unless any key is already exhausted.

        A limit of 0 or less turns limiting off: every attempt is allowed and none is kept.
        """
        if self._limit <= 0:
            return True
        now = self._clock()
        with self._lock:
            if len(self._hits) >= self._max_keys:
                for key in list(self._hits):
                    self._prune(key, now)
            for key in keys:
                hits = self._prune(key, now)
                if hits is not None and len(hits) >= self._limit:
                    return False
            for key in keys:
                self._hits.setdefault(key, deque()).append(now)
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
    if user is None or user.disabled or kept_off_this_site(store, user):
        store.delete_admin_session(id_hash)
        return None
    if now - session.last_seen_at >= _TOUCH_SECONDS:
        store.touch_admin_session(id_hash, at=now)
    return session, user


def is_secure(ctx: AdminContext) -> bool:
    """Whether cookies get the Secure flag: the public address is https."""
    return effective_public_url(ctx).lower().startswith("https://")


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


def clear_session_cookie(response: Response, *, secure: bool) -> None:
    """Remove the session cookie, with the same flags it was set with."""
    response.delete_cookie(
        SESSION_COOKIE,
        path=_COOKIE_PATH,
        httponly=True,
        samesite="lax",
        secure=secure,
    )


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


def client_ip(request: Request) -> str | None:
    """The caller's address, as ClientAddressMiddleware records it."""
    return request.client.host if request.client else None


def safe_next(value: str | None) -> str:
    """Return a redirect target inside the admin site, or the admin home."""
    if value and value.startswith("/admin/") and not value.startswith("//") and "\\" not in value:
        return value
    return "/admin/"


async def read_form(request: Request, *, presession: bool = False) -> FormData:
    """Read a submitted form, refusing it unless it carries the right CSRF token.

    Args:
        request: The current request
        presession: Also accept the pre-session cookie's value (double-submit).
            Pass True only for forms shown before sign-in: the sign-in POST and
            setup step 1. Every other form accepts only the session's token, so
            a cookie planted by another site cannot stand in for it.

    Raises:
        HTTPException: 403 when the token is missing or wrong
    """
    form = await request.form()
    presented = str(form.get(CSRF_FIELD) or request.headers.get(CSRF_HEADER) or "")
    candidates = [getattr(request.state, "csrf_token", "")]
    if presession:
        secure = is_secure(request.app.state.ctx)
        candidates.append(request.cookies.get(cookie_name(PRESESSION_COOKIE, secure), ""))
    expected = [token for token in candidates if token]
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
                target = path + (f"?{request.url.query}" if request.url.query else "")
                return RedirectResponse(f"/admin/sign-in?next={quote(target)}", status_code=303)
            raise HTTPException(403, "Sign in first.")
        if user.must_change_password and path not in ("/admin/account/password", "/admin/sign-out"):
            return RedirectResponse("/admin/account/password", status_code=303)
        return await handler(request)

    return wrapper


def admin_only(handler: Handler) -> Handler:
    """Require a signed-in admin."""

    @signed_in
    @wraps(handler)
    async def wrapper(request: Request) -> Response:
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
        await self.app(scope, receive, _no_store(scope, send))


def _no_store(scope: dict[str, Any], send: Any) -> Any:
    """Mark every admin response except static files `Cache-Control: no-store`.

    Pages already say so; redirects must too. Browsers replay cached redirects
    on Back, and the wizard's redirects change once setup is finished, so a
    cached chain (/admin/ to /admin/setup to /admin/setup/admin) looped forever.
    """
    path = scope["path"]
    root = scope.get("root_path", "")
    if root and path.startswith(root):
        path = path[len(root) :]
    if path.startswith("/static/"):
        return send

    async def send_no_store(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            headers = MutableHeaders(scope=message)
            headers.setdefault("cache-control", "no-store")
        await send(message)

    return send_no_store


def _allowed(ip: str | None, networks: list[Any]) -> bool:
    if ip is None:
        return False
    try:
        address: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # On a dual-stack bind IPv4 clients arrive as ::ffff:a.b.c.d; match them as IPv4.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return any(address in network for network in networks)
