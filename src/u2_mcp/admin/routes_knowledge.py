"""Admin-only browsing and revision-checked editing of persisted database notes."""

from __future__ import annotations

from urllib.parse import urlencode

from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from ..store.knowledge import KnowledgeTopic
from ..store.repo import StaleEdit
from .security import admin_only, read_form
from .templating import admin_context, render


def _url(scope: str, key: str | None = None, *, delete: bool = False) -> str:
    params = {"scope": scope}
    path = "/admin/knowledge"
    if key is not None:
        params["topic"] = key
        path += "/delete" if delete else "/topic"
    return path + "?" + urlencode(params)


# Column -> (sort key, the direction a first click uses). Newest first is the
# useful way to start on dates; names start A to Z.
_SORTS = {
    "topic": (lambda t: (t.key, t.updated_at), "asc"),
    "updated": (lambda t: (t.updated_at, t.key), "desc"),
}


def _sorted(
    topics: list[KnowledgeTopic], column: str | None, order: str | None
) -> tuple[list[KnowledgeTopic], str, str]:
    """Sort topics by a known column and direction; anything else means topic, A to Z."""
    if column not in _SORTS:
        column, order = "topic", "asc"
    key, first = _SORTS[column]
    if order not in ("asc", "desc"):
        order = first
    return sorted(topics, key=key, reverse=order == "desc"), column, order


def _sort_links(scope: str, column: str, order: str) -> dict[str, dict[str, str]]:
    """Each header's link and its aria-sort state: clicking the sorted column reverses it."""
    links = {}
    for name, (_, first) in _SORTS.items():
        current = name == column
        next_order = ("desc" if order == "asc" else "asc") if current else first
        links[name] = {
            "url": "/admin/knowledge?"
            + urlencode({"scope": scope, "sort": name, "order": next_order}),
            "aria": ("ascending" if order == "asc" else "descending") if current else "none",
            "arrow": ("▲" if order == "asc" else "▼") if current else "",
        }
    return links


def _topic(request: Request) -> KnowledgeTopic:
    topic = admin_context(request).store.get_knowledge_topic(
        request.query_params.get("scope", ""),
        " ".join(request.query_params.get("topic", "").split()).lower(),
    )
    if topic is None:
        raise HTTPException(404, "That knowledge topic no longer exists.")
    return topic


def _topic_page(
    request: Request,
    topic: KnowledgeTopic,
    *,
    delete: bool = False,
    content: str | None = None,
    revision: str | None = None,
    error: str = "",
    status: int = 200,
) -> Response:
    namespace = next(
        (
            n
            for n in admin_context(request).store.list_knowledge_namespaces()
            if n.scope == topic.scope
        ),
        None,
    )
    return render(
        request,
        "knowledge/delete.html" if delete else "knowledge/edit.html",
        status_code=status,
        topic=topic,
        label=namespace.label if namespace else topic.scope,
        content=topic.content if content is None else content,
        revision=topic.revision if revision is None else revision,
        error=error,
        topic_url=_url(topic.scope, topic.key),
        delete_url=_url(topic.scope, topic.key, delete=True),
        list_url=_url(topic.scope),
    )


@admin_only
async def list_knowledge(request: Request) -> Response:
    store = admin_context(request).store
    namespaces = store.list_knowledge_namespaces()
    scope = request.query_params.get("scope")
    selected = next((n for n in namespaces if n.scope == scope), None)
    if scope is not None and selected is None:
        raise HTTPException(404, "That knowledge namespace no longer exists.")
    topics = store.list_knowledge_topics(scope) if scope is not None else []
    topics, column, order = _sorted(
        topics, request.query_params.get("sort"), request.query_params.get("order")
    )
    return render(
        request,
        "knowledge/list.html",
        namespaces=namespaces,
        selected=selected,
        entries=[(topic, _url(topic.scope, topic.key)) for topic in topics],
        sort_links=_sort_links(scope, column, order) if scope is not None else {},
    )


@admin_only
async def topic_detail(request: Request) -> Response:
    return _topic_page(request, _topic(request))


@admin_only
async def delete_detail(request: Request) -> Response:
    return _topic_page(request, _topic(request), delete=True)


async def _change(request: Request, *, delete: bool) -> Response:
    data = await read_form(request)
    topic = _topic(request)
    revision = str(data.get("revision", ""))
    content = str(data.get("content", ""))
    store = admin_context(request).store
    try:
        changed = store.change_knowledge_topic(
            topic.scope, topic.key, revision=revision, content=None if delete else content
        )
    except StaleEdit as stale:
        return _topic_page(
            request,
            topic,
            delete=delete,
            content=content,
            revision=revision,
            error=str(stale),
            status=409,
        )
    if not changed:
        raise HTTPException(404, "That knowledge topic no longer exists.")
    actor = request.state.user
    store.add_audit(
        kind="admin",
        action="knowledge.delete" if delete else "knowledge.update",
        outcome="ok",
        actor_user_id=actor.id,
        actor_label=actor.label,
        params={"scope": topic.scope, "topic": topic.topic},
    )
    if delete:
        target = (
            _url(topic.scope) + "&notice=deleted"
            if store.list_knowledge_topics(topic.scope)
            else "/admin/knowledge?notice=deleted"
        )
    else:
        target = _url(topic.scope, topic.key) + "&notice=saved"
    return RedirectResponse(target, status_code=303)


@admin_only
async def topic_save(request: Request) -> Response:
    return await _change(request, delete=False)


@admin_only
async def topic_delete(request: Request) -> Response:
    return await _change(request, delete=True)


routes = [
    Route("/knowledge", list_knowledge, methods=["GET"]),
    Route("/knowledge/topic", topic_detail, methods=["GET"]),
    Route("/knowledge/topic", topic_save, methods=["POST"]),
    Route("/knowledge/delete", delete_detail, methods=["GET"]),
    Route("/knowledge/delete", topic_delete, methods=["POST"]),
]
