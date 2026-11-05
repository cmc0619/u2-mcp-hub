"""Saved notes about a database, kept in SQLite.

Team mode keeps them in the settings database; stdio keeps them in
~/.u2-mcp/u2-mcp.db. Both scope notes by normalized server/account, independent
of connection names or logins. Topics ignore case and surrounding whitespace.
"""

from __future__ import annotations

import contextlib
import sqlite3
import threading
import time
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from ..routing import current_route
from ..store import get_store
from ..store.db import DATABASE_FILENAME, Locked, connect
from ..store.knowledge import database_scope
from ..store.schema import KNOWLEDGE_SCHEMA

# stdio only; team mode never opens it.
STDIO_DATABASE = Path.home() / ".u2-mcp" / DATABASE_FILENAME

EMPTY = "# U2 Database Knowledge\n\nNo knowledge has been saved yet.\n"


def _topic_name(topic: str) -> str:
    return " ".join(topic.split())


def _stamp(at: float) -> str:
    return datetime.fromtimestamp(at).strftime("%Y-%m-%d %H:%M")


class KnowledgeStore:
    """The notes in one scope.

    Args:
        locked: Yields the database connection under its lock
        scope: Hash of the normalized database server/account
    """

    def __init__(self, locked: Locked, scope: str) -> None:
        self._locked = locked
        self.scope = scope

    def _rows(self) -> list[sqlite3.Row]:
        with self._locked() as conn:
            return conn.execute(
                "SELECT topic, content, updated_at FROM knowledge WHERE scope = ? "
                "ORDER BY topic_key",
                (self.scope,),
            ).fetchall()

    def _row(self, topic: str) -> sqlite3.Row | None:
        with self._locked() as conn:
            row: sqlite3.Row | None = conn.execute(
                "SELECT topic, content, updated_at FROM knowledge "
                "WHERE scope = ? AND topic_key = ?",
                (self.scope, _topic_name(topic).lower()),
            ).fetchone()
            return row

    def get_all(self) -> str:
        """Every topic, rendered as Markdown."""
        rows = self._rows()
        if not rows:
            return EMPTY
        sections = [
            f"## {row['topic']}\n\n*Updated: {_stamp(row['updated_at'])}*\n\n{row['content']}\n"
            for row in rows
        ]
        return "# U2 Database Knowledge\n\n" + "\n".join(sections)

    def list_topics(self) -> list[dict[str, str]]:
        """Each topic with its first line as a summary."""
        topics = []
        for row in self._rows():
            first = next((line.strip() for line in row["content"].splitlines() if line.strip()), "")
            summary = first[:100] + ("..." if len(first) > 100 else "")
            topics.append({"topic": row["topic"], "summary": summary})
        return topics

    def get_topic(self, topic: str) -> str | None:
        """A topic's content, or None when there is no such topic."""
        row = self._row(topic)
        return None if row is None else str(row["content"])

    def save_topic(
        self, topic: str, content: str, append: bool = False, may_replace: bool = True
    ) -> dict[str, Any]:
        """Save a topic, replacing it or (append=True) adding to it.

        With may_replace False an existing topic can only be added to: replacing
        it would let someone who may not delete a note empty it instead.
        """
        name = _topic_name(topic)
        if not name:
            return {"status": "error", "error": "A topic name is required"}
        now = time.time()
        text = content.strip()
        with self._locked() as conn:
            existing = conn.execute(
                "SELECT topic, content FROM knowledge WHERE scope = ? AND topic_key = ?",
                (self.scope, name.lower()),
            ).fetchone()
            appended = append and existing is not None
            if existing is not None and not append and not may_replace:
                return {
                    "status": "error",
                    "error": (
                        f"Topic '{existing['topic']}' already exists and only an admin can "
                        "replace it. Use append=True to add to it."
                    ),
                }
            if existing is not None:
                name = existing["topic"]
                if appended:
                    text = f"{existing['content']}\n\n{text}"
            conn.execute(
                "INSERT INTO knowledge (scope, topic, topic_key, content, updated_at) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT (scope, topic_key) DO UPDATE SET "
                "content = excluded.content, updated_at = excluded.updated_at",
                (self.scope, name, name.lower(), text, now),
            )
        return {
            "status": "saved",
            "topic": name,
            "action": "appended" if appended else "saved",
            "timestamp": _stamp(now),
        }

    def delete_topic(self, topic: str) -> dict[str, Any]:
        """Delete a topic."""
        with self._locked() as conn:
            deleted = conn.execute(
                "DELETE FROM knowledge WHERE scope = ? AND topic_key = ?",
                (self.scope, _topic_name(topic).lower()),
            ).rowcount
        if not deleted:
            return {"status": "error", "error": f"Topic '{topic}' not found"}
        return {"status": "deleted", "topic": _topic_name(topic)}

    def search(self, query: str) -> list[dict[str, Any]]:
        """Topics whose name or lines mention the query (case-insensitive)."""
        needle = query.lower()
        results = []
        for row in self._rows():
            lines = [line.strip() for line in row["content"].splitlines() if needle in line.lower()]
            if lines or needle in row["topic"].lower():
                results.append(
                    {"topic": row["topic"], "matches": lines[:5], "match_count": len(lines)}
                )
        return results


_stdio_conn: sqlite3.Connection | None = None
_stdio_lock = threading.RLock()


@contextlib.contextmanager
def _stdio_locked() -> Iterator[sqlite3.Connection]:
    global _stdio_conn
    with _stdio_lock:
        if _stdio_conn is None:
            _stdio_conn = connect(STDIO_DATABASE)
            _stdio_conn.executescript(KNOWLEDGE_SCHEMA)
        yield _stdio_conn


def close_stdio_database() -> None:
    """Close stdio's knowledge database (tests point STDIO_DATABASE elsewhere)."""
    global _stdio_conn
    with _stdio_lock:
        if _stdio_conn is not None:
            _stdio_conn.close()
            _stdio_conn = None


def get_knowledge_store() -> KnowledgeStore:
    """Database notes reached through this call's authorized connection."""
    settings = get_store()
    if settings is not None:
        route = current_route()
        if route is None:
            raise RuntimeError("no connection was chosen for this call")
        return KnowledgeStore(
            settings.locked, database_scope(route.connection.host, route.connection.account)
        )

    from ..server import get_connection_manager  # deferred: server imports the tools

    manager = get_connection_manager()
    scope = database_scope(manager.config.host, manager.credentials.account)
    return KnowledgeStore(_stdio_locked, scope)
