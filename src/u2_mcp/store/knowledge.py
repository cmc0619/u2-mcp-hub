"""Database knowledge identity: notes are scoped by normalized server/account."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import sqlite3
from contextlib import suppress
from dataclasses import dataclass


def database_identity(host: str, account: str) -> tuple[str, str]:
    """Normalize server/account without resolving DNS aliases.

    Ignore surrounding whitespace, case and DNS's trailing dot; canonicalize
    numeric IP addresses, including bracketed IPv6. Account paths otherwise stay
    literal: no slash, alias or filesystem resolution.
    """
    server = host.strip().rstrip(".").casefold()
    address = server[1:-1] if server.startswith("[") and server.endswith("]") else server
    with suppress(ValueError):  # A hostname is already normalized above.
        server = str(ipaddress.ip_address(address))
    return server, account.strip().casefold()


def database_scope(host: str, account: str) -> str:
    """Hash only normalized server/account."""
    identity = json.dumps(database_identity(host, account), ensure_ascii=True)
    return "db:" + hashlib.sha256(identity.encode("utf-8")).hexdigest()


def remember_database(conn: sqlite3.Connection, host: str, account: str) -> None:
    """Retain readable identity independently of a connection's lifetime."""
    server, account = database_identity(host, account)
    conn.execute(
        "INSERT INTO knowledge_namespaces (scope, server, account) VALUES (?, ?, ?) "
        "ON CONFLICT (scope) DO NOTHING",
        (database_scope(server, account), server, account),
    )


@dataclass(frozen=True)
class KnowledgeNamespace:
    scope: str
    server: str
    account: str
    count: int

    @property
    def label(self) -> str:
        return f"{self.server} / {self.account}"


@dataclass(frozen=True)
class KnowledgeTopic:
    scope: str
    topic: str
    key: str
    content: str
    updated_at: float

    @property
    def revision(self) -> str:
        """Bind stale-edit detection to the exact database, topic and saved content."""
        value = json.dumps([self.scope, self.key, self.content, self.updated_at])
        return hashlib.sha256(value.encode("utf-8")).hexdigest()
