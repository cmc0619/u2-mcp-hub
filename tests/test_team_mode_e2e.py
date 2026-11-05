"""The real server, over real HTTP, with real tokens: who reaches what."""

import contextlib
import json
import os
import shlex
import shutil
import socket
import subprocess
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import anyio
import httpx
import pytest
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.auth.provider import AccessToken
from mcp.shared.exceptions import McpError

import u2_mcp.server as server
from tests.mocks.mock_uopy import MockSession
from u2_mcp.admin.services import curl_example
from u2_mcp.config import U2Config
from u2_mcp.identity import set_identity_resolver
from u2_mcp.store import get_store, install_store
from u2_mcp.team_auth import PatVerifier
from u2_mcp.tokens import create_token, hash_token


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.fixture
def running(mock_env: dict[str, str], mock_uopy: MockSession, tmp_path: Path) -> Iterator[Any]:
    """Serve build_streamable_http_app on a real port, in team mode without SSO.

    World: "default" (everyone = Developer) and "Test", with only alice granted (Viewer).
    """
    port = _free_port()
    env = {
        "U2_SECRET_KEY": "e" * 40,
        "U2_DATA_DIR": str(tmp_path),
        "U2_HTTP_HOST": "127.0.0.1",
        "U2_HTTP_PORT": str(port),
    }
    with patch.dict(os.environ, env):
        app = server.build_streamable_http_app(U2Config())
        store = get_store()
        assert store is not None

        viewer = store.get_role_by_name("Viewer")
        developer = store.get_role_by_name("Developer")
        assert viewer is not None and developer is not None
        default = store.add_connection(
            name="default",
            host="test-host.example.com",
            port=31438,
            service="uvcs",
            account="TEST",
            shared_user="test-user",
            shared_password="test-password",
            read_only=False,
        )
        store.add_grant(connection_id=default.id, subject_type="everyone", role_id=developer.id)
        alice = store.get_or_create_sso_user("alice")
        bob = store.get_or_create_sso_user("bob")
        store.record_sso_login(alice.id, [])
        store.record_sso_login(bob.id, [])
        test = store.add_connection(
            name="Test",
            host="test.example",
            port=1,
            service="uvcs",
            account="TRAIN",
            shared_user="tsvc",
            shared_password="t",
            read_only=False,
        )
        store.add_grant(
            connection_id=test.id,
            subject_type="user",
            subject_id=alice.id,
            role_id=viewer.id,
        )
        mock_uopy.add_file("CUSTOMERS", {"1": "SMITH"})

        with _serving(app, port):
            yield {
                "url": f"http://127.0.0.1:{port}/",
                "store": store,
                "session": mock_uopy,
                "alice": create_token(store, alice.id, "laptop")[0],
                "bob": create_token(store, bob.id, "laptop")[0],
                "alice_id": alice.id,
                "bob_id": bob.id,
                "test_id": test.id,
            }


@contextlib.contextmanager
def _serving(app: Any, port: int) -> Iterator[None]:
    """Run the app under uvicorn on a thread, and undo team mode afterwards."""
    uv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=uv.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not uv.started:
        if time.time() > deadline:
            raise RuntimeError("test server did not start")
        time.sleep(0.05)
    try:
        yield
    finally:
        uv.should_exit = True
        thread.join(10)
        install_store(None)
        set_identity_resolver(None)
        server.reset_connection_manager()


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


@pytest.mark.asyncio
async def test_each_token_sees_only_its_owners_connections(running: dict[str, Any]) -> None:
    alice = json.loads(await _call(running["url"], running["alice"], "list_connections", {}))
    bob = json.loads(await _call(running["url"], running["bob"], "list_connections", {}))
    assert [c["name"] for c in alice["connections"]] == ["Test", "default"]
    assert [c["name"] for c in bob["connections"]] == ["default"]


@pytest.mark.asyncio
async def test_a_call_reaches_the_named_server_and_no_other(running: dict[str, Any]) -> None:
    args = {"file_name": "CUSTOMERS", "record_id": "1"}
    session: MockSession = running["session"]

    await _call(running["url"], running["alice"], "read_record", {**args, "connection": "Test"})
    assert session.connect_kwargs["host"] == "test.example"

    await _call(running["url"], running["alice"], "read_record", {**args, "connection": "default"})
    assert session.connect_kwargs["host"] == "test-host.example.com"

    refused = await _call(
        running["url"], running["bob"], "read_record", {**args, "connection": "Test"}
    )
    assert "unknown connection 'Test'" in refused
    assert session.connect_kwargs["host"] == "test-host.example.com"


@pytest.mark.skipif(shutil.which("curl") is None, reason="needs curl")
def test_the_curl_example_on_my_access_initializes_a_session(running: dict[str, Any]) -> None:
    """My access's one example works as printed once the token is filled in."""
    command = curl_example(running["url"]).replace("<token>", running["alice"])
    argv = shlex.split(command.replace("\\\n", " "))  # as a shell joins continued lines
    argv[0] = shutil.which("curl") or "curl"

    done = subprocess.run([*argv, "-sS", "--fail"], capture_output=True, text=True, timeout=30)  # noqa: S603

    assert done.returncode == 0, done.stderr
    data = [line[5:] for line in done.stdout.splitlines() if line.startswith("data:")]
    result = json.loads(data[0] if data else done.stdout)["result"]
    assert result["protocolVersion"] == "2025-06-18"
    assert result["serverInfo"]["name"]


@pytest.mark.asyncio
async def test_requests_without_a_valid_token_are_turned_away(running: dict[str, Any]) -> None:
    body = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    accept = {"Accept": "application/json, text/event-stream"}
    async with httpx.AsyncClient() as client:
        missing = await client.post(running["url"], json=body, headers=accept)
        forged = await client.post(
            running["url"],
            json=body,
            headers={**accept, "Authorization": "Bearer u2pat_" + "x" * 43},
        )
    assert missing.status_code == 401
    assert forged.status_code == 401


@pytest.mark.asyncio
async def test_tool_calls_are_audited_with_the_person(running: dict[str, Any]) -> None:
    await _call(
        running["url"],
        running["alice"],
        "read_record",
        {"file_name": "CUSTOMERS", "record_id": "1", "connection": "Test"},
    )
    rows = [r for r in running["store"].recent_audit(20) if r["action"] == "read_record"]
    assert rows
    assert rows[0]["actor_user_id"] == running["alice_id"]
    assert rows[0]["connection_id"] == running["test_id"]
    assert rows[0]["outcome"] == "ok"


@pytest.mark.asyncio
async def test_a_call_without_a_connection_is_audited_with_the_one_it_used(
    running: dict[str, Any],
) -> None:
    """Bob sees only "default", so the guard picks it; the audit row must name it."""
    store = running["store"]
    default = store.get_connection_by_name("default")
    assert default is not None
    await _call(
        running["url"],
        running["bob"],
        "read_record",
        {"file_name": "CUSTOMERS", "record_id": "1"},
    )
    rows = [r for r in store.recent_audit(20) if r["action"] == "read_record"]
    assert rows
    assert rows[0]["connection_id"] == default.id


# --- One MCP session, more than one bearer token ---------------------------------
#
# The SDK runs each MCP session's server task inside the context of the request that
# opened it, so anything read from a context variable describes that first request,
# not the one carrying the current message. These tests change the bearer token
# between calls on one session and check who the server thinks is calling.

_verify_pat = PatVerifier.verify_token


async def _one_shared_client(self: PatVerifier, token: str) -> AccessToken | None:
    """Verify as usual, but report every token under one OAuth-style client id.

    This is what an OAuth deployment looks like: people sign in through the same
    registered client, so the client id cannot tell them apart. Personal tokens each
    carry their own client id, which would hide the problem being tested.
    """
    access = await _verify_pat(self, token)
    return access.model_copy(update={"client_id": "shared-client"}) if access else None


def _names(result: Any) -> list[str]:
    text = "\n".join(getattr(block, "text", "") for block in result.content)
    return [c["name"] for c in json.loads(text)["connections"]]


def _list_connections_actors(store: Any) -> list[int | None]:
    rows = [r for r in store.recent_audit(50) if r["action"] == "list_connections"]
    return [r["actor_user_id"] for r in rows]


@pytest.mark.asyncio
async def test_another_persons_token_cannot_use_a_session_as_its_opener(
    running: dict[str, Any],
) -> None:
    """Bob's token on Alice's session must never run as Alice.

    The secure outcome is a refusal at the transport: the SDK compares the caller of
    each request with the one that opened the session, and answers a mismatch with
    404 "Session not found", which the client reports as a terminated session. Bob
    can open a session of his own; he cannot borrow Alice's.
    """
    http_client = httpx.AsyncClient(headers={"Authorization": f"Bearer {running['alice']}"})
    second: Any = None
    refused: McpError | None = None
    with patch.object(PatVerifier, "verify_token", _one_shared_client):
        try:
            async with (
                streamable_http_client(running["url"], http_client=http_client) as (read, write, _),
                ClientSession(read, write) as session,
            ):
                await session.initialize()
                first = await session.call_tool("list_connections", {})
                http_client.headers["Authorization"] = f"Bearer {running['bob']}"
                with anyio.fail_after(10):
                    try:
                        second = await session.call_tool("list_connections", {})
                    except McpError as exc:
                        refused = exc
        finally:
            await http_client.aclose()

    assert _names(first) == ["Test", "default"]
    assert second is None, f"Bob's request ran in Alice's session and saw {_names(second)}"
    assert refused is not None
    assert _list_connections_actors(running["store"]) == [running["alice_id"]]


@pytest.mark.asyncio
@pytest.mark.parametrize("retire", ["revoked", "deleted"])
async def test_a_session_follows_its_person_onto_a_new_token(
    running: dict[str, Any], retire: str
) -> None:
    """A long session outlives the token that opened it, and keeps its person.

    Alice opens the session with one token, which is then retired server-side --
    revoked, or deleted the way expired OAuth access tokens are purged -- while her
    client moves on to a second valid token. The next call must still work, as Alice.
    """
    store = running["store"]
    opening = running["alice"]
    renewed, _ = create_token(store, running["alice_id"], "renewed")
    opening_record = store.get_token_by_hash(hash_token(opening))
    assert opening_record is not None

    http_client = httpx.AsyncClient(headers={"Authorization": f"Bearer {opening}"})
    with patch.object(PatVerifier, "verify_token", _one_shared_client):
        try:
            async with (
                streamable_http_client(running["url"], http_client=http_client) as (read, write, _),
                ClientSession(read, write) as session,
            ):
                await session.initialize()
                before = await session.call_tool("list_connections", {})
                http_client.headers["Authorization"] = f"Bearer {renewed}"
                if retire == "revoked":
                    store.revoke_token(opening_record.id, at=time.time())
                else:
                    store._conn.execute("DELETE FROM tokens WHERE id = ?", (opening_record.id,))
                with anyio.fail_after(10):
                    after = await session.call_tool("list_connections", {})
        finally:
            await http_client.aclose()

    assert _names(before) == ["Test", "default"]
    assert not after.isError, after.content
    assert _names(after) == ["Test", "default"]
    assert _list_connections_actors(store) == [running["alice_id"], running["alice_id"]]


@pytest.mark.asyncio
async def test_a_basic_journey_from_refusal_to_an_audited_save(running: dict[str, Any]) -> None:
    store = running["store"]
    session: MockSession = running["session"]
    session.add_program_file("BP", {"HELLO": "CRT 'HI'"})
    args = {"file_name": "BP", "program": "HELLO", "connection": "Test"}

    refused = await _call(running["url"], running["alice"], "read_program", args)
    assert "you need basic.read on Test; ask an admin" in refused

    developer = store.get_role_by_name("Developer")
    assert developer is not None
    grant = store.grants_for(running["alice_id"], [], running["test_id"])[0]
    store.update_grant(grant.id, role_id=developer.id)

    read = json.loads(
        await _call(running["url"], running["alice"], "read_program", {**args, "numbered": False})
    )
    assert read["source"] == "CRT 'HI'"
    saved = json.loads(
        await _call(
            running["url"],
            running["alice"],
            "write_program",
            {**args, "source": "CRT 'HELLO'", "expected_hash": read["hash"], "confirm": True},
        )
    )
    assert saved["status"] == "saved"
    assert session._files["BP"]["HELLO"] == "CRT 'HELLO'"

    row = next(r for r in store.recent_audit(20) if r["action"] == "write_program")
    assert row["params"]["source"] == {"chars": 11, "lines": 1, "sha256": saved["hash"]}
    assert "CRT 'HELLO'" not in json.dumps(row, default=str)
