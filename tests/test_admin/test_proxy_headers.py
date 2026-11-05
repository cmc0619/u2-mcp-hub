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
        tmp_path,
        monkeypatch,
        client=PROXY_PEER,
        U2_TRUSTED_PROXIES="10.0.0.1",
        U2_ADMIN_ALLOWED_IPS="203.0.113.7",
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
            data = {
                "csrf_token": csrf_from(page.text),
                "username": username,
                "password": "wrong",
                "next": "",
            }
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
    monkeypatch.setattr(server, "build_streamable_http_app", lambda config: object())
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: seen.update(kwargs))
    server.run_streamable_http_server()
    assert seen["proxy_headers"] is False


def test_tls_files_are_handed_to_uvicorn(
    monkeypatch: pytest.MonkeyPatch, mock_env: dict[str, str], tmp_path: Path
) -> None:
    seen: dict[str, object] = {}
    cert, key_file = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert.write_text("cert")
    key_file.write_text("key")
    for key, value in {
        "U2_TLS_CERT": str(cert),
        "U2_TLS_KEY": str(key_file),
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(server, "build_streamable_http_app", lambda config: object())
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: seen.update(kwargs))
    server.run_streamable_http_server()
    assert seen["ssl_certfile"] == str(cert) and seen["ssl_keyfile"] == str(key_file)


def test_a_certificate_without_its_key_is_refused(
    monkeypatch: pytest.MonkeyPatch, mock_env: dict[str, str]
) -> None:
    from u2_mcp.config import U2Config

    monkeypatch.setenv("U2_TLS_CERT", "/certs/cert.pem")
    with pytest.raises(ValueError, match="U2_TLS_CERT and U2_TLS_KEY"):
        U2Config()
