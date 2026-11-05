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
        (
            "10.0.0.2",
            _h(x_forwarded_for="6.6.6.6, 198.51.100.1, 10.0.0.3"),
            PROXY,
            ("198.51.100.1", "http"),
        ),
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
    [
        ("1.2.3.4", "1.2.3.4"),
        ("1.2.3.4:5678", "1.2.3.4"),
        ("[::1]", "::1"),
        ("::ffff:1.2.3.4", "1.2.3.4"),
        ("nope", None),
        ("", None),
    ],
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
