"""Believe X-Forwarded-* headers only from the reverse proxies named in U2_TRUSTED_PROXIES.

Behind a proxy every request arrives from the proxy's address. Without this, one
person's failed sign-ins would lock everyone out (the limiter keys on address),
U2_ADMIN_ALLOWED_IPS would see only the proxy, and https would look like http.

Anyone can send these headers, so they are believed only when the direct peer is
a configured proxy. X-Forwarded-For is walked from the right, the end the proxies
appended to, and the first address that is not itself a trusted proxy is the
client. Entries further left were written by the client and are ignored.
X-Forwarded-Host is not applied: every URL this server builds comes from its
saved public address.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
Address = ipaddress.IPv4Address | ipaddress.IPv6Address


def parse_ip(value: str) -> Address | None:
    """Parse one address as proxies write it: bare, bracketed, or IPv4 with a port."""
    text = value.strip()
    if text.startswith("[") and "]" in text:
        text = text[1 : text.index("]")]
    elif text.count(":") == 1 and "." in text:
        text = text.split(":", 1)[0]
    try:
        address: Address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _trusted(address: Address, networks: Sequence[Network]) -> bool:
    return any(address in network for network in networks)


def _values(headers: Sequence[tuple[bytes, bytes]], name: bytes) -> list[str]:
    found: list[str] = []
    for key, value in headers:
        if key.lower() == name:
            found += [part.strip() for part in value.decode("latin-1").split(",")]
    return [part for part in found if part]


def resolve(
    peer: str | None,
    headers: Sequence[tuple[bytes, bytes]],
    scheme: str,
    trusted: Sequence[Network],
) -> tuple[str | None, str]:
    """Return the address and scheme the request really came from.

    Args:
        peer: The direct peer's address (ASGI scope["client"][0])
        headers: The raw ASGI headers
        scheme: The scheme of the connection to this server
        trusted: U2_TRUSTED_PROXIES as networks

    Returns:
        (client address, scheme); the peer and scheme unchanged unless the peer
        is a trusted proxy
    """
    peer_address = parse_ip(peer) if peer else None
    if peer_address is None or not _trusted(peer_address, trusted):
        return peer, scheme
    client = str(peer_address)
    for hop in reversed(_values(headers, b"x-forwarded-for")):
        address = parse_ip(hop)
        if address is None:
            break  # unreadable: keep the last address a trusted proxy vouched for
        client = str(address)
        if not _trusted(address, trusted):
            break
    protos = _values(headers, b"x-forwarded-proto")
    if protos and protos[-1].lower() in ("http", "https"):
        scheme = protos[-1].lower()
    return client, scheme
