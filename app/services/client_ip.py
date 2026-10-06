"""Client-IP resolution with an explicit trusted-proxy policy (FG-167).

Rules (nothing here assumes a particular hosting topology):

* The identity of a request is the address of the TCP peer. ``X-Forwarded-For`` is attacker-controlled text and is
  ignored UNLESS the peer itself is a configured trusted proxy (``TRUSTED_PROXIES``: explicit IPs / CIDR ranges;
  empty by default; wildcards are rejected).
* For a trusted peer the chain is read right-to-left (each hop appends the address it received the request
  from), skipping hops that are themselves trusted proxies; the first untrusted hop is the client. The left-most
  entry is never used: it is whatever the client wrote.
* Anything malformed, oversized or entirely trusted falls back to the peer. Garbage is never trusted.
* ``X-Real-IP`` and every other forwarding header are not consulted.
* Addresses are normalised (IPv6 compressed, IPv4-mapped IPv6 -> IPv4, port / brackets / zone stripped) so the same
  client cannot get several rate-limit keys by varying the spelling.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable, Optional, Sequence, Union

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

MAX_HEADER_CHARS = 2000
MAX_HOPS = 40


def parse_trusted_proxies(value: str | None) -> tuple[IPNetwork, ...]:
    """Parse ``"10.0.0.1, 100.64.0.0/10, ::1"``. Empty -> nothing trusted. Invalid or wildcard -> ValueError
    (a typo must stop the app, not silently trust nobody - or everybody)."""
    out: list[IPNetwork] = []
    for raw in (value or "").split(","):
        item = raw.strip()
        if not item:
            continue
        if item in ("*", "0.0.0.0/0", "::/0") or item.endswith("/0"):
            raise ValueError(
                "TRUSTED_PROXIES must list explicit proxy addresses/ranges; a wildcard or /0 would let any "
                "client choose its own IP"
            )
        try:
            out.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            raise ValueError(
                "TRUSTED_PROXIES contains an entry that is not an IP address or CIDR range"
            ) from None
    return tuple(out)


def _to_address(text: str) -> Optional[IPAddress]:
    """Parse one address as it can appear in a forwarding chain; None if it is not a plain IP."""
    s = text.strip().strip('"')
    if not s or len(s) > 64:
        return None
    if s.startswith("["):  # [v6] or [v6]:port
        end = s.find("]")
        if end < 0:
            return None
        s = s[1:end]
    elif s.count(":") == 1:  # v4:port
        s = s.split(":", 1)[0]
    s = s.split("%", 1)[0]  # zone id
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def normalize_ip(text: str | None) -> Optional[str]:
    addr = _to_address(text or "")
    return addr.compressed if addr is not None else None


def _is_trusted(addr: IPAddress, trusted: Sequence[IPNetwork]) -> bool:
    return any(addr.version == net.version and addr in net for net in trusted)


def resolve_client_ip(
    peer: str | None,
    forwarded_for: str | None,
    trusted: Iterable[IPNetwork] = (),
) -> str:
    """The client identity to rate-limit / attribute on. ``peer`` is the socket peer, ``forwarded_for`` the
    (joined) X-Forwarded-For header value, ``trusted`` the parsed TRUSTED_PROXIES."""
    trusted = tuple(trusted)
    peer_addr = _to_address(peer or "")
    # A non-IP peer string (test clients, unix sockets) cannot be spoofed by a request header: keep it verbatim.
    peer_id = (
        peer_addr.compressed
        if peer_addr is not None
        else (peer or "unknown").strip() or "unknown"
    )
    if not trusted or peer_addr is None or not _is_trusted(peer_addr, trusted):
        return peer_id
    if not forwarded_for or len(forwarded_for) > MAX_HEADER_CHARS:
        return peer_id
    hops = [h for h in forwarded_for.split(",")]
    if len(hops) > MAX_HOPS:
        return peer_id
    for hop in reversed(hops):
        addr = _to_address(hop)
        if addr is None:
            return peer_id  # malformed hop: do not guess
        if _is_trusted(addr, trusted):
            continue
        return addr.compressed
    return peer_id
