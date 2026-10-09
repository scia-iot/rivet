"""Validation helpers for network values used by privileged operations."""

import ipaddress

_RFC1918_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)


def is_rfc1918_ipv4_network(
    value: str,
    *,
    require_cidr: bool = False,
) -> bool:
    """Return whether a value is a canonical RFC 1918 IPv4 network.

    A bare IPv4 address is treated as a single-host network unless explicit
    CIDR notation is required. CIDR values containing host bits, IPv6 values,
    and non-RFC 1918 special-use ranges are rejected.

    Args:
        value: IPv4 address or network text to validate.
        require_cidr: Require an explicit prefix length when true.

    Returns:
        True when the value is canonical and wholly contained in RFC 1918.
    """
    if require_cidr and "/" not in value:
        return False

    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError:
        return False

    if not isinstance(network, ipaddress.IPv4Network):
        return False
    return any(network.subnet_of(private) for private in _RFC1918_NETWORKS)
