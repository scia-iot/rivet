import pytest

from sciaiot.ovpncp.utils.network import is_rfc1918_ipv4_network


@pytest.mark.parametrize(
    "value",
    [
        "10.0.0.0/8",
        "172.16.5.0/24",
        "192.168.1.8",
    ],
)
def test_accepts_canonical_rfc1918_ipv4(value: str):
    assert is_rfc1918_ipv4_network(value)


@pytest.mark.parametrize(
    "value",
    [
        "127.0.0.0/8",
        "169.254.0.0/16",
        "192.0.2.0/24",
        "8.8.8.0/24",
        "192.168.1.3/24",
        "fc00::/7",
        "not-a-network",
    ],
)
def test_rejects_non_rfc1918_or_noncanonical_network(value: str):
    assert not is_rfc1918_ipv4_network(value)


def test_can_require_explicit_cidr_notation():
    assert not is_rfc1918_ipv4_network(
        "192.168.1.8",
        require_cidr=True,
    )
    assert is_rfc1918_ipv4_network(
        "192.168.1.8/32",
        require_cidr=True,
    )
