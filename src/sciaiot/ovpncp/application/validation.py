"""Pure boundary validation and redaction shared by public routes."""

from sciaiot.ovpncp.utils.logging import mask_sensitive
from sciaiot.ovpncp.utils.network import is_rfc1918_ipv4_network

__all__ = ["is_rfc1918_ipv4_network", "mask_sensitive"]
