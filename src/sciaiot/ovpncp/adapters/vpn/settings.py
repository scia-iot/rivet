"""Fail-closed backend and trusted Unix peer configuration."""

import dataclasses
import os
from pathlib import PurePosixPath


def validate_socket_path(value: str) -> str:
    """Accept a canonical absolute filesystem Unix socket name."""
    path = PurePosixPath(value)
    if (
        not value.isascii()
        or not path.is_absolute()
        or str(path) != value
        or ".." in path.parts
        or len(value.encode()) > 107
        or any(ord(char) <= 32 or ord(char) == 127 for char in value)
        or path.name in {"", ".", ".."}
        or value == "/"
    ):
        raise ValueError(
            "OVPNCP_AGENT_SOCKET must be a canonical absolute socket path."
        )
    return value


@dataclasses.dataclass(frozen=True)
class BackendSettings:
    """Validated startup settings; agent identity never comes from a request."""

    backend: str = "host"
    socket_path: str = "/run/ovpn-agent/agent.sock"
    peer_uid: int | None = None

    @classmethod
    def from_environment(cls) -> "BackendSettings":
        """Validate all supplied settings before selecting an implementation."""
        backend = os.environ.get("OVPNCP_VPN_BACKEND", "host")
        if backend not in {"host", "agent"}:
            raise ValueError("OVPNCP_VPN_BACKEND must be host or agent.")
        path = validate_socket_path(
            os.environ.get("OVPNCP_AGENT_SOCKET", "/run/ovpn-agent/agent.sock")
        )
        uid = os.environ.get("OVPNCP_AGENT_UID")
        if uid is not None and (not uid.isascii() or not uid.isdecimal()):
            raise ValueError("OVPNCP_AGENT_UID must be a numeric trusted UID.")
        peer_uid = int(uid) if uid is not None else None
        if peer_uid is not None and not 0 <= peer_uid < 2**32 - 1:
            raise ValueError("OVPNCP_AGENT_UID is outside the supported UID range.")
        if backend == "agent" and peer_uid is None:
            raise ValueError("OVPNCP_AGENT_UID is required for the agent backend.")
        return cls(backend, path, peer_uid)
