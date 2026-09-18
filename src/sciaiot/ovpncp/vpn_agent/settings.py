"""Explicit deployment-owned identities and private observation paths."""

import dataclasses
import os
from pathlib import Path

from sciaiot.ovpncp.adapters.vpn.settings import validate_socket_path


@dataclasses.dataclass(frozen=True)
class Settings:
    """Configuration never supplied by an API request.

    Paths refer to read-only agent mounts. Socket parent ownership is checked
    again at bind/connect time; numeric identities are deployment choices.
    """

    config_path: Path
    pki_path: Path
    ccd_path: Path
    management_socket: str
    management_uid: int
    management_gid: int
    api_uid: int
    control_socket: str = "/run/ovpn-agent/agent.sock"
    ownership_path: Path | None = None

    def __post_init__(self) -> None:
        for value in (self.management_uid, self.management_gid, self.api_uid):
            if type(value) is not int or not 0 <= value < 2**32 - 1:
                raise ValueError("Explicit valid peer identities are required.")
        for socket_path in (self.management_socket, self.control_socket):
            validate_socket_path(socket_path)
        for path in (
            self.config_path,
            self.pki_path,
            self.ccd_path,
            self.ownership_path,
        ):
            if path is not None and (not path.is_absolute() or ".." in path.parts):
                raise ValueError("Canonical absolute observation paths required.")

    @classmethod
    def from_environment(cls) -> "Settings":
        """Fail startup when an explicit trust identity is missing or invalid."""
        try:

            def identity(name: str) -> int:
                value = os.environ[name]
                if not value.isascii() or not value.isdecimal():
                    raise ValueError
                return int(value)

            ownership = os.environ.get("OVPNCP_AGENT_OWNERSHIP")
            return cls(
                config_path=Path(os.environ["OVPNCP_AGENT_CONFIG"]),
                pki_path=Path(os.environ["OVPNCP_AGENT_PKI"]),
                ccd_path=Path(os.environ["OVPNCP_AGENT_CCD"]),
                management_socket=os.environ["OVPNCP_MANAGEMENT_SOCKET"],
                management_uid=identity("OVPNCP_MANAGEMENT_UID"),
                management_gid=identity("OVPNCP_MANAGEMENT_GID"),
                api_uid=identity("OVPNCP_API_UID"),
                control_socket=os.environ.get(
                    "OVPNCP_AGENT_SOCKET", "/run/ovpn-agent/agent.sock"
                ),
                ownership_path=Path(ownership) if ownership is not None else None,
            )
        except (KeyError, ValueError):
            raise ValueError(
                "Invalid or missing private agent configuration."
            ) from None
