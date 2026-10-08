"""Explicit deployment-owned identities and private observation paths."""

import dataclasses
import os
from pathlib import Path

from sciaiot.ovpncp.adapters.vpn.settings import validate_socket_path


@dataclasses.dataclass(frozen=True)
class Settings:
    """Configuration never supplied by an API request.

    Paths refer to deployment-owned agent state and runtime projections.
    Mutation families explicitly opt into writes. Socket parent ownership is
    checked at bind/connect time; numeric identities are deployment choices.
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

    event_uid: int | None = None
    event_socket: str | None = None
    journal_path: Path | None = None
    mutation_families: frozenset[str] = frozenset()
    route_protocol: int | None = None
    easyrsa_path: Path = Path("/usr/share/easy-rsa/easyrsa")
    projection_path: Path | None = None

    def __post_init__(self) -> None:
        allowed = {"assignments", "routes", "access", "pki", "events", "management"}
        if not self.mutation_families <= allowed:
            raise ValueError("Unknown agent mutation family.")
        if self.mutation_families and self.journal_path is None:
            raise ValueError("Mutation families require a durable journal.")
        if self.route_protocol is not None and (
            type(self.route_protocol) is not int or not 1 <= self.route_protocol <= 255
        ):
            raise ValueError("An operator-allocated route protocol is required.")
        if "routes" in self.mutation_families and self.route_protocol is None:
            raise ValueError("Route writes require an allocated protocol.")
        for value in (
            self.management_uid,
            self.management_gid,
            self.api_uid,
            self.event_uid if self.event_uid is not None else self.management_uid,
        ):
            if type(value) is not int or not 0 <= value < 2**32 - 1:
                raise ValueError("Explicit valid peer identities are required.")
        if self.event_socket is not None:
            validate_socket_path(self.event_socket)
        if "events" in self.mutation_families and self.event_socket is None:
            raise ValueError("Events require a protected local producer socket.")
        for socket_path in (self.management_socket, self.control_socket):
            validate_socket_path(socket_path)
        for path in (
            self.config_path,
            self.pki_path,
            self.ccd_path,
            self.ownership_path,
            self.journal_path,
            self.easyrsa_path,
            self.projection_path,
        ):
            if path is not None and (not path.is_absolute() or ".." in path.parts):
                raise ValueError("Canonical absolute observation paths required.")

    @classmethod
    def from_environment(cls) -> Settings:
        """Fail startup when an explicit trust identity is missing or invalid."""
        try:

            def identity(name: str) -> int:
                value = os.environ[name]
                if not value.isascii() or not value.isdecimal():
                    raise ValueError
                return int(value)

            ownership = os.environ.get("OVPNCP_AGENT_OWNERSHIP")
            journal = os.environ.get("OVPNCP_AGENT_JOURNAL")
            projection = os.environ.get("OVPNCP_AGENT_PROJECTION")
            protocol = os.environ.get("OVPNCP_AGENT_ROUTE_PROTOCOL")
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
                journal_path=Path(journal) if journal is not None else None,
                event_socket=os.environ.get("OVPNCP_AGENT_EVENT_SOCKET"),
                event_uid=identity("OVPNCP_OPENVPN_UID")
                if "OVPNCP_OPENVPN_UID" in os.environ
                else None,
                projection_path=Path(projection) if projection is not None else None,
                route_protocol=int(protocol) if protocol is not None else None,
                mutation_families=frozenset(
                    filter(
                        None, os.environ.get("OVPNCP_AGENT_MUTATIONS", "").split(",")
                    )
                ),
                easyrsa_path=Path(
                    os.environ.get(
                        "OVPNCP_AGENT_EASYRSA", "/usr/share/easy-rsa/easyrsa"
                    )
                ),
            )
        except KeyError, ValueError:
            raise ValueError(
                "Invalid or missing private agent configuration."
            ) from None
