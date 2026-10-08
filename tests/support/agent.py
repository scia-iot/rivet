"""Disposable agent settings and request builders for agent tests."""

import os
import uuid
from pathlib import Path

from sciaiot.ovpncp.application.vpn_control import schemas as s
from sciaiot.ovpncp.vpn_agent.settings import Settings

STATUS = (
    "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\t"
    "Connected Since (time_t)\tClient ID\tPeer ID\n"
    "CLIENT_LIST\talpha\t192.0.2.1:1234\t10.8.0.10\t1700000000\t0\t1"
)


def settings(tmp_path: Path) -> Settings:
    """Build explicit disposable agent settings."""
    return Settings(
        config_path=tmp_path / "server.conf",
        pki_path=tmp_path / "pki",
        ccd_path=tmp_path / "ccd",
        management_socket=str(tmp_path / "management.sock"),
        management_uid=os.getuid(),
        management_gid=os.getgid(),
        api_uid=os.getuid(),
        control_socket=str(tmp_path / "agent.sock"),
    )


def request(command: s.Command) -> s.Request:
    """Create a valid request including mutation fencing where required."""
    return s.Request(
        request_id=str(uuid.uuid4()),
        command=command,
        operation_id=str(uuid.uuid4()) if command.kind in s.MUTATION_KINDS else None,
        expected_generation=0 if command.kind in s.MUTATION_KINDS else None,
    )
