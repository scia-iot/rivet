"""Unprivileged API service proof for the attested Phase 4 namespace runner.

The parent imports dependencies before chroot. Only a shared control socket and
an API-owned data directory and read-only entropy device are visible inside the child filesystem.
"""

import ctypes
import os
import pathlib
import subprocess
import time
import uuid
from typing import NoReturn
from unittest import mock

from sqlmodel import Session, SQLModel, create_engine

from sciaiot.ovpncp import dependencies
from sciaiot.ovpncp.adapters.vpn.agent import AgentVpnControl
from sciaiot.ovpncp.application.vpn_control import schemas as s
from sciaiot.ovpncp.application.vpn_control.errors import ControlError
from sciaiot.ovpncp.services.client_config import (
    render_client_config,
    replace_client_config,
)
from sciaiot.ovpncp.services.vpn import VpnService, get_server_config

LIBC = ctypes.CDLL(None)


class CapabilityHeader(ctypes.Structure):
    """Linux capability v3 header for checking the child's effective privileges."""

    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class CapabilityData(ctypes.Structure):
    """One 32-bit portion of each kernel capability set."""

    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]


def forbidden_process(*args: object, **kwargs: object) -> NoReturn:
    """Fail the proof if any API service attempts a local system command."""
    raise AssertionError("API attempted a local subprocess.")


def run(jail: pathlib.Path, socket_path: str) -> None:
    """Drop root and all capabilities before exercising real remote services."""
    os.chroot(jail)
    os.chdir("/")
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)
    assert os.geteuid() == 65534
    header = CapabilityHeader(0x20080522, 0)
    capabilities = (CapabilityData * 2)()
    assert LIBC.capget(ctypes.byref(header), ctypes.byref(capabilities)) == 0
    assert all(
        not item.effective and not item.permitted and not item.inheritable
        for item in capabilities
    )
    assert {path.name for path in pathlib.Path("/").iterdir()} == {"api", "run", "dev"}
    mock.patch.object(subprocess, "run", forbidden_process).start()
    mock.patch.object(subprocess, "Popen", forbidden_process).start()
    mock.patch.object(os, "system", forbidden_process).start()
    control = AgentVpnControl(socket_path, peer_uid=0)
    dependencies.vpn_control = control
    dependencies.certs_directory = "/api/certs"
    deadline = time.monotonic() + 20
    while True:
        try:
            health = control.execute(
                s.Request(request_id=str(uuid.uuid4()), command=s.Health())
            ).result
            if isinstance(health, s.HealthResult) and health.ready:
                break
        except ControlError:
            pass
        if time.monotonic() >= deadline:
            raise AssertionError("Agent unavailable to unprivileged API.")
        time.sleep(0.1)
    pathlib.Path("/api/certs").mkdir(mode=0o700)
    replacement = replace_client_config(
        "/api/client.ovpn",
        render_client_config(get_server_config(), "vpn.example.test"),
    )
    replacement.commit()
    engine = create_engine("sqlite:////api/history.sqlite3")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        service = VpnService(session)
        assert any(
            item is not None and item[0] == "existing-client"
            for item in service.discoveries()
        )
        service.change_client("api-managed", "issue")
        service.finish()
        session.commit()
        assert service.certificate("api-managed")["issued_to"] == "api-managed"
    observed = control.execute(
        s.Request(
            request_id=str(uuid.uuid4()), command=s.GetClient(client="api-managed")
        )
    ).result
    assert isinstance(observed, s.ClientResult)
    with control.open_archive(
        s.Request(
            request_id=str(uuid.uuid4()),
            command=s.Archive(
                client="api-managed", generation=observed.item.generation
            ),
        )
    ) as stream:
        assert sum(len(chunk) for chunk in stream) > 0
        assert stream.verified
    with Session(engine) as session:
        service = VpnService(session)
        service.change_client("api-managed", "delete")
        service.finish()
        session.commit()
    engine.dispose()
