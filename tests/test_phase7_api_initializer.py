"""Operator bootstrap keeps imported VPN identities aligned with a fresh API."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from sciaiot.ovpncp import dependencies
from sciaiot.ovpncp.data.server import Client, Server
from tests.integration.phase7_api_initializer import (
    BootstrapError,
    initialize,
    read_remote_host,
)


@pytest.fixture(name="session")
def session_fixture():
    """Provide a separate empty API database for each operator run."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


def _configuration() -> dict[str, object]:
    """Return a small projection matching the agent's public config shape."""
    return {
        "port": "1194",
        "proto": "udp",
        "dev": "tun0",
        "ca": "agent-managed",
        "cert": "agent-managed",
        "key": "agent-managed",
        "dh": "agent-managed",
        "data_ciphers_fallback": "AES-256-CBC",
        "topology": "subnet",
        "server": "10.8.0.0 255.255.255.0",
        "ip": "10.8.0.1",
        "ifconfig_pool_persist": "agent-managed",
        "client_config_dir": "agent-managed",
        "ccd_exclusive": True,
        "keepalive": "10 120",
        "persist_key": True,
        "persist_tun": True,
        "status": "agent-managed",
        "log": "agent-managed",
        "verb": "3",
        "explicit_exit_notify": "1",
    }


def _discoveries():
    """Return one active assigned client and one revoked identity."""
    now = datetime.now(timezone.utc)
    return [
        (
            "kept_client",
            {
                "issued_by": "CA",
                "issued_to": "kept_client",
                "issued_on": now - timedelta(days=1),
                "expires_on": now + timedelta(days=1),
            },
            "10.8.0.11",
        ),
        None,
    ]


def test_operator_initializer_imports_only_active_client(
    session: Session, tmp_path: Path
) -> None:
    """An exact preflight creates API rows and a public shared profile."""
    profile = tmp_path / "client.ovpn"
    with (
        patch.object(dependencies, "client_config_path", str(profile)),
        patch(
            "sciaiot.ovpncp.routes.server.openvpn.get_server_config",
            return_value=_configuration(),
        ),
        patch(
            "tests.integration.phase7_api_initializer.VpnService.discoveries",
            return_value=_discoveries(),
        ),
    ):
        outcome = initialize(
            session,
            remote_host="vpn.example.test",
            expected_active=1,
            expected_assigned=1,
        )

    assert outcome == {"active": 1, "assigned": 1, "skipped": 1}
    assert len(session.exec(select(Server)).all()) == 1
    clients = session.exec(select(Client)).all()
    assert [item.name for item in clients] == ["kept_client"]
    assert clients[0].virtual_address is not None
    assert clients[0].virtual_address.ip == "10.8.0.11"
    assert b"remote vpn.example.test 1194\n" in profile.read_bytes()


@pytest.mark.parametrize(
    ("active", "assigned"),
    [(2, 1), (1, 0)],
)
def test_operator_initializer_fails_before_writes_on_inventory_mismatch(
    session: Session, tmp_path: Path, active: int, assigned: int
) -> None:
    """A wrong reviewed baseline cannot create API state or a profile."""
    profile = tmp_path / "client.ovpn"
    with (
        patch.object(dependencies, "client_config_path", str(profile)),
        patch(
            "tests.integration.phase7_api_initializer.VpnService.discoveries",
            return_value=_discoveries(),
        ),
        pytest.raises(BootstrapError, match="inventory"),
    ):
        initialize(
            session,
            remote_host="vpn.example.test",
            expected_active=active,
            expected_assigned=assigned,
        )

    assert session.exec(select(Server)).all() == []
    assert session.exec(select(Client)).all() == []
    assert not profile.exists()


def test_operator_endpoint_file_rejects_symlink_and_open_mode(
    tmp_path: Path,
) -> None:
    """Operator input cannot redirect reads or expose the endpoint to peers."""
    endpoint = tmp_path / "endpoint"
    endpoint.write_text("vpn.example.test\n", encoding="ascii")
    endpoint.chmod(0o600)
    assert read_remote_host(endpoint) == "vpn.example.test"

    alias = tmp_path / "alias"
    alias.symlink_to(endpoint)
    with pytest.raises(OSError):
        read_remote_host(alias)

    endpoint.chmod(0o644)
    with pytest.raises(BootstrapError, match="endpoint file"):
        read_remote_host(endpoint)
