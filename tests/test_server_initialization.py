import asyncio
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from sciaiot.rivet import dependencies
from sciaiot.rivet.data.server import Server, VirtualAddress
from sciaiot.rivet.routes.server import (
    ServerInitializationRequest,
    init_server,
)
from sciaiot.rivet.services.client_config import ClientConfigGenerationError


@pytest.fixture(name="session")
def session_fixture():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    SQLModel.metadata.drop_all(engine)
    engine.dispose()


def server_config() -> dict[str, object]:
    return {
        "port": "1194",
        "proto": "udp",
        "dev": "tun",
        "ca": "ca.crt",
        "cert": "server.crt",
        "key": "server.key",
        "dh": "dh.pem",
        "data_ciphers_fallback": "AES-256-CBC",
        "topology": "subnet",
        "server": "10.8.0.0 255.255.255.0",
        "ifconfig_pool_persist": "ipp.txt",
        "client_config_dir": "ccd",
        "ccd_exclusive": True,
        "keepalive": "10 120",
        "persist_key": True,
        "persist_tun": True,
        "status": "status.log",
        "log": "openvpn.log",
        "verb": "3",
        "explicit_exit_notify": "1",
    }


def test_commit_failure_restores_profile_and_rolls_back_rows(
    session: Session,
    tmp_path: Path,
) -> None:
    target = tmp_path / "client.ovpn"
    previous = b"client\nremote old.example.test 1194\n"
    target.write_bytes(previous)
    request = ServerInitializationRequest(remote_host="secret-vpn.example.test")

    with (
        patch.object(dependencies, "client_config_path", str(target)),
        patch(
            "sciaiot.rivet.routes.server.openvpn.get_server_config",
            return_value=server_config(),
        ),
        patch.object(session, "commit", side_effect=OSError("commit failed")),
        pytest.raises(HTTPException) as caught,
    ):
        asyncio.run(init_server(request, session, None))  # type: ignore[arg-type]

    assert caught.value.status_code == 500
    assert caught.value.detail == (
        "The server and shared client configuration could not be initialized. "
        "Check the host OpenVPN configuration and profile path, then retry."
    )
    assert str(target) not in str(caught.value.detail)
    assert request.remote_host not in str(caught.value.detail)
    assert target.read_bytes() == previous
    assert session.exec(select(Server)).all() == []
    assert session.exec(select(VirtualAddress)).all() == []


def test_profile_install_failure_persists_no_server_rows(
    session: Session,
    tmp_path: Path,
) -> None:
    target = tmp_path / "client.ovpn"
    request = ServerInitializationRequest(remote_host="vpn.example.test")

    with (
        patch.object(dependencies, "client_config_path", str(target)),
        patch(
            "sciaiot.rivet.routes.server.openvpn.get_server_config",
            return_value=server_config(),
        ),
        patch(
            "sciaiot.rivet.routes.server.replace_client_config",
            side_effect=ClientConfigGenerationError,
        ),
        pytest.raises(HTTPException) as caught,
    ):
        asyncio.run(init_server(request, session, None))  # type: ignore[arg-type]

    assert caught.value.status_code == 500
    assert not target.exists()
    assert session.exec(select(Server)).all() == []
    assert session.exec(select(VirtualAddress)).all() == []
