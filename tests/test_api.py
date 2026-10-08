import logging
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlmodel import Session, select

from sciaiot.ovpncp import dependencies
from sciaiot.ovpncp.data.network import RestrictedNetwork
from sciaiot.ovpncp.data.server import Cert, Client, Connection, VirtualAddress
from sciaiot.ovpncp.dependencies import get_session
from sciaiot.ovpncp.main import app
from sciaiot.ovpncp.routes.server import load_from_config
from sciaiot.ovpncp.utils import openvpn
from tests.support.api import MOCKED_ROUTES, SERVER_CONFIG_LINES, SERVER_STATUS_ACTIVE


@pytest.fixture(name="client")
def client_fixture(db_session: Session) -> Generator[TestClient]:
    """Authenticate API requests against one test-local database."""

    def get_session_override() -> Session:
        return db_session

    previous_override = app.dependency_overrides.get(get_session)
    app.dependency_overrides[get_session] = get_session_override
    try:
        with (
            patch(
                "sciaiot.ovpncp.middlewares.azure_security.validate_token",
                return_value={
                    "iss": "https://login.example/tenant/v2.0",
                    "sub": "service-object-id",
                    "oid": "service-object-id",
                    "roles": ["ServiceAdmin"],
                },
            ),
            patch(
                "sciaiot.ovpncp.middlewares.azure_security.TENANT_ID",
                "mocked_tenant_id",
            ),
            patch(
                "sciaiot.ovpncp.middlewares.azure_security.APP_CLIENT_ID",
                "mocked_app_client_id",
            ),
            patch("sciaiot.ovpncp.middlewares.azure_security.USER_ROLE", "user"),
            patch("sciaiot.ovpncp.middlewares.azure_security.ADMIN_ROLE", "admin"),
            patch(
                "sciaiot.ovpncp.middlewares.azure_security.SERVICE_ADMIN_ROLE",
                "ServiceAdmin",
            ),
        ):
            client = TestClient(app)
            try:
                yield client
            finally:
                client.close()
    finally:
        if previous_override is not None:
            app.dependency_overrides[get_session] = previous_override
        else:
            app.dependency_overrides.pop(get_session, None)


@pytest.fixture
def initialized_server(db_session: Session) -> None:
    """Persist the same host server represented by the API sample config."""
    with patch("builtins.open", new_callable=mock_open, read_data=SERVER_CONFIG_LINES):
        config = openvpn.get_server_config()
    db_session.add(load_from_config(config))
    db_session.commit()


@pytest.fixture
def seeded_clients(initialized_server: None, db_session: Session) -> None:
    """Add the three clients used by client and network API scenarios."""
    issued = datetime(2026, 1, 1, tzinfo=UTC)
    expires = datetime(2027, 1, 1, tzinfo=UTC)
    for name, cidr in (
        ("test_client_1", None),
        ("test_client_2", None),
        ("test_gateway_1", "192.168.1.0/24"),
    ):
        client = Client(name=name, cidr=cidr)
        client.cert = Cert(
            issued_by="mock",
            issued_to="client",
            issued_on=issued,
            expires_on=expires,
        )
        db_session.add(client)
    db_session.commit()


@pytest.fixture
def assigned_clients(seeded_clients: None, db_session: Session) -> None:
    """Assign the addresses expected by access and client API scenarios."""
    for name, address in (
        ("test_client_1", "10.8.0.2"),
        ("test_client_2", "10.8.0.3"),
        ("test_gateway_1", "10.8.0.11"),
    ):
        client = db_session.exec(select(Client).where(Client.name == name)).one()
        virtual_address = db_session.exec(
            select(VirtualAddress).where(VirtualAddress.ip == address)
        ).one()
        client.virtual_address = virtual_address
        db_session.add(client)
    db_session.commit()


@pytest.fixture
def connected_clients(assigned_clients: None, db_session: Session) -> None:
    """Add one live connection for each ordinary client."""
    for name, remote_address in (
        ("test_client_1", "172.205.176.207:60374"),
        ("test_client_2", "172.205.176.208:60374"),
    ):
        client = db_session.exec(select(Client).where(Client.name == name)).one()
        db_session.add(
            Connection(
                client=client,
                remote_address=remote_address,
                connected_time=datetime(2026, 1, 1, tzinfo=UTC),
            )
        )
    db_session.commit()


@pytest.fixture
def restricted_networks(assigned_clients: None, db_session: Session) -> None:
    """Persist the two access grants exercised by network deletion tests."""
    for destination_name, address, private_addresses in (
        ("test_client_2", "10.8.0.3", ""),
        (
            "test_gateway_1",
            "10.8.0.11",
            "192.168.1.1,192.168.1.2,192.168.1.3",
        ),
    ):
        db_session.add(
            RestrictedNetwork(
                source_name="test_client_1",
                source_virtual_address="10.8.0.2",
                destination_name=destination_name,
                destination_virtual_address=address,
                private_network_addresses=private_addresses,
                start_time=datetime(2026, 1, 1, tzinfo=UTC),
            )
        )
    db_session.commit()


def _assert_problem_detail(response: Response, detail: str) -> None:
    """Assert the shared RFC 7807 shape while focusing on route detail."""
    problem = response.json()
    assert response.headers["content-type"].startswith("application/problem+json")
    assert problem["status"] == response.status_code
    assert problem["detail"] == detail
    assert all(key in problem for key in ("type", "title", "instance"))


@patch("builtins.open", new_callable=mock_open, read_data=SERVER_CONFIG_LINES)
def test_init_server(mock_open, client: TestClient, tmp_path: Path):
    response = client.get("/server")
    assert response.status_code == 404
    _assert_problem_detail(response, "Server not found!")

    profile_path = tmp_path / "client.ovpn"
    with patch.object(
        dependencies,
        "client_config_path",
        str(profile_path),
    ):
        response = client.post(
            "/server",
            json={"remote_host": "VPN.Example.Test."},
        )
    assert response.status_code == 200

    profile = profile_path.read_text(encoding="utf-8")
    assert "dev tun\n" in profile
    assert "proto udp\n" in profile
    assert "remote vpn.example.test 1194\n" in profile
    assert "data-ciphers-fallback AES-256-CBC\n" in profile
    assert "tls-auth" not in profile
    assert "tls-crypt" not in profile

    server = response.json()
    assert server is not None
    assert server["ip"] == "10.8.0.1"
    assert server["dev"] == "tun0"
    assert server["script_security"] == "2"
    assert server["virtual_addresses"] is not None
    assert len(server["virtual_addresses"]) == 253

    mock_open.assert_called_with("/etc/openvpn/server.conf", "r")


@pytest.mark.usefixtures("initialized_server")
def test_get_server(client: TestClient):
    response = client.get("/server")
    assert response.status_code == 200

    server = response.json()
    assert server["ip"] == "10.8.0.1"


@patch("builtins.open", new_callable=mock_open, read_data=SERVER_CONFIG_LINES)
@pytest.mark.usefixtures("initialized_server")
def test_regenerate_shared_client_profile(
    mock_open,
    client: TestClient,
    tmp_path: Path,
):
    profile_path = tmp_path / "client.ovpn"
    profile_path.write_text(
        "client\nremote old.example.test 1194\n",
        encoding="utf-8",
    )

    with patch.object(
        dependencies,
        "client_config_path",
        str(profile_path),
    ):
        response = client.put(
            "/server/client-config",
            json={"remote_host": "new.example.test"},
        )

    assert response.status_code == 204
    assert "remote new.example.test 1194\n" in profile_path.read_text()
    mock_open.assert_called_once_with("/etc/openvpn/server.conf", "r")


def test_initialize_rejects_invalid_remote_without_path_leak(
    client: TestClient,
    tmp_path: Path,
):
    profile_path = tmp_path / "should-not-exist.ovpn"
    with patch.object(
        dependencies,
        "client_config_path",
        str(profile_path),
    ):
        response = client.post(
            "/server",
            json={"remote_host": "vpn host.example"},
        )

    assert response.status_code == 422
    assert response.json()["detail"] == (
        "The request did not satisfy the API contract."
    )
    assert str(profile_path) not in response.text
    assert not profile_path.exists()


@patch("subprocess.run", return_value=MagicMock(stdout=SERVER_STATUS_ACTIVE))
def test_get_service_health(mock_run, client: TestClient):
    response = client.get("/server/health")
    assert response.status_code == 200

    health = response.json()
    assert health["status"] == "active (running)"
    assert health["period"] == "15s"

    mock_run.assert_called_once_with(
        ["systemctl", "status", "openvpn"], capture_output=True, text=True, check=True
    )


@pytest.mark.usefixtures("initialized_server")
def test_get_assignable_virtual_addresses(client: TestClient):
    response = client.get("/server/assignable-virtual-addresses")
    assert response.status_code == 200

    addresses = response.json()
    assert len(addresses) == 253


@patch("subprocess.run", return_value=MagicMock(stdout=MOCKED_ROUTES))
@pytest.mark.usefixtures("initialized_server")
def test_get_routes(mock_run, client: TestClient):
    response = client.get("/server/routes")
    assert response.status_code == 200

    routes = response.json()
    assert len(routes) == 2


@patch("sciaiot.ovpncp.utils.iproute.add")
@pytest.mark.usefixtures("initialized_server")
def test_add_route(mock_add, client: TestClient):
    response = client.post("/server/routes", json={"network": "192.168.1.0/24"})
    assert response.status_code == 204

    mock_add.assert_called_once_with("192.168.1.0/24", "10.8.0.1", "tun0")


@pytest.mark.usefixtures("initialized_server")
def test_add_wrong_route(client: TestClient):
    response = client.post("/server/routes", json={"network": "invalid_address"})
    assert response.status_code == 400
    _assert_problem_detail(response, "Only internal network address is allowed!")


@pytest.mark.parametrize(
    "network",
    [
        "127.0.0.0/8",
        "169.254.0.0/16",
        "192.0.2.0/24",
        "192.168.1.1/24",
        "192.168.1.1",
    ],
)
@pytest.mark.usefixtures("initialized_server")
def test_add_route_rejects_non_rfc1918_or_noncanonical_network(
    network: str,
    client: TestClient,
):
    with patch("sciaiot.ovpncp.utils.iproute.add") as mock_add:
        response = client.post("/server/routes", json={"network": network})

    assert response.status_code == 400
    _assert_problem_detail(response, "Only internal network address is allowed!")
    mock_add.assert_not_called()


@patch(
    "sciaiot.ovpncp.utils.iproute.add",
    side_effect=RuntimeError("route 192.168.77.0/24 failed"),
)
@pytest.mark.usefixtures("initialized_server")
def test_add_route_command_failure_is_safe(mock_add, client: TestClient, caplog):
    response = client.post("/server/routes", json={"network": "192.168.77.0/24"})

    assert response.status_code == 500
    _assert_problem_detail(
        response,
        "The server route could not be added. Check the host route service and retry.",
    )
    assert "192.168.77.0/24" not in response.text
    assert "192.168.77.0/24" not in caplog.text
    mock_add.assert_called_once()


@patch("sciaiot.ovpncp.utils.iproute.delete")
@patch(
    "sciaiot.ovpncp.utils.iproute.list",
    return_value=[
        "10.8.0.0/24 proto kernel scope link src 10.8.0.1",
        "192.168.1.0/24 via 10.8.0.1",
    ],
)
@pytest.mark.usefixtures("initialized_server")
def test_delete_route(mock_list, mock_delete, client: TestClient):
    response = client.delete("/server/routes", params={"network": "192.168.1.0/24"})
    assert response.status_code == 204

    mock_list.assert_called_once_with("tun0")
    mock_delete.assert_called_once_with("192.168.1.0/24 via 10.8.0.1", "tun0")


@patch(
    "sciaiot.ovpncp.utils.iproute.list",
    return_value=["10.8.0.0/24 proto kernel scope link src 10.8.0.1"],
)
@pytest.mark.usefixtures("initialized_server")
def test_delete_wrong_route(mock_list, client: TestClient):
    response = client.delete("/server/routes", params={"network": "192.168.1.0/24"})
    assert response.status_code == 404
    _assert_problem_detail(response, "The requested server route was not found.")

    mock_list.assert_called_once_with("tun0")


cert_details = {
    "issued_by": "mock",
    "issued_to": "client",
    "issued_on": datetime.now(UTC),
    "expires_on": datetime.now(UTC),
}


@patch("sciaiot.ovpncp.utils.openvpn.read_client_cert", return_value=cert_details)
@patch("sciaiot.ovpncp.utils.openvpn.build_client", return_value=True)
def test_create_client(mock_build_client, mock_read_client_cert, client: TestClient):
    response = client.get("/clients/test_client")
    assert response.status_code == 404
    _assert_problem_detail(response, 'Client "test_client" not found!')

    response = client.post("/clients", json={"name": "test_client_1"})
    assert response.status_code == 200

    content = response.json()
    assert content["name"] == "test_client_1"
    assert content["id"] == 1

    mock_build_client.assert_called_with("test_client_1")
    mock_read_client_cert.assert_called_with("test_client_1")

    response = client.post("/clients", json={"name": "test_client_2"})
    assert response.status_code == 200

    content = response.json()
    assert content["name"] == "test_client_2"
    assert content["id"] == 2

    mock_build_client.assert_called_with("test_client_2")
    mock_read_client_cert.assert_called_with("test_client_2")

    response = client.post(
        "/clients", json={"name": "test_gateway_1", "cidr": "192.168.1.0/24"}
    )

    content = response.json()
    assert content["name"] == "test_gateway_1"
    assert content["cidr"] == "192.168.1.0/24"

    mock_build_client.assert_called_with("test_gateway_1")
    mock_read_client_cert.assert_called_with("test_gateway_1")


@pytest.mark.usefixtures("seeded_clients")
def test_get_clients(client: TestClient):
    response = client.get("/clients")
    assert response.status_code == 200

    content = response.json()
    assert content is not None
    assert len(content) == 3


@patch("sciaiot.ovpncp.utils.openvpn.add_iroute")
@patch("sciaiot.ovpncp.utils.openvpn.assign_client_ip")
@pytest.mark.usefixtures("seeded_clients")
def test_assign_virtual_address(
    mock_assign_client_ip,
    mock_add_iroute,
    client: TestClient,
    caplog: pytest.LogCaptureFixture,
):
    caplog.set_level(logging.INFO)
    response = client.put("/clients/test_client_1/assign-ip", json={"ip": "10.0.0.1"})
    assert response.status_code == 404
    _assert_problem_detail(response, "The virtual address was not found.")

    response = client.put("/clients/test_client_1/assign-ip", json={"ip": "10.8.0.2"})
    assert response.status_code == 200

    content = response.json()
    assert content["name"] == "test_client_1"
    assert content["virtual_address"]["ip"] == "10.8.0.2"

    response = client.put("/clients/test_client_2/assign-ip", json={"ip": "10.8.0.3"})
    assert response.status_code == 200

    content = response.json()
    assert content["name"] == "test_client_2"
    assert content["virtual_address"]["ip"] == "10.8.0.3"
    application_logs = "\n".join(
        record.getMessage()
        for record in caplog.records
        if record.name.startswith("sciaiot.ovpncp")
    )
    assert "10.8.0.2" not in application_logs
    assert "10.8.0.3" not in application_logs

    caplog.clear()
    with caplog.at_level(logging.ERROR):
        response = client.put(
            "/clients/test_client_2/assign-ip", json={"ip": "10.8.0.2"}
        )
    assert response.status_code == 409
    _assert_problem_detail(
        response,
        "The virtual address is assigned to another client.",
    )
    assert "10.8.0.2" not in response.text
    assert "10.8.0.2" not in caplog.text

    response = client.get("/server/assignable-virtual-addresses")
    addresses = response.json()
    assert len(addresses) == 251

    mock_assign_client_ip.assert_called_with(
        "test_client_2", "10.8.0.3", "255.255.255.0"
    )

    caplog.clear()
    response = client.put("/clients/test_gateway_1/assign-ip", json={"ip": "10.8.0.11"})
    assert response.status_code == 200

    content = response.json()
    assert content["name"] == "test_gateway_1"
    assert content["virtual_address"]["ip"] == "10.8.0.11"
    application_logs = "\n".join(
        record.getMessage()
        for record in caplog.records
        if record.name.startswith("sciaiot.ovpncp")
    )
    assert "10.8.0.11" not in application_logs
    assert "192.168.1.0" not in application_logs

    mock_assign_client_ip.assert_called_with(
        "test_gateway_1", "10.8.0.11", "255.255.255.0"
    )
    mock_add_iroute.assert_called_with("test_gateway_1", "192.168.1.0 255.255.255.0")


@pytest.mark.usefixtures("seeded_clients")
def test_start_connection(client: TestClient):
    response = client.post(
        "/clients/test_client_1/connections",
        json={
            "remote_address": "172.205.176.207:60374",
            "connected_time": datetime.now(UTC).isoformat(),
        },
    )
    assert response.status_code == 200

    content = response.json()
    assert content["id"] is not None
    assert content["connected_time"] is not None

    response = client.post(
        "/clients/test_client_2/connections",
        json={
            "remote_address": "172.205.176.208:60374",
            "connected_time": datetime.now(UTC).isoformat(),
        },
    )
    assert response.status_code == 200


@patch("sciaiot.ovpncp.utils.iptables.apply_rules")
@patch(
    "sciaiot.ovpncp.utils.iptables.list_rules",
    return_value=["DROP all -- anywhere anywhere"],
)
@pytest.mark.usefixtures("assigned_clients")
def test_create_restricted_network(
    mock_list_rules, mock_apply_rules, client: TestClient
):
    response = client.get("/networks/1")
    assert response.status_code == 404
    _assert_problem_detail(response, "Network with ID 1 not found!")

    response = client.post(
        "/networks",
        json={
            "source_name": "test_client_1",
            "destination_name": "test_client_2",
            "private_network_addresses": "",
        },
    )
    assert response.status_code == 200

    content = response.json()
    assert content["id"] == 1
    assert content["source_virtual_address"] == "10.8.0.2"
    assert content["destination_virtual_address"] == "10.8.0.3"
    assert content["private_network_addresses"] == ""
    assert content["start_time"] is not None

    rules = [
        "-i tun0 -s 10.8.0.2 -d 10.8.0.3 -j ACCEPT",
        "-i tun0 -s 10.8.0.3 -d 10.8.0.2 -j ACCEPT",
    ]
    mock_list_rules.assert_called_with("FORWARD")
    mock_apply_rules.assert_called_with("FORWARD", 1, rules)


@patch(
    "sciaiot.ovpncp.routes.network.get_client_by_name", return_value=Client(name="N/A")
)
@pytest.mark.usefixtures("initialized_server")
def test_create_restricted_network_fail(mock_get_client_by_name, client: TestClient):
    response = client.post(
        "/networks",
        json={"source_name": "N/A", "destination_name": "another-client"},
    )
    assert response.status_code == 412

    assert mock_get_client_by_name.call_count == 2


@patch("sciaiot.ovpncp.utils.openvpn.push_client_routes")
@patch("sciaiot.ovpncp.utils.iptables.apply_rules")
@patch(
    "sciaiot.ovpncp.utils.iptables.list_rules",
    return_value=["DROP all -- anywhere anywhere"],
)
@pytest.mark.usefixtures("assigned_clients")
def test_create_restricted_network_with_private_network_addresses(
    mock_list_rules, mock_apply_rules, mock_push_client_routes, client: TestClient
):
    response = client.post(
        "/networks",
        json={
            "source_name": "test_client_1",
            "destination_name": "test_gateway_1",
            "private_network_addresses": "192.168.1.1,192.168.1.2,192.168.1.3",
        },
    )
    assert response.status_code == 200

    content = response.json()
    assert content["source_virtual_address"] == "10.8.0.2"
    assert content["destination_virtual_address"] == "10.8.0.11"
    assert content["private_network_addresses"] == "192.168.1.1,192.168.1.2,192.168.1.3"

    rules = [
        "-i tun0 -s 10.8.0.2 -d 10.8.0.11 -j ACCEPT",
        "-i tun0 -s 10.8.0.11 -d 10.8.0.2 -j ACCEPT",
        "-i tun0 -s 10.8.0.2 -d 192.168.1.1 -j ACCEPT",
        "-i tun0 -s 192.168.1.1 -d 10.8.0.2 -j ACCEPT",
        "-i tun0 -s 10.8.0.2 -d 192.168.1.2 -j ACCEPT",
        "-i tun0 -s 192.168.1.2 -d 10.8.0.2 -j ACCEPT",
        "-i tun0 -s 10.8.0.2 -d 192.168.1.3 -j ACCEPT",
        "-i tun0 -s 192.168.1.3 -d 10.8.0.2 -j ACCEPT",
    ]
    routes = [
        "192.168.1.1 255.255.255.255 10.8.0.11",
        "192.168.1.2 255.255.255.255 10.8.0.11",
        "192.168.1.3 255.255.255.255 10.8.0.11",
    ]
    mock_list_rules.assert_called_with("FORWARD")
    mock_apply_rules.assert_called_with("FORWARD", 1, rules)
    mock_push_client_routes.assert_called_with("test_client_1", routes)


@pytest.mark.parametrize(
    "private_network",
    [
        "127.0.0.1",
        "169.254.1.0/24",
        "192.0.2.0/24",
        "192.168.1.3/24",
    ],
)
@pytest.mark.usefixtures("assigned_clients")
def test_create_restricted_network_rejects_non_rfc1918_or_noncanonical_address(
    private_network: str,
    client: TestClient,
):
    with (
        patch("sciaiot.ovpncp.utils.iptables.list_rules") as mock_list_rules,
        patch("sciaiot.ovpncp.utils.iptables.apply_rules") as mock_apply_rules,
        patch("sciaiot.ovpncp.utils.openvpn.push_client_routes") as mock_push,
    ):
        response = client.post(
            "/networks",
            json={
                "source_name": "test_client_1",
                "destination_name": "test_gateway_1",
                "private_network_addresses": private_network,
            },
        )

    assert response.status_code == 422
    _assert_problem_detail(
        response,
        "The request did not satisfy the API contract.",
    )
    mock_list_rules.assert_not_called()
    mock_apply_rules.assert_not_called()
    mock_push.assert_not_called()


@pytest.mark.usefixtures("assigned_clients")
def test_create_restricted_network_rejects_identical_clients(
    client: TestClient,
):
    with (
        patch("sciaiot.ovpncp.routes.network.get_client_by_name") as mock_get_client,
        patch("sciaiot.ovpncp.utils.iptables.list_rules") as mock_list_rules,
        patch("sciaiot.ovpncp.utils.iptables.apply_rules") as mock_apply_rules,
        patch("sciaiot.ovpncp.utils.openvpn.push_client_routes") as mock_push,
    ):
        response = client.post(
            "/networks",
            json={
                "source_name": "test_client_1",
                "destination_name": "test_client_1",
            },
        )

    assert response.status_code == 400
    _assert_problem_detail(
        response,
        "Source and destination VPN clients must be different.",
    )
    mock_get_client.assert_not_called()
    mock_list_rules.assert_not_called()
    mock_apply_rules.assert_not_called()
    mock_push.assert_not_called()


@pytest.mark.usefixtures("assigned_clients")
def test_create_restricted_network_rejects_invalid_private_network(
    client: TestClient,
):
    response = client.post(
        "/networks",
        json={
            "source_name": "test_client_1",
            "destination_name": "test_gateway_1",
            "private_network_addresses": "192.168.1.0/24; unsafe",
        },
    )

    assert response.status_code == 422
    _assert_problem_detail(
        response,
        "The request did not satisfy the API contract.",
    )


@patch(
    "sciaiot.ovpncp.utils.iptables.apply_rules",
    side_effect=RuntimeError("firewall 10.8.0.2 failed"),
)
@patch(
    "sciaiot.ovpncp.utils.iptables.list_rules",
    return_value=["DROP all -- anywhere anywhere"],
)
@pytest.mark.usefixtures("assigned_clients")
def test_create_restricted_network_command_failure_is_safe(
    mock_list_rules,
    mock_apply_rules,
    client: TestClient,
    caplog,
):
    response = client.post(
        "/networks",
        json={
            "source_name": "test_client_1",
            "destination_name": "test_client_2",
        },
    )

    assert response.status_code == 500
    _assert_problem_detail(
        response,
        "The restricted network could not be created. Check the host firewall and retry.",
    )
    assert "10.8.0.2" not in response.text
    assert "10.8.0.2" not in caplog.text
    mock_list_rules.assert_called_once()
    mock_apply_rules.assert_called_once()


@pytest.mark.usefixtures("connected_clients")
def test_close_connection(client: TestClient):
    response = client.put(
        "/clients/test_client_1/connections",
        json={
            "remote_address": "10.8.0.2",
            "disconnected_time": datetime.now(UTC).isoformat(),
        },
    )
    assert response.status_code == 404
    _assert_problem_detail(
        response,
        'Connection with client "test_client_1" from "***.***.***.***" not found!',
    )

    response = client.put(
        "/clients/test_client_1/connections",
        json={
            "remote_address": "172.205.176.207:60374",
            "disconnected_time": datetime.now(UTC).isoformat(),
        },
    )
    assert response.status_code == 200

    content = response.json()
    assert content["disconnected_time"] is not None

    response = client.put(
        "/clients/test_client_2/connections",
        json={
            "remote_address": "172.205.176.208:60374",
            "disconnected_time": datetime.now(UTC).isoformat(),
        },
    )
    assert response.status_code == 200


@patch("sciaiot.ovpncp.utils.openvpn.pull_client_routes")
@patch("sciaiot.ovpncp.utils.iptables.drop_rules")
@pytest.mark.usefixtures("restricted_networks")
def test_drop_restricted_network(
    mock_drop_rules, mock_pull_client_routes, client: TestClient
):
    response = client.get("/networks")
    assert response.status_code == 200
    content = response.json()
    assert len(content) > 0
    assert content[0]["end_time"] is None

    response = client.delete("/networks/1")
    assert response.status_code == 204

    response = client.get("/networks/1")
    assert response.status_code == 200

    content = response.json()
    assert content["end_time"] is not None

    rules = [
        "-i tun0 -s 10.8.0.2 -d 10.8.0.3 -j ACCEPT",
        "-i tun0 -s 10.8.0.3 -d 10.8.0.2 -j ACCEPT",
    ]
    mock_drop_rules.assert_called_with("FORWARD", rules)

    mock_drop_rules.reset_mock()
    mock_pull_client_routes.reset_mock()
    response = client.delete("/networks/1")
    assert response.status_code == 204
    mock_drop_rules.assert_not_called()
    mock_pull_client_routes.assert_not_called()

    response = client.delete("/networks/2")
    assert response.status_code == 204

    rules = [
        "-i tun0 -s 10.8.0.2 -d 10.8.0.11 -j ACCEPT",
        "-i tun0 -s 10.8.0.11 -d 10.8.0.2 -j ACCEPT",
        "-i tun0 -s 10.8.0.2 -d 192.168.1.1 -j ACCEPT",
        "-i tun0 -s 192.168.1.1 -d 10.8.0.2 -j ACCEPT",
        "-i tun0 -s 10.8.0.2 -d 192.168.1.2 -j ACCEPT",
        "-i tun0 -s 192.168.1.2 -d 10.8.0.2 -j ACCEPT",
        "-i tun0 -s 10.8.0.2 -d 192.168.1.3 -j ACCEPT",
        "-i tun0 -s 192.168.1.3 -d 10.8.0.2 -j ACCEPT",
    ]
    mock_pull_client_routes.assert_called_with("test_client_1")
    mock_drop_rules.assert_called_with("FORWARD", rules)


@patch("sciaiot.ovpncp.utils.openvpn.unassign_client_ip")
@pytest.mark.usefixtures("assigned_clients")
def test_unassign_virtual_address(mock_unassign_client_ip, client: TestClient):
    response = client.delete("/clients/test_client_2/unassign-ip")
    assert response.status_code == 204

    response = client.delete("/clients/test_client_2/unassign-ip")
    assert response.status_code == 412

    response = client.get("/clients/test_client_2")
    assert response.status_code == 200

    content = response.json()
    assert content["virtual_address"] is None

    mock_unassign_client_ip.assert_called_with("test_client_2")


@pytest.mark.usefixtures("connected_clients")
def test_get_client(client: TestClient):
    response = client.get("/clients/test_client_1")
    assert response.status_code == 200

    content = response.json()

    assert content["name"] == "test_client_1"
    assert content["virtual_address"]["ip"] == "10.8.0.2"
    assert len(content["connections"]) == 1
    assert len(content["cert"]) is not None


@patch(
    "sciaiot.ovpncp.utils.openvpn.package_client_cert",
    return_value="/opt/ovpncp/certs/test_client_1.zip",
)
@pytest.mark.usefixtures("seeded_clients")
def test_package_client_cert(mock_package_client_cert, client: TestClient):
    response = client.put("/clients/test_client_1/package-cert")
    assert response.status_code == 204
    assert response.content == b""

    mock_package_client_cert.assert_called_once_with(
        "test_client_1", "/opt/ovpncp/certs"
    )


@patch("builtins.open", new_callable=mock_open, read_data=b"file content in bytes")
@pytest.mark.usefixtures("seeded_clients")
def test_download_client_cert(mock_open, client: TestClient):
    response = client.get("/clients/test_client_1/download-cert")
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/zip"
    assert response.content == b"file content in bytes"
    assert response.headers["Cache-Control"] == "no-store"
    assert (
        response.headers["Content-Disposition"]
        == 'attachment; filename="test_client_1.zip"'
    )
    mock_open.assert_called_once_with("/opt/ovpncp/certs/test_client_1.zip", "rb")


@patch("builtins.open", side_effect=OSError("local archive unavailable"))
@pytest.mark.usefixtures("seeded_clients")
def test_download_client_cert_uses_azure_without_local_archive(
    mock_open,
    client: TestClient,
) -> None:
    """Azure downloads do not depend on a leftover local archive."""
    downloader = MagicMock()
    downloader.readall.return_value = b"azure archive"
    blob = MagicMock()
    blob.download_blob.return_value = downloader
    container = MagicMock()
    container.get_blob_client.return_value = blob

    with (
        patch(
            "sciaiot.ovpncp.middlewares.azure_storage.STORAGE_CONNECTION_STRING",
            "configured",
        ),
        patch(
            "sciaiot.ovpncp.middlewares.azure_storage.container_client",
            container,
            create=True,
        ),
    ):
        response = client.get("/clients/test_client_1/download-cert")

    assert response.status_code == 200
    assert response.content == b"azure archive"
    assert response.headers["Cache-Control"] == "no-store"
    mock_open.assert_not_called()
    container.get_blob_client.assert_called_once_with("test_client_1.zip")


@patch("builtins.open")
@pytest.mark.usefixtures("seeded_clients")
def test_download_client_cert_failure_is_safe(
    mock_open,
    client: TestClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Local archive failures expose neither filesystem nor token details."""
    sensitive = "/server/private/archive.zip?sig=secret-token"
    mock_open.side_effect = OSError(sensitive)

    caplog.clear()
    with caplog.at_level(logging.ERROR):
        response = client.get("/clients/test_client_1/download-cert")

    assert response.status_code == 500
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["detail"] == "The certificate operation failed."
    assert sensitive not in response.text
    assert sensitive not in caplog.text


@patch("sciaiot.ovpncp.utils.openvpn.renew_client_cert", return_value=cert_details)
@pytest.mark.usefixtures("seeded_clients")
def test_renew_client(mock_renew_client_cert, client: TestClient):
    response = client.put("/clients/test_client_1/renew-cert")
    assert response.status_code == 200

    content = response.json()

    assert content["issued_by"] == "mock"
    assert content["issued_on"] is not None
    assert content["expires_on"] is not None

    mock_renew_client_cert.assert_called_once_with("test_client_1")


@patch("sciaiot.ovpncp.utils.openvpn.renew_client_cert", return_value={})
@pytest.mark.usefixtures("seeded_clients")
def test_renew_client_rejects_empty_certificate(
    mock_renew_client_cert, client: TestClient
):
    before = client.get("/clients/test_client_2").json()["cert"]

    response = client.put("/clients/test_client_2/renew-cert")

    assert response.status_code == 500
    assert response.json()["detail"] == "The certificate operation failed."
    assert client.get("/clients/test_client_2").json()["cert"] == before
    mock_renew_client_cert.assert_called_once_with("test_client_2")


@pytest.mark.parametrize(
    ("revoke_result", "crl_result"),
    [(False, True), (True, False)],
)
@patch("sciaiot.ovpncp.utils.openvpn.revoke_client")
@patch("sciaiot.ovpncp.utils.openvpn.generate_crl")
@pytest.mark.usefixtures("seeded_clients")
def test_revoke_client_rejects_unsuccessful_result(
    mock_generate_crl,
    mock_revoke_client,
    revoke_result: bool,
    crl_result: bool,
    client: TestClient,
):
    mock_revoke_client.return_value = revoke_result
    mock_generate_crl.return_value = crl_result

    response = client.put("/clients/test_client_2/revoke")

    assert response.status_code == 500
    assert response.json()["detail"] == "The certificate operation failed."
    assert client.get("/clients/test_client_2").json()["revoked"] is False


@patch("sciaiot.ovpncp.utils.openvpn.revoke_client", return_value=True)
@patch("sciaiot.ovpncp.utils.openvpn.generate_crl", return_value=True)
@pytest.mark.usefixtures("seeded_clients")
def test_revoke_client(mock_generate_crl, mock_revoke_client, client: TestClient):
    response = client.put("/clients/test_client_1/revoke")
    assert response.status_code == 200

    content = response.json()
    assert content["name"] == "test_client_1"
    assert content["revoked"] is True

    mock_generate_crl.assert_called_once()
    mock_revoke_client.assert_called_once_with("test_client_1")


@patch("sciaiot.ovpncp.utils.openvpn.list_client_certs")
@patch("sciaiot.ovpncp.utils.openvpn.read_client_cert")
@patch("sciaiot.ovpncp.utils.openvpn.read_client_ip")
@pytest.mark.usefixtures("initialized_server")
def test_import_clients(
    mock_read_ip, mock_read_cert, mock_list_certs, client: TestClient
):
    # 1. First import: two new clients, one with IP
    mock_list_certs.return_value = ["existing_client_1", "existing_client_2"]
    mock_read_cert.side_effect = [
        {
            "issued_by": "CA",
            "issued_to": "existing_client_1",
            "issued_on": datetime.now(UTC),
            "expires_on": datetime.now(UTC),
        },
        {
            "issued_by": "CA",
            "issued_to": "existing_client_2",
            "issued_on": datetime.now(UTC),
            "expires_on": datetime.now(UTC),
        },
    ]
    mock_read_ip.side_effect = ["10.8.0.11", None]

    response = client.post("/clients/import")
    assert response.status_code == 200
    assert response.json() == {
        "added": 2,
        "updated": 0,
        "clients_skipped": 0,
        "devices_created": 0,
        "devices_already_linked": 0,
        "device_conflicts": 0,
    }

    # Verify IP assignment
    response = client.get("/clients/existing_client_1")
    assert response.json()["virtual_address"]["ip"] == "10.8.0.11"

    response = client.get("/clients/existing_client_2")
    assert response.json()["virtual_address"] is None

    # 2. Second import: update existing client with new IP
    mock_list_certs.return_value = ["existing_client_2"]
    mock_read_cert.side_effect = [
        {
            "issued_by": "CA",
            "issued_to": "existing_client_2",
            "issued_on": datetime.now(UTC),
            "expires_on": datetime.now(UTC),
        }
    ]
    mock_read_ip.side_effect = ["10.8.0.12"]

    response = client.post("/clients/import")
    assert response.status_code == 200
    assert response.json() == {
        "added": 0,
        "updated": 1,
        "clients_skipped": 0,
        "devices_created": 0,
        "devices_already_linked": 0,
        "device_conflicts": 0,
    }

    response = client.get("/clients/existing_client_2")
    assert response.json()["virtual_address"]["ip"] == "10.8.0.12"

    # 3. Third import: one cert read failure
    mock_list_certs.return_value = ["fail_client"]
    mock_read_cert.side_effect = [{}]
    mock_read_ip.return_value = None

    response = client.post("/clients/import")
    assert response.status_code == 200
    assert response.json() == {
        "added": 0,
        "updated": 0,
        "clients_skipped": 1,
        "devices_created": 0,
        "devices_already_linked": 0,
        "device_conflicts": 0,
    }


@pytest.mark.parametrize(
    ("method", "path", "body", "patch_target"),
    [
        (
            "post",
            "/clients",
            {"name": "failure-client"},
            "sciaiot.ovpncp.utils.openvpn.build_client",
        ),
        (
            "put",
            "/clients/test_client_1/package-cert",
            None,
            "sciaiot.ovpncp.utils.openvpn.package_client_cert",
        ),
        (
            "put",
            "/clients/test_client_1/renew-cert",
            None,
            "sciaiot.ovpncp.utils.openvpn.renew_client_cert",
        ),
        (
            "put",
            "/clients/test_client_1/revoke",
            None,
            "sciaiot.ovpncp.utils.openvpn.revoke_client",
        ),
        (
            "post",
            "/clients/import",
            None,
            "sciaiot.ovpncp.utils.openvpn.list_client_certs",
        ),
    ],
)
@pytest.mark.usefixtures("seeded_clients")
def test_certificate_operation_failures_hide_sensitive_details(
    method: str,
    path: str,
    body: dict[str, str] | None,
    patch_target: str,
    client: TestClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Privileged certificate failures expose only fixed safe diagnostics."""
    sensitive = "/server/private/archive.zip?sig=secret-token"
    caplog.clear()
    with (
        patch(patch_target, side_effect=RuntimeError(sensitive)),
        caplog.at_level(logging.ERROR),
    ):
        response = getattr(client, method)(path, json=body)

    assert response.status_code == 500
    assert response.json()["detail"] == "The certificate operation failed."
    assert sensitive not in response.text
    assert sensitive not in caplog.text


@patch(
    "sciaiot.ovpncp.utils.openvpn.list_client_certs",
    return_value=["in-loop-client"],
)
@patch("sciaiot.ovpncp.utils.openvpn.read_client_cert")
def test_import_in_loop_failure_hides_sensitive_details(
    mock_read_cert,
    mock_list_certs,
    client: TestClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Import-loop failures use the same fixed safe boundary."""
    sensitive = "/server/private/issued/client.crt?sig=secret-token"
    mock_read_cert.side_effect = RuntimeError(sensitive)
    caplog.clear()
    with caplog.at_level(logging.ERROR):
        response = client.post("/clients/import")

    assert response.status_code == 500
    assert response.json()["detail"] == "The certificate operation failed."
    assert sensitive not in response.text
    assert sensitive not in caplog.text
    mock_list_certs.assert_called_once()
