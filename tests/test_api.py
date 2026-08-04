import os
import stat
from datetime import datetime, timezone
from unittest.mock import MagicMock, mock_open, patch

import pytest
from fastapi.testclient import TestClient
from httpx import Response

from sciaiot.ovpncp.data.server import Client
from sciaiot.ovpncp.dependencies import get_session
from sciaiot.ovpncp.main import app
from tests import test_iproute, test_openvpn


@pytest.fixture(name="client")
def client_fixture(db_session):
    def get_session_override():
        return db_session

    app.dependency_overrides[get_session] = get_session_override

    with (
        patch(
            "sciaiot.ovpncp.middlewares.azure_security.validate_token",
            return_value={"sub": "mocked_sub"},
        ),
        patch(
            "sciaiot.ovpncp.middlewares.azure_security.TENANT_ID", "mocked_tenant_id"
        ),
        patch(
            "sciaiot.ovpncp.middlewares.azure_security.APP_CLIENT_ID",
            "mocked_app_client_id",
        ),
        patch(
            "sciaiot.ovpncp.middlewares.azure_security.APP_ROLE",
            "mocked_app_role",
        ),
    ):
        client = TestClient(app)
        yield client

    app.dependency_overrides.clear()


def _assert_problem_detail(response: Response, detail: str) -> None:
    """Assert the shared RFC 7807 shape while focusing on route detail."""
    problem = response.json()
    assert response.headers["content-type"].startswith("application/problem+json")
    assert problem["status"] == response.status_code
    assert problem["detail"] == detail
    assert all(key in problem for key in ("type", "title", "instance"))


@patch(
    "builtins.open", new_callable=mock_open, read_data=test_openvpn.server_config_lines
)
def test_init_server(mock_open, client: TestClient):
    response = client.get("/server")
    assert response.status_code == 404
    _assert_problem_detail(response, "Server not found!")

    response = client.post("/server")
    assert response.status_code == 200

    server = response.json()
    assert server is not None
    assert server["ip"] == "10.8.0.1"
    assert server["dev"] == "tun0"
    assert server["script_security"] == "2"
    assert server["virtual_addresses"] is not None
    assert len(server["virtual_addresses"]) == 253

    mock_open.assert_called_with("/etc/openvpn/server.conf", "r")


def test_get_server(client: TestClient):
    response = client.get("/server")
    assert response.status_code == 200

    server = response.json()
    assert server["ip"] == "10.8.0.1"


@patch(
    "subprocess.run", return_value=MagicMock(stdout=test_openvpn.server_status_active)
)
def test_get_service_health(mock_run, client: TestClient):
    response = client.get("/server/health")
    assert response.status_code == 200

    health = response.json()
    assert health["status"] == "active (running)"
    assert health["period"] == "15s"

    mock_run.assert_called_once_with(
        ["systemctl", "status", "openvpn"], capture_output=True, text=True, check=True
    )


def test_get_assignable_virtual_addresses(client: TestClient):
    response = client.get("/server/assignable-virtual-addresses")
    assert response.status_code == 200

    addresses = response.json()
    assert len(addresses) == 253


@patch("subprocess.run", return_value=MagicMock(stdout=test_iproute.mocked_routes))
def test_get_routes(mock_run, client: TestClient):
    response = client.get("/server/routes")
    assert response.status_code == 200

    routes = response.json()
    assert len(routes) == 2


@patch("sciaiot.ovpncp.utils.iproute.add")
def test_add_route(mock_add, client: TestClient):
    response = client.post("/server/routes", json={"network": "192.168.1.0/24"})
    assert response.status_code == 204

    mock_add.assert_called_once_with("192.168.1.0/24", "10.8.0.1", "tun0")


def test_add_wrong_route(client: TestClient):
    response = client.post("/server/routes", json={"network": "invalid_address"})
    assert response.status_code == 400
    _assert_problem_detail(response, "Only internal network address is allowed!")


@patch("sciaiot.ovpncp.utils.iproute.delete")
@patch(
    "sciaiot.ovpncp.utils.iproute.list",
    return_value=[
        "10.8.0.0/24 proto kernel scope link src 10.8.0.1",
        "192.168.1.0/24 via 10.8.0.1",
    ],
)
def test_delete_route(mock_list, mock_delete, client: TestClient):
    response = client.delete("/server/routes", params={"network": "192.168.1.0/24"})
    assert response.status_code == 204

    mock_list.assert_called_once_with("tun0")
    mock_delete.assert_called_once_with("192.168.1.0/24 via 10.8.0.1", "tun0")


@patch(
    "sciaiot.ovpncp.utils.iproute.list",
    return_value=["10.8.0.0/24 proto kernel scope link src 10.8.0.1"],
)
def test_delete_wrong_route(mock_list, client: TestClient):
    response = client.delete("/server/routes", params={"network": "192.168.1.0/24"})
    assert response.status_code == 404
    _assert_problem_detail(response, 'Network "192.168.1.0/24" not found in routes!')

    mock_list.assert_called_once_with("tun0")


cert_details = {
    "issued_by": "mock",
    "issued_to": "client",
    "issued_on": datetime.now(timezone.utc),
    "expires_on": datetime.now(timezone.utc),
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


def test_get_clients(client: TestClient):
    response = client.get("/clients")
    assert response.status_code == 200

    content = response.json()
    assert content is not None
    assert len(content) == 3


@patch("sciaiot.ovpncp.utils.openvpn.add_iroute")
@patch("sciaiot.ovpncp.utils.openvpn.assign_client_ip")
def test_assign_virtual_address(
    mock_assign_client_ip, mock_add_iroute, client: TestClient
):
    response = client.put("/clients/test_client_1/assign-ip", json={"ip": "10.0.0.1"})
    assert response.status_code == 404
    _assert_problem_detail(response, 'Virtual address with IP "10.0.0.1" not found!')

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

    response = client.get("/server/assignable-virtual-addresses")
    addresses = response.json()
    assert len(addresses) == 251

    mock_assign_client_ip.assert_called_with(
        "test_client_2", "10.8.0.3", "255.255.255.0"
    )

    response = client.put("/clients/test_gateway_1/assign-ip", json={"ip": "10.8.0.11"})
    assert response.status_code == 200

    content = response.json()
    assert content["name"] == "test_gateway_1"
    assert content["virtual_address"]["ip"] == "10.8.0.11"

    mock_assign_client_ip.assert_called_with(
        "test_gateway_1", "10.8.0.11", "255.255.255.0"
    )
    mock_add_iroute.assert_called_with("test_gateway_1", "192.168.1.0 255.255.255.0")


def test_start_connection(client: TestClient):
    response = client.post(
        "/clients/test_client_1/connections",
        json={
            "remote_address": "172.205.176.207:60374",
            "connected_time": datetime.now(timezone.utc).isoformat(),
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
            "connected_time": datetime.now(timezone.utc).isoformat(),
        },
    )
    assert response.status_code == 200


@patch("sciaiot.ovpncp.utils.iptables.apply_rules")
@patch(
    "sciaiot.ovpncp.utils.iptables.list_rules",
    return_value=["DROP all -- anywhere anywhere"],
)
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
def test_create_restricted_network_fail(mock_get_client_by_name, client: TestClient):
    response = client.post(
        "/networks", json={"source_name": "N/A", "destination_name": "N/A"}
    )
    assert response.status_code == 412

    assert mock_get_client_by_name.call_count == 2


@patch("sciaiot.ovpncp.utils.openvpn.push_client_routes")
@patch("sciaiot.ovpncp.utils.iptables.apply_rules")
@patch(
    "sciaiot.ovpncp.utils.iptables.list_rules",
    return_value=["DROP all -- anywhere anywhere"],
)
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


def test_close_connection(client: TestClient):
    response = client.put(
        "/clients/test_client_1/connections",
        json={
            "remote_address": "10.8.0.2",
            "disconnected_time": datetime.now(timezone.utc).isoformat(),
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
            "disconnected_time": datetime.now(timezone.utc).isoformat(),
        },
    )
    assert response.status_code == 200

    content = response.json()
    assert content["disconnected_time"] is not None

    response = client.put(
        "/clients/test_client_2/connections",
        json={
            "remote_address": "172.205.176.208:60374",
            "disconnected_time": datetime.now(timezone.utc).isoformat(),
        },
    )
    assert response.status_code == 200


@patch("sciaiot.ovpncp.utils.openvpn.pull_client_routes")
@patch("sciaiot.ovpncp.utils.iptables.drop_rules")
def test_drop_restricted_network(
    mock_drop_rules, mock_pull_client_routes, client: TestClient
):
    response = client.get("/networks?source_name=test_client_1")
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
def test_package_client_cert(mock_package_client_cert, client: TestClient):
    response = client.put("/clients/test_client_1/package-cert")
    assert response.status_code == 200

    content = response.json()
    assert content["file_path"] == "/opt/ovpncp/certs/test_client_1.zip"

    mock_package_client_cert.assert_called_once_with(
        "test_client_1", "/opt/ovpncp/certs"
    )


@patch("builtins.open", new_callable=mock_open, read_data=b"file content in bytes")
@patch("os.stat")
def test_download_client_cert(mock_stat, mock_open, client: TestClient):
    mode = stat.S_IFREG | 0o644
    mock_stat_result = os.stat_result((mode, 0, 0, 0, 0, 0, 1024, 0, 0, 0))
    mock_stat.return_value = mock_stat_result

    response = client.get("/clients/test_client_1/download-cert")
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/octet-stream"
    assert response.headers["Content-Length"] == "1024"
    assert (
        response.headers["Content-Disposition"]
        == 'attachment; filename="test_client_1.zip"'
    )

    mock_stat.assert_called_with("/opt/ovpncp/certs/test_client_1.zip")
    mock_open.assert_called_with(
        "/opt/ovpncp/certs/test_client_1.zip", "rb", -1, None, None, None, True, None
    )


@patch("sciaiot.ovpncp.utils.openvpn.renew_client_cert", return_value=cert_details)
def test_renew_client(mock_renew_client_cert, client: TestClient):
    response = client.put("/clients/test_client_1/renew-cert")
    assert response.status_code == 200

    content = response.json()

    assert content["issued_by"] == "mock"
    assert content["issued_on"] is not None
    assert content["expires_on"] is not None

    mock_renew_client_cert.assert_called_once_with("test_client_1")


@patch("sciaiot.ovpncp.utils.openvpn.revoke_client", return_value=True)
@patch("sciaiot.ovpncp.utils.openvpn.generate_crl", return_value=True)
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
def test_import_clients(
    mock_read_ip, mock_read_cert, mock_list_certs, client: TestClient
):
    # 1. First import: two new clients, one with IP
    mock_list_certs.return_value = ["existing_client_1", "existing_client_2"]
    mock_read_cert.side_effect = [
        {
            "issued_by": "CA",
            "issued_to": "existing_client_1",
            "issued_on": datetime.now(timezone.utc),
            "expires_on": datetime.now(timezone.utc),
        },
        {
            "issued_by": "CA",
            "issued_to": "existing_client_2",
            "issued_on": datetime.now(timezone.utc),
            "expires_on": datetime.now(timezone.utc),
        },
    ]
    mock_read_ip.side_effect = ["10.8.0.11", None]

    response = client.post("/clients/import")
    assert response.status_code == 200
    assert response.json() == {"added": 2, "updated": 0}

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
            "issued_on": datetime.now(timezone.utc),
            "expires_on": datetime.now(timezone.utc),
        }
    ]
    mock_read_ip.side_effect = ["10.8.0.12"]

    response = client.post("/clients/import")
    assert response.status_code == 200
    assert response.json() == {"added": 0, "updated": 1}

    response = client.get("/clients/existing_client_2")
    assert response.json()["virtual_address"]["ip"] == "10.8.0.12"

    # 3. Third import: one cert read failure
    mock_list_certs.return_value = ["fail_client"]
    mock_read_cert.side_effect = [{}]
    mock_read_ip.return_value = None

    response = client.post("/clients/import")
    assert response.status_code == 200
    assert response.json() == {"added": 0, "updated": 0}
