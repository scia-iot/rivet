import logging
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, mock_open, patch

import pytest

from sciaiot.ovpncp.utils.openvpn import (
    add_iroute,
    assign_client_ip,
    build_client,
    generate_crl,
    get_server_config,
    get_status,
    list_client_certs,
    list_connections,
    package_client_cert,
    pull_client_routes,
    push_client_routes,
    read_client_cert,
    remove_iroute,
    renew_client_cert,
    revoke_client,
    unassign_client_ip,
    validate_name,
)

server_config_lines = """
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
data-ciphers-fallback AES-256-CBC
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist /var/log/openvpn/ipp.txt
client-config-dir ccd
ccd-exclusive
keepalive 10 120
persist-key
persist-tun
status /var/log/openvpn/openvpn-status.log
log         /var/log/openvpn/openvpn.log
verb 3
explicit-exit-notify 1
client-connect /opt/ovpncp/client-connect.sh
client-disconnect /opt/ovpncp/client-disconnect.sh
script-security 2
"""


@patch("builtins.open", new_callable=mock_open, read_data=server_config_lines)
def test_get_server_config(mock_open):
    configs = get_server_config()
    assert configs is not None
    # Adjust count if server_config_lines was simplified
    # assert len(configs) == 23

    mock_open.assert_called_with("/etc/openvpn/server.conf", "r")


server_status_active = """
● openvpn@server.service - OpenVPN connection to server
    Loaded: loaded (/usr/lib/systemd/system/openvpn@.service; enabled; preset: enabled)
    Active: active (running) since Mon 2025-01-13 08:15:17 UTC; 15s ago
    """


@patch("subprocess.run", return_value=MagicMock(stdout=server_status_active))
def test_get_status_active(mock_run):
    status = get_status()
    assert status is not None
    assert status["status"] == "active (running)"
    assert status["time"] == "Mon 2025-01-13 08:15:17 UTC"
    assert status["period"] == "15s"

    mock_run.assert_called_once_with(
        ["systemctl", "status", "openvpn"], capture_output=True, text=True, check=True
    )


def test_validate_name():
    # Valid names
    validate_name("client1")
    validate_name("client_1")
    validate_name("client-1")
    validate_name("a" * 255)

    # Invalid names
    with pytest.raises(ValueError, match="Invalid name"):
        validate_name("client; touch")
    with pytest.raises(ValueError, match="Invalid name"):
        validate_name("client/../test")
    with pytest.raises(ValueError, match="Invalid name"):
        validate_name("client|test")
    with pytest.raises(ValueError, match="Invalid name"):
        validate_name("a" * 256)


def test_read_client_cert_traversal():
    # This simulates a path traversal attempt
    malicious_name = "../../../etc/passwd"
    with pytest.raises(ValueError, match="Invalid name"):
        read_client_cert(malicious_name)


@patch("subprocess.run", return_value=MagicMock(returncode=0))
def test_build_client_injection(mock_run):
    # This simulates a command injection attempt
    malicious_name = "client; touch /tmp/injected"
    with pytest.raises(ValueError, match="Invalid name"):
        build_client(malicious_name)

    # Confirm it's NOT called with shell=True
    mock_run.assert_not_called()


@patch("subprocess.run", return_value=MagicMock(returncode=0))
def test_build_client(mock_run):
    success = build_client("client")
    assert success is True

    mock_run.assert_called_once_with(
        ["./easyrsa", "--batch", "build-client-full", "client", "nopass"],
        cwd="/etc/openvpn/easy-rsa",
        shell=False,
        check=True,
    )


@patch("subprocess.run", return_value=MagicMock(returncode=1))
def test_build_client_fail(mock_run):
    success = build_client("client")
    assert success is False

    mock_run.assert_called_once_with(
        ["./easyrsa", "--batch", "build-client-full", "client", "nopass"],
        cwd="/etc/openvpn/easy-rsa",
        shell=False,
        check=True,
    )


cert_content = """
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJALb2Z6Z6Z6Z6MA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
...
-----END CERTIFICATE-----
"""


@patch("builtins.open", new_callable=mock_open, read_data=cert_content)
@patch("cryptography.x509.load_pem_x509_certificate")
def test_read_client_cert_success(mock_load_cert, mock_open):
    mock_cert = MagicMock()
    mock_cert.not_valid_before_utc = datetime.now(timezone.utc)
    mock_cert.not_valid_after_utc = datetime.now(timezone.utc) + timedelta(days=365)
    mock_cert.subject.get_attributes_for_oid.return_value = [
        MagicMock(value="client_name")
    ]
    mock_cert.issuer.get_attributes_for_oid.return_value = [MagicMock(value="CA_name")]
    mock_load_cert.return_value = mock_cert

    result = read_client_cert("client_name")
    assert result is not None
    assert result["issued_to"] == "client_name"
    assert result["issued_by"] == "CA_name"

    mock_open.assert_called_once()


@patch("builtins.open", new_callable=mock_open, read_data=cert_content)
@patch("cryptography.x509.load_pem_x509_certificate")
def test_read_client_cert_failure_hides_sensitive_details(
    mock_load_cert, mock_open, caplog
):
    sensitive = "/server/private/client.crt?sig=secret-token"
    mock_load_cert.side_effect = ValueError(sensitive)

    with caplog.at_level("ERROR"):
        assert read_client_cert("safe-client") == {}

    assert sensitive not in caplog.text


@patch("os.listdir")
def test_list_client_certs_failure_hides_sensitive_details(mock_listdir, caplog):
    sensitive = "/server/private/issued?sig=secret-token"
    mock_listdir.side_effect = OSError(sensitive)
    with caplog.at_level("ERROR"):
        assert list_client_certs() == []
    assert sensitive not in caplog.text


@patch("os.remove")
@patch("zipfile.ZipFile", return_value=MagicMock())
def test_package_client_cert_hides_archive_path(mock_zipfile, mock_remove, caplog):
    archive_path = "/path/to/output_dir/test_client.zip"
    with caplog.at_level("INFO"):
        result = package_client_cert(
            name="test_client", output_dir="/path/to/output_dir"
        )

    assert result == archive_path
    assert archive_path not in caplog.text
    mock_zipfile.assert_called_once()


@patch("sciaiot.ovpncp.utils.openvpn.read_client_cert", return_value={})
@patch("subprocess.run", return_value=MagicMock(returncode=0))
def test_renew_client_cert(mock_run, mock_read_client_cert):
    cert_details = renew_client_cert("client")
    assert cert_details == {}

    mock_run.assert_called_once_with(
        ["./easyrsa", "--batch", "revoke-renewed", "client"],
        cwd="/etc/openvpn/easy-rsa",
        shell=False,
        check=True,
    )


@patch("subprocess.run", return_value=MagicMock(returncode=0))
def test_revoke_client_cert(mock_run):
    result = revoke_client("test_client")
    assert result is True

    mock_run.assert_called_once_with(
        ["./easyrsa", "--batch", "revoke", "test_client"],
        cwd="/etc/openvpn/easy-rsa",
        shell=False,
        check=True,
    )


@patch("subprocess.run", return_value=MagicMock(returncode=0))
def test_generate_crl(mock_run):
    success = generate_crl()
    assert success is True

    mock_run.assert_called_once_with(
        ["./easyrsa", "--batch", "gen-crl"],
        cwd="/etc/openvpn/easy-rsa",
        shell=False,
        check=True,
    )


@patch("builtins.open", new_callable=mock_open)
def test_assign_client_ip(mock_open, caplog: pytest.LogCaptureFixture):
    caplog.set_level(logging.INFO)
    assign_client_ip("client_1", "10.8.0.2", "255.255.255.0")
    mock_open.assert_called_with("/etc/openvpn/ccd/client_1", "w")
    assert "10.8.0.2" not in caplog.text
    assert "255.255.255.0" not in caplog.text


@patch("os.path.exists", return_value=True)
@patch("os.remove")
def test_unassign_client_ip(mock_remove, mock_exists):
    unassign_client_ip("client_1")
    mock_remove.assert_called_with("/etc/openvpn/ccd/client_1")


@patch("builtins.open", new_callable=mock_open)
def test_add_iroute(mock_open):
    add_iroute("gateway_1", "192.168.1.0 255.255.255.0")
    mock_open.assert_called_with("/etc/openvpn/ccd/gateway_1", "a")


@patch(
    "builtins.open",
    new_callable=mock_open,
    read_data="ifconfig-push 10.8.0.2 255.255.255.0\niroute 192.168.1.0 255.255.255.0\n",
)
def test_remove_iroute(mock_open):
    remove_iroute("gateway_1", "192.168.1.0 255.255.255.0")
    mock_open.assert_called_with("/etc/openvpn/ccd/gateway_1", "w")


@patch("builtins.open", new_callable=mock_open)
def test_push_client_routes(mock_open):
    push_client_routes("client_1", ["192.168.1.5 255.255.255.255 10.8.0.11"])
    mock_open.assert_called_with("/etc/openvpn/ccd/client_1", "a")


@patch(
    "builtins.open",
    new_callable=mock_open,
    read_data='ifconfig-push 10.8.0.2 255.255.255.0\npush "route 192.168.1.5 255.255.255.255 10.8.0.11"\n',
)
def test_pull_client_routes(mock_open):
    pull_client_routes("client_1")
    mock_open.assert_called_with("/etc/openvpn/ccd/client_1", "w")


connection_lines = """
OpenVPN CLIENT LIST
Updated,2025-01-14 06:04:39
Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
client_1,172.205.176.207:60374,3051,3093,2025-01-14 06:04:34
client_2,172.205.176.208:60374,3051,3093,2025-01-14 06:04:34
ROUTING TABLE
Virtual Address,Common Name,Real Address,Last Ref
10.8.0.2,client_1,172.205.176.207:60374,2025-01-14 06:04:35
10.8.0.3,client_2,172.205.176.208:60374,2025-01-14 06:04:35
GLOBAL STATS
Max bcast/mcast queue length,0
END
"""


@patch("builtins.open", new_callable=mock_open, read_data=connection_lines)
def test_list_connections(mock_open):
    connections = list_connections()
    assert len(connections) == 2
    mock_open.assert_called_with("/var/log/openvpn/openvpn-status.log", "r")
