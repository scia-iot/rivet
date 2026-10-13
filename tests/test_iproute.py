import logging
from unittest.mock import MagicMock, patch

import pytest

from sciaiot.rivet.utils import iproute
from tests.support.api import MOCKED_ROUTES


@patch("subprocess.run", return_value=MagicMock(stdout=MOCKED_ROUTES))
def test_list_routes(mock_run):
    shell_command = ["ip", "route", "show", "dev", "tun0"]
    routes = iproute.list("tun0")
    assert len(routes) == 2

    mock_run.assert_called_once_with(
        shell_command, capture_output=True, text=True, check=True
    )


@patch("subprocess.run")
def test_add_injection(mock_run, caplog):
    malicious_network = "192.168.1.0/24; touch /tmp/iproute_injected"
    with pytest.raises(ValueError, match="Invalid IP or network"):
        iproute.add(malicious_network, "10.8.0.1", "tun0")

    mock_run.assert_not_called()
    assert malicious_network not in caplog.text


@patch("subprocess.run")
def test_add_route(mock_run):
    iproute.add("192.168.1.0/24", "10.8.0.1", "tun0")

    mock_run.assert_called_once_with(
        ["ip", "route", "add", "192.168.1.0/24", "via", "10.8.0.1", "dev", "tun0"],
        shell=False,
        check=True,
    )


@patch("subprocess.run")
def test_add_route_does_not_log_addresses(mock_run, caplog):
    private_network = "192.168.1.0/24"
    server_ip = "10.8.0.1"

    with caplog.at_level(logging.INFO):
        iproute.add(private_network, server_ip, "tun0")

    assert private_network not in caplog.text
    assert server_ip not in caplog.text


@patch("subprocess.run")
def test_delete_route(mock_run):
    iproute.delete("192.168.1.0/24 via 10.8.0.1", "tun0")

    mock_run.assert_called_once_with(
        ["ip", "route", "del", "192.168.1.0/24", "via", "10.8.0.1", "dev", "tun0"],
        shell=False,
        check=True,
    )


@patch("subprocess.run")
def test_delete_route_does_not_log_route(mock_run, caplog):
    route = "192.168.1.0/24 via 10.8.0.1"

    with caplog.at_level(logging.INFO):
        iproute.delete(route, "tun0")

    assert route not in caplog.text
    assert "192.168.1.0/24" not in caplog.text
    assert "10.8.0.1" not in caplog.text


def test_validate_ip_or_net():
    from sciaiot.rivet.utils.iproute import validate_ip_or_net

    validate_ip_or_net("1.2.3.4")
    validate_ip_or_net("1.2.3.4/24")
    with pytest.raises(ValueError):
        validate_ip_or_net("invalid")


def test_validate_dev():
    from sciaiot.rivet.utils.iproute import validate_dev

    validate_dev("tun0")
    validate_dev("eth0")
    with pytest.raises(ValueError):
        validate_dev("tun0; touch")
