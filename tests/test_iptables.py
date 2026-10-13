import logging
from unittest.mock import MagicMock, call, patch

import pytest

from sciaiot.rivet.utils.iptables import apply_rules, drop_rules, list_rules

rules_output = """Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination
 1    100 DROP       all  --  tun0   *       0.0.0.0/0            0.0.0.0/0
"""


@patch("subprocess.run")
def test_list_rules(mock_run):
    mock_run.return_value = MagicMock(stdout=rules_output)

    result = list_rules("FORWARD")
    expected_output = [
        " 1    100 DROP       all  --  tun0   *       0.0.0.0/0            0.0.0.0/0"
    ]
    assert result == expected_output

    mock_run.assert_called_once_with(
        ["iptables", "-L", "FORWARD", "--line-numbers"],
        capture_output=True,
        text=True,
        check=True,
    )


@patch("subprocess.run")
def test_apply_rules_injection(mock_run, caplog):
    malicious_rule = "-j ACCEPT; touch /tmp/iptables_injected"
    with pytest.raises(ValueError, match="Malicious characters"):
        apply_rules("FORWARD", 1, [malicious_rule])

    mock_run.assert_not_called()
    assert malicious_rule not in caplog.text


@patch("subprocess.run")
def test_apply_rules(mock_run):
    rules = [
        "-i tun0 -s 10.8.0.2 -d 10.8.0.3 -j ACCEPT",
        "-i tun0 -s 10.8.0.3 -d 10.8.0.3 -j ACCEPT",
    ]

    apply_rules("FORWARD", 1, rules)

    assert mock_run.call_count == 2
    mock_run.assert_has_calls(
        [
            call(
                [
                    "iptables",
                    "-I",
                    "FORWARD",
                    "1",
                    "-i",
                    "tun0",
                    "-s",
                    "10.8.0.2",
                    "-d",
                    "10.8.0.3",
                    "-j",
                    "ACCEPT",
                ],
                shell=False,
                check=True,
            ),
            call(
                [
                    "iptables",
                    "-I",
                    "FORWARD",
                    "2",
                    "-i",
                    "tun0",
                    "-s",
                    "10.8.0.3",
                    "-d",
                    "10.8.0.3",
                    "-j",
                    "ACCEPT",
                ],
                shell=False,
                check=True,
            ),
        ]
    )


@patch("subprocess.run")
def test_apply_rules_does_not_log_rules_or_commands(mock_run, caplog):
    rule = "-i tun0 -s 10.8.0.2 -d 10.8.0.3 -j ACCEPT"

    with caplog.at_level(logging.INFO):
        apply_rules("FORWARD", 1, [rule])

    assert rule not in caplog.text
    assert "10.8.0.2" not in caplog.text
    assert "10.8.0.3" not in caplog.text
    assert "iptables -I" not in caplog.text


@patch("subprocess.run")
def test_drop_rules(mock_run):
    rules = [
        "-i tun0 -s 10.8.0.2 -d 10.8.0.3 -j ACCEPT",
        "-i tun0 -s 10.8.0.3 -d 10.8.0.3 -j ACCEPT",
    ]

    drop_rules("FORWARD", rules)

    assert mock_run.call_count == 2
    mock_run.assert_has_calls(
        [
            call(
                [
                    "iptables",
                    "-D",
                    "FORWARD",
                    "-i",
                    "tun0",
                    "-s",
                    "10.8.0.2",
                    "-d",
                    "10.8.0.3",
                    "-j",
                    "ACCEPT",
                ],
                shell=False,
                check=True,
            ),
            call(
                [
                    "iptables",
                    "-D",
                    "FORWARD",
                    "-i",
                    "tun0",
                    "-s",
                    "10.8.0.3",
                    "-d",
                    "10.8.0.3",
                    "-j",
                    "ACCEPT",
                ],
                shell=False,
                check=True,
            ),
        ]
    )


@patch("subprocess.run")
def test_drop_rules_does_not_log_rules_or_commands(mock_run, caplog):
    rule = "-i tun0 -s 10.8.0.2 -d 10.8.0.3 -j ACCEPT"

    with caplog.at_level(logging.INFO):
        drop_rules("FORWARD", [rule])

    assert rule not in caplog.text
    assert "10.8.0.2" not in caplog.text
    assert "10.8.0.3" not in caplog.text
    assert "iptables -D" not in caplog.text


def test_validate_chain():
    from sciaiot.rivet.utils.iptables import validate_chain

    validate_chain("FORWARD")
    with pytest.raises(ValueError, match="Invalid chain"):
        validate_chain("INVALID_CHAIN")
