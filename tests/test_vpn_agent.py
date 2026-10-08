"""Read-only agent security and observation behavior."""

from pathlib import Path

import pytest

from sciaiot.ovpncp.application.vpn_control import schemas as s
from sciaiot.ovpncp.application.vpn_control.errors import ControlError
from sciaiot.ovpncp.vpn_agent.control import ReadOnlyVpnControl
from tests.support.agent import request, settings


@pytest.mark.parametrize(
    "command",
    [
        s.Reload(),
        s.AckEvents(through=0),
        s.ChangeClient(client="test", action="issue"),
        s.Archive(client="test", generation=0),
        s.PollEvents(),
    ],
)
def test_agent_has_no_mutation_or_archive_support(tmp_path: Path, command: s.Command):
    """Every unavailable operation fails before reading any runtime state."""
    with pytest.raises(ControlError, match="unavailable"):
        ReadOnlyVpnControl(settings(tmp_path)).execute(request(command))


def test_agent_config_is_sanitized(tmp_path: Path):
    """Secrets and arbitrary paths cannot appear in the wire projection."""
    configured = settings(tmp_path)
    configured.config_path.write_text(
        "dev tun0\nserver 10.8.0.0 255.255.255.0\nport 1194\n"
        "proto udp\ntopology subnet\nkeepalive 10 120\n"
        "key /private/secret.key\npersist-key\npersist-tun\n"
    )
    result = ReadOnlyVpnControl(configured).execute(request(s.ServerConfig())).result
    assert isinstance(result, s.ConfigResult)
    assert result.server_address == "10.8.0.1"
    assert "secret" not in result.model_dump_json()
