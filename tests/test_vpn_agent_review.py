"""Independent malformed-observation and isolation regressions for Phase 3."""

import time
from pathlib import Path

import pytest

from sciaiot.ovpncp.application.vpn_control.errors import ControlError
from sciaiot.ovpncp.vpn_agent.management import Management
from tests.support.agent import settings


@pytest.mark.parametrize(
    "content",
    [
        "HEADER\tCLIENT_LIST\tCommon Name\n",
        "HEADER\tCLIENT_LIST\n",
        "HEADER\tCLIENT_LIST\tUnexpected\n",
    ],
)
def test_empty_status_still_requires_complete_header(
    tmp_path: Path, monkeypatch, content
):
    """Truncated headers must not silently report an empty valid connection set."""
    management = Management(settings(tmp_path))
    monkeypatch.setattr(management, "read", lambda *_: content)
    with pytest.raises(ControlError):
        management.sessions(time.monotonic() + 1)


def test_rehearsal_refuses_host_before_fixture_setup(monkeypatch):
    """The explicit integration entry cannot construct PKI before attestation."""
    from sciaiot.ovpncp.migration.models import MigrationError
    from tests.integration import vpn_agent_rehearsal as rehearsal

    monkeypatch.setattr(rehearsal.sys, "argv", ["rehearsal", "--easyrsa", "/unused"])
    calls = []

    def refuse():
        raise MigrationError("initial namespace refused")

    monkeypatch.setattr(rehearsal.fixture, "require_isolation", refuse)
    monkeypatch.setattr(
        rehearsal, "AgentRehearsal", lambda *args, **kwargs: calls.append(True)
    )
    with pytest.raises(MigrationError, match="namespace"):
        rehearsal.main()
    assert not calls
