"""Public Rivet identity and compatibility with existing persistent state."""

import importlib
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_rivet_distribution_and_commands() -> None:
    """The qualified distribution installs the advertised Rivet commands."""
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert project["name"] == "sciaiot-rivet"
    assert project["scripts"]["rivet"] == "sciaiot.rivet.native_api:main"
    assert project["scripts"]["rivet-agent"] == "sciaiot.rivet.vpn_agent.cli:main"
    assert all(not name.startswith("ovpncp") for name in project["scripts"])
    assert project["optional-dependencies"]["security"] == ["sciaiot-rivet[api]"]


def test_agent_distribution_uses_matching_core_without_api_extra() -> None:
    """The agent package selects the same core release without duplicating it."""
    core = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    agent = tomllib.loads((ROOT / "packages/agent/pyproject.toml").read_text())[
        "project"
    ]
    assert agent["name"] == "sciaiot-rivet-agent"
    assert agent["version"] == core["version"]
    assert agent["dependencies"] == [f"sciaiot-rivet=={core['version']}"]
    assert agent["requires-python"] == core["requires-python"]


def test_rivet_preserves_persistent_ownership_and_backup_identifiers() -> None:
    """A product rename cannot change encrypted formats or owned firewall state."""
    bundle = importlib.import_module("sciaiot.rivet.migration.bundle")
    recovery = importlib.import_module("sciaiot.rivet.recovery_set")
    target = importlib.import_module("sciaiot.rivet.migration.target")
    access = importlib.import_module("sciaiot.rivet.vpn_agent.access_mutations")
    assert bundle.MAGIC == b"OVPNCP-MIGRATION\x00\x01AES256GCM\x00"
    assert recovery.MAGIC == b"OVPNCP-RECOVERY\x00\x01AES256GCM\x00"
    assert target.MARKER == ".ovpncp-migration.json"
    assert access.CHAIN == "OVPNCP_FORWARD"
    assert ".ovpncp-journal-identity" in recovery.CONFIG_INTENT


def test_rivet_api_identity() -> None:
    """API documentation identifies the product and its owner."""
    main = importlib.import_module("sciaiot.rivet.main")
    assert main.app.title == "Rivet"
    assert main.app.description == "OpenVPN control plane from SCIA IoT."


def test_source_hook_rejects_added_arguments() -> None:
    """Legacy recognition must not permit modified privileged hook commands."""
    target = importlib.import_module("sciaiot.rivet.migration.container_target")
    for command in (target.HOOK_COMMAND, target.LEGACY_HOOK_COMMAND):
        with pytest.raises(ValueError, match="unsupported container checkpoint hook"):
            target.source_hook(command + " --agent-uid 0")
