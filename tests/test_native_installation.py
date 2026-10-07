"""Native wheel and service contracts for separate API and VPN identities."""

import os
import shlex
import shutil
import stat
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from sciaiot.ovpncp import native_api, native_assets, native_firewall
from sciaiot.ovpncp.native_assets import export
from sciaiot.ovpncp.vpn_agent import access_mutations, network

ROOT = Path(__file__).resolve().parents[1]


def test_package_metadata_keeps_agent_install_small() -> None:
    """The base wheel does not pull API, cloud or database dependencies."""
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    dependencies = " ".join(project["dependencies"]).lower()
    api = " ".join(project["optional-dependencies"]["api"]).lower()

    assert project["requires-python"] == ">=3.14"
    assert "pydantic" in dependencies
    assert "cryptography" in dependencies
    for excluded in ("fastapi", "sqlmodel", "uvicorn", "jose", "azure"):
        assert excluded not in dependencies
    for required in ("fastapi", "sqlmodel", "uvicorn", "python-jose"):
        assert required in api
    assert "sciaiot.ovpncp.native_api:main" == project["scripts"]["ovpncp"]


def test_built_wheel_contains_native_templates(tmp_path: Path) -> None:
    """Exportable service templates must survive a real wheel build."""
    source = tmp_path / "source"
    source.mkdir()
    for name in ("pyproject.toml", "README.md"):
        shutil.copy2(ROOT / name, source / name)
    shutil.copytree(
        ROOT / "src",
        source / "src",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.egg-info"),
    )
    wheel_dir = tmp_path / "wheels"
    wheel_dir.mkdir()
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(wheel_dir),
            str(source),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    wheel = next(wheel_dir.glob("ovpncp-*.whl"))
    with zipfile.ZipFile(wheel) as archive:
        for name in (
            "ovpncp.service",
            "ovpncp-vpn-agent.service",
            "ovpncp-openvpn.service",
            "ovpncp-forward-policy.service",
            "ovpncp.conf",
            "api.env.example",
            "agent.env.example",
            "server.conf.example",
            "nginx.conf.template",
            "web-config.sh",
        ):
            assert f"sciaiot/ovpncp/native_assets/{name}" in archive.namelist()
        assert "sciaiot/ovpncp/log.yml" in archive.namelist()


@pytest.mark.parametrize(
    "overrides",
    [
        {},
        {"OVPNCP_VPN_BACKEND": "host"},
        {"OVPNCP_AGENT_UID": ""},
        {"OVPNCP_AGENT_UID": "1234"},
        {"AZURE_ENTRAID_TENANT_ID": ""},
    ],
)
def test_native_api_rejects_incomplete_isolation(
    monkeypatch: pytest.MonkeyPatch, overrides: dict[str, str]
) -> None:
    """A native API cannot start with a privileged backend or missing auth."""
    monkeypatch.setattr(native_api.os, "geteuid", lambda: 1234)
    for key in list(os.environ):
        if key.startswith(("OVPNCP_", "AZURE_ENTRAID_")):
            monkeypatch.delenv(key)
    values = {
        "OVPNCP_VPN_BACKEND": "agent",
        "OVPNCP_AGENT_UID": "1235",
        "AZURE_ENTRAID_TENANT_ID": "11111111-1111-4111-8111-111111111111",
        "AZURE_ENTRAID_APP_CLIENT_ID": "22222222-2222-4222-8222-222222222222",
        "AZURE_ENTRAID_USER_ROLE": "device_user",
        "AZURE_ENTRAID_ADMIN_ROLE": "sysadmin",
        "AZURE_ENTRAID_SERVICE_ADMIN_ROLE": "ServiceAdmin",
    }
    values.update(overrides)
    for key, value in values.items():
        monkeypatch.setenv(key, value)

    if not overrides:
        monkeypatch.delenv("OVPNCP_VPN_BACKEND")
    with pytest.raises(ValueError, match="native API configuration"):
        native_api.validate_environment()


def test_native_api_rejects_root(monkeypatch: pytest.MonkeyPatch) -> None:
    """Native service refuses accidental root execution."""
    monkeypatch.setattr(native_api.os, "geteuid", lambda: 0)
    with pytest.raises(ValueError, match="unprivileged"):
        native_api.validate_environment()


def test_native_api_starts_after_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    """A complete native configuration reaches the API runner."""
    monkeypatch.setattr(native_api.os, "geteuid", lambda: 1234)
    values = {
        "OVPNCP_VPN_BACKEND": "agent",
        "OVPNCP_AGENT_UID": "1235",
        "AZURE_ENTRAID_TENANT_ID": "11111111-1111-4111-8111-111111111111",
        "AZURE_ENTRAID_APP_CLIENT_ID": "22222222-2222-4222-8222-222222222222",
        "AZURE_ENTRAID_USER_ROLE": "device_user",
        "AZURE_ENTRAID_ADMIN_ROLE": "sysadmin",
        "AZURE_ENTRAID_SERVICE_ADMIN_ROLE": "ServiceAdmin",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    native_api.validate_environment()


def test_native_api_main_runs_after_preflight(monkeypatch: pytest.MonkeyPatch) -> None:
    """The installed CLI reaches the existing API runner after checks."""
    from sciaiot.ovpncp import main as api_main

    runner = Mock()
    monkeypatch.setattr(native_api, "validate_environment", lambda: None)
    monkeypatch.setattr(api_main, "run", runner)
    native_api.main()
    runner.assert_called_once_with()


def test_native_api_main_reports_missing_extra(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Base installs receive an actionable error from the API command."""
    monkeypatch.setattr(native_api.importlib.util, "find_spec", lambda _: None)
    with pytest.raises(SystemExit, match=r"ovpncp\[api\]"):
        native_api.main()


def test_native_firewall_bootstrap_is_scoped_to_tun0() -> None:
    """An empty owned chain supersedes foreign FORWARD rules without flushing."""
    snapshot = (
        "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n-A FORWARD -i eth0 -j ACCEPT\nCOMMIT\n"
    )
    restore = native_firewall.plan(snapshot, network.Ownership(), "tun0")
    assert restore is not None
    assert ":OVPNCP_FORWARD - [0:0]" in restore
    assert "-I FORWARD 1 -i tun0" in restore
    assert "-I FORWARD 1 -o tun0" in restore
    assert "ovpncp:terminal-deny -j DROP" in restore
    assert "-F FORWARD" not in restore
    assert "-P FORWARD" not in restore


def test_native_firewall_rejects_foreign_owned_collision() -> None:
    """A foreign partial chain cannot be adopted as bootstrap state."""
    snapshot = (
        "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n:OVPNCP_FORWARD - [0:0]\nCOMMIT\n"
    )
    with pytest.raises(ValueError, match="owned firewall"):
        native_firewall.plan(snapshot, network.Ownership(), "tun0")


def test_native_firewall_rejects_recreating_declared_grants() -> None:
    """An absent chain with declared grants requires a reviewed recovery."""
    from sciaiot.ovpncp.application.vpn_control.schemas import AccessIntent

    snapshot = (
        "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\nCOMMIT\n"
    )
    intent = AccessIntent.model_validate(
        {
            "access_id": "11111111-1111-4111-8111-111111111111",
            "source_client": "a",
            "destination_client": "b",
            "source_address": "10.8.0.2",
            "destination_address": "10.8.0.3",
            "private_networks": (),
        }
    )
    inventory = network.Ownership(access=(intent,))
    with pytest.raises(ValueError, match="owned firewall"):
        native_firewall.plan(snapshot, inventory, "tun0")


def test_native_firewall_rejects_configured_device_mismatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The boot guard cannot protect a different interface than OpenVPN."""
    ownership = tmp_path / "ownership.json"
    ownership.write_text("{}")
    settings = SimpleNamespace(ownership_path=ownership)
    monkeypatch.setattr(
        native_firewall.Settings,
        "from_environment",
        lambda: settings,
    )
    monkeypatch.setattr(
        native_firewall.files,
        "configuration",
        lambda *_: SimpleNamespace(device="tun1", device_type="tun"),
    )
    monkeypatch.setenv("OVPNCP_FIREWALL_DEVICE", "tun0")
    observe = Mock()
    monkeypatch.setattr(native_firewall.bounded, "observe", observe)
    with pytest.raises(ValueError, match="does not match"):
        native_firewall.ensure()
    observe.assert_not_called()


@pytest.mark.parametrize("existing", [False, True])
def test_native_firewall_initializes_or_verifies_owned_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, existing: bool
) -> None:
    """The guard changes only an absent empty chain and verifies the result."""
    ownership = tmp_path / "ownership.json"
    ownership.write_text("{}")
    settings = SimpleNamespace(ownership_path=ownership)
    monkeypatch.setattr(native_firewall.Settings, "from_environment", lambda: settings)
    monkeypatch.setattr(
        native_firewall.files,
        "configuration",
        lambda *_: SimpleNamespace(device="tun0", device_type="tun"),
    )
    monkeypatch.setattr(
        native_firewall,
        "read_ipv4_sysctl",
        lambda key: "1" if key == "ip_forward" else "0",
    )
    inventory = network.Ownership()
    monkeypatch.setattr(native_firewall.network, "ownership", lambda *_: inventory)
    monkeypatch.setenv("OVPNCP_FIREWALL_DEVICE", "tun0")
    header = (
        "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n"
    )
    before = header + "COMMIT\n"
    ready = (
        header
        + ":OVPNCP_FORWARD - [0:0]\n"
        + "\n".join(
            shlex.join(rule) for rule in access_mutations.rules(inventory, "tun0")
        )
        + "\nCOMMIT\n"
    )
    observe = Mock(
        side_effect=[ready.encode(), ready.encode()]
        if existing
        else [before.encode(), ready.encode()]
    )
    command = Mock(return_value=b"")
    monkeypatch.setattr(native_firewall.bounded, "observe", observe)
    monkeypatch.setattr(native_firewall.bounded, "command", command)

    native_firewall.ensure()
    assert observe.call_count == 2
    assert command.call_count == (0 if existing else 1)
    if not existing:
        assert b"--comment ovpncp:terminal-deny -j DROP" in command.call_args.args[2]


def test_native_firewall_rejects_missing_sysctl(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Forwarding prerequisites fail before any iptables mutation."""
    ownership = tmp_path / "ownership.json"
    ownership.write_text("{}")
    monkeypatch.setattr(
        native_firewall.Settings,
        "from_environment",
        lambda: SimpleNamespace(ownership_path=ownership),
    )
    monkeypatch.setattr(
        native_firewall.files,
        "configuration",
        lambda *_: SimpleNamespace(device="tun0", device_type="tun"),
    )
    monkeypatch.setattr(native_firewall, "read_ipv4_sysctl", lambda _: "0")
    monkeypatch.setenv("OVPNCP_FIREWALL_DEVICE", "tun0")
    command = Mock()
    monkeypatch.setattr(native_firewall.bounded, "command", command)
    with pytest.raises(ValueError, match="sysctls"):
        native_firewall.ensure()
    command.assert_not_called()


def test_native_firewall_cli_redacts_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Privileged startup failures never expose kernel or state content."""

    def fail() -> None:
        raise ValueError("sensitive-address")

    monkeypatch.setattr(native_firewall, "ensure", fail)
    with pytest.raises(SystemExit, match="1"):
        native_firewall.main()
    assert "sensitive-address" not in capsys.readouterr().err


def test_export_rejects_symlink_ancestor(tmp_path: Path) -> None:
    """Template export cannot follow a substituted parent directory."""
    actual = tmp_path / "actual"
    actual.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)
    with pytest.raises(ValueError, match="real directories"):
        export(alias / "templates")


def test_export_assets_refuses_existing_files(tmp_path: Path) -> None:
    """A template export cannot overwrite operator-edited configuration."""
    target = tmp_path / "native"
    target.mkdir()
    (target / "ovpncp.service").write_text("operator")
    with pytest.raises(FileExistsError):
        export(target)
    assert (target / "ovpncp.service").read_text() == "operator"


def test_export_assets_writes_reviewable_complete_set(tmp_path: Path) -> None:
    """A fresh export contains every native unit and runtime template."""
    target = tmp_path / "native"
    export(target)
    assert {entry.name for entry in target.iterdir()} == set(native_assets.ASSETS)
    assert stat.S_IMODE(target.stat().st_mode) == 0o700
    assert stat.S_IMODE((target / "web-config.sh").stat().st_mode) == 0o755
    assert "User=ovpn-api" in (target / "ovpncp.service").read_text()
    assert (
        "location = /runtime-config.js" in (target / "nginx.conf.template").read_text()
    )


def test_export_cli_reports_existing_target(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """The command exits cleanly without replacing reviewed operator files."""
    target = tmp_path / "native"
    export(target)
    monkeypatch.setattr(sys, "argv", ["ovpncp-export-native", str(target)])
    with pytest.raises(SystemExit, match="1"):
        native_assets.main()
    assert "Refusing to replace" in capsys.readouterr().err


def test_native_units_keep_api_out_of_vpn_state() -> None:
    """The API and agent units have distinct identities and writable roots."""
    assets = ROOT / "src/sciaiot/ovpncp/native_assets"
    api = (assets / "ovpncp.service").read_text()
    agent = (assets / "ovpncp-vpn-agent.service").read_text()
    runtime = (assets / "ovpncp.conf").read_text()

    assert "User=ovpn-api" in api
    assert "OVPNCP_VPN_BACKEND=agent" in api
    assert "CapabilityBoundingSet=" in api
    assert "ReadWritePaths=/opt/ovpncp" in api
    assert "ReadWritePaths=/var/lib/ovpn-agent" not in api
    assert "InaccessiblePaths=-/var/lib/ovpn-agent" in api
    assert "User=ovpn-agent" in agent
    assert "Group=ovpn-runtime" in agent
    assert "AmbientCapabilities=CAP_NET_ADMIN" in agent
    assert "CapabilityBoundingSet=CAP_NET_ADMIN" in agent
    assert "ReadWritePaths=/var/lib/ovpn-agent" in agent
    assert "d /run/ovpn-agent 2750 ovpn-agent ovpn-control" in runtime
