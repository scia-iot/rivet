"""Security boundaries and non-destructive container state preparation."""

import importlib.util
import stat
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _prepare_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "prepare_state", ROOT / "deploy/containers/prepare_state.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_new_state_permissions_and_empty_pool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only a new tree is initialized, with distinct service identities."""
    module = _prepare_module()
    ownership: dict[Path, tuple[int, int]] = {}
    monkeypatch.setattr(
        module.os,
        "chown",
        lambda path, uid, gid, **kwargs: ownership.update({path: (uid, gid)}),
    )
    root = tmp_path / "state"
    module.prepare(root)
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert ownership[root / "agent-socket"] == (65532, 65531)
    assert ownership[root / "management-socket"] == (65530, 65532)
    assert stat.S_IMODE((root / "agent-socket").stat().st_mode) == 0o2750
    assert stat.S_IMODE((root / "event-socket").stat().st_mode) == 0o2770
    assert stat.S_IMODE((root / "vpn-pool/ipp.txt").stat().st_mode) == 0o660
    assert (root / "vpn-pool/ipp.txt").read_bytes() == b""
    assert not (root / "vpn-pki/private/ca.key").exists()


def test_existing_tree_is_never_changed(tmp_path: Path) -> None:
    """Migration state, pool contents and unexpected symlinks are preserved."""
    module = _prepare_module()
    marker = tmp_path / "marker"
    marker.write_text("retain")
    with pytest.raises(FileExistsError):
        module.prepare(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError):
        module.prepare(link / "new")
    with pytest.raises(ValueError):
        module.prepare(Path("relative"))
    assert marker.read_text() == "retain"
    assert not (tmp_path / "new").exists()


def test_compose_enforces_privilege_and_mount_boundaries() -> None:
    """Only VPN workloads share host networking; API cannot reach PKI."""
    document = yaml.safe_load((ROOT / "deploy/compose.yml").read_text())
    services = document["services"]
    assert set(services) == {"openvpn", "agent", "api", "web"}
    for service in services.values():
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        expected_tmpfs = (
            "/tmp:rw,noexec,nosuid,nodev,"
            f"size={'16m' if service is services['openvpn'] else '32m'},"
            "mode=1777"
        )
        assert service["tmpfs"] == [expected_tmpfs]
        assert "no-new-privileges:true" in service["security_opt"]
        assert not service.get("privileged", False)
        assert service.get("pid") != "host"
        assert "_IMAGE:?" in service["image"]
        for mount in service.get("volumes", []):
            assert mount["bind"]["create_host_path"] is False
            assert "docker.sock" not in mount["target"]
    assert services["agent"]["network_mode"] == "host"
    assert services["openvpn"]["network_mode"] == "host"
    assert services["agent"]["cap_add"] == ["NET_ADMIN", "SETUID", "SETGID"]
    assert services["agent"]["user"] == "0:65532"
    assert not services["agent"].get("devices")
    assert services["openvpn"]["cap_add"] == ["NET_ADMIN", "SETUID", "SETGID"]
    assert not services["api"].get("ports")
    assert not services["api"].get("cap_add")
    assert not services["web"].get("volumes")
    api_mounts = {m["target"]: m for m in services["api"]["volumes"]}
    assert set(api_mounts) == {
        "/opt/rivet",
        "/opt/rivet/certs",
        "/var/lib/ovpn-api/profile",
        "/run/ovpn-agent",
    }
    assert api_mounts["/run/ovpn-agent"]["read_only"] is True
    assert not services["openvpn"].get("depends_on")
    assert (
        "RIVET_AGENT_ROUTE_PROTOCOL:?"
        in (services["agent"]["environment"]["RIVET_AGENT_ROUTE_PROTOCOL"])
    )


def test_compose_starts_control_plane_after_service_readiness() -> None:
    """Each dependent starts after its upstream health check succeeds."""
    services = yaml.safe_load((ROOT / "deploy/compose.yml").read_text())["services"]
    for downstream, upstream in (
        ("agent", "openvpn"),
        ("api", "agent"),
        ("web", "api"),
    ):
        assert services[downstream]["depends_on"] == {
            upstream: {"condition": "service_healthy"}
        }
    assert not services["openvpn"].get("depends_on")


def test_build_manifest_has_four_independent_images() -> None:
    """Build and push need no runtime state or production image digests."""
    document = yaml.safe_load((ROOT / "deploy/compose.build.yml").read_text())
    assert set(document["services"]) == {"openvpn", "agent", "api", "web"}
    for service in document["services"].values():
        assert service["platform"] == "${RIVET_PLATFORM:-linux/amd64}"
        assert (ROOT / service["build"]["dockerfile"]).is_file()
        assert not service.get("volumes")
        assert not service.get("network_mode")


def test_state_cli_requires_operator_and_redacts_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Wrong privilege and existing paths fail with actionable generic errors."""
    module = _prepare_module()
    monkeypatch.setattr("sys.argv", ["prepare_state", str(tmp_path)])
    monkeypatch.setattr(module.os, "geteuid", lambda: 1000)
    with pytest.raises(SystemExit) as failure:
        module.main()
    assert failure.value.code == 2
    assert "root privileges" in capsys.readouterr().err
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    with pytest.raises(SystemExit) as failure:
        module.main()
    assert failure.value.code == 1
    assert str(tmp_path) not in capsys.readouterr().err


def test_event_producer_can_record_ingestion_loss() -> None:
    """A daemon hook can persist the gap marker while API lacks ingress access."""
    services = yaml.safe_load((ROOT / "deploy/compose.yml").read_text())["services"]
    mounts = {mount["target"]: mount for mount in services["openvpn"]["volumes"]}
    assert not mounts["/run/ovpn-events"].get("read_only", False)
    assert mounts["/var/lib/ovpn-agent/projection"]["read_only"] is True


def test_compose_preserves_explicit_auth_values_for_startup_validation() -> None:
    """Blank selectors and conflicting aliases must reach strict validation."""
    services = yaml.safe_load((ROOT / "deploy/compose.yml").read_text())["services"]
    api = services["api"]["environment"]
    assert api["RIVET_AUTH_PROVIDER"] == "${RIVET_AUTH_PROVIDER-entra}"
    assert api["RIVET_AUTH_AUTO_REGISTER_USERS"] == (
        "${RIVET_AUTH_AUTO_REGISTER_USERS-${AZURE_ENTRAID_AUTO_REGISTER_USERS-true}}"
    )
    assert api["AZURE_ENTRAID_AUTO_REGISTER_USERS"] == (
        "${AZURE_ENTRAID_AUTO_REGISTER_USERS-${RIVET_AUTH_AUTO_REGISTER_USERS-true}}"
    )
    assert services["web"]["environment"]["RIVET_UI_AUTH_PROVIDER"] == (
        "${RIVET_UI_AUTH_PROVIDER-entra}"
    )
