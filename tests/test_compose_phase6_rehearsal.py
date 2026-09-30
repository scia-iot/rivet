"""Safety regressions for the opt-in Phase 6 Compose rehearsal."""

import copy
import json
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from tests.integration import compose_phase6_rehearsal as phase6
from tests.integration import vpn_container_rehearsal as base


def _rendered() -> tuple[dict[str, Any], dict[str, str]]:
    """Build the smallest model needed to exercise namespace substitution."""
    images = {
        role: f"example.test/ovpncp-{role}@sha256:{role[0] * 64}"
        for role in ("openvpn", "agent", "api", "web")
    }
    services: dict[str, dict[str, object]] = {}
    for role, image in images.items():
        services[role] = {
            "image": image,
            "environment": {},
            "volumes": [],
            "networks": {"web": {}},
            "ports": ["8080:8080"],
        }
    model: dict[str, Any] = {
        "name": "ovpncp",
        "networks": {
            "web": {
                "name": "ovpncp_web",
                "driver": "bridge",
                "ipam": {"config": [{"subnet": "172.30.250.0/28"}]},
            }
        },
        "services": services,
        "x-bind": {},
        "x-runtime": {},
    }
    return model, images


def _anchors() -> dict[str, str]:
    """Return only run-owned anchor names."""
    return {
        role: f"ovpncp-p6-{'a' * 12}-anchor-{role}"
        for role in ("server", "a", "b", "c", "http")
    }


def test_isolation_remaps_every_service_to_owned_namespaces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rendered Compose cannot retain bridge, host network or published ports."""
    monkeypatch.setattr(phase6, "_attest_service", Mock())
    model, images = _rendered()
    fixture = tmp_path / "fixture"
    isolated = phase6.isolated_bundle(
        model,
        images=images,
        state=tmp_path,
        fixture=fixture,
        anchors=_anchors(),
        token="a" * 12,
        upgrade=True,
    )
    assert "networks" not in isolated
    assert model["name"] == "ovpncp"
    services = isolated["services"]
    for role, service in services.items():
        assert "networks" not in service
        assert "ports" not in service
        anchor = "server" if role in {"openvpn", "agent"} else "http"
        assert service["network_mode"] == f"container:{_anchors()[anchor]}"
        assert service["logging"] == {"driver": "none"}
        assert service["restart"] == "no"
        assert service["labels"] == {"ovpncp.rehearsal": "a" * 12}
        assert "extra_hosts" not in service
    assert services["api"]["volumes"] == [
        {
            "type": "bind",
            "source": str(fixture / "ca.crt"),
            "target": "/tmp/phase6-ca.crt",
            "read_only": True,
            "bind": {"create_host_path": False},
        }
    ]
    assert services["api"]["environment"]["SSL_CERT_FILE"] == ("/tmp/phase6-ca.crt")
    assert services["web"]["environment"]["OVPNCP_UI_ENTRA_API_SCOPE"] == (
        phase6.UPGRADE_SCOPE
    )


@pytest.mark.parametrize("change", ["resource", "network", "image", "anchor"])
def test_isolation_rejects_unreviewed_rendered_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    """Unexpected resources, networks, images and anchor IDs fail closed."""
    monkeypatch.setattr(phase6, "_attest_service", Mock())
    model, images = _rendered()
    anchors = _anchors()
    if change == "resource":
        model["volumes"] = {"production": {}}
    elif change == "network":
        model["networks"]["web"]["ipam"]["config"][0]["subnet"] = "172.30.250.0/24"
    elif change == "image":
        model["services"]["api"]["image"] = "mutable:latest"
    else:
        anchors["http"] = "foreign"
    with pytest.raises(ValueError):
        phase6.isolated_bundle(
            model,
            images=images,
            state=tmp_path,
            fixture=tmp_path,
            anchors=anchors,
            token="a" * 12,
        )


def test_service_attestation_rejects_dns_and_mount_expansion(
    tmp_path: Path,
) -> None:
    """A future Compose edit cannot add service DNS or unexpected bind grants."""
    for service in (
        {"extra_hosts": ["api:127.0.0.1"]},
        {"volumes": [{"source": str(tmp_path), "target": "/host"}]},
    ):
        with pytest.raises(ValueError):
            phase6._attest_service("api", service, tmp_path)


def test_http_aliases_live_only_on_isolated_anchor() -> None:
    """Synthetic DNS aliases cannot be attached to VPN or foreign namespaces."""
    run = base.Rehearsal.__new__(base.Rehearsal)
    run.images = {"openvpn": "image"}
    run.launch = Mock(return_value="anchor")  # type: ignore[method-assign]
    run.docker = Mock(side_effect=RuntimeError("stop"))  # type: ignore[method-assign]
    aliases = ("login.microsoftonline.com=127.0.0.1", "api=127.0.0.1")
    with pytest.raises(RuntimeError, match="stop"):
        run.anchor("http", host_aliases=aliases)
    options = run.launch.call_args.args[2]
    assert options[:2] == ["--entrypoint=/bin/sleep", "--user=65530:65532"]
    assert set(options[2:]) == {f"--add-host={alias}" for alias in aliases}
    assert run.launch.call_args.args[3] == ["1800"]
    run.launch.reset_mock()
    for role, invalid in (("server", aliases), ("http", ("host=127.0.0.1",))):
        with pytest.raises(ValueError):
            run.anchor(role, host_aliases=invalid)
    run.launch.assert_not_called()


def test_cleanup_refuses_foreign_compose_container(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cleanup cannot remove a container with only a matching project label."""
    run = phase6.ComposeRehearsal.__new__(phase6.ComposeRehearsal)
    run.compose_invoked = True
    run.project = "ovpncp-p6-" + "a" * 12
    run.token = "a" * 12
    run.images = {"api": "image"}
    container = "b" * 64
    responses = [
        f"{container}\n".encode(),
        json.dumps(
            [
                {
                    "Id": container,
                    "Config": {
                        "Labels": {
                            "ovpncp.rehearsal": "foreign",
                            "com.docker.compose.project": run.project,
                            "com.docker.compose.service": "api",
                        }
                    },
                }
            ]
        ).encode(),
    ]
    run.docker = Mock(side_effect=responses)  # type: ignore[method-assign]
    parent_close = Mock()
    monkeypatch.setattr(base.Rehearsal, "close", parent_close)
    with pytest.raises(RuntimeError, match="ownership"):
        run.close()
    assert run.docker.call_count == 2
    parent_close.assert_not_called()


def test_service_identity_checks_actual_cached_image_id() -> None:
    """A tag or stale image cache cannot masquerade as the reviewed digest."""
    run = phase6.ComposeRehearsal.__new__(phase6.ComposeRehearsal)
    run.project = "ovpncp-p6-" + "a" * 12
    run.token = "a" * 12
    run.active_bundle = Path("initial")
    run.upgrade_bundle = Path("upgrade")
    image = "example.test/ovpncp-api@sha256:" + "c" * 64
    run.images = {"api": image}
    run.upgrade_images = copy.copy(run.images)
    run.cached_image_ids = {image: "sha256:" + "e" * 64}
    container = "b" * 64
    info = {
        "Id": container,
        "Image": "sha256:" + "d" * 64,
        "State": {"Pid": 123},
        "Config": {
            "Image": image,
            "Labels": {
                "ovpncp.rehearsal": run.token,
                "com.docker.compose.project": run.project,
                "com.docker.compose.service": "api",
            },
        },
    }
    run.compose = Mock(return_value=container.encode())  # type: ignore[method-assign]
    run.docker = Mock(return_value=json.dumps([info]).encode())  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="unexpected image"):
        run.service_identity("api")
    run.docker.assert_called_once_with("inspect", container)


def test_compose_preflight_caches_each_unique_image_once() -> None:
    """Runtime identity checks use reviewed IDs without repeated daemon lookups."""
    run = phase6.ComposeRehearsal.__new__(phase6.ComposeRehearsal)
    run.images = {
        "openvpn": "image-a",
        "agent": "image-b",
        "api": "image-c",
        "web": "image-d",
    }
    run.upgrade_images = {**run.images, "api": "image-e"}
    image_id = "sha256:" + "f" * 64
    run.docker = Mock(  # type: ignore[method-assign]
        return_value=json.dumps([{"Id": image_id}]).encode()
    )
    run.check_image_cache()
    assert run.docker.call_count == 5
    assert set(run.cached_image_ids) == set(run.images.values()) | set(
        run.upgrade_images.values()
    )
    assert set(run.cached_image_ids.values()) == {image_id}


def test_compose_typed_probe_uses_idle_sleep_process() -> None:
    """The API-image helper needs Python only for bounded docker exec calls."""
    run = phase6.ComposeRehearsal.__new__(phase6.ComposeRehearsal)
    run.images = {"api": "api-image", "openvpn": "vpn-image"}
    run.launch = Mock(return_value="helper")  # type: ignore[method-assign]
    run.mount = Mock(return_value=[])  # type: ignore[method-assign]
    run._render = Mock()  # type: ignore[method-assign]
    run.compose = Mock(return_value=b"")  # type: ignore[method-assign]
    run.http_probe = Mock()  # type: ignore[method-assign]
    run.wait_ready = Mock()  # type: ignore[method-assign]
    run.service_identity = Mock(return_value=("agent-id", 123))  # type: ignore[method-assign]
    run.services(_anchors())
    probe = next(call for call in run.launch.call_args_list if call.args[0] == "probe")
    assert "--entrypoint=/bin/sleep" in probe.args[2]
    assert probe.args[3] == ["1800"]
