"""Ownership and rollback regressions for opt-in host-topology rehearsal."""

import copy
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from tests.integration import compose_phase6_host_rehearsal as host
from tests.integration import compose_phase6_rehearsal as isolated


def _rendered() -> tuple[dict[str, Any], dict[str, str]]:
    """Return a small rendered model for topology transformation tests."""
    images = {role: f"image-{role}" for role in ("openvpn", "agent", "api", "web")}
    services = {
        role: {
            "image": image,
            "network_mode": "host" if role in {"openvpn", "agent"} else None,
            "networks": {"web": {"ipv4_address": "172.30.250.2"}},
            "ports": ["127.0.0.1:8080:8080"] if role == "web" else None,
            "logging": {},
            "restart": "unless-stopped",
            "environment": {},
            "volumes": [],
        }
        for role, image in images.items()
    }
    model: dict[str, Any] = {
        "name": "rivet",
        "networks": {
            "web": {
                "name": "rivet_web",
                "driver": "bridge",
                "ipam": {"config": [{"subnet": "172.30.250.0/28"}]},
            }
        },
        "services": services,
        "x-bind": {},
        "x-runtime": {},
    }
    return model, images


def test_host_bundle_retains_source_network_modes_and_ports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the project identity and synthetic fixture grants change."""
    attest = Mock()
    monkeypatch.setattr(host, "_attest_service", attest)
    rendered, images = _rendered()
    original = copy.deepcopy(rendered)
    bundle = host.host_bundle(
        rendered,
        images=images,
        state=tmp_path,
        fixture=tmp_path / "fixture",
        token="a" * 12,
        upgrade=True,
    )
    assert rendered == original
    assert attest.call_count == 4
    assert all(call.args[3] == "186" for call in attest.call_args_list)
    assert bundle["name"] == "rivet-p6-" + "a" * 12
    assert bundle["networks"]["web"]["name"] == bundle["name"] + "_web"
    for role in ("openvpn", "agent", "api", "web"):
        service = bundle["services"][role]
        assert service["network_mode"] == original["services"][role]["network_mode"]
        assert service["networks"] == original["services"][role]["networks"]
        assert service["ports"] == original["services"][role]["ports"]
        assert service["labels"] == {"rivet.rehearsal": "a" * 12}
    assert bundle["services"]["api"]["volumes"][0]["read_only"] is True
    assert (
        bundle["services"]["web"]["environment"]["RIVET_UI_ENTRA_API_SCOPE"]
        == isolated.UPGRADE_SCOPE
    )


@pytest.mark.parametrize("change", ["extra", "network", "image"])
def test_host_bundle_rejects_unreviewed_topology(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    """No extra resource, bridge prefix or image can enter the host bundle."""
    monkeypatch.setattr(host, "_attest_service", Mock())
    rendered, images = _rendered()
    if change == "extra":
        rendered["volumes"] = {"foreign": {}}
    elif change == "network":
        rendered["networks"]["web"]["ipam"]["config"][0]["subnet"] = "172.30.250.0/24"
    else:
        rendered["services"]["api"]["image"] = "other"
    with pytest.raises(ValueError):
        host.host_bundle(
            rendered,
            images=images,
            state=tmp_path,
            fixture=tmp_path,
            token="a" * 12,
        )


def _runner(tmp_path: Path) -> host.HostComposeRehearsal:
    """Create a side-effect-free runner shell with known ownership values."""
    run = host.HostComposeRehearsal.__new__(host.HostComposeRehearsal)
    run.token = "a" * 12
    run.project = "rivet-p6-" + run.token
    run.device = "tunp6" + "a" * 8
    run.bridge = run.project + "_web"
    run.root = tmp_path / "state"
    run.root.mkdir()
    run.containers = []
    run.namespaces = {}
    run.compose_invoked = False
    run.project_started = False
    run.chain_started = True
    run.sysctl_before = "1"
    run.firewall_before = None
    return run


def _filter(run: host.HostComposeRehearsal, *, foreign_first: bool = False) -> bytes:
    """Render the exact owned baseline with optional foreign first rule."""
    anchors, members = run._expected_firewall()
    lines = ["*filter", ":FORWARD ACCEPT [0:0]", ":OVPNCP_FORWARD - [0:0]"]
    if foreign_first:
        lines.append("-A FORWARD -j ACCEPT")
    lines.extend(" ".join(rule) for rule in anchors)
    lines.extend(" ".join(rule) for rule in members)
    lines.extend(["COMMIT", ""])
    return "\n".join(lines).encode()


def test_firewall_readiness_requires_first_two_forward_rules(tmp_path: Path) -> None:
    """A Docker or foreign rule ahead of the anchors blocks traffic claims."""
    run = _runner(tmp_path)
    run.command = Mock(return_value=_filter(run))  # type: ignore[method-assign]
    run._attest_firewall(ready=True)
    run.command = Mock(return_value=_filter(run, foreign_first=True))  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="not ready"):
        run._attest_firewall(ready=True)


def test_firewall_cleanup_refuses_foreign_jump(tmp_path: Path) -> None:
    """Cleanup never deletes a chain referenced from another host chain."""
    run = _runner(tmp_path)
    raw = _filter(run).replace(b"COMMIT", b"-A INPUT -j OVPNCP_FORWARD\nCOMMIT")
    run.command = Mock(return_value=raw)  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="ownership"):
        run._remove_firewall()
    assert all(
        call.args[0] == ["iptables-nft-save", "-t", "filter"]
        for call in run.command.call_args_list
    )


def test_firewall_cleanup_deletes_only_owned_rules(tmp_path: Path) -> None:
    """Foreign FORWARD rules stay in place while exact test rules are removed."""
    run = _runner(tmp_path)
    raw = _filter(run, foreign_first=True)
    run.command = Mock(return_value=raw)  # type: ignore[method-assign]
    run._remove_firewall()
    calls = [call.args[0] for call in run.command.call_args_list]
    mutations = [args for args in calls if args[0] == "iptables-nft"]
    assert len(mutations) == 4
    assert all(args[1] in {"-D", "-X"} for args in mutations)
    assert ["iptables-nft", "-D", "FORWARD", "-j", "ACCEPT"] not in mutations
    assert mutations[-1] == ["iptables-nft", "-X", "OVPNCP_FORWARD"]
    assert run.chain_started is False


def test_cleanup_retains_state_and_restores_sysctl_on_container_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Failed owned-container cleanup cannot erase recovery evidence."""
    run = _runner(tmp_path)
    cleanup = Mock(side_effect=RuntimeError("private"))
    monkeypatch.setattr(isolated.ComposeRehearsal, "close", cleanup)
    run.command = Mock(return_value=b"")  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="incomplete"):
        run.close()
    cleanup.assert_called_once_with(remove_state=False)
    run.command.assert_called_once_with(
        ["sysctl", "-w", "net.ipv4.conf.all.send_redirects=1"]
    )
    assert run.root.exists()


def test_filter_normalization_ignores_counters_and_timestamps() -> None:
    """Before/after checks compare rules while discarding volatile counters."""
    before = b"# Generated by iptables-save\n:FORWARD ACCEPT [1:60]\nCOMMIT\n"
    after = b"# Completed on later date\n:FORWARD ACCEPT [9:540]\nCOMMIT\n"
    assert host.normalized_filter(before) == host.normalized_filter(after)


def test_docker_network_overlap_accepts_null_host_network_ipam() -> None:
    """Docker host/none networks may report a null IPAM.Config value."""
    assert host.docker_network_overlaps({"IPAM": {"Config": None}}) is False
    assert host.docker_network_overlaps({"IPAM": None}) is False
    assert (
        host.docker_network_overlaps(
            {"IPAM": {"Config": [{"Subnet": "172.17.0.0/16"}]}}
        )
        is False
    )
    assert (
        host.docker_network_overlaps(
            {"IPAM": {"Config": [{"Subnet": "10.253.0.0/24"}]}}
        )
        is True
    )


def test_host_access_uses_recoverable_mutation_protocol(tmp_path: Path) -> None:
    """An accepted asynchronous rule update is looked up before traffic proof."""
    run = _runner(tmp_path)
    run.access_id = "12345678-1234-4234-8234-123456789abc"
    run.query = Mock()  # type: ignore[method-assign]
    run.access(True)
    code = run.query.call_args.args[0]
    assert "mutate(s.SetAccess(intent=intent, present=True))" in code
    assert "adapter.execute(request)" not in code
