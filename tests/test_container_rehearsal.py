"""Safety regressions for the explicitly invoked disposable Docker rehearsal."""

import os
from pathlib import Path
from unittest.mock import Mock

import pytest

from tests.integration import vpn_container_rehearsal as rehearsal


def test_image_requires_repository_digest() -> None:
    """Tags, shell text and wrong repositories cannot select mutable images."""
    for invalid in ("agent:latest", "agent@sha256:abc", ";id", "../agent"):
        with pytest.raises(ValueError):
            rehearsal.validate_image(invalid, "agent")
    rehearsal.validate_image("example.test/ovpncp-agent@sha256:" + "a" * 64, "agent")


def test_namespace_refuses_host_and_reused_namespace() -> None:
    """No fixture command may run in the host or another anchor namespace."""
    with pytest.raises(RuntimeError):
        rehearsal.validate_namespace(17, 17, set())
    with pytest.raises(RuntimeError):
        rehearsal.validate_namespace(18, 17, {18})
    rehearsal.validate_namespace(18, 17, set())


def test_network_command_uses_pinned_namespace(tmp_path: Path) -> None:
    """All ip/firewall commands enter an attested namespace by open descriptor."""
    run = rehearsal.Rehearsal.__new__(rehearsal.Rehearsal)
    run.namespaces = {"server": 42}
    run.command = Mock(return_value=b"")  # type: ignore[method-assign]
    run.network("server", ["ip", "link", "set", "lo", "up"])
    run.command.assert_called_once_with(
        ["nsenter", "--net=/proc/self/fd/42", "--", "ip", "link", "set", "lo", "up"],
        pass_fds=(42,),
    )
    with pytest.raises(KeyError):
        run.network("unknown", ["ip", "link", "set", "lo", "up"])


def test_launch_forbids_implicit_network_and_pull() -> None:
    """Disposable launch defaults cannot touch a Docker bridge or pull images."""
    run = rehearsal.Rehearsal.__new__(rehearsal.Rehearsal)
    run.token = "a" * 12
    run.containers = []
    run.command = Mock(return_value=b"container-id")  # type: ignore[method-assign]
    name = run.launch("anchor", "image", [], ["python", "-c", "pass"])
    argv = run.command.call_args.args[0]
    assert argv[argv.index("--network") + 1] == "none"
    assert "--pull=never" in argv
    assert "--read-only" in argv
    assert "--privileged" not in argv
    assert "--publish" not in argv
    assert name in run.containers


def test_failed_launch_is_tracked_for_cleanup() -> None:
    """A timeout after Docker creates the object must not leave it untracked."""
    run = rehearsal.Rehearsal.__new__(rehearsal.Rehearsal)
    run.token = "a" * 12
    run.containers = []
    run.command = Mock(  # type: ignore[method-assign]
        side_effect=RuntimeError("redacted")
    )
    with pytest.raises(RuntimeError):
        run.launch("anchor", "image", [], ["python", "-c", "pass"])
    assert run.containers == ["ovpncp-p6-aaaaaaaaaaaa-anchor"]


def test_cleanup_preserves_state_when_container_removal_fails(tmp_path: Path) -> None:
    """Mounted synthetic state must survive a failed teardown for safe recovery."""
    run = rehearsal.Rehearsal.__new__(rehearsal.Rehearsal)
    run.root = tmp_path / "state"
    run.root.mkdir()
    run.containers = ["owned"]
    run.namespaces = {}
    run.command = Mock(  # type: ignore[method-assign]
        side_effect=RuntimeError("redacted")
    )
    with pytest.raises(RuntimeError):
        run.close()
    assert run.root.exists()


def test_private_files_get_explicit_grants(tmp_path: Path) -> None:
    """Fixture credentials never depend on the invoking shell's umask."""
    path = tmp_path / "key"
    rehearsal.write_file(path, b"synthetic", os.getuid(), os.getgid(), 0o600)
    assert path.read_bytes() == b"synthetic"
    assert path.stat().st_mode & 0o777 == 0o600


def test_mount_rejects_escape_and_missing_paths(tmp_path: Path) -> None:
    """Live host paths cannot be included through the mount helper."""
    run = rehearsal.Rehearsal.__new__(rehearsal.Rehearsal)
    run.state = tmp_path / "fixture"
    run.state.mkdir()
    (run.state / "escape").symlink_to(tmp_path, target_is_directory=True)
    for source in ("/etc", "../", "escape", "missing"):
        with pytest.raises(ValueError):
            run.mount(source, "/fixture")


def test_launch_rejects_host_and_unowned_network() -> None:
    """Network overrides are limited to anchors owned by this exact run."""
    run = rehearsal.Rehearsal.__new__(rehearsal.Rehearsal)
    run.token = "a" * 12
    run.containers = []
    for network in ("host", "bridge", "container:foreign"):
        with pytest.raises(ValueError):
            run.launch("test", "image", [], [], network=network)
    assert run.containers == []


def test_cleanup_refuses_foreign_label(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A container name collision never authorizes deleting another object."""
    import json

    run = rehearsal.Rehearsal.__new__(rehearsal.Rehearsal)
    run.token = "ours"
    run.root = tmp_path
    run.containers = ["collision"]
    run.namespaces = {}
    command = Mock(
        return_value=json.dumps(
            [
                {
                    "Config": {"Labels": {"ovpncp.rehearsal": "foreign"}},
                    "Id": "a" * 64,
                }
            ]
        ).encode()
    )
    monkeypatch.setattr(run, "command", command)
    with pytest.raises(RuntimeError):
        run.close()
    assert command.call_count == 1
    assert "rm" not in command.call_args.args[0]


def test_cleanup_removes_ids_before_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A successful teardown removes the attested container and its private data."""
    import json

    run = rehearsal.Rehearsal.__new__(rehearsal.Rehearsal)
    run.token = "ours"
    run.root = tmp_path / "state"
    run.root.mkdir()
    run.containers = ["owned"]
    run.namespaces = {}
    command = Mock(
        side_effect=[
            json.dumps(
                [
                    {
                        "Config": {"Labels": {"ovpncp.rehearsal": "ours"}},
                        "Id": "a" * 64,
                    }
                ]
            ).encode(),
            b"",
        ]
    )
    monkeypatch.setattr(run, "command", command)
    run.close()
    assert command.call_args.args[0][-3:] == ["rm", "--force", "a" * 64]
    assert not run.root.exists()


def test_command_redacts_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Subprocess diagnostics must never become the public failure message."""
    import subprocess

    run = rehearsal.Rehearsal.__new__(rehearsal.Rehearsal)
    monkeypatch.setattr(
        rehearsal.subprocess,
        "run",
        Mock(
            return_value=subprocess.CompletedProcess(
                ["fixture"], 1, b"private-material", b"private-material"
            )
        ),
    )
    with pytest.raises(RuntimeError) as caught:
        run.command(["fixture"])
    assert "private-material" not in str(caught.value)


def test_anchor_rejects_host_before_network_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Even a running, correctly labelled container cannot confer host access."""
    import json
    from types import SimpleNamespace

    run = rehearsal.Rehearsal.__new__(rehearsal.Rehearsal)
    run.token = "a" * 12
    run.images = {"openvpn": "image"}
    run.containers = []
    run.namespaces = {}
    info = [
        {
            "State": {"Running": True, "Pid": 123},
            "HostConfig": {"NetworkMode": "none"},
            "Config": {"Labels": {"ovpncp.rehearsal": run.token}},
        }
    ]
    command = Mock(side_effect=[b"id", json.dumps(info).encode()])
    monkeypatch.setattr(run, "command", command)
    monkeypatch.setattr(rehearsal.os, "open", Mock(return_value=77))
    monkeypatch.setattr(
        rehearsal.os, "fstat", Mock(return_value=SimpleNamespace(st_ino=42))
    )
    monkeypatch.setattr(
        rehearsal.os, "stat", Mock(return_value=SimpleNamespace(st_ino=42))
    )
    close = Mock()
    monkeypatch.setattr(rehearsal.os, "close", close)
    with pytest.raises(RuntimeError):
        run.anchor("server")
    assert run.namespaces == {}
    close.assert_called_once_with(77)
    assert all(call.args[0][0] == "docker" for call in command.call_args_list)


def test_packet_counters_redact_rule_addresses_and_unowned_comments() -> None:
    """Diagnostics expose only reviewed counter labels and numeric values."""
    access_id = "12345678-1234-4234-8234-123456789abc"
    rules = f"""*filter
+[3:180] -A FORWARD -i tun0 -m comment --comment "ovpncp:anchor:ingress" -j OVPNCP_FORWARD
+[2:120] -A OVPNCP_FORWARD -s 10.231.0.10/32 -d 10.231.0.20/32 -m comment --comment "ovpncp:{access_id}:forward" -j ACCEPT
+[1:60] -A OVPNCP_FORWARD -m comment --comment "ovpncp:terminal-deny" -j DROP
+[9:540] -A FORWARD -m comment --comment "private-address-10.2.3.4" -j ACCEPT
+COMMIT
+""".replace("\n+", "\n")
    counters = rehearsal.rule_counters(rules.encode(), access_id)
    assert counters == {
        "ingress_anchor": {"packets": 3, "bytes": 180},
        "allow_forward": {"packets": 2, "bytes": 120},
        "terminal_deny": {"packets": 1, "bytes": 60},
    }
    assert "10." not in str(counters)
    assert access_id not in str(counters)


def test_interface_counters_exclude_identifying_fields() -> None:
    """Only numeric packet/error counters and the up state leave the fixture."""
    raw = [
        {
            "ifname": "tun-client",
            "address": "private-material",
            "flags": ["UP"],
            "stats64": {
                "rx": {"packets": 4, "bytes": 200, "errors": 0, "dropped": 1},
                "tx": {"packets": 5, "bytes": 300, "errors": 0, "dropped": 0},
            },
        }
    ]
    result = rehearsal.interface_counters(raw)
    assert result["up"] is True
    assert result["rx_packets"] == 4
    assert result["tx_packets"] == 5
    assert "private-material" not in str(result)
    assert "tun-client" not in str(result)


def test_ping_summary_redacts_addresses_and_reports_failures() -> None:
    """Only counters and known diagnostic categories leave ping output."""
    raw = b"""PING private-host (10.231.0.20) 56(84) bytes of data.
From 10.231.0.1: icmp_seq=1 Redirect Host(New nexthop: 10.231.0.20)
From 10.231.0.20 icmp_seq=1 Destination Host Unreachable
1 packets transmitted, 0 received, +1 errors, 100% packet loss, time 0ms
"""
    result = rehearsal.ping_summary(raw, b"", 1)
    assert result["transmitted"] == 1
    assert result["received"] == 0
    assert result["errors"] == 1
    assert result["redirect"] is True
    assert result["unreachable"] is True
    assert result["exit_code"] == 1
    assert "10." not in str(result)
    assert "private-host" not in str(result)


def test_ping_summary_distinguishes_reply_without_sensitive_text() -> None:
    """Successful replies preserve exact counts without reflecting free text."""
    result = rehearsal.ping_summary(
        b"1 packets transmitted, 1 received, 0% packet loss, time 0ms\n",
        b"unknown-private-error",
        0,
    )
    assert result["received"] == 1
    assert result["unreachable"] is False
    assert result["stderr_present"] is True
    assert "unknown-private-error" not in str(result)


def test_icmp_observer_emits_only_direction_type_and_code(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Raw packet bytes and endpoint metadata remain inside the observer."""
    import json
    import sys
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    packet = bytearray(64)
    packet[0] = 0x45
    packet[9] = 1
    packet[12:20] = bytes([10, 231, 0, 10, 10, 231, 0, 20])
    packet[20:22] = bytes([8, 0])
    packet[30:46] = b"private-payload!"
    sock = MagicMock()
    sock.__enter__.return_value = sock
    sock.recvfrom.return_value = (bytes(packet), ("tun-client", 0, 4))
    socket_module = SimpleNamespace(
        AF_PACKET=17,
        SOCK_DGRAM=2,
        PACKET_OUTGOING=4,
        htons=lambda value: value,
        socket=Mock(return_value=sock),
    )
    clock_module = SimpleNamespace(monotonic=Mock(side_effect=[0, 1, 5]))
    with monkeypatch.context() as patch:
        patch.setitem(sys.modules, "socket", socket_module)
        patch.setitem(sys.modules, "time", clock_module)
        exec(rehearsal.ICMP_OBSERVER, {})  # noqa: S102 - fixed source, mocked I/O
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "READY"
    assert json.loads(lines[1]) == {"out:8:0": 1}
    assert "private" not in str(lines)
    assert "10." not in str(lines)


def test_gateway_redirect_policy_is_confined_and_precedes_tun_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only the disposable server sets all/default redirect policy pre-TUN."""
    run = rehearsal.Rehearsal.__new__(rehearsal.Rehearsal)
    run.namespaces = {"server": 11, "a": 12, "b": 13, "c": 14}
    monkeypatch.setattr(run, "anchor", Mock(side_effect=["server", "a", "b", "c"]))
    network = Mock(return_value=b"")
    monkeypatch.setattr(run, "network", network)
    run.topology()
    writes = [
        call.args for call in network.call_args_list if call.args[1][0] == "sysctl"
    ]
    assert ("server", ["sysctl", "-w", "net.ipv4.conf.all.send_redirects=0"]) in writes
    assert (
        "server",
        ["sysctl", "-w", "net.ipv4.conf.default.send_redirects=0"],
    ) in writes
    assert all(role == "server" for role, _ in writes)
    assert all("tun0" not in args for _, args in writes)


def test_packet_snapshot_includes_all_redirect_flags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A complete diagnostic retains forwarding and all three redirect scopes."""
    import json

    run = rehearsal.Rehearsal.__new__(rehearsal.Rehearsal)
    run.access_id = "fixture"

    def observe(role: str, argv: list[str]) -> bytes:
        if argv[0] == "sysctl":
            return b"1\n2\n2\n0\n0\n0\n0\n"
        if argv[0] == "iptables-nft-save":
            return b""
        device = "tun0" if role == "server" else "tun-client"
        if "route" in argv:
            return json.dumps([{"dev": device}]).encode()
        counters = {"packets": 0, "bytes": 0, "errors": 0, "dropped": 0}
        return json.dumps(
            [{"flags": ["UP"], "stats64": {"rx": counters, "tx": counters}}]
        ).encode()

    monkeypatch.setattr(run, "network", observe)
    result = run.packet_snapshot()
    assert result["server_flags"] == {
        "forwarding": 1,
        "all_rp_filter": 2,
        "tun_rp_filter": 2,
        "ignore_echo": 0,
        "all_send_redirects": 0,
        "default_send_redirects": 0,
        "tun_send_redirects": 0,
    }


def test_topology_gives_lifecycle_client_its_own_namespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The issued client must not reuse an authenticated client's TUN or socket."""
    run = rehearsal.Rehearsal.__new__(rehearsal.Rehearsal)
    run.namespaces = {"server": 11, "a": 12, "b": 13, "c": 14}
    anchor = Mock(side_effect=["server", "a", "b", "c"])
    monkeypatch.setattr(run, "anchor", anchor)
    network = Mock(return_value=b"")
    monkeypatch.setattr(run, "network", network)
    assert set(run.topology()) == {"server", "a", "b", "c"}
    network.assert_any_call(
        "server",
        ["ip", "link", "set", "peer-c", "netns", "/proc/self/fd/14"],
        extra_fds=(14,),
    )


def test_http_api_uses_real_entrypoint_without_privileged_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HTTP outage proof starts the API as its real UID with synthetic auth."""
    run = rehearsal.Rehearsal.__new__(rehearsal.Rehearsal)
    run.images = {"api": "immutable-api"}
    run.state = tmp_path
    (tmp_path / "agent-socket").mkdir()
    launch = Mock(return_value="api")
    monkeypatch.setattr(run, "launch", launch)
    monkeypatch.setattr(run, "wait_http", Mock())
    assert run.start_http_api() == "api"
    args = launch.call_args.args
    assert args[0] == "http-api" and args[3] == []
    options = args[2]
    assert "--user=65531:65531" in options
    assert not any("--entrypoint" in value for value in options)
    assert not any("cap-add" in value or "/dev/net/tun" in value for value in options)
    assert not any("vpn-pki" in value or "vpn-projection" in value for value in options)
    assert "--env=OVPNCP_VPN_BACKEND=agent" in options
    assert "--env=OVPNCP_VPN_EVENTS=0" in options
    assert any("dst=/run/ovpn-agent,readonly" in value for value in options)


def test_credential_export_rejects_unexpected_archive_paths(tmp_path: Path) -> None:
    """An unexpected ZIP member must fail before any credential is written."""
    import io
    import zipfile

    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w") as archive:
        archive.writestr("ca.crt", b"synthetic-ca")
        archive.writestr("issued/managed-client.crt", b"synthetic-leaf")
        archive.writestr("../escape.key", b"synthetic-key")
    with pytest.raises(ValueError):
        rehearsal.export_archive(raw.getvalue(), tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_credential_export_limits_members_and_sets_private_modes(
    tmp_path: Path,
) -> None:
    """Only three fixed destinations are created with runtime-group read grants."""
    import io
    import zipfile

    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w") as archive:
        archive.writestr("ca.crt", b"synthetic-ca")
        archive.writestr("issued/managed-client.crt", b"synthetic-leaf")
        archive.writestr("private/managed-client.key", b"synthetic-key")
    rehearsal.export_archive(raw.getvalue(), tmp_path)
    assert {path.name for path in tmp_path.iterdir()} == {
        "ca.crt",
        "client.crt",
        "client.key",
    }
    assert all(path.stat().st_mode & 0o777 == 0o640 for path in tmp_path.iterdir())
    assert (tmp_path / "client.key").read_bytes() == b"synthetic-key"
    with pytest.raises(FileExistsError):
        rehearsal.export_archive(raw.getvalue(), tmp_path)


def test_outage_stops_real_api_and_probe_before_traffic_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Successful traffic during the outage cannot be inferred from startup health."""
    run = rehearsal.Rehearsal.__new__(rehearsal.Rehearsal)
    run.probe = "probe"
    events: list[object] = []
    monkeypatch.setattr(run, "start_http_api", Mock(return_value="api"))
    monkeypatch.setattr(run, "docker", lambda *args: events.append(args))
    monkeypatch.setattr(run, "wait_http", lambda name: events.append("http-ready"))
    monkeypatch.setattr(run, "wait_ready", lambda: events.append("agent-ready"))

    def flow() -> bool:
        events.append("traffic")
        return True

    monkeypatch.setattr(run, "peer_flow", flow)
    run.control_plane_outage()
    assert events == [
        ("stop", "--time=10", "api", "probe"),
        "traffic",
        ("start", "api", "probe"),
        "http-ready",
        "agent-ready",
        "traffic",
    ]


def test_outage_requires_live_traffic(monkeypatch: pytest.MonkeyPatch) -> None:
    """A failed outage packet cannot become a passing phase result."""
    run = rehearsal.Rehearsal.__new__(rehearsal.Rehearsal)
    run.probe = "probe"
    monkeypatch.setattr(run, "start_http_api", Mock(return_value="api"))
    docker = Mock(return_value=b"")
    monkeypatch.setattr(run, "docker", docker)
    monkeypatch.setattr(run, "peer_flow", Mock(return_value=False))
    with pytest.raises(RuntimeError):
        run.control_plane_outage()
    docker.assert_called_once_with("stop", "--time=10", "api", "probe")
