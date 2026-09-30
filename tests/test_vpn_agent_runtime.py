"""Bounded agent parser, actual-state, transport and shadow regressions."""

import dataclasses
import datetime
import grp
import json
import logging
import os
import pwd
import socket
import threading
import time
import uuid
from pathlib import Path
from unittest.mock import Mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from sciaiot.ovpncp.adapters.vpn.agent import AgentVpnControl
from sciaiot.ovpncp.adapters.vpn.host import HostVpnControl
from sciaiot.ovpncp.adapters.vpn.shadow import ShadowHostVpnControl, projection
from sciaiot.ovpncp.application.vpn_control import schemas as s
from sciaiot.ovpncp.application.vpn_control.errors import ControlError, ErrorCode
from sciaiot.ovpncp.vpn_agent import bounded, cli, files, network
from sciaiot.ovpncp.vpn_agent.control import ReadOnlyVpnControl
from sciaiot.ovpncp.vpn_agent.management import Management
from sciaiot.ovpncp.vpn_agent.server import UnixAgentServer
from sciaiot.ovpncp.vpn_agent.settings import Settings
from tests.test_vpn_agent import request, settings


@pytest.fixture
def runtime(tmp_path):
    """Create only public signed certs, index and CCD under a disposable root."""
    configured = settings(tmp_path)
    configured.pki_path.mkdir()
    (configured.pki_path / "issued").mkdir()
    configured.ccd_path.mkdir()
    configured.config_path.write_text(
        "dev tun0\nserver 10.8.0.0 255.255.255.0\nproto udp\nport 1194\n"
        "topology subnet\nkeepalive 10 120\npersist-key\npersist-tun\n"
        "data-ciphers AES-256-GCM:AES-128-GCM\n"
        "data-ciphers-fallback AES-256-CBC\nverb 3\nexplicit-exit-notify 1\n"
        f"management {configured.management_socket} unix\n"
        f"management-client-user {pwd.getpwuid(os.getuid()).pw_name}\n"
        f"management-client-group {grp.getgrgid(os.getgid()).gr_name}\n"
    )
    now = datetime.datetime.now(datetime.UTC).replace(microsecond=0)
    key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(key, hashes.SHA256())
    )
    (configured.pki_path / "ca.crt").write_bytes(
        ca.public_bytes(serialization.Encoding.PEM)
    )
    index = []
    for serial, name in enumerate(("alpha", "beta", "server"), 2):
        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=20))
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.SERVER_AUTH
                        if name == "server"
                        else ExtendedKeyUsageOID.CLIENT_AUTH
                    ]
                ),
                False,
            )
            .sign(key, hashes.SHA256())
        )
        (configured.pki_path / "issued" / f"{name}.crt").write_bytes(
            certificate.public_bytes(serialization.Encoding.PEM)
        )
        index.append(
            f"{'R' if name == 'beta' else 'V'}\t260930000000Z\t\t{serial:X}\tunknown\t/CN={name}\n"
        )
    (configured.pki_path / "index.txt").write_text("".join(index))
    (configured.ccd_path / "alpha").write_text(
        "ifconfig-push 10.8.0.10 255.255.255.0\niroute 192.168.3.0 255.255.255.0\n"
    )
    return configured


def test_configuration_clients_and_stale_pages(runtime):
    control = ReadOnlyVpnControl(runtime)
    config = control.execute(request(s.ServerConfig())).result
    assert isinstance(config, s.ConfigResult)
    assert config.data_ciphers == ("AES-256-GCM", "AES-128-GCM")
    first = control.execute(request(s.ListClients(limit=1))).result
    assert isinstance(first, s.ClientsResult)
    assert first.items[0].issuer == "test-ca"
    assert first.items[0].assignment.network == "192.168.3.0/24"
    second = control.execute(
        request(s.ListClients(cursor=first.next_cursor, limit=1))
    ).result
    assert second.items[0].state == "revoked"
    assert (
        control.execute(request(s.GetClient(client="alpha"))).result.item
        == first.items[0]
    )
    with pytest.raises(ControlError, match="not_found"):
        control.execute(request(s.GetClient(client="missing")))
    (runtime.ccd_path / "beta").write_text("ifconfig-push 10.8.0.11 255.255.255.0\n")
    with pytest.raises(ControlError, match="conflict"):
        control.execute(request(s.ListClients(cursor=first.next_cursor, limit=1)))
    for cursor in ("nonsense", "1_a", f"{first.generation}_0"):
        with pytest.raises(ControlError, match="conflict"):
            control.execute(request(s.ListClients(cursor=cursor)))


@pytest.mark.parametrize(
    "content",
    [
        "config /secret",
        "<key>secret</key>",
        "dev tun\nserver 10.8.0.0 255.255.255.0",
        "dev tun0\nserver 10.8.0.0 255.255.255.0\nport 1\nport 2",
        "dev tun0\nserver 10.8.0.0 255.255.255.0\nifconfig 10.9.0.1 255.255.255.0",
        "x" * 8193,
    ],
)
def test_config_rejects_unsupported_and_ambiguous(runtime, content):
    runtime.config_path.write_text(content)
    with pytest.raises(ControlError):
        ReadOnlyVpnControl(runtime).execute(request(s.ServerConfig()))


@pytest.mark.parametrize(
    "attack",
    ["index", "duplicate", "serial", "ccd", "iroutes", "symlink", "name", "huge"],
)
def test_client_inventory_fails_closed(runtime, attack, monkeypatch):
    if attack == "index":
        (runtime.pki_path / "index.txt").write_text("bogus")
    elif attack == "duplicate":
        path = runtime.pki_path / "index.txt"
        path.write_text(path.read_text() * 2)
    elif attack == "serial":
        (runtime.pki_path / "index.txt").write_text("")
    elif attack == "ccd":
        (runtime.ccd_path / "alpha").write_text("ifconfig-push bogus\n")
    elif attack == "iroutes":
        with (runtime.ccd_path / "alpha").open("a") as stream:
            stream.write("iroute 192.168.4.0 255.255.255.0\n")
    elif attack == "symlink":
        (runtime.pki_path / "issued" / "link.crt").symlink_to(
            runtime.pki_path / "ca.crt"
        )
    elif attack == "name":
        (runtime.pki_path / "issued" / "bad name.crt").write_text("")
    else:
        monkeypatch.setattr(bounded, "MAX_RECORDS", 1)
    with pytest.raises(ControlError):
        ReadOnlyVpnControl(runtime).execute(request(s.ListClients()))


def test_bounded_files_and_commands(tmp_path, monkeypatch):
    path = tmp_path / "data"
    path.write_bytes(b"1234")
    deadline = time.monotonic() + 2
    assert bounded.read_file(path, deadline) == b"1234"
    with pytest.raises(ControlError, match="exhausted"):
        bounded.read_file(path, deadline, 3)
    with pytest.raises(ControlError, match="timeout"):
        bounded.read_file(path, 0)
    link = tmp_path / "link"
    link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(OSError):
        bounded.read_file(link / "data", deadline)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(ControlError):
        bounded.read_file(fifo, deadline)
    with pytest.raises(ControlError, match="invalid_input"):
        bounded.observe("routes", "tun0;id", deadline)
    with pytest.raises(ControlError, match="invalid_input"):
        bounded.observe("delete", "tun0", deadline)
    # Replace only process creation: real pipes/selectors enforce output bounds.
    import subprocess

    popen = subprocess.Popen
    monkeypatch.setattr(
        bounded.subprocess,
        "Popen",
        lambda *a, **kw: popen(["/bin/echo", "observed"], **kw),
    )
    assert bounded.observe("routes", "tun0", deadline) == b"observed\n"
    monkeypatch.setattr(bounded, "MAX_BYTES", 2)
    with pytest.raises(ControlError, match="exhausted"):
        bounded.observe("routes", "tun0", deadline)


def management_peer(tmp_path, response):
    """Serve one bounded management exchange and record received command bytes."""
    directory = tmp_path / uuid.uuid4().hex[:4]
    directory.mkdir(mode=0o770)
    configured = dataclasses.replace(
        settings(directory), management_socket=str(directory / "m.sock")
    )
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(configured.management_socket)
    listener.listen()
    observed = []

    def serve():
        with listener:
            connection, _ = listener.accept()
            with connection:
                observed.append(connection.recv(100))
                if observed[-1]:
                    connection.sendall(response)

    thread = threading.Thread(target=serve)
    thread.start()
    return configured, thread, observed


def test_management_real_uds_identity_and_fixed_commands(tmp_path):
    configured, thread, observed = management_peer(
        tmp_path, b">INFO:hello\r\nOpenVPN Version: OpenVPN 2.6.19\r\nEND\r\n"
    )
    manager = Management(configured)
    assert "2.6.19" in manager.read("version", time.monotonic() + 2)
    thread.join(2)
    assert observed == [b"version\n"]
    with pytest.raises(ControlError, match="invalid_input"):
        manager.read("signal SIGTERM", time.monotonic() + 2)
    configured, thread, observed = management_peer(tmp_path, b"END\n")
    denied = dataclasses.replace(configured, management_uid=os.getuid() + 1)
    with pytest.raises(ControlError, match="unauthorized"):
        Management(denied).read("state", time.monotonic() + 2)
    thread.join(2)
    assert observed == [b""]
    configured, thread, _ = management_peer(tmp_path, b"END\n")
    assert Management(configured).read("state", time.monotonic() + 2) == ""
    thread.join(2)


STATUS = "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tConnected Since (time_t)\tClient ID\tPeer ID\nCLIENT_LIST\talpha\t192.0.2.1:1234\t10.8.0.10\t1700000000\t0\t1"


def test_sessions_and_health(runtime, monkeypatch):
    control = ReadOnlyVpnControl(runtime)
    responses = {
        "version": "OpenVPN Version: OpenVPN 2.6.19",
        "state": "1700000000,CONNECTED,SUCCESS,10.8.0.1",
        "status 3": STATUS,
    }
    monkeypatch.setattr(
        control.management, "read", lambda cmd, deadline: responses[cmd]
    )
    monkeypatch.setattr(
        bounded,
        "observe",
        lambda kind, *args: (
            b"iptables-save (nf_tables)"
            if kind == "backend"
            else b'[{"ifname":"tun0","flags":["UP"]}]'
        ),
    )
    assert control.execute(request(s.Health())).result.ready
    result = control.execute(request(s.ListSessions())).result
    assert result.items[0].client == "alpha"
    assert result == control.execute(request(s.ListSessions())).result
    responses["state"] = "1700000000,RECONNECTING,init"
    assert not control.execute(request(s.Health())).result.ready
    responses["version"] = "OpenVPN Version: OpenVPN 2.5.1"
    with pytest.raises(ControlError, match="version_mismatch"):
        control.execute(request(s.Health()))
    for invalid in (
        "",
        "CLIENT_LIST\talpha",
        STATUS + "\nHEADER\tCLIENT_LIST\tx",
        STATUS.replace("192.0.2.1", "secret-bad"),
    ):
        responses["status 3"] = invalid
        with pytest.raises(ControlError):
            control.execute(request(s.ListSessions()))
    with runtime.config_path.open("a") as stream:
        stream.write("management-signal\n")
    with pytest.raises(ControlError, match="unauthorized"):
        control.execute(request(s.Health()))


def ownership_fixture(runtime):
    """Return exact declared state and expected iproute/iptables observations."""
    route = s.ManagedRoute(
        route_id=str(uuid.uuid4()), network="192.168.3.0/24", gateway="10.8.0.10"
    )
    intent = s.AccessIntent(
        access_id=str(uuid.uuid4()),
        source_client="alpha",
        destination_client="beta",
        source_address="10.8.0.10",
        destination_address="10.8.0.11",
        private_networks=("192.168.3.0/24",),
    )
    push = s.OwnedPushes(
        intent_id=intent.access_id,
        client="alpha",
        routes=(s.PushRoute(network=route.network, gateway=route.gateway),),
    )
    path = runtime.config_path.parent / "ownership.json"
    path.write_text(
        network.Ownership(
            routes=(route,), access=(intent,), pushes=(push,)
        ).model_dump_json()
    )
    configured = dataclasses.replace(runtime, ownership_path=path)
    with (runtime.ccd_path / "alpha").open("a") as stream:
        stream.write('push "route 192.168.3.0 255.255.255.0 10.8.0.10"\n')
    rules = [
        f"-A FORWARD -{flag} tun0 -m comment --comment ovpncp:anchor:{direction} -j OVPNCP_FORWARD"
        for direction, flag in (("ingress", "i"), ("egress", "o"))
    ]
    for destination, prefix in (
        ("10.8.0.11/32", f"ovpncp:{intent.access_id}"),
        ("192.168.3.0/24", f"ovpncp:{intent.access_id}:private:0"),
    ):
        rules.extend(
            " ".join(network._rule(source, dest, marker, "tun0"))
            for source, dest, marker in (
                ("10.8.0.10/32", destination, prefix + ":forward"),
                (destination, "10.8.0.10/32", prefix + ":reverse"),
            )
        )
    outputs = {
        "backend": b"iptables-save v1.8.9 (nf_tables)",
        "rules": "\n".join(rules).encode(),
        "routes": json.dumps(
            [
                {
                    "dst": route.network,
                    "gateway": route.gateway,
                    "dev": "tun0",
                    "protocol": 200,
                },
                {
                    "dst": "192.168.4.0/24",
                    "gateway": "10.8.0.11",
                    "dev": "tun0",
                    "protocol": 201,
                },
            ]
        ).encode(),
    }
    return configured, outputs


def test_owned_network_realization_and_foreign_state(runtime, monkeypatch):
    configured, outputs = ownership_fixture(runtime)
    monkeypatch.setattr(bounded, "observe", lambda kind, *_: outputs[kind])
    control = ReadOnlyVpnControl(configured)
    assert len(control.execute(request(s.ListRoutes())).result.items) == 1
    result = control.execute(request(s.ListAccess())).result
    assert len(result.items) == len(result.pushes) == 1
    outputs["rules"] = outputs["rules"].splitlines()[0]
    with pytest.raises(ControlError, match="conflict"):
        control.execute(request(s.ListAccess()))
    outputs["routes"] = outputs["routes"].replace(b"200", b"201")
    with pytest.raises(ControlError, match="conflict"):
        control.execute(request(s.ListRoutes()))
    assert not ReadOnlyVpnControl(runtime).execute(request(s.ListRoutes())).result.items
    assert not ReadOnlyVpnControl(runtime).execute(request(s.ListAccess())).result.items


def test_ownership_unknown_duplicate_and_backend_failures(runtime, monkeypatch):
    configured, outputs = ownership_fixture(runtime)
    monkeypatch.setattr(bounded, "observe", lambda kind, *_: outputs[kind])
    outputs["backend"] = b"legacy"
    with pytest.raises(ControlError, match="unavailable"):
        ReadOnlyVpnControl(configured).execute(request(s.ListAccess()))
    inventory = json.loads(configured.ownership_path.read_text())
    inventory["routes"] *= 2
    configured.ownership_path.write_text(json.dumps(inventory))
    with pytest.raises(ControlError, match="integrity"):
        ReadOnlyVpnControl(configured).execute(request(s.ListRoutes()))


def test_real_agent_transport_and_mutation_rejection(runtime, monkeypatch):
    directory = runtime.config_path.parent / "control"
    directory.mkdir(mode=0o2750)
    directory.chmod(0o2750)
    configured = dataclasses.replace(
        runtime, control_socket=str(directory / "agent.sock")
    )
    control = ReadOnlyVpnControl(configured)
    monkeypatch.setattr(
        control, "_health", lambda deadline: s.HealthResult(ready=True, generation=1)
    )
    with UnixAgentServer(configured, control) as server:
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        agent = AgentVpnControl(configured.control_socket, peer_uid=os.getuid())
        assert isinstance(
            agent.execute(request(s.ServerConfig())).result, s.ConfigResult
        )
        with pytest.raises(ControlError, match="unavailable"):
            agent.execute(request(s.Reload()))
        server.shutdown()
        thread.join(2)
        assert not thread.is_alive()
    assert not Path(configured.control_socket).exists()
    with pytest.raises(ControlError, match="unavailable"):
        agent.execute(request(s.Health()))


def test_peer_rejected_before_any_reads(runtime):
    directory = runtime.config_path.parent / "control"
    directory.mkdir()
    directory.chmod(0o2750)
    configured = dataclasses.replace(
        runtime, control_socket=str(directory / "a.sock"), api_uid=os.getuid() + 1
    )
    import struct

    connection = Mock()
    connection.getsockopt.return_value = struct.pack("iII", 1, os.getuid(), os.getgid())
    with (
        UnixAgentServer(configured) as server,
        pytest.raises(ControlError, match="unauthorized"),
    ):
        server.handle(connection)
    connection.recv.assert_not_called()


@pytest.mark.parametrize(
    "payload",
    [
        b"GET /v1/archive HTTP/1.1\r\n\r\n",
        b"POST /v1/control HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
        b"POST /v1/control HTTP/1.1\r\nContent-Length: 9999999\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",
        b"x" * 17000,
        b"POST /v1/control HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
    ],
)
def test_malformed_http_is_bounded(runtime, payload):
    directory = runtime.config_path.parent / "control"
    directory.mkdir()
    directory.chmod(0o2750)
    configured = dataclasses.replace(runtime, control_socket=str(directory / "a.sock"))
    sender, receiver = socket.socketpair()
    with sender, receiver, UnixAgentServer(configured) as server:
        sender.sendall(payload)
        sender.shutdown(socket.SHUT_WR)
        with pytest.raises(ControlError):
            server.handle(receiver)


def test_settings_and_cli_fail_closed(runtime, monkeypatch):
    with pytest.raises(ValueError):
        dataclasses.replace(runtime, api_uid=-1)
    with pytest.raises(ValueError):
        dataclasses.replace(runtime, config_path=Path("relative"))
    environment = {
        "OVPNCP_AGENT_CONFIG": str(runtime.config_path),
        "OVPNCP_AGENT_PKI": str(runtime.pki_path),
        "OVPNCP_AGENT_CCD": str(runtime.ccd_path),
        "OVPNCP_MANAGEMENT_SOCKET": runtime.management_socket,
        "OVPNCP_MANAGEMENT_UID": str(os.getuid()),
        "OVPNCP_MANAGEMENT_GID": str(os.getgid()),
        "OVPNCP_API_UID": str(os.getuid()),
        "OVPNCP_AGENT_SOCKET": runtime.control_socket,
    }
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    assert Settings.from_environment() == runtime
    monkeypatch.setenv("OVPNCP_API_UID", "invalid")
    with pytest.raises(ValueError):
        Settings.from_environment()
    with pytest.raises(SystemExit, match="Private VPN agent unavailable"):
        cli.main()


def test_shadow_preserves_legacy_results_and_redacts_failures(
    runtime, monkeypatch, caplog
):
    agent = Mock()
    control = ShadowHostVpnControl(agent)
    monkeypatch.setattr(
        HostVpnControl,
        "health",
        lambda self: {"status": "active (running)", "time": "original"},
    )
    agent.execute.return_value = s.Response(
        request_id=str(uuid.uuid4()), result=s.HealthResult(ready=True, generation=123)
    )
    with caplog.at_level(logging.INFO):
        assert control.health()["time"] == "original"
        agent.execute.side_effect = RuntimeError("secret 192.0.2.1")
        assert control.health()["time"] == "original"
    assert "health match" in caplog.text
    assert "health unavailable" in caplog.text
    assert "secret" not in caplog.text and "192.0.2.1" not in caplog.text
    agent.reset_mock()
    control.fault = "failed"
    control.execute(request(s.ChangeClient(client="alpha", action="issue")))
    agent.execute.assert_not_called()
    assert projection({"generation": 1, "items": [1]}) == {"items": [1]}


def test_shadow_all_legacy_read_projections(runtime, monkeypatch, caplog):
    """Each compatibility read compares typed data without replacing its value."""
    observed = ReadOnlyVpnControl(runtime)
    agent = Mock()
    agent.execute.side_effect = observed.execute
    control = ShadowHostVpnControl(agent)
    raw = {
        "server": "10.8.0.0 255.255.255.0",
        "dev": "tun0",
        "port": "1194",
        "proto": "udp",
        "topology": "subnet",
        "keepalive": "10 120",
        "persist_key": True,
        "persist_tun": True,
        "data_ciphers": "AES-256-GCM:AES-128-GCM",
        "data_ciphers_fallback": "AES-256-CBC",
        "verb": "3",
        "explicit_exit_notify": "1",
        "key": "/private/key",
    }
    monkeypatch.setattr(HostVpnControl, "configuration", lambda self: raw)
    monkeypatch.setattr(
        HostVpnControl, "discovered_names", lambda self: ["alpha", "beta"]
    )
    monkeypatch.setattr(
        HostVpnControl, "client_revoked", lambda self, name: name == "beta"
    )
    monkeypatch.setattr(
        HostVpnControl, "client_address", lambda self, name: "10.8.0.10"
    )
    monkeypatch.setattr(
        HostVpnControl,
        "route_lines",
        lambda self, device: ["192.168.3.0/24 via 10.8.0.10"],
    )
    item = observed.execute(request(s.GetClient(client="alpha"))).result.item
    details = {
        "issued_by": item.issuer,
        "issued_to": item.subject,
        "issued_on": datetime.datetime.fromtimestamp(
            item.not_before / 1_000_000, datetime.UTC
        ),
        "expires_on": datetime.datetime.fromtimestamp(
            item.not_after / 1_000_000, datetime.UTC
        ),
    }
    monkeypatch.setattr(
        HostVpnControl, "read_certificate", lambda self, client: details
    )
    with caplog.at_level(logging.INFO):
        assert control.configuration() is raw
        assert control.discovered_names() == ["alpha", "beta"]
        assert control.client_revoked("beta")
        assert control.client_address("alpha") == "10.8.0.10"
        assert control.read_certificate("alpha") is details
        assert control.route_lines("tun0") == ["192.168.3.0/24 via 10.8.0.10"]
        assert isinstance(
            control.execute(request(s.ServerConfig())).result, s.ConfigResult
        )
        monkeypatch.setattr(
            HostVpnControl, "client_address", lambda self, name: "10.8.0.99"
        )
        assert control.client_address("alpha") == "10.8.0.99"
    assert "server_config match" in caplog.text
    assert "get_client mismatch" in caplog.text
    assert "10.8.0" not in caplog.text
    assert "/private" not in caplog.text


def test_cli_normal_lifecycle_and_module_entry(monkeypatch):
    """CLI closes its server and supports both installed and module entry points."""
    import runpy

    server = Mock()
    server.__enter__ = Mock(return_value=server)
    server.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(cli.Settings, "from_environment", lambda: object())
    monkeypatch.setattr(cli, "UnixAgentServer", lambda settings: server)
    handlers = []
    monkeypatch.setattr(
        cli.signal, "signal", lambda signal, handler: handlers.append(handler)
    )
    cli.main()
    server.serve_forever.assert_called_once()
    for handler in handlers:
        handler(None, None)
    assert server.shutdown.call_count == 2
    mocked = Mock()
    monkeypatch.setattr(cli, "main", mocked)
    runpy.run_module("sciaiot.ovpncp.vpn_agent", run_name="__main__")
    mocked.assert_called_once()


def test_shadow_settings_selection_and_service_clone(runtime, monkeypatch):
    """Application host compatibility survives construction for each request."""
    from sqlmodel import Session, create_engine

    from sciaiot.ovpncp import dependencies
    from sciaiot.ovpncp.adapters.vpn.settings import BackendSettings
    from sciaiot.ovpncp.services.vpn import VpnService

    monkeypatch.setenv("OVPNCP_VPN_BACKEND", "shadow")
    monkeypatch.setenv("OVPNCP_AGENT_UID", str(os.getuid()))
    monkeypatch.setenv("OVPNCP_AGENT_SOCKET", runtime.control_socket)
    assert BackendSettings.from_environment().backend == "shadow"
    dependencies._configured_vpn_control.cache_clear()
    try:
        configured = dependencies._configured_vpn_control()
        assert isinstance(configured, ShadowHostVpnControl)
        monkeypatch.setattr(dependencies, "vpn_control", configured)
        with Session(create_engine("sqlite://")) as session:
            service = VpnService(session)
            assert isinstance(service.control, ShadowHostVpnControl)
            assert service.control.agent is configured.agent
            assert service.host
    finally:
        dependencies._configured_vpn_control.cache_clear()


def test_shadow_outage_does_not_repeat_delays(monkeypatch):
    agent = Mock()
    agent.execute.side_effect = ControlError(ErrorCode.UNAVAILABLE)
    control = ShadowHostVpnControl(agent)
    monkeypatch.setattr(
        HostVpnControl, "health", lambda self: {"status": "active (running)"}
    )
    assert control.health() == control.health()
    agent.execute.assert_called_once()


def test_cross_file_client_drift_is_rejected(runtime, monkeypatch):
    original = files._clients_once
    calls = 0

    def drifting(settings, deadline):
        nonlocal calls
        result = original(settings, deadline)
        calls += 1
        if calls == 1:
            (runtime.ccd_path / "beta").write_text(
                "ifconfig-push 10.8.0.11 255.255.255.0\n"
            )
        return result

    monkeypatch.setattr(files, "_clients_once", drifting)
    with pytest.raises(ControlError, match="conflict"):
        ReadOnlyVpnControl(runtime).execute(request(s.ListClients()))


def test_readiness_requires_backend_and_complete_owned_rules(runtime, monkeypatch):
    configured, outputs = ownership_fixture(runtime)
    control = ReadOnlyVpnControl(configured)
    monkeypatch.setattr(
        control.management,
        "read",
        lambda command, deadline: (
            "OpenVPN Version: OpenVPN 2.6.19"
            if command == "version"
            else "1,CONNECTED,SUCCESS"
        ),
    )
    outputs["link"] = b'[{"ifname":"tun0","flags":["UP"]}]'
    monkeypatch.setattr(bounded, "observe", lambda kind, *_: outputs[kind])
    assert control.execute(request(s.Health())).result.ready
    outputs["rules"] += b"\n-A OVPNCP_FORWARD -j ACCEPT"
    with pytest.raises(ControlError, match="conflict"):
        control.execute(request(s.Health()))
    outputs["backend"] = b"legacy"
    with pytest.raises(ControlError, match="unavailable"):
        control.execute(request(s.Health()))


def test_server_failed_bind_setup_removes_only_its_socket(runtime, monkeypatch):
    directory = runtime.config_path.parent / "control"
    directory.mkdir()
    directory.chmod(0o2750)
    configured = dataclasses.replace(runtime, control_socket=str(directory / "a.sock"))
    monkeypatch.setattr(os, "chmod", Mock(side_effect=PermissionError))
    with pytest.raises(PermissionError):
        UnixAgentServer(configured)
    assert not Path(configured.control_socket).exists()


def test_subprocess_timeout_kills_reaps_and_closes_pipes(monkeypatch):
    """A stalled observation cannot leave a child or pipe behind."""
    import subprocess

    popen = subprocess.Popen
    children = []

    def stalled(*args, **kwargs):
        child = popen(["/bin/sleep", "10"], **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(bounded.subprocess, "Popen", stalled)
    with pytest.raises(ControlError, match="timeout"):
        bounded.observe("routes", "tun0", time.monotonic() + 0.05)
    assert children[0].poll() is not None
    assert children[0].stdout.closed


def test_shadow_recovers_after_failure_cooldown(monkeypatch, caplog):
    """A temporary agent outage does not permanently disable observations."""
    agent = Mock()
    agent.execute.side_effect = ControlError(ErrorCode.UNAVAILABLE)
    control = ShadowHostVpnControl(agent)
    monkeypatch.setattr(
        HostVpnControl, "health", lambda self: {"status": "active (running)"}
    )
    now = [10.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    with caplog.at_level(logging.INFO):
        control.health()
        now[0] = 16.0
        agent.execute.side_effect = None
        agent.execute.return_value = s.Response(
            request_id=str(uuid.uuid4()),
            result=s.HealthResult(ready=True, generation=1),
        )
        control.health()
    assert agent.execute.call_count == 2
    assert "health match" in caplog.text


def test_image_source_subset_imports_without_api_packages(tmp_path):
    """Exercise the Docker COPY subset independently of the workspace package."""
    import shutil
    import subprocess
    import sys

    import cryptography
    import pydantic

    root = Path(__file__).parents[1]
    staged = tmp_path / "image"
    dockerfile = (root / "deploy/agent/Dockerfile").read_text()
    for line in dockerfile.splitlines():
        if not line.startswith("COPY src/"):
            continue
        _, source, destination = line.split()
        if not source.startswith("src/"):
            continue
        original = root / source
        target = staged / Path(destination).relative_to("/opt/agent")
        target.parent.mkdir(parents=True, exist_ok=True)
        if original.is_dir():
            shutil.copytree(original, target)
        else:
            shutil.copyfile(original, target)
    program = """
import importlib
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(root))
sys.path.extend(sys.argv[2:])
for name in ("cli", "server", "control", "management", "network", "files"):
    module = importlib.import_module("sciaiot.ovpncp.vpn_agent." + name)
    assert pathlib.Path(module.__file__).is_relative_to(root)
assert not any(name.split(".")[0] in {"fastapi", "sqlmodel", "azure"} for name in sys.modules)
assert not (root / "sciaiot/ovpncp/utils").exists()
print("agent image source subset imports independently")
"""
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            program,
            str(staged),
            str(Path(pydantic.__file__).parents[1]),
            str(Path(cryptography.__file__).parents[1]),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.stdout.strip() == "agent image source subset imports independently"


def test_observation_rejects_hardlinked_state(tmp_path):
    """A second filesystem alias cannot smuggle state across mount ownership."""
    original = tmp_path / "original"
    original.write_bytes(b"private fixture")
    alias = tmp_path / "alias"
    alias.hardlink_to(original)
    with pytest.raises(ControlError):
        bounded.read_file(alias, time.monotonic() + 1)
