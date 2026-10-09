"""Explicit Phase 3 proof in disposable mount, PID and network namespaces.

Never collected by pytest. All PKI, sockets, interfaces and rules are synthetic.
The outer runner masks live OpenVPN paths and attests namespace isolation first.
"""

import argparse
import hashlib
import json
import logging
import logging.handlers
import os
import pathlib
import shutil
import subprocess
import sys
import time
import traceback
import uuid

from sciaiot.rivet.adapters.vpn import shadow
from sciaiot.rivet.adapters.vpn.agent import AgentVpnControl
from sciaiot.rivet.adapters.vpn.host import HostVpnControl
from sciaiot.rivet.application.vpn_control import schemas as s
from sciaiot.rivet.application.vpn_control.errors import ControlError, ErrorCode
from sciaiot.rivet.migration import filesystem, target
from sciaiot.rivet.utils import openvpn
from tests.integration import migration_rehearsal as fixture


class AgentRehearsal(fixture.Rehearsal):
    """Compare real read observations and prove VPN survival of agent loss."""

    def start(
        self, name: str, argv: list[str], env: dict[str, str] | None = None
    ) -> subprocess.Popen[bytes]:
        """Track only children started inside the attested namespaces."""
        path = self.root / f"{name}.log"
        filesystem.write_private(path, b"")
        stream = path.open("ab")
        self.streams.append(stream)
        process = subprocess.Popen(
            argv, cwd=self.root, stdout=stream, stderr=subprocess.STDOUT, env=env
        )
        self.processes.append(process)
        return process

    def setup(self) -> tuple[pathlib.Path, dict[str, str]]:
        """Generate fresh CA/leaves and connect through a nested client namespace."""
        shutil.copyfile(
            self.easyrsa.parent / "openssl-easyrsa.cnf",
            self.source / "openssl-easyrsa.cnf",
        )
        pki = self.source / "pki"
        self.easy(pki, "init-pki")
        self.easy(pki, "build-ca", "nopass")
        self.easy(pki, "build-server-full", "server", "nopass")
        for name in ("existing-client", "edge-peer", "already-revoked"):
            self.easy(pki, "build-client-full", name, "nopass")
        revoked_certificate = (pki / "issued/already-revoked.crt").read_bytes()
        self.easy(pki, "revoke", "already-revoked")
        filesystem.write_private(
            pki / "issued/already-revoked.crt", revoked_certificate
        )
        self.easy(pki, "gen-crl")
        ccd = self.source / "ccd"
        ccd.mkdir(mode=0o700)
        filesystem.write_private(
            ccd / "existing-client",
            (
                b"ifconfig-push 10.231.0.10 255.255.255.0\n"
                b'push "route 10.234.0.0 255.255.255.0 10.231.0.20"\n'
            ),
        )
        filesystem.write_private(
            ccd / "edge-peer",
            (
                b"ifconfig-push 10.231.0.20 255.255.255.0\n"
                b"iroute 10.234.0.0 255.255.255.0\n"
            ),
        )
        runtime = pathlib.Path("/run/p3-openvpn")
        runtime.mkdir(mode=0o2770)
        runtime.chmod(0o2770)
        control = pathlib.Path("/run/p3-agent")
        control.mkdir(mode=0o2750)
        control.chmod(0o2750)
        config = self.source / "server.conf"
        filesystem.write_private(
            config,
            f"""local 172.31.250.1
port 1194
proto udp
dev tun0
topology subnet
server 10.231.0.0 255.255.255.0
ca {pki}/ca.crt
cert {pki}/issued/server.crt
key {pki}/private/server.key
crl-verify {pki}/crl.pem
dh none
client-config-dir {ccd}
keepalive 10 120
persist-key
persist-tun
data-ciphers AES-256-GCM:AES-128-GCM
verb 3
management {runtime}/management.sock unix
management-client-user root
management-client-group root
status {runtime}/status.log 1
status-version 3
""".encode(),
        )
        client = self.source / "client.conf"
        filesystem.write_private(
            client,
            f"""client
remote 172.31.250.1 1194
proto udp
dev tun-client
nobind
ca {pki}/ca.crt
cert {pki}/issued/existing-client.crt
key {pki}/private/existing-client.key
remote-cert-tls server
data-ciphers AES-256-GCM:AES-128-GCM
verb 3
""".encode(),
        )
        commands = [
            ["link", "set", "lo", "up"],
            ["netns", "add", "p3-client"],
            ["link", "add", "p3-server", "type", "veth", "peer", "name", "p3-client"],
            ["link", "set", "p3-client", "netns", "p3-client"],
            ["address", "add", "172.31.250.1/30", "dev", "p3-server"],
            ["link", "set", "p3-server", "up"],
            [
                "-n",
                "p3-client",
                "address",
                "add",
                "172.31.250.2/30",
                "dev",
                "p3-client",
            ],
            ["-n", "p3-client", "link", "set", "p3-client", "up"],
            ["-n", "p3-client", "link", "set", "lo", "up"],
        ]
        for command in commands:
            self.run(["/usr/sbin/ip", *command])
        self.start(
            "server", ["/usr/sbin/openvpn", "--config", str(config), "--disable-dco"]
        )
        self.start(
            "client",
            [
                "/usr/sbin/ip",
                "netns",
                "exec",
                "p3-client",
                "/usr/sbin/openvpn",
                "--config",
                str(client),
                "--disable-dco",
            ],
        )
        end = time.monotonic() + 45
        while time.monotonic() < end:
            if any(item.poll() is not None for item in self.processes):
                raise RuntimeError("Disposable OpenVPN startup failed.")
            if (
                b"Initialization Sequence Completed"
                in (self.root / "client.log").read_bytes()
            ):
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("Disposable client connection timed out.")
        self.ping()
        ownership = self.source / "ownership.json"
        access_id, route_id = str(uuid.uuid4()), str(uuid.uuid4())
        self.access = s.AccessIntent(
            access_id=access_id,
            source_client="existing-client",
            destination_client="edge-peer",
            source_address="10.231.0.10",
            destination_address="10.231.0.20",
            private_networks=("10.234.0.0/24",),
        )
        self.route = s.ManagedRoute(
            route_id=route_id, network="10.234.0.0/24", gateway="10.231.0.20"
        )
        self.push = s.OwnedPushes(
            intent_id=access_id,
            client="existing-client",
            routes=(s.PushRoute(network="10.234.0.0/24", gateway="10.231.0.20"),),
        )
        filesystem.write_private(
            ownership,
            json.dumps(
                {
                    "version": "1.0",
                    "routes": [self.route.model_dump(mode="json")],
                    "access": [self.access.model_dump(mode="json")],
                    "pushes": [self.push.model_dump(mode="json")],
                }
            ).encode(),
        )
        for network, protocol in [("10.234.0.0/24", "200"), ("10.235.0.0/24", "201")]:
            self.run(
                [
                    "/usr/sbin/ip",
                    "route",
                    "add",
                    network,
                    "via",
                    "10.231.0.20",
                    "dev",
                    "tun0",
                    "proto",
                    protocol,
                ]
            )
        self.run(["/usr/sbin/iptables-nft", "-N", "OVPNCP_FORWARD"])
        for flag, direction in [("-i", "ingress"), ("-o", "egress")]:
            self.run(
                [
                    "/usr/sbin/iptables-nft",
                    "-A",
                    "FORWARD",
                    flag,
                    "tun0",
                    "-m",
                    "comment",
                    "--comment",
                    f"ovpncp:anchor:{direction}",
                    "-j",
                    "OVPNCP_FORWARD",
                ]
            )
        for destination, marker in [
            ("10.231.0.20/32", f"ovpncp:{access_id}"),
            ("10.234.0.0/24", f"ovpncp:{access_id}:private:0"),
        ]:
            for source, dest, direction in [
                ("10.231.0.10/32", destination, "forward"),
                (destination, "10.231.0.10/32", "reverse"),
            ]:
                self.run(
                    [
                        "/usr/sbin/iptables-nft",
                        "-A",
                        "OVPNCP_FORWARD",
                        "-s",
                        source,
                        "-d",
                        dest,
                        "-m",
                        "comment",
                        "--comment",
                        f"{marker}:{direction}",
                        "-j",
                        "ACCEPT",
                    ]
                )
        self.run(
            [
                "/usr/sbin/iptables-nft",
                "-A",
                "FORWARD",
                "-s",
                "192.0.2.1/32",
                "-j",
                "DROP",
            ]
        )
        env = dict(os.environ)
        env.update(
            RIVET_AGENT_CONFIG=str(config),
            RIVET_AGENT_PKI=str(pki),
            RIVET_AGENT_CCD=str(ccd),
            RIVET_MANAGEMENT_SOCKET=str(runtime / "management.sock"),
            RIVET_MANAGEMENT_UID="0",
            RIVET_MANAGEMENT_GID="0",
            RIVET_API_UID="0",
            RIVET_AGENT_SOCKET=str(control / "agent.sock"),
            RIVET_AGENT_OWNERSHIP=str(ownership),
        )
        return control / "agent.sock", env

    def ping(self) -> None:
        """Require packets to cross the authenticated TUN in separate network namespaces."""
        self.run(
            [
                "/usr/sbin/ip",
                "netns",
                "exec",
                "p3-client",
                "/usr/bin/ping",
                "-I",
                "tun-client",
                "-c",
                "1",
                "-W",
                "2",
                "10.231.0.1",
            ]
        )

    def kernel_digest(self) -> str:
        """Hash only namespace-owned route/rule configuration, excluding counters."""
        routes = self.run(["/usr/sbin/ip", "-N", "-j", "-4", "route", "show"])
        rules = self.run(["/usr/sbin/iptables-nft-save", "-t", "filter"])
        stable = b"\n".join(
            line for line in rules.splitlines() if not line.startswith(b"#")
        )
        return hashlib.sha256(routes + stable).hexdigest()

    def execute_agent(self) -> dict[str, object]:
        """Run the real entry point and exact production transport without mutations."""
        socket_path, env = self.setup()
        before_files = target._hash_tree(self.source)
        before_kernel = self.kernel_digest()
        agent = self.start(
            "agent", [sys.executable, "-m", "sciaiot.rivet.vpn_agent"], env
        )
        adapter = AgentVpnControl(str(socket_path), peer_uid=0)
        end = time.monotonic() + 15
        while time.monotonic() < end:
            if agent.poll() is not None:
                raise RuntimeError("Disposable agent startup failed.")
            if socket_path.exists():
                break
            time.sleep(0.1)

        def query(command: s.Command) -> s.Result:
            return adapter.execute(
                s.Request(request_id=str(uuid.uuid4()), command=command)
            ).result

        health = query(s.Health())
        assert isinstance(health, s.HealthResult) and health.ready
        config = query(s.ServerConfig())
        assert isinstance(config, s.ConfigResult) and config.device == "tun0"
        clients = query(s.ListClients())
        assert isinstance(clients, s.ClientsResult)
        expected_names = {"existing-client", "edge-peer", "already-revoked"}
        assert expected_names == {item.client for item in clients.items}
        assert (
            next(
                item for item in clients.items if item.client == "already-revoked"
            ).state
            == "revoked"
        )
        assert "server" not in {item.client for item in clients.items}
        existing = query(s.GetClient(client="existing-client"))
        assert (
            isinstance(existing, s.ClientResult)
            and existing.item.assignment is not None
        )
        assert existing.item.assignment.address == "10.231.0.10"
        routes = query(s.ListRoutes())
        assert isinstance(routes, s.RoutesResult) and routes.items == (self.route,)
        access = query(s.ListAccess())
        assert isinstance(access, s.AccessResult) and access.items == (self.access,)
        assert access.pushes == (self.push,)
        sessions = query(s.ListSessions())
        assert isinstance(sessions, s.SessionsResult) and len(sessions.items) == 1
        assert sessions.items[0].client == "existing-client"
        openvpn.openvpn_dir = str(self.source)
        openvpn.easyrsa_dir = str(self.source)
        host = HostVpnControl(device="tun0")
        legacy = host.execute(
            s.Request(request_id=str(uuid.uuid4()), command=s.ServerConfig())
        ).result
        assert isinstance(legacy, s.ConfigResult)
        assert legacy.model_dump(exclude={"generation"}) == config.model_dump(
            exclude={"generation"}
        )
        for item in clients.items:
            observed = host.execute(
                s.Request(
                    request_id=str(uuid.uuid4()),
                    command=s.GetClient(client=item.client),
                )
            ).result
            assert isinstance(observed, s.ClientResult)
            for field in (
                "client",
                "state",
                "issuer",
                "subject",
                "certificate_sha256",
                "not_before",
                "not_after",
            ):
                assert getattr(observed.item, field) == getattr(item, field)
            assert host.client_address(item.client) == (
                item.assignment.address if item.assignment else None
            )
        assert any(
            self.route.network in line and self.route.gateway in line
            for line in host.route_lines("tun0")
        )
        capture = logging.handlers.BufferingHandler(100)
        previous_level = shadow.logger.level
        shadow.logger.setLevel(logging.INFO)
        shadow.logger.addHandler(capture)
        observer = shadow.ShadowHostVpnControl(adapter, device="tun0")
        try:
            assert observer.configuration() == host.configuration()
            assert observer.discovered_names() == host.discovered_names()
            for item in clients.items:
                assert observer.read_certificate(item.client) == host.read_certificate(
                    item.client
                )
                assert observer.client_revoked(item.client) == host.client_revoked(
                    item.client
                )
                assert observer.client_address(item.client) == host.client_address(
                    item.client
                )
            assert observer.route_lines("tun0") == host.route_lines("tun0")
            assert len(capture.buffer) >= 12
            assert all(
                record.getMessage().endswith(" match") for record in capture.buffer
            )
        finally:
            shadow.logger.removeHandler(capture)
            shadow.logger.setLevel(previous_level)
        try:
            adapter.execute(
                s.Request(
                    request_id=str(uuid.uuid4()),
                    command=s.Reload(),
                    operation_id=str(uuid.uuid4()),
                    expected_generation=config.generation,
                )
            )
        except ControlError as error:
            assert error.code == ErrorCode.UNAVAILABLE
        else:
            raise AssertionError("Read-only agent accepted mutation.")
        assert target._hash_tree(self.source) == before_files
        assert self.kernel_digest() == before_kernel
        agent.terminate()
        agent.wait(timeout=5)
        try:
            query(s.Health())
        except ControlError as error:
            assert error.code == ErrorCode.UNAVAILABLE
        else:
            raise AssertionError("Stopped agent remained available.")
        assert all(process.poll() is None for process in self.processes[:2])
        self.ping()
        return {
            "read_only_observations": "passed",
            "legacy_projection_comparison": "passed",
            "shadow_comparison": "passed",
            "owned_and_foreign_network_state": "passed",
            "mutation_rejected": "passed",
            "pki_config_ccd_unchanged": True,
            "namespace_routes_rules_unchanged": True,
            "agent_loss_unavailable": True,
            "openvpn_survived_agent_loss": True,
            "cross_namespace_tun_ping_before_and_after": "passed",
        }


def main() -> int:
    """Refuse ordinary execution before creating or changing any fixture."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--easyrsa", type=pathlib.Path, required=True)
    parser.add_argument("--failure-evidence-dir", type=pathlib.Path)
    args = parser.parse_args()
    fixture.require_isolation()
    if args.failure_evidence_dir is not None:
        fixture.validate_evidence_directory(args.failure_evidence_dir)
    rehearsal = AgentRehearsal(args.easyrsa, network=True, version="2.6.19")
    try:
        result = rehearsal.execute_agent()
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:  # noqa: BLE001 - redact private fixture failures
        if args.failure_evidence_dir is not None:
            rehearsal.retain_failure_evidence(args.failure_evidence_dir)
            agent_log = rehearsal.root / "agent.log"
            if agent_log.exists():
                filesystem.write_private(
                    args.failure_evidence_dir / "agent.log",
                    filesystem.read_file(agent_log),
                )
        print(
            json.dumps(
                {
                    "result": "failed",
                    "error_type": type(error).__name__,
                    "code": error.code.value
                    if isinstance(error, ControlError)
                    else None,
                    "frames": [
                        (pathlib.Path(frame.filename).name, frame.lineno, frame.name)
                        for frame in traceback.extract_tb(error.__traceback__)
                    ],
                }
            ),
            file=sys.stderr,
        )
        return 1
    finally:
        rehearsal.stop()


if __name__ == "__main__":
    raise SystemExit(main())
