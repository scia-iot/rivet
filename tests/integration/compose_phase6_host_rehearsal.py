"""Opt-in Phase 6 reference-topology rehearsal on a stopped-source host.

This is an operator-invoked root tool. It uses fresh synthetic state and a
token-scoped Compose project, but OpenVPN and agent use real host networking
and API/web use the real bridge topology. Source service stop/restore and an
encrypted source backup are required outside this runner.
"""

import argparse
import copy
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time
import traceback
import uuid
from pathlib import Path
from typing import Any

from tests.integration.compose_phase6_rehearsal import (
    AUDIENCE,
    SCOPE,
    SPA,
    TENANT,
    UPGRADE_SCOPE,
    ComposeRehearsal,
    _attest_service,
)
from tests.integration.vpn_container_rehearsal import validate_namespace

VPN_NETWORK = ipaddress.IPv4Network("10.253.0.0/24")
WEB_NETWORK = ipaddress.IPv4Network("172.30.250.0/28")
ROUTE_PROTOCOL = "186"
SOURCE_UNITS = ("rivet.service", "openvpn@server.service")


def docker_network_overlaps(details: dict[str, Any]) -> bool:
    """Check allocated IPv4 subnets; host and none may have null IPAM data."""
    configs = (details.get("IPAM") or {}).get("Config") or []
    if not isinstance(configs, list):
        raise TypeError("Unexpected Docker network IPAM configuration.")
    for config in configs:
        if not isinstance(config, dict):
            raise TypeError("Unexpected Docker network IPAM entry.")
        subnet = config.get("Subnet")
        if subnet is None:
            continue
        try:
            existing = ipaddress.IPv4Network(subnet, strict=False)
        except (ValueError, ipaddress.AddressValueError):
            continue
        if existing.overlaps(VPN_NETWORK) or existing.overlaps(WEB_NETWORK):
            return True
    return False


def normalized_filter(raw: bytes) -> tuple[str, ...]:
    """Drop volatile counters and tool comments from a firewall snapshot."""
    normalized: list[str] = []
    for line in raw.decode().splitlines():
        if not line or line.startswith("#"):
            continue
        normalized.append(re.sub(r"\[\d+:\d+\]", "[0:0]", line))
    return tuple(normalized)


def host_bundle(
    rendered: dict[str, Any],
    *,
    images: dict[str, str],
    state: Path,
    fixture: Path,
    token: str,
    upgrade: bool = False,
) -> dict[str, Any]:
    """Attest source Compose and retain its host, bridge and port topology.

    Raises:
        ValueError: A reviewed source topology or service grant changed.
    """
    model = copy.deepcopy(rendered)
    if not re.fullmatch(r"[a-f0-9]{12}", token):
        raise ValueError("Invalid disposable run identifier.")
    if set(model) != {"name", "networks", "services", "x-bind", "x-runtime"}:
        raise ValueError("Unexpected top-level Compose resource.")
    if model["name"] != "rivet" or model["networks"] != {
        "web": {
            "name": "rivet_web",
            "driver": "bridge",
            "ipam": {"config": [{"subnet": str(WEB_NETWORK)}]},
        }
    }:
        raise ValueError("Unexpected Compose network topology.")
    services = model["services"]
    if not isinstance(services, dict) or set(services) != set(images):
        raise ValueError("Unexpected Compose service set.")
    for role, service in services.items():
        if service.get("image") != images[role]:
            raise ValueError("Compose image differs from reviewed digest.")
        _attest_service(role, service, state, ROUTE_PROTOCOL)
        service["logging"] = {"driver": "none"}
        service["restart"] = "no"
        service["labels"] = {"rivet.rehearsal": token}
    services["api"]["environment"]["SSL_CERT_FILE"] = "/tmp/phase6-ca.crt"
    services["api"]["volumes"].append(
        {
            "type": "bind",
            "source": str(fixture / "ca.crt"),
            "target": "/tmp/phase6-ca.crt",
            "read_only": True,
            "bind": {"create_host_path": False},
        }
    )
    if upgrade:
        services["web"]["environment"]["RIVET_UI_ENTRA_API_SCOPE"] = UPGRADE_SCOPE
    project = f"rivet-p6-{token}"
    model["name"] = project
    model["networks"]["web"]["name"] = f"{project}_web"
    model.pop("x-bind")
    model.pop("x-runtime")
    return model


class HostComposeRehearsal(ComposeRehearsal):
    """Own only synthetic state, named test rules and a private Compose project."""

    def __init__(
        self,
        agent: str,
        openvpn: str,
        api: str,
        web: str,
        manifest: Path,
        upgrade_api: str,
        ssh_peer: str,
    ) -> None:
        super().__init__(agent, openvpn, api, web, manifest, upgrade_api, None)
        self.ssh_peer = str(ipaddress.IPv4Address(ssh_peer))
        self.device = f"tunp6{self.token[:8]}"
        self.bridge = f"{self.project}_web"
        self.sysctl_before: str | None = None
        self.firewall_before: bytes | None = None
        self.chain_started = False
        self.project_started = False
        self.bridge_anchors: dict[str, str] = {}
        self.host_probe: str | None = None

    def _plain(self, argv: list[str]) -> subprocess.CompletedProcess[bytes]:
        """Run a fixed read-only host inspection without reflecting output."""
        return subprocess.run(argv, capture_output=True, check=False, timeout=15)

    def preflight(self) -> None:
        """Require a paused source and no conflicting host-owned resources."""
        for unit in SOURCE_UNITS:
            result = self._plain(
                ["systemctl", "show", "--property=ActiveState", "--value", unit]
            )
            if result.returncode != 0 or result.stdout.strip() != b"inactive":
                raise RuntimeError("Source VPN or application service is active.")
        route = json.loads(self.command(["ip", "-j", "route", "get", self.ssh_peer]))
        if len(route) != 1 or str(route[0].get("dev", "")).startswith(("tun", "tap")):
            raise RuntimeError("SSH reachability depends on a VPN tunnel.")
        routes = json.loads(self.command(["ip", "-j", "route", "show", "table", "all"]))
        for item in routes:
            destination = item.get("dst")
            if destination is None or destination == "default":
                continue
            try:
                network = ipaddress.IPv4Network(destination, strict=False)
            except (ValueError, ipaddress.AddressValueError):
                continue
            if network.overlaps(VPN_NETWORK) or network.overlaps(WEB_NETWORK):
                raise RuntimeError("Synthetic subnet overlaps a host route.")
        if json.loads(
            self.command(
                ["ip", "-j", "route", "show", "table", "all", "proto", ROUTE_PROTOCOL]
            )
        ):
            raise RuntimeError("Reserved route protocol is in use.")
        links = json.loads(self.command(["ip", "-j", "link", "show"]))
        if any(link.get("ifname") == self.device for link in links):
            raise RuntimeError("Disposable TUN name already exists.")
        rules = self.command(["iptables-nft-save", "-t", "filter"])
        if b"OVPNCP_FORWARD" in rules:
            raise RuntimeError("Existing agent firewall ownership blocks the test.")
        self.firewall_before = rules
        names = self.docker("network", "ls", "--format", "{{.Name}}")
        if self.bridge in names.decode().splitlines():
            raise RuntimeError("Disposable bridge name already exists.")
        network_ids = self.docker("network", "ls", "--quiet").decode().splitlines()
        for network_id in network_ids:
            if not re.fullmatch(r"[a-f0-9]{12,64}", network_id):
                raise RuntimeError("Unrecognized Docker network identity.")
            details = json.loads(self.docker("network", "inspect", network_id))
            if len(details) != 1 or docker_network_overlaps(details[0]):
                raise RuntimeError("Synthetic subnet overlaps a Docker network.")
        for family, kind, address, port in (
            (socket.AF_INET, socket.SOCK_DGRAM, "0.0.0.0", 1194),
            (socket.AF_INET, socket.SOCK_STREAM, "127.0.0.1", 8080),
        ):
            with socket.socket(family, kind) as probe:
                try:
                    probe.bind((address, port))
                except OSError:
                    raise RuntimeError("Reference port is already occupied.") from None
        if self.command(["sysctl", "-n", "net.ipv4.ip_forward"]).strip() != b"1":
            raise RuntimeError("Host forwarding prerequisite is missing.")
        value = self.command(
            ["sysctl", "-n", "net.ipv4.conf.all.send_redirects"]
        ).strip()
        if value not in {b"0", b"1"}:
            raise RuntimeError("Unexpected host redirect setting.")
        self.sysctl_before = value.decode()

    def prepare(self) -> None:
        """Create synthetic state with a unique host TUN and unused VPN pool."""
        super().prepare()
        for relative in (
            "vpn-config/server.conf",
            "vpn-projection/server.conf",
            "vpn-ccd/client-a",
            "vpn-ccd/client-b",
            "vpn-projection/ccd/client-a",
            "vpn-projection/ccd/client-b",
            "client-a/client.conf",
            "client-b/client.conf",
        ):
            path = self.state / relative
            source = path.read_text()
            updated = source.replace("10.231.0.", "10.253.0.")
            updated = updated.replace("dev tun0\n", f"dev {self.device}\n")
            if relative.endswith("server.conf"):
                updated = updated.replace(
                    "port 1194\n", "local 172.30.250.1\nport 1194\n"
                )
            updated = re.sub(
                r"remote 172\.31\.25[0-2]\.1 1194", "remote 172.30.250.1 1194", updated
            )
            if updated == source:
                raise RuntimeError("Synthetic topology input did not match.")
            path.write_text(updated)

    def _render(self, anchors: dict[str, str] | None = None) -> None:
        """Render and attest real host/bridge services in a unique project."""
        settings = {
            "RIVET_PLATFORM": "linux/amd64",
            "RIVET_STATE_ROOT": str(self.state),
            "RIVET_AGENT_ROUTE_PROTOCOL": ROUTE_PROTOCOL,
            "RIVET_AGENT_MUTATIONS": "assignments,routes,access,pki,events,management",
            "RIVET_VPN_EVENTS": "0",
            "RIVET_VPN_RECONCILE": "0",
            "RIVET_UI_ENTRA_TENANT_ID": TENANT,
            "RIVET_UI_ENTRA_CLIENT_ID": SPA,
            "RIVET_UI_ENTRA_API_SCOPE": SCOPE,
            "AZURE_ENTRAID_TENANT_ID": TENANT,
            "AZURE_ENTRAID_APP_CLIENT_ID": AUDIENCE,
            "AZURE_ENTRAID_USER_ROLE": "device_user",
            "AZURE_ENTRAID_ADMIN_ROLE": "sysadmin",
            "AZURE_ENTRAID_SERVICE_ADMIN_ROLE": "ServiceAdmin",
        }
        for role, image in self.images.items():
            settings[f"RIVET_{role.upper()}_IMAGE"] = image
        env = self.root / "render.env"
        env.write_text("".join(f"{key}={value}\n" for key, value in settings.items()))
        env.chmod(0o600)
        rendered = json.loads(
            self.command(
                [
                    "docker",
                    "--host=unix:///var/run/docker.sock",
                    "compose",
                    "--env-file",
                    str(env),
                    "-f",
                    str(self.manifest),
                    "config",
                    "--format",
                    "json",
                ]
            )
        )
        for path, images, upgrade in (
            (self.initial_bundle, self.images, False),
            (self.upgrade_bundle, self.upgrade_images, True),
        ):
            model = host_bundle(
                rendered,
                images=self.images,
                state=self.state,
                fixture=self.state / "http-fixture",
                token=self.token,
                upgrade=upgrade,
            )
            for role in ("api", "web"):
                model["services"][role]["image"] = images[role]
            path.write_text(json.dumps(model))
            path.chmod(0o600)
            self.compose("config", "--quiet", bundle=path)

    def _network_identity(self) -> str:
        """Require the bridge to belong to this exact disposable project."""
        details = json.loads(self.docker("network", "inspect", self.bridge))
        if len(details) != 1:
            raise RuntimeError("Disposable bridge identity is missing.")
        item = details[0]
        labels = item.get("Labels", {})
        if (
            item.get("Name") != self.bridge
            or not re.fullmatch(r"[a-f0-9]{64}", item.get("Id", ""))
            or labels.get("com.docker.compose.project") != self.project
            or labels.get("com.docker.compose.network") != "web"
            or item.get("IPAM", {}).get("Config", [{}])[0].get("Subnet")
            != str(WEB_NETWORK)
            or item.get("IPAM", {}).get("Config", [{}])[0].get("Gateway")
            != "172.30.250.1"
        ):
            raise RuntimeError("Disposable bridge ownership changed.")
        return item["Id"]

    def _firewall_rules(
        self,
    ) -> tuple[
        list[tuple[str, ...]],
        list[tuple[str, ...]],
        list[tuple[str, ...]],
        bool,
    ]:
        """Parse only FORWARD and the dedicated test-owned chain."""
        raw = self.command(["iptables-nft-save", "-t", "filter"])
        lines = raw.decode().splitlines()
        chain = any(line.startswith(":OVPNCP_FORWARD ") for line in lines)
        rules = [tuple(shlex.split(line)) for line in lines if line.startswith("-A ")]
        forward = [rule for rule in rules if rule[1] == "FORWARD"]
        owned = [rule for rule in rules if rule[1] == "OVPNCP_FORWARD"]
        jumps = [
            rule
            for rule in rules
            if any(
                flag in rule and rule[rule.index(flag) + 1] == "OVPNCP_FORWARD"
                for flag in ("-j", "-g")
            )
        ]
        return forward, jumps, owned, chain

    def _expected_firewall(
        self,
    ) -> tuple[tuple[tuple[str, ...], ...], set[tuple[str, ...]]]:
        """Render the only rules that may be removed during test cleanup."""
        anchors = tuple(
            (
                "-A",
                "FORWARD",
                flag,
                self.device,
                "-m",
                "comment",
                "--comment",
                f"ovpncp:anchor:{direction}",
                "-j",
                "OVPNCP_FORWARD",
            )
            for flag, direction in (("-i", "ingress"), ("-o", "egress"))
        )
        terminal = (
            "-A",
            "OVPNCP_FORWARD",
            "-m",
            "comment",
            "--comment",
            "ovpncp:terminal-deny",
            "-j",
            "DROP",
        )
        members: set[tuple[str, ...]] = {terminal}
        if hasattr(self, "access_id"):
            for source, target, direction in (
                ("10.253.0.10/32", "10.253.0.20/32", "forward"),
                ("10.253.0.20/32", "10.253.0.10/32", "reverse"),
            ):
                members.add(
                    (
                        "-A",
                        "OVPNCP_FORWARD",
                        "-s",
                        source,
                        "-d",
                        target,
                        "-i",
                        self.device,
                        "-o",
                        self.device,
                        "-m",
                        "comment",
                        "--comment",
                        f"ovpncp:{self.access_id}:{direction}",
                        "-j",
                        "ACCEPT",
                    )
                )
        return anchors, members

    def _attest_firewall(
        self, *, ready: bool
    ) -> tuple[list[tuple[str, ...]], list[tuple[str, ...]]]:
        """Return only rules validated as disposable test ownership."""
        forward, jumps, members, chain = self._firewall_rules()
        anchors, allowed = self._expected_firewall()
        if (
            not chain
            or any(item not in anchors for item in jumps)
            or any(item not in allowed for item in members)
            or len(set(jumps)) != len(jumps)
            or len(set(members)) != len(members)
        ):
            raise RuntimeError("Disposable firewall ownership changed.")
        if ready and (
            forward[:2] != list(anchors)
            or jumps != list(anchors)
            or members[-1:] != [next(item for item in allowed if item[-1] == "DROP")]
        ):
            raise RuntimeError("Disposable firewall baseline is not ready.")
        return jumps, members

    def _install_firewall(self) -> None:
        """Create only the exclusive chain and exact test TUN anchors."""
        _, jumps, members, chain = self._firewall_rules()
        if chain or jumps or members:
            raise RuntimeError("Existing agent firewall ownership blocks the test.")
        self.command(["iptables-nft", "-N", "OVPNCP_FORWARD"])
        self.chain_started = True
        anchors, allowed = self._expected_firewall()
        for position, rule in enumerate(anchors, 1):
            self.command(["iptables-nft", "-I", "FORWARD", str(position), *rule[2:]])
        terminal = next(item for item in allowed if item[-1] == "DROP")
        self.command(["iptables-nft", *terminal])
        self._attest_firewall(ready=True)

    def _remove_firewall(self) -> None:
        """Delete only exact test-owned rules and then the empty owned chain."""
        if not self.chain_started:
            return
        _, jumps, members, chain = self._firewall_rules()
        if not chain and not jumps and not members:
            self.chain_started = False
            return
        jumps, members = self._attest_firewall(ready=False)
        for rule in reversed(members):
            self.command(["iptables-nft", "-D", *rule[1:]])
        for rule in reversed(jumps):
            self.command(["iptables-nft", "-D", *rule[1:]])
        self.command(["iptables-nft", "-X", "OVPNCP_FORWARD"])
        self.chain_started = False

    def bridge_anchor(self, role: str, *, jwks_alias: bool = False) -> str:
        """Pin a bridge-attached helper namespace and its exact Docker identity."""
        if role not in {"a", "b", "c", "http"}:
            raise ValueError("Unexpected bridge anchor role.")
        name = f"rivet-p6-{self.token}-bridge-{role}"
        self.containers.append(name)
        options = [
            "docker",
            "--host=unix:///var/run/docker.sock",
            "run",
            "--pull=never",
            "--name",
            name,
            "--label",
            f"rivet.rehearsal={self.token}",
            "--network",
            self.bridge,
            *(["--network-alias=login.microsoftonline.com"] if jwks_alias else []),
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--security-opt=apparmor=docker-default",
            "--pids-limit=128",
            "--memory=512m",
            "--cpus=1",
            "--log-driver=none",
            "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777",
            "--no-healthcheck",
            "--detach",
            "--entrypoint=/bin/sleep",
            "--user=65530:65532",
            self.images["openvpn"],
            "1800",
        ]
        self.command(options)
        details = json.loads(self.docker("inspect", name))
        if len(details) != 1:
            raise RuntimeError("Disposable bridge anchor identity is missing.")
        item = details[0]
        endpoint = item["NetworkSettings"]["Networks"].get(self.bridge, {})
        address = ipaddress.IPv4Address(endpoint.get("IPAddress", "0.0.0.0"))
        if (
            not item["State"]["Running"]
            or item["HostConfig"]["NetworkMode"] != self.bridge
            or item["Config"]["Labels"].get("rivet.rehearsal") != self.token
            or address not in WEB_NETWORK
            or address
            in {
                ipaddress.IPv4Address("172.30.250.1"),
                ipaddress.IPv4Address("172.30.250.2"),
                ipaddress.IPv4Address("172.30.250.3"),
            }
        ):
            raise RuntimeError("Disposable bridge anchor attestation failed.")
        pid = item["State"]["Pid"]
        if type(pid) is not int or pid <= 1:
            raise RuntimeError("Invalid disposable bridge anchor PID.")
        fd = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY)
        try:
            validate_namespace(
                os.fstat(fd).st_ino,
                os.stat("/proc/1/ns/net").st_ino,
                {os.fstat(value).st_ino for value in self.namespaces.values()},
            )
        except BaseException:
            os.close(fd)
            raise
        self.namespaces[role] = fd
        self.bridge_anchors[role] = name
        return name

    def _start_host_probe(self) -> str:
        """Run only the fixed HTTP probe against the real loopback web port."""
        name = f"rivet-p6-{self.token}-host-probe"
        self.containers.append(name)
        self.command(
            [
                "docker",
                "--host=unix:///var/run/docker.sock",
                "run",
                "--pull=never",
                "--name",
                name,
                "--label",
                f"rivet.rehearsal={self.token}",
                "--network",
                "host",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true",
                "--security-opt=apparmor=docker-default",
                "--pids-limit=128",
                "--memory=512m",
                "--cpus=1",
                "--log-driver=none",
                "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777",
                "--no-healthcheck",
                "--detach",
                "--user=65531:65531",
                "--entrypoint=/bin/sleep",
                *self.mount("http-fixture", "/fixture", readonly=False),
                self.images["api"],
                "1800",
            ]
        )
        details = json.loads(self.docker("inspect", name))
        if len(details) != 1 or (
            details[0]["HostConfig"]["NetworkMode"] != "host"
            or details[0]["Config"]["Labels"].get("rivet.rehearsal") != self.token
            or not details[0]["State"]["Running"]
        ):
            raise RuntimeError("Disposable HTTP probe identity changed.")
        self.host_probe = name
        return name

    def service_identity(self, role: str) -> tuple[str, int]:
        """Attest image, process and actual source-defined network attachment."""
        container, pid = super().service_identity(role)
        details = json.loads(self.docker("inspect", container))[0]
        mode = details["HostConfig"]["NetworkMode"]
        expected = "host" if role in {"openvpn", "agent"} else self.bridge
        if mode != expected:
            raise RuntimeError("Compose service has the wrong runtime network.")
        if role in {"api", "web"}:
            endpoint = details["NetworkSettings"]["Networks"].get(self.bridge, {})
            address = "172.30.250.3" if role == "api" else "172.30.250.2"
            if endpoint.get("IPAddress") != address:
                raise RuntimeError("Compose service bridge address changed.")
        if role == "web" and details["HostConfig"]["PortBindings"] != {
            "8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]
        }:
            raise RuntimeError("Compose web publication changed.")
        return container, pid

    def _helpers(self) -> None:
        """Attach synthetic identity and client namespaces to the owned bridge."""
        self._network_identity()
        jwks_anchor = self.bridge_anchor("http", jwks_alias=True)
        self.jwks_server = self.launch(
            "jwks",
            self.images["api"],
            [
                "--entrypoint=python",
                "--user=65531:65531",
                "--cap-add=NET_BIND_SERVICE",
                "--env=RIVET_FIXTURE_LISTEN=0.0.0.0",
                *self.mount("http-fixture", "/fixture"),
            ],
            ["/fixture/fixture.py", "serve"],
            network=f"container:{jwks_anchor}",
        )
        self.jwks = self._start_host_probe()
        self.probe = self.launch(
            "probe",
            self.images["api"],
            [
                "--user=65531:65531",
                "--entrypoint=/bin/sleep",
                *self.mount("agent-socket", "/run/ovpn-agent", readonly=True),
                *self.mount("probe-credentials", "/probe-credentials"),
            ],
            ["1800"],
        )
        for role in ("a", "b"):
            anchor = self.bridge_anchor(role)
            self.launch(
                f"client-{role}",
                self.images["openvpn"],
                [
                    "--user=0:0",
                    "--cap-add=NET_ADMIN",
                    "--device=/dev/net/tun:/dev/net/tun:rwm",
                    "--entrypoint=/usr/local/sbin/openvpn",
                    *self.mount(f"client-{role}", "/fixture", readonly=True),
                ],
                ["--config", "/fixture/client.conf"],
                network=f"container:{anchor}",
            )

    def peer_flow(self) -> bool:
        """Require a real client-to-client ICMP reply across the host TUN."""
        return self.ping("a", "10.253.0.20")

    def access(self, present: bool) -> None:
        """Use the real agent to change only the synthetic client pair."""
        self.query(f"""
intent = s.AccessIntent(access_id='{self.access_id}', source_client='client-a', destination_client='client-b', source_address='10.253.0.10', destination_address='10.253.0.20', private_networks=())
mutate(s.SetAccess(intent=intent, present={present!r}))
print(json.dumps({{'mutation': 'passed'}}))
""")

    def _wait_clients(self) -> None:
        """Require live UDP sessions and the synthetic CCD addresses."""
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if all(self.ping(role, "10.253.0.1") for role in ("a", "b")):
                result = self.query("""
sessions = query(s.ListSessions())
print(json.dumps({'clients': sorted(item.client for item in sessions.items)}))
""")
                if result["clients"] == ["client-a", "client-b"]:
                    return
            time.sleep(0.5)
        raise RuntimeError("Reference-topology UDP clients did not connect.")

    def execute(self) -> dict[str, object]:
        """Prove real host/bridge Compose startup and selected-service rollback."""
        self.stage = "image-cache"
        self.check_image_cache()
        self.stage = "host-preflight"
        self.preflight()
        self.stage = "synthetic-pki"
        self.prepare()
        self.stage = "actual-compose-render"
        self._render()
        self.preflight()
        self.stage = "actual-compose-create"
        self.project_started = True
        self.compose_invoked = True
        self.compose("create", "--pull", "never", "--no-build")
        self._network_identity()
        self.stage = "host-firewall-baseline"
        self._install_firewall()
        if self.sysctl_before == "1":
            self.command(["sysctl", "-w", "net.ipv4.conf.all.send_redirects=0"])
        self.stage = "actual-compose-up"
        self.compose("up", "--pull", "never", "--wait", "--wait-timeout", "240")
        if not json.loads(
            self.command(["ip", "-j", "link", "show", "dev", self.device])
        ):
            raise RuntimeError("Test-owned host TUN did not appear.")
        self.command(["sysctl", "-w", f"net.ipv4.conf.{self.device}.send_redirects=0"])
        self._attest_firewall(ready=True)
        for role in ("openvpn", "agent", "api", "web"):
            self.service_identity(role)
        self.stage = "bridge-helpers"
        self._helpers()
        self.http_probe(SCOPE)
        self.wait_ready()
        self.stage = "real-udp-clients"
        self._wait_clients()
        self.access_id = str(uuid.uuid4())
        self.stage = "default-deny"
        if self.peer_flow():
            raise RuntimeError("Synthetic peer traffic escaped default deny.")
        self.stage = "access-allow"
        self.access(True)
        if not self.peer_flow():
            raise RuntimeError("Allowed synthetic peer traffic failed.")
        self.stage = "access-remove"
        self.access(False)
        if self.peer_flow():
            raise RuntimeError("Removed synthetic access still passed.")
        self.access(True)
        self.control_plane_outage()
        return {
            "actual_host_bridge_topology": "passed",
            "source_state_imported": False,
            "compose_up_wait": "passed",
            "web_proxy_signed_jwt_rbac": "passed",
            "api_identity_persistence": "passed",
            "api_web_upgrade_rollback": "passed",
            "vpn_traffic_and_process_survival": "passed",
            "synthetic_allowed_denied_flows": "passed",
            "full_phase6": False,
        }

    def close(self, *, remove_state: bool = True) -> None:
        """Remove only attested test resources before source service recovery."""
        cleanup_error: Exception | None = None
        try:
            super().close(remove_state=False)
            if self.project_started:
                names = self.docker("network", "ls", "--format", "{{.Name}}")
                if self.bridge in names.decode().splitlines():
                    network_id = self._network_identity()
                    details = json.loads(self.docker("network", "inspect", network_id))[
                        0
                    ]
                    if details.get("Containers"):
                        raise RuntimeError("Disposable bridge still has endpoints.")
                    self.docker("network", "rm", network_id)
            self._remove_firewall()
        except Exception as error:  # noqa: BLE001 - retain state for review
            cleanup_error = error
        if self.sysctl_before is not None:
            try:
                self.command(
                    [
                        "sysctl",
                        "-w",
                        f"net.ipv4.conf.all.send_redirects={self.sysctl_before}",
                    ]
                )
            except Exception as error:  # noqa: BLE001 - retain state for review
                cleanup_error = error
        if cleanup_error is not None:
            raise RuntimeError("Reference-topology cleanup is incomplete.") from None
        if self.firewall_before is not None and normalized_filter(
            self.command(["iptables-nft-save", "-t", "filter"])
        ) != normalized_filter(self.firewall_before):
            raise RuntimeError("Host firewall baseline did not return exactly.")
        for unit in SOURCE_UNITS:
            result = self._plain(
                ["systemctl", "show", "--property=ActiveState", "--value", unit]
            )
            if result.returncode != 0 or result.stdout.strip() != b"inactive":
                raise RuntimeError("Source service state changed during test.")
        if remove_state:
            shutil.rmtree(self.root)


def main() -> int:
    """Require explicit root invocation and expose only redacted evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    for role in ("agent", "openvpn", "api", "web"):
        parser.add_argument(f"--{role}-image", required=True)
    parser.add_argument("--upgrade-api-image", required=True)
    parser.add_argument("--compose", type=Path, required=True)
    parser.add_argument("--ssh-peer", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Reviewed root execution is required.")
    os.umask(0o077)

    def interrupted(signum: int, frame: object) -> None:
        raise RuntimeError("Reference-topology rehearsal interrupted.")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    rehearsal = HostComposeRehearsal(
        args.agent_image,
        args.openvpn_image,
        args.api_image,
        args.web_image,
        args.compose,
        args.upgrade_api_image,
        args.ssh_peer,
    )
    result: dict[str, object] = {}
    code = 0
    try:
        result = rehearsal.execute()
    except Exception as error:  # noqa: BLE001 - raw output remains private
        code = 1
        result = {
            "result": "failed",
            "error_type": type(error).__name__,
            "stage": getattr(rehearsal, "stage", "initialization"),
            "last_command": getattr(rehearsal, "last_command", {}),
            "http_failure": getattr(rehearsal, "http_failure", "unknown"),
            "probe_failure": getattr(rehearsal, "probe_failure", {}),
            "frames": [
                (Path(frame.filename).name, frame.lineno, frame.name)
                for frame in traceback.extract_tb(error.__traceback__)
            ],
        }
    finally:
        try:
            rehearsal.close()
            result["cleanup"] = "passed"
        except Exception:  # noqa: BLE001 - preserve uncertain test state
            code = 1
            result["cleanup"] = "incomplete"
            result["run_id"] = rehearsal.token
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
