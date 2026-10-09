"""Explicit synthetic Docker VPN rehearsal; never collected by pytest.

Requires rootful local Docker, Linux iproute2/nsenter/iptables-nft/ping, and
cached immutable images. No host network, bridge, published ports, or live
state is used. All kernel mutations enter pinned disposable network namespaces.
"""

import argparse
import base64
import importlib.util
import inspect
import json
import os
import re
import select
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import traceback
import uuid
from pathlib import Path
from typing import Any


def validate_image(value: str, role: str) -> None:
    """Reject mutable or unexpected image references before invoking Docker."""
    registry = r"[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]+)?"
    namespace = r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
    if not re.fullmatch(
        rf"{registry}{namespace}/rivet-{re.escape(role)}@sha256:[a-f0-9]{{64}}",
        value,
    ):
        raise ValueError("A reviewed repository digest is required.")


def validate_namespace(inode: int, host: int, occupied: set[int]) -> None:
    """Refuse the host and shared anchors before permitting any mutation."""
    if inode == host or inode in occupied:
        raise RuntimeError("Disposable network namespace attestation failed.")


def write_file(path: Path, data: bytes, uid: int, gid: int, mode: int) -> None:
    """Create a synthetic file with explicit grants and no overwrite."""
    with path.open("xb") as stream:
        stream.write(data)
    os.chown(path, uid, gid)
    path.chmod(mode)


def export_archive(payload: bytes, directory: Path) -> None:
    """Write only expected synthetic client members into its private API fixture."""
    import io
    import zipfile

    expected = {
        "ca.crt": "ca.crt",
        "issued/managed-client.crt": "client.crt",
        "private/managed-client.key": "client.key",
    }
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        members = archive.infolist()
        if (
            len(members) != 3
            or {member.filename for member in members} != set(expected)
            or sum(member.file_size for member in members) > 196608
            or archive.testzip() is not None
        ):
            raise ValueError("Unexpected synthetic credential archive.")
        for member, filename in expected.items():
            path = directory / filename
            with path.open("xb") as stream:
                stream.write(archive.read(member))
            path.chmod(0o640)


def ping_summary(stdout: bytes, stderr: bytes, code: int) -> dict[str, int | bool]:
    """Allowlist diagnostic categories and counters; never reflect ping text."""
    text = stdout.decode(errors="replace").lower()
    combined = text + stderr.decode(errors="replace").lower()
    result: dict[str, int | bool] = {
        "exit_code": code,
        "stderr_present": bool(stderr),
        "redirect": "redirect" in combined,
        "unreachable": "unreachable" in combined,
        "checksum_error": "checksum" in combined,
        "duplicate": "dup!" in combined,
        "permission_error": "not permitted" in combined
        or "permission denied" in combined,
        "wrong_data": "wrong data" in combined,
        "truncated": "truncated" in combined,
    }
    counts = re.search(
        r"(\d+) packets? transmitted, (\d+) (?:packets? )?received", text
    )
    if counts is not None:
        result.update(transmitted=int(counts[1]), received=int(counts[2]))
    errors = re.search(r"\+(\d+) errors", text)
    result["errors"] = int(errors[1]) if errors is not None else 0
    return result


# The bounded observer exposes only direction plus ICMP type/code counts. It
# never writes packet bytes, addresses, payloads or exception text anywhere.
ICMP_OBSERVER = """import json, socket, time
counts = {}
with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800)) as sock:
    sock.bind(('tun-client', 0))
    sock.settimeout(0.2)
    print('READY', flush=True)
    end = time.monotonic() + 4
    while time.monotonic() < end:
        try:
            packet, address = sock.recvfrom(4096)
        except TimeoutError:
            continue
        if len(packet) < 20 or packet[0] >> 4 != 4 or packet[9] != 1:
            continue
        offset = (packet[0] & 15) * 4
        if offset < 20 or len(packet) < offset + 2:
            continue
        direction = 'out' if address[2] == socket.PACKET_OUTGOING else 'in'
        key = f'{direction}:{packet[offset]}:{packet[offset + 1]}'
        counts[key] = counts.get(key, 0) + 1
print(json.dumps(counts), flush=True)
"""


def rule_counters(raw: bytes, access_id: str) -> dict[str, dict[str, int]]:
    """Reduce namespace rule observations to fixed labels and integer counters."""
    allowed = {
        "ovpncp:anchor:ingress": "ingress_anchor",
        "ovpncp:anchor:egress": "egress_anchor",
        "ovpncp:terminal-deny": "terminal_deny",
        f"ovpncp:{access_id}:forward": "allow_forward",
        f"ovpncp:{access_id}:reverse": "allow_reverse",
    }
    result = {}
    for line in raw.decode().splitlines():
        match = re.match(r"^\[(\d+):(\d+)\] (-A .*)$", line)
        if match is None:
            continue
        tokens = shlex.split(match[3])
        if "--comment" not in tokens:
            continue
        marker = tokens[tokens.index("--comment") + 1]
        if marker in allowed:
            result[allowed[marker]] = {"packets": int(match[1]), "bytes": int(match[2])}
    return result


def interface_counters(raw: list[dict[str, Any]]) -> dict[str, int | bool]:
    """Keep only TUN up state and numeric traffic/error/drop counters."""
    if len(raw) != 1:
        raise ValueError("Expected one disposable tunnel interface.")
    item = raw[0]
    stats = item.get("stats64", item.get("stats", {}))
    result: dict[str, int | bool] = {"up": "UP" in item.get("flags", [])}
    for direction in ("rx", "tx"):
        for metric in ("packets", "bytes", "errors", "dropped"):
            result[f"{direction}_{metric}"] = int(stats[direction][metric])
    return result


class Rehearsal:
    """Own one bounded set of synthetic state, containers and namespace FDs."""

    def __init__(self, agent: str, openvpn: str, api: str) -> None:
        self.images = {"agent": agent, "openvpn": openvpn, "api": api}
        for role, value in self.images.items():
            validate_image(value, role)
        self.token = uuid.uuid4().hex[:12]
        self.containers: list[str] = []
        self.namespaces: dict[str, int] = {}
        self.root = Path(tempfile.mkdtemp(prefix=f"rivet-p6-{self.token}-"))
        self.state = self.root / "state"

    def command(
        self,
        argv: list[str],
        *,
        pass_fds: tuple[int, ...] = (),
        input_data: bytes | None = None,
        timeout: int = 90,
    ) -> bytes:
        """Suppress raw command errors, addresses, certificate and daemon output."""
        program = Path(argv[0]).name
        action = (
            argv[2]
            if program == "docker"
            else (argv[3] if program == "nsenter" else "run")
        )
        self.last_command = {"program": program, "action": action}
        try:
            result = subprocess.run(
                argv,
                input=input_data,
                capture_output=True,
                pass_fds=pass_fds,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise RuntimeError("Disposable command could not complete.") from None
        self.last_command["exit_code"] = str(result.returncode)
        if program == "nsenter" and action == "ping":
            self.last_ping = ping_summary(
                result.stdout, result.stderr, result.returncode
            )
        if result.returncode != 0:
            raise RuntimeError("Disposable command failed; output withheld.")
        return result.stdout

    def launch(
        self,
        role: str,
        image: str,
        options: list[str],
        command: list[str],
        *,
        network: str = "none",
        detached: bool = True,
        healthcheck: bool = False,
    ) -> str:
        """Track names before launch so timeouts cannot orphan known objects."""
        if not re.fullmatch(r"[a-z0-9-]+", role):
            raise ValueError("Invalid disposable container role.")
        name = f"rivet-p6-{self.token}-{role}"
        if network != "none" and network not in {
            f"container:{item}" for item in self.containers
        }:
            raise ValueError("Only owned namespace anchors can be shared.")
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
                network,
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true",
                "--security-opt=apparmor=docker-default",
                "--pids-limit=128",
                "--memory=512m",
                "--cpus=1",
                "--log-driver=none",
                "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777",
                *([] if healthcheck else ["--no-healthcheck"]),
                *(["--detach"] if detached else []),
                *options,
                image,
                *command,
            ]
        )
        return name

    def docker(self, *argv: str, input_data: bytes | None = None) -> bytes:
        """Use only the local rootful socket, ignoring ambient Docker contexts."""
        return self.command(
            ["docker", "--host=unix:///var/run/docker.sock", *argv],
            input_data=input_data,
        )

    def anchor(self, role: str, *, host_aliases: tuple[str, ...] = ()) -> str:
        """Start an empty namespace and pin its identity before network setup."""
        if host_aliases and (
            role != "http"
            or set(host_aliases)
            != {
                "login.microsoftonline.com=127.0.0.1",
                "api=127.0.0.1",
            }
        ):
            raise ValueError("Unexpected disposable namespace host aliases.")
        name = self.launch(
            f"anchor-{role}",
            self.images["openvpn"],
            [
                "--entrypoint=/bin/sleep",
                "--user=65530:65532",
                *(f"--add-host={alias}" for alias in host_aliases),
            ],
            ["1800"],
        )
        info = json.loads(self.docker("inspect", name))[0]
        if (
            not info["State"]["Running"]
            or info["HostConfig"]["NetworkMode"] != "none"
            or info["Config"]["Labels"]["rivet.rehearsal"] != self.token
        ):
            raise RuntimeError("Disposable container attestation failed.")
        pid = info["State"]["Pid"]
        if type(pid) is not int or pid <= 1:
            raise RuntimeError("Invalid namespace anchor PID.")
        fd = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY)
        try:
            validate_namespace(
                os.fstat(fd).st_ino,
                os.stat("/proc/1/ns/net").st_ino,
                {os.fstat(item).st_ino for item in self.namespaces.values()},
            )
        except BaseException:
            os.close(fd)
            raise
        self.namespaces[role] = fd
        return name

    def network(
        self, role: str, argv: list[str], *, extra_fds: tuple[int, ...] = ()
    ) -> bytes:
        """Execute kernel commands exclusively inside an attested pinned netns."""
        fd = self.namespaces[role]
        return self.command(
            ["nsenter", f"--net=/proc/self/fd/{fd}", "--", *argv],
            pass_fds=(fd, *extra_fds),
        )

    def mount(
        self, source: str, destination: str, *, readonly: bool = False
    ) -> list[str]:
        """Bind only a reviewed path inside this run's newly created state."""
        path = self.state / source
        if not path.exists() or not path.resolve().is_relative_to(self.state):
            raise ValueError("Invalid disposable state mount.")
        suffix = ",readonly" if readonly else ""
        return ["--mount", f"type=bind,src={path},dst={destination}{suffix}"]

    def prepare(self) -> None:
        """Generate a new disposable CA using the cached agent's Easy-RSA."""
        helper = (
            Path(__file__).resolve().parents[2] / "deploy/containers/prepare_state.py"
        )
        spec = importlib.util.spec_from_file_location("prepare_state", helper)
        if spec is None or spec.loader is None:
            raise RuntimeError("Missing reviewed state preparation helper.")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.prepare(self.state)
        credentials = self.state / "probe-credentials"
        credentials.mkdir(mode=0o750)
        os.chown(credentials, 65531, 65531)
        credentials.chmod(0o750)
        pki = self.state / "vpn-pki"
        # Easy-RSA init-pki requires a fresh nonexisting PKI destination.
        pki.rmdir()
        options = [
            "--user=0:0",
            "--entrypoint=/usr/share/easy-rsa/easyrsa",
            "--env=EASYRSA_BATCH=1",
            "--env=EASYRSA_ALGO=ec",
            "--env=EASYRSA_CURVE=prime256v1",
            "--env=EASYRSA_PKI=/fixture/vpn-pki",
            "--mount",
            f"type=bind,src={self.state},dst=/fixture",
        ]
        commands = [
            ["init-pki"],
            ["build-ca", "nopass"],
            ["build-server-full", "server", "nopass"],
            ["build-client-full", "client-a", "nopass"],
            ["build-client-full", "client-b", "nopass"],
            ["gen-crl"],
        ]
        for index, args in enumerate(commands):
            current_options = list(options)
            if args[0] == "build-ca":
                current_options.append(
                    "--env=EASYRSA_REQ_CN=Disposable-Container-Rehearsal"
                )
            self.launch(
                f"pki-{index}",
                self.images["agent"],
                current_options,
                args,
                detached=False,
            )
        for path in [pki, *pki.rglob("*")]:
            if path.is_symlink():
                raise RuntimeError("Unexpected synthetic PKI symlink.")
            os.chown(path, 65532, 65532)
            path.chmod(0o700 if path.is_dir() else 0o600)
        projection = self.state / "vpn-projection"
        for source, destination in (
            ("ca.crt", "ca.crt"),
            ("issued/server.crt", "server.crt"),
            ("private/server.key", "server.key"),
            ("crl.pem", "crl.pem"),
        ):
            write_file(
                projection / destination,
                (pki / source).read_bytes(),
                65532,
                65532,
                0o640,
            )
        template = helper.parent / "server.conf.example"
        config = template.read_text().replace("local <vpn-bind-ip>\n", "")
        config = config.replace("10.8.0.0", "10.231.0.0")
        config = config.replace("status.log 10", "status.log 1")
        for directory, mode in (("vpn-config", 0o600), ("vpn-projection", 0o640)):
            write_file(
                self.state / directory / "server.conf",
                config.encode(),
                65532,
                65532,
                mode,
            )
        ownership = {"version": "1.0", "routes": [], "access": [], "pushes": []}
        write_file(
            self.state / "vpn-config/ownership.json",
            json.dumps(ownership).encode(),
            65532,
            65532,
            0o600,
        )
        for index, name in enumerate(("client-a", "client-b")):
            ccd = f"ifconfig-push 10.231.0.{10 + index * 10} 255.255.255.0\n"
            for directory, mode in (("vpn-ccd", 0o600), ("vpn-projection/ccd", 0o640)):
                write_file(
                    self.state / directory / name, ccd.encode(), 65532, 65532, mode
                )
            client = self.state / name
            client.mkdir(mode=0o700)
            for source, target in (
                ("ca.crt", "ca.crt"),
                (f"issued/{name}.crt", "client.crt"),
                (f"private/{name}.key", "client.key"),
            ):
                write_file(client / target, (pki / source).read_bytes(), 0, 0, 0o600)
            config = f"""client
remote 172.31.{250 + index}.1 1194
proto udp
dev tun-client
nobind
ca /fixture/ca.crt
cert /fixture/client.crt
key /fixture/client.key
remote-cert-tls server
data-ciphers AES-256-GCM:AES-128-GCM
disable-dco
log /dev/null
verb 0
"""
            write_file(client / "client.conf", config.encode(), 0, 0, 0o600)

    def topology(self) -> dict[str, str]:
        """Wire only disposable namespaces; host interfaces never receive a veth."""
        anchors = {role: self.anchor(role) for role in ("server", "a", "b", "c")}
        for role in anchors:
            self.network(role, ["ip", "link", "set", "lo", "up"])
        for index, role in enumerate(("a", "b", "c")):
            fd = self.namespaces[role]
            self.network(
                "server",
                [
                    "ip",
                    "link",
                    "add",
                    f"wire-{role}",
                    "type",
                    "veth",
                    "peer",
                    "name",
                    f"peer-{role}",
                ],
            )
            self.network(
                "server",
                ["ip", "link", "set", f"peer-{role}", "netns", f"/proc/self/fd/{fd}"],
                extra_fds=(fd,),
            )
            for target, interface, suffix in (
                ("server", f"wire-{role}", 1),
                (role, f"peer-{role}", 2),
            ):
                self.network(
                    target,
                    [
                        "ip",
                        "address",
                        "add",
                        f"172.31.{250 + index}.{suffix}/30",
                        "dev",
                        interface,
                    ],
                )
                self.network(target, ["ip", "link", "set", interface, "up"])
        self.network("server", ["sysctl", "-w", "net.ipv4.ip_forward=1"])
        # TUN-to-TUN forwarding must not advertise a direct client gateway.
        # Linux enables redirects when either all or interface is enabled;
        # default=0 ensures the later-created TUN inherits the disabled policy.
        for scope in ("all", "default"):
            self.network(
                "server", ["sysctl", "-w", f"net.ipv4.conf.{scope}.send_redirects=0"]
            )
        self.network("server", ["iptables-nft", "-N", "OVPNCP_FORWARD"])
        for flag, direction in (("-i", "ingress"), ("-o", "egress")):
            self.network(
                "server",
                [
                    "iptables-nft",
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
                ],
            )
        self.network(
            "server",
            [
                "iptables-nft",
                "-A",
                "OVPNCP_FORWARD",
                "-m",
                "comment",
                "--comment",
                "ovpncp:terminal-deny",
                "-j",
                "DROP",
            ],
        )
        self.network(
            "server",
            [
                "iptables-nft",
                "-A",
                "FORWARD",
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ],
        )
        return anchors

    def services(self, anchors: dict[str, str]) -> str:
        """Launch reviewed daemon entrypoints with their restricted grants."""
        caps = ["--cap-add=NET_ADMIN", "--cap-add=SETUID", "--cap-add=SETGID"]
        self.launch(
            "server",
            self.images["openvpn"],
            [
                "--user=0:65532",
                *caps,
                "--device=/dev/net/tun:/dev/net/tun:rwm",
                *self.mount(
                    "vpn-projection", "/var/lib/ovpn-agent/projection", readonly=True
                ),
                *self.mount("vpn-pool", "/var/lib/openvpn"),
                *self.mount("management-socket", "/run/openvpn"),
                *self.mount("event-socket", "/run/ovpn-events"),
            ],
            [],
            network=f"container:{anchors['server']}",
            healthcheck=True,
        )
        paths = {
            "CONFIG": "/var/lib/ovpn-agent/config/server.conf",
            "PKI": "/var/lib/ovpn-agent/pki",
            "CCD": "/var/lib/ovpn-agent/ccd",
            "JOURNAL": "/var/lib/ovpn-agent/journal",
            "PROJECTION": "/var/lib/ovpn-agent/projection",
            "OWNERSHIP": "/var/lib/ovpn-agent/config/ownership.json",
            "SOCKET": "/run/ovpn-agent/agent.sock",
            "EVENT_SOCKET": "/run/ovpn-events/events.sock",
            "ROUTE_PROTOCOL": "200",
            "MUTATIONS": "assignments,routes,access,pki,events,management",
        }
        options = ["--user=0:65532", "--group-add=65531", *caps]
        for key, value in paths.items():
            options.append(f"--env=RIVET_AGENT_{key}={value}")
        options.extend(
            [
                "--env=RIVET_MANAGEMENT_SOCKET=/run/openvpn/management.sock",
                "--env=RIVET_MANAGEMENT_UID=0",
                "--env=RIVET_MANAGEMENT_GID=65532",
                "--env=RIVET_OPENVPN_UID=65530",
                "--env=RIVET_API_UID=65531",
            ]
        )
        for source, target, readonly in (
            ("vpn-config", "/var/lib/ovpn-agent/config", False),
            ("vpn-pki", "/var/lib/ovpn-agent/pki", False),
            ("vpn-ccd", "/var/lib/ovpn-agent/ccd", False),
            ("vpn-journal", "/var/lib/ovpn-agent/journal", False),
            ("vpn-projection", "/var/lib/ovpn-agent/projection", False),
            ("agent-socket", "/run/ovpn-agent", False),
            ("management-socket", "/run/openvpn", True),
            ("event-socket", "/run/ovpn-events", False),
            ("vpn-pool", "/var/lib/openvpn", True),
        ):
            options.extend(self.mount(source, target, readonly=readonly))
        agent = self.launch(
            "agent",
            self.images["agent"],
            options,
            [],
            network=f"container:{anchors['server']}",
            healthcheck=True,
        )
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
        self.wait_ready()
        for role in ("a", "b"):
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
                network=f"container:{anchors[role]}",
            )
        return agent

    def query(self, code: str) -> dict[str, object]:
        """Run fixed typed probe code as the actual API identity and capability set."""
        prelude = """import json, os, time, uuid
from pathlib import Path
assert os.getuid() == 65531 and os.getgid() == 65531
status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
assert all(int(status[key].strip(), 16) == 0 for key in ("CapEff", "CapPrm", "CapInh", "CapAmb"))
assert status["NoNewPrivs"].strip() == "1"
assert not Path("/dev/net/tun").exists()
assert not Path("/var/lib/ovpn-agent").exists()
assert not Path("/run/openvpn/management.sock").exists()
from sciaiot.rivet.adapters.vpn.agent import AgentVpnControl
from sciaiot.rivet.application.vpn_control import schemas as s
from sciaiot.rivet.application.vpn_control import wire
from sciaiot.rivet.application.vpn_control.errors import ControlError, ErrorCode
adapter = AgentVpnControl('/run/ovpn-agent/agent.sock', peer_uid=65532)
def query(command):
    return adapter.execute(s.Request(request_id=str(uuid.uuid4()), command=command)).result

def mutate(command):
    health = query(s.Health())
    request = s.Request(request_id=str(uuid.uuid4()), operation_id=str(uuid.uuid4()), expected_generation=health.generation, command=command)
    try:
        response = adapter.execute(request)
    except ControlError as error:
        if error.code not in {ErrorCode.TIMEOUT, ErrorCode.UNAVAILABLE, ErrorCode.UNKNOWN_OUTCOME}:
            raise
        response = adapter.execute(s.Request(request_id=str(uuid.uuid4()), command=s.LookupOperation(operation_id=request.operation_id)))
    end = time.monotonic() + 60
    while isinstance(response.result, s.MutationResult) and response.result.state in {'pending', 'partial', 'unknown'}:
        if time.monotonic() >= end:
            raise RuntimeError('Mutation recovery deadline exceeded.')
        time.sleep(0.2)
        response = adapter.execute(s.Request(request_id=str(uuid.uuid4()), command=s.LookupOperation(operation_id=request.operation_id)))
    wire.require_success(response)
    assert response.result.state == 'succeeded'
    assert adapter.execute(request).result == response.result
    return response.result
"""
        wrapped = (
            prelude
            + "\ntry:\n"
            + textwrap.indent(code, "    ")
            + "\nexcept Exception as error:\n"
            + "    print(json.dumps({'probe_failure': {'type': type(error).__name__, 'code': error.code.value if isinstance(error, ControlError) else None}}))\n"
        )
        result = json.loads(
            self.docker(
                "exec", "-i", self.probe, "python", "-", input_data=wrapped.encode()
            )
        )
        self.probe_failure = result.get("probe_failure", {})
        if self.probe_failure:
            raise RuntimeError("Typed fixture probe failed; details redacted.")
        return result

    def wait_ready(self) -> None:
        """Bound startup recovery and require actual agent readiness."""
        end = time.monotonic() + 45
        while time.monotonic() < end:
            try:
                result = self.query(
                    "print(json.dumps({'ready': query(s.Health()).ready}))"
                )
                if result["ready"]:
                    return
            except RuntimeError:
                pass
            time.sleep(0.5)
        raise RuntimeError("Container agent readiness deadline exceeded.")

    def ping(self, role: str, destination: str) -> bool:
        """Observe real tunnel traffic without exposing command output."""
        try:
            self.network(
                role, ["ping", "-I", "tun-client", "-c", "1", "-W", "2", destination]
            )
            return True
        except RuntimeError:
            return False

    def packet_snapshot(self) -> dict[str, object]:
        """Inspect only disposable namespaces and export no addresses or rules."""
        snapshot: dict[str, object] = {}
        for role in ("server", "a", "b"):
            device = "tun0" if role == "server" else "tun-client"
            try:
                raw = self.network(
                    role, ["ip", "-j", "-s", "link", "show", "dev", device]
                )
                snapshot[f"{role}_tun"] = interface_counters(json.loads(raw))
                flags = self.network(
                    role,
                    [
                        "sysctl",
                        "-n",
                        "net.ipv4.ip_forward",
                        "net.ipv4.conf.all.rp_filter",
                        f"net.ipv4.conf.{device}.rp_filter",
                        "net.ipv4.icmp_echo_ignore_all",
                        "net.ipv4.conf.all.send_redirects",
                        "net.ipv4.conf.default.send_redirects",
                        f"net.ipv4.conf.{device}.send_redirects",
                    ],
                )
                values = [int(value) for value in flags.split()]
                snapshot[f"{role}_flags"] = dict(
                    zip(
                        (
                            "forwarding",
                            "all_rp_filter",
                            "tun_rp_filter",
                            "ignore_echo",
                            "all_send_redirects",
                            "default_send_redirects",
                            "tun_send_redirects",
                        ),
                        values,
                        strict=True,
                    )
                )
            except (RuntimeError, ValueError, KeyError) as error:
                snapshot[f"{role}_error"] = type(error).__name__
        for role, destination in (
            ("a", "10.231.0.20"),
            ("b", "10.231.0.10"),
            ("server", "10.231.0.20"),
        ):
            try:
                raw = self.network(
                    role, ["ip", "-j", "-4", "route", "get", destination]
                )
                routes = json.loads(raw)
                expected = "tun0" if role == "server" else "tun-client"
                snapshot[f"{role}_peer_route_uses_tun"] = (
                    len(routes) == 1 and routes[0].get("dev") == expected
                )
            except (RuntimeError, ValueError, KeyError) as error:
                snapshot[f"{role}_route_error"] = type(error).__name__
        try:
            snapshot["server_rules"] = rule_counters(
                self.network("server", ["iptables-nft-save", "-c", "-t", "filter"]),
                self.access_id,
            )
        except (RuntimeError, ValueError, KeyError) as error:
            snapshot["server_rules_error"] = type(error).__name__
        return snapshot

    def peer_flow(self) -> bool:
        """Record redacted counters and ICMP types around one peer packet attempt."""
        before = self.packet_snapshot()
        fd = self.namespaces["a"]
        observer = subprocess.Popen(
            [
                "nsenter",
                f"--net=/proc/self/fd/{fd}",
                "--",
                sys.executable,
                "-I",
                "-c",
                ICMP_OBSERVER,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            pass_fds=(fd,),
            bufsize=0,
        )
        packets: dict[str, object] = {}
        try:
            if (
                observer.stdout is None
                or not select.select([observer.stdout], [], [], 3)[0]
                or observer.stdout.readline() != b"READY\n"
            ):
                raise RuntimeError("Disposable ICMP observer could not start.")
            passed = self.ping("a", "10.231.0.20")
            last_command = self.last_command
            raw, _ = observer.communicate(timeout=6)
            if observer.returncode != 0:
                raise RuntimeError("Disposable ICMP observer failed.")
            decoded = json.loads(raw)
            if not isinstance(decoded, dict) or any(
                not re.fullmatch(r"(?:in|out):[0-9]{1,3}:[0-9]{1,3}", key)
                or type(value) is not int
                or value < 0
                for key, value in decoded.items()
            ):
                raise RuntimeError("Invalid disposable packet summary.")
            packets.update(decoded)
        finally:
            if observer.poll() is None:
                observer.kill()
            observer.communicate(timeout=3)
        after = self.packet_snapshot()
        self.last_command = last_command
        self.flow_diagnostics = {
            "stage": self.stage,
            "before": before,
            "after": after,
            "ping": self.last_ping,
            "icmp_types": packets,
        }
        return passed

    def access(self, present: bool) -> None:
        """Change a fixed owned access pair and prove exact request replay."""
        self.query(f"""
intent = s.AccessIntent(access_id='{self.access_id}', source_client='client-a', destination_client='client-b', source_address='10.231.0.10', destination_address='10.231.0.20', private_networks=())
health = query(s.Health())
request = s.Request(request_id=str(uuid.uuid4()), operation_id=str(uuid.uuid4()), expected_generation=health.generation, command=s.SetAccess(intent=intent, present={present!r}))
response = adapter.execute(request)
wire.require_success(response)
assert response.result.state == 'succeeded'
assert adapter.execute(request).result == response.result
print(json.dumps({{'mutation': 'passed'}}))
""")

    def wait_http(self, container: str) -> None:
        """Require real API HTTP authentication denial without a token bypass."""
        end = time.monotonic() + 30
        while time.monotonic() < end:
            try:
                self.docker("exec", container, "python", "/opt/container/api_health.py")
                return
            except RuntimeError:
                time.sleep(0.5)
        raise RuntimeError("HTTP API authentication-denial probe timed out.")

    def start_http_api(self) -> str:
        """Start the actual unprivileged API with synthetic public Entra settings."""
        settings = {
            "RIVET_VPN_BACKEND": "agent",
            "RIVET_AGENT_SOCKET": "/run/ovpn-agent/agent.sock",
            "RIVET_AGENT_UID": "65532",
            "RIVET_VPN_EVENTS": "0",
            "RIVET_VPN_RECONCILE": "0",
            "RIVET_PROXY_IP": "172.30.250.2",
            "AZURE_ENTRAID_TENANT_ID": "11111111-1111-4111-8111-111111111111",
            "AZURE_ENTRAID_APP_CLIENT_ID": "22222222-2222-4222-8222-222222222222",
            "AZURE_ENTRAID_USER_ROLE": "device_user",
            "AZURE_ENTRAID_ADMIN_ROLE": "sysadmin",
            "AZURE_ENTRAID_SERVICE_ADMIN_ROLE": "ServiceAdmin",
        }
        options = [
            "--user=65531:65531",
            "--tmpfs=/opt/rivet:rw,noexec,nosuid,nodev,size=32m,mode=0700,uid=65531,gid=65531",
            *self.mount("agent-socket", "/run/ovpn-agent", readonly=True),
        ]
        options.extend(f"--env={key}={value}" for key, value in settings.items())
        container = self.launch(
            "http-api", self.images["api"], options, [], healthcheck=True
        )
        self.wait_http(container)
        return container

    def control_plane_outage(self) -> None:
        """Prove VPN traffic survives stopping both real HTTP API and typed probe."""
        self.stage = "http-api-startup"
        api = self.start_http_api()
        self.stage = "api-and-probe-outage"
        self.docker("stop", "--time=10", api, self.probe)
        if not self.peer_flow():
            raise RuntimeError("VPN traffic failed during API and probe outage.")
        self.stage = "api-and-probe-restart"
        self.docker("start", api, self.probe)
        self.wait_http(api)
        self.wait_ready()
        if not self.peer_flow():
            raise RuntimeError("VPN traffic failed after API and probe restart.")

    def wait_managed_client(self) -> None:
        """Require both an authenticated management session and actual TUN packets."""
        end = time.monotonic() + 45
        while time.monotonic() < end:
            if self.ping("c", "10.231.0.1"):
                observed = self.query(
                    "print(json.dumps({'connected': any(item.client == 'managed-client' for item in query(s.ListSessions()).items)}))"
                )
                if observed["connected"]:
                    addresses = json.loads(
                        self.network(
                            "c",
                            ["ip", "-j", "-4", "address", "show", "dev", "tun-client"],
                        )
                    )
                    if "10.231.0.30" not in {
                        item["local"]
                        for link in addresses
                        for item in link["addr_info"]
                    }:
                        raise RuntimeError(
                            "Issued client's tunnel differs from its CCD."
                        )
                    return
            time.sleep(0.5)
        raise RuntimeError("Issued credential did not establish a real VPN tunnel.")

    def credential_lifecycle(self, anchor: str) -> None:
        """Issue, stream, reconnect, revoke and delete through the real nonroot agent."""
        self.stage = "credential-issue"
        self.query(
            "mutate(s.ChangeClient(client='managed-client', action='issue'))\nprint(json.dumps({'issued': True}))"
        )
        self.query(
            "mutate(s.SetAssignment(client='managed-client', assignment=s.Assignment(address='10.231.0.30')))\nprint(json.dumps({'assigned': True}))"
        )
        self.stage = "credential-stream"
        self.query(
            inspect.getsource(export_archive)
            + """
metadata = query(s.GetClient(client='managed-client'))
with adapter.open_archive(s.Request(request_id=str(uuid.uuid4()), command=s.Archive(client='managed-client', generation=metadata.item.generation))) as stream:
    payload = b''.join(stream)
    assert stream.verified
export_archive(payload, Path('/probe-credentials'))
print(json.dumps({'archive': 'verified'}))
"""
        )
        credentials = self.state / "probe-credentials"
        config = b"""client
remote 172.31.252.1 1194
proto udp
dev tun-client
nobind
ca /fixture/ca.crt
cert /fixture/client.crt
key /fixture/client.key
remote-cert-tls server
data-ciphers AES-256-GCM:AES-128-GCM
connect-retry 1 1
hand-window 5
tls-timeout 1
disable-dco
log /dev/null
verb 0
"""
        write_file(credentials / "client.conf", config, 65531, 65531, 0o640)
        self.stage = "issued-client-connect"
        client = self.launch(
            "managed-client",
            self.images["openvpn"],
            [
                "--user=0:65531",
                "--cap-add=NET_ADMIN",
                "--device=/dev/net/tun:/dev/net/tun:rwm",
                "--entrypoint=/usr/local/sbin/openvpn",
                *self.mount("probe-credentials", "/fixture", readonly=True),
            ],
            ["--config", "/fixture/client.conf"],
            network=f"container:{anchor}",
        )
        self.wait_managed_client()
        self.stage = "issued-client-reconnect"
        self.docker("stop", "--time=5", client)
        self.docker("start", client)
        self.wait_managed_client()
        self.stage = "credential-revoke"
        before_crl = (self.state / "vpn-projection/crl.pem").read_bytes()
        self.query(
            "mutate(s.ChangeClient(client='managed-client', action='revoke'))\nassert query(s.GetClient(client='managed-client')).item.state == 'revoked'\nprint(json.dumps({'revoked': True}))"
        )
        crl = (self.state / "vpn-projection/crl.pem").read_bytes()
        if crl == before_crl or crl != (self.state / "vpn-pki/crl.pem").read_bytes():
            raise RuntimeError("Revocation CRL was not projected exactly.")
        self.query(f"""
import base64
from cryptography import x509
crl = x509.load_pem_x509_crl(base64.b64decode({base64.b64encode(crl).decode()!r}, validate=True))
certificate = x509.load_pem_x509_certificate(Path('/probe-credentials/client.crt').read_bytes())
ca = x509.load_pem_x509_certificate(Path('/probe-credentials/ca.crt').read_bytes())
assert crl.is_signature_valid(ca.public_key())
assert certificate.serial_number in {{entry.serial_number for entry in crl}}
print(json.dumps({{'signed_crl_contains_revoked_leaf': True}}))
""")
        self.query("""
metadata = query(s.GetClient(client='managed-client'))
try:
    with adapter.open_archive(s.Request(request_id=str(uuid.uuid4()), command=s.Archive(client='managed-client', generation=metadata.item.generation))) as stream:
        list(stream)
except ControlError as error:
    assert error.code == ErrorCode.CONFLICT
else:
    raise AssertionError('Revoked credential archive remained available.')
sessions = query(s.ListSessions())
current = next(item for item in sessions.items if item.client == 'managed-client')
mutate(s.Disconnect(client=current.client, session_id=current.session_id))
print(json.dumps({'revoked_archive_denied': True, 'disconnected': True}))
""")
        # Fresh process and TUN prevent stale session state from masking admission.
        self.docker("stop", "--time=5", client)
        self.stage = "revoked-client-reconnect-denied"
        before = interface_counters(
            json.loads(
                self.network("c", ["ip", "-j", "-s", "link", "show", "dev", "peer-c"])
            )
        )
        self.docker("start", client)
        end = time.monotonic() + 15
        while time.monotonic() < end:
            if self.ping("c", "10.231.0.1"):
                raise RuntimeError("Revoked credentials re-established VPN traffic.")
            result = self.query(
                "print(json.dumps({'connected': any(item.client == 'managed-client' for item in query(s.ListSessions()).items)}))"
            )
            if result["connected"]:
                raise RuntimeError("Revoked credentials acquired a live session.")
            time.sleep(0.5)
        after = interface_counters(
            json.loads(
                self.network("c", ["ip", "-j", "-s", "link", "show", "dev", "peer-c"])
            )
        )
        if after["tx_packets"] <= before["tx_packets"]:
            raise RuntimeError("Revoked client did not attempt a fresh handshake.")
        if not self.peer_flow():
            raise RuntimeError("Unaffected VPN clients failed during revocation proof.")
        self.stage = "credential-delete"
        self.docker("stop", "--time=5", client)
        self.query(
            """
mutate(s.ChangeClient(client='managed-client', action='delete'))
try:
    query(s.GetClient(client='managed-client'))
except ControlError as error:
    assert error.code == ErrorCode.NOT_FOUND
else:
    raise AssertionError('Deleted client remained discoverable.')
print(json.dumps({'deleted': True}))
"""
        )
        if (self.state / "vpn-pki/private/managed-client.key").exists():
            raise RuntimeError("Deleted client private key remained in agent PKI.")

    def check_image_cache(self) -> None:
        """Require every reviewed image to be present before launching state."""
        for image in self.images.values():
            self.docker("image", "inspect", image)

    def execute(self) -> dict[str, object]:
        """Prove UDP/CCD, packet allow/deny, API isolation and agent crash survival."""
        self.stage = "image-cache"
        self.check_image_cache()
        self.stage = "synthetic-pki"
        self.prepare()
        self.stage = "isolated-topology"
        anchors = self.topology()
        self.stage = "container-services"
        agent = self.services(anchors)
        self.stage = "real-client-connectivity"
        deadline = time.monotonic() + 45
        while not all(self.ping(role, "10.231.0.1") for role in ("a", "b")):
            if time.monotonic() > deadline:
                raise RuntimeError("Real VPN client connectivity deadline exceeded.")
            time.sleep(0.5)
        self.stage = "ccd-and-sessions"
        self.query("""
sessions = query(s.ListSessions())
assert {item.client for item in sessions.items} == {'client-a', 'client-b'}
for name, address in [('client-a', '10.231.0.10'), ('client-b', '10.231.0.20')]:
    client = query(s.GetClient(client=name))
    assert client.item.assignment.address == address
print(json.dumps({'ccd_sessions': 'passed'}))
""")
        for role, expected in (("a", "10.231.0.10"), ("b", "10.231.0.20")):
            observed = json.loads(
                self.network(
                    role, ["ip", "-j", "-4", "address", "show", "dev", "tun-client"]
                )
            )
            if expected not in {
                item["local"] for link in observed for item in link["addr_info"]
            }:
                raise RuntimeError("Actual tunnel address differs from CCD.")
        self.stage = "default-deny"
        self.access_id = str(uuid.uuid4())
        if self.peer_flow():
            raise RuntimeError("Default-denied peer traffic was admitted.")
        self.stage = "access-allow"
        self.access(True)
        if not self.peer_flow():
            raise RuntimeError("Allowed peer traffic did not cross the tunnel.")
        self.stage = "access-remove"
        self.access(False)
        if self.peer_flow():
            raise RuntimeError("Removed access admitted established peer traffic.")
        self.stage = "access-allow"
        self.access(True)
        self.stage = "agent-loss"
        self.docker("kill", "--signal=KILL", agent)
        if not self.peer_flow():
            raise RuntimeError("Data plane failed during agent loss.")
        self.stage = "agent-restart"
        self.docker("start", agent)
        self.wait_ready()
        if not self.peer_flow():
            raise RuntimeError("Data plane failed after agent restart.")
        self.control_plane_outage()
        self.credential_lifecycle(anchors["c"])
        return {
            "real_udp_clients": 3,
            "credential_issue_archive_reconnect_revoke_delete": "passed",
            "crl_projection_and_revoked_handshake_denial": "passed",
            "http_authentication_denial": "passed",
            "api_and_probe_outage_restart": "passed",
            "ccd_addresses": "passed",
            "allowed_denied_flows": "passed",
            "same_id_replay": "passed",
            "agent_loss_and_restart": "passed",
            "full_phase6": False,
        }

    def close(self, *, remove_state: bool = True) -> None:
        """Remove tracked objects first; retain state if teardown is uncertain."""
        failed = False
        for name in reversed(self.containers):
            try:
                info = json.loads(self.docker("inspect", name))[0]
                if info["Config"]["Labels"].get(
                    "rivet.rehearsal"
                ) != self.token or not re.fullmatch(r"[a-f0-9]{64}", info["Id"]):
                    raise RuntimeError("Cleanup object ownership mismatch.")
                self.docker("rm", "--force", info["Id"])
            except (RuntimeError, ValueError, KeyError, IndexError):
                failed = True
        for fd in self.namespaces.values():
            os.close(fd)
        self.namespaces.clear()
        if failed:
            raise RuntimeError(
                "Container cleanup incomplete; synthetic state retained."
            )
        if remove_state:
            shutil.rmtree(self.root)


def main() -> int:
    """Require explicit operator invocation, redact failures and always clean up."""
    parser = argparse.ArgumentParser(description=__doc__)
    for role in ("agent", "openvpn", "api"):
        parser.add_argument(f"--{role}-image", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Reviewed root execution is required.")
    os.umask(0o077)

    def interrupted(signum: int, frame: object) -> None:
        raise RuntimeError("Disposable rehearsal interrupted.")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    rehearsal = Rehearsal(args.agent_image, args.openvpn_image, args.api_image)
    result: dict[str, object] = {}
    code = 0
    try:
        result = rehearsal.execute()
    except Exception as error:  # noqa: BLE001 - never disclose private output
        code = 1
        result = {
            "result": "failed",
            "error_type": type(error).__name__,
            "stage": getattr(rehearsal, "stage", "initialization"),
            "last_command": getattr(rehearsal, "last_command", {}),
            "flow_diagnostics": getattr(rehearsal, "flow_diagnostics", {}),
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
        except Exception:  # noqa: BLE001 - report teardown separately
            code = 1
            result["cleanup"] = "incomplete"
            result["run_id"] = rehearsal.token
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
