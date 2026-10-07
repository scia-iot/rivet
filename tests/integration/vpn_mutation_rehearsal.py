"""Phase 4 mutation proof, exclusively inside attested disposable namespaces.

Never collected by pytest. Uses a new synthetic CA and the production Unix
transport. The namespace runner masks host VPN paths before this module runs.
"""

import argparse
import io
import json
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import time
import traceback
import uuid
import zipfile

from sqlmodel import Session, SQLModel, create_engine, select

from sciaiot.ovpncp.adapters.vpn.agent import AgentVpnControl
from sciaiot.ovpncp.application.vpn_control import schemas as s
from sciaiot.ovpncp.application.vpn_control import wire
from sciaiot.ovpncp.application.vpn_control.errors import ControlError, ErrorCode
from sciaiot.ovpncp.data.server import Client, Connection
from sciaiot.ovpncp.data.vpn_events import EventCursor
from sciaiot.ovpncp.migration import filesystem
from sciaiot.ovpncp.services.vpn_events import EventConsumer
from tests.integration import migration_rehearsal as fixture
from tests.integration.vpn_agent_rehearsal import AgentRehearsal


class MutationRehearsal(AgentRehearsal):
    """Exercise privileged effects against fresh namespace-owned resources."""

    def start(
        self, name: str, argv: list[str], env: dict[str, str] | None = None
    ) -> subprocess.Popen[bytes]:
        """Project minimal server material before starting the disposable daemon."""
        if name == "server":
            projection = self.source / "projection"
            projection.mkdir(mode=0o750)
            shutil.copytree(self.source / "ccd", projection / "ccd")
            for relative, destination in (
                ("ca.crt", "ca.crt"),
                ("issued/server.crt", "server.crt"),
                ("private/server.key", "server.key"),
                ("crl.pem", "crl.pem"),
            ):
                shutil.copyfile(
                    self.source / "pki" / relative, projection / destination
                )
                (projection / destination).chmod(0o640)
            event_runtime = pathlib.Path("/run/p4-events")
            event_runtime.mkdir(mode=0o2770)
            event_runtime.chmod(0o2770)
            launcher = self.root / "event-hook.py"
            source = pathlib.Path(__file__).resolve().parents[2] / "src"
            filesystem.write_private(
                launcher,
                (
                    f"import sys\nsys.path.insert(0, {str(source)!r})\n"
                    "from sciaiot.ovpncp.vpn_agent.event_hook import main\nmain()\n"
                ).encode(),
            )
            hook = shlex.join(
                [
                    sys.executable,
                    str(launcher),
                    "--socket",
                    str(event_runtime / "events.sock"),
                    "--management-socket",
                    "/run/p3-openvpn/management.sock",
                    "--agent-uid",
                    "0",
                ]
            )
            config = self.source / "server.conf"
            text = config.read_text().replace("keepalive 10 120", "keepalive 1 5")
            for original, replacement in (
                (f"ca {self.source}/pki/ca.crt", f"ca {projection}/ca.crt"),
                (
                    f"cert {self.source}/pki/issued/server.crt",
                    f"cert {projection}/server.crt",
                ),
                (
                    f"key {self.source}/pki/private/server.key",
                    f"key {projection}/server.key",
                ),
                (
                    f"crl-verify {self.source}/pki/crl.pem",
                    f"crl-verify {projection}/crl.pem",
                ),
                (
                    f"client-config-dir {self.source}/ccd",
                    f"client-config-dir {projection}/ccd",
                ),
            ):
                text = text.replace(original, replacement)
            text += f'\ndisable-dco\nscript-security 2\nclient-connect "{hook}"\nclient-disconnect "{hook}"\n'
            config.write_bytes(text.encode())
        return super().start(name, argv, env)

    def query(self, command: s.Command) -> s.Result:
        """Use the production adapter and its strict response validation."""
        return self.adapter.execute(
            s.Request(request_id=str(uuid.uuid4()), command=command)
        ).result

    def mutate(self, command: s.Command) -> s.Request:
        """Require durable success and exact same-ID replay without generation drift."""
        health = self.query(s.Health())
        assert isinstance(health, s.HealthResult) and health.ready
        original = s.Request(
            request_id=str(uuid.uuid4()),
            operation_id=str(uuid.uuid4()),
            expected_generation=health.generation,
            command=command,
        )
        assert original.operation_id is not None
        try:
            response = self.adapter.execute(original)
        except ControlError as error:
            if error.code not in {
                ErrorCode.UNAVAILABLE,
                ErrorCode.TIMEOUT,
                ErrorCode.UNKNOWN_OUTCOME,
            }:
                raise
            response = self.adapter.execute(
                s.Request(
                    request_id=str(uuid.uuid4()),
                    command=s.LookupOperation(operation_id=original.operation_id),
                )
            )
        deadline = time.monotonic() + 60
        while isinstance(
            response.result, s.MutationResult
        ) and response.result.state in {"pending", "partial", "unknown"}:
            if time.monotonic() >= deadline:
                raise RuntimeError("Mutation recovery did not reach a proven result.")
            time.sleep(0.2)
            response = self.adapter.execute(
                s.Request(
                    request_id=str(uuid.uuid4()),
                    command=s.LookupOperation(operation_id=original.operation_id),
                )
            )
        wire.require_success(response)
        assert isinstance(response.result, s.MutationResult)
        assert response.result.generation == health.generation + 1
        deadline = time.monotonic() + 20
        while True:
            try:
                replay = self.adapter.execute(original)
                break
            except ControlError as error:
                if error.code != ErrorCode.UNAVAILABLE or time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)
        assert replay.result == response.result
        return original

    def start_agent(self, env: dict[str, str]) -> subprocess.Popen[bytes]:
        """Require readiness after fresh launch or crash recovery."""
        process = self.start(
            f"agent-{len(self.processes)}",
            [sys.executable, "-m", "sciaiot.ovpncp.vpn_agent"],
            env,
        )
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("Disposable mutation agent startup failed.")
            try:
                health = self.query(s.Health())
                if isinstance(health, s.HealthResult) and health.ready:
                    return process
            except ControlError:
                pass
            time.sleep(0.1)
        raise RuntimeError("Disposable mutation agent readiness timed out.")

    def archive(self, name: str, generation: int) -> None:
        """Validate the complete framed ZIP without publishing private material."""
        with self.adapter.open_archive(
            s.Request(
                request_id=str(uuid.uuid4()),
                command=s.Archive(client=name, generation=generation),
            )
        ) as stream:
            data = b"".join(stream)
            assert stream.verified
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            assert set(archive.namelist()) == {
                "ca.crt",
                f"issued/{name}.crt",
                f"private/{name}.key",
            }
            assert archive.testzip() is None

    def start_peer(self) -> None:
        """Connect a second real client for kernel-forwarded allow/deny checks."""
        for arguments in (
            ["netns", "add", "p4-peer"],
            ["link", "add", "p4-server", "type", "veth", "peer", "name", "p4-peer"],
            ["link", "set", "p4-peer", "netns", "p4-peer"],
            ["address", "add", "172.31.251.1/30", "dev", "p4-server"],
            ["link", "set", "p4-server", "up"],
            ["-n", "p4-peer", "address", "add", "172.31.251.2/30", "dev", "p4-peer"],
            ["-n", "p4-peer", "link", "set", "p4-peer", "up"],
            ["-n", "p4-peer", "link", "set", "lo", "up"],
            ["-n", "p4-peer", "route", "add", "172.31.250.1/32", "via", "172.31.251.1"],
        ):
            self.run(["/usr/sbin/ip", *arguments])
        self.run(["/usr/sbin/sysctl", "-w", "net.ipv4.ip_forward=1"])
        config = self.source / "peer.conf"
        text = (
            (self.source / "client.conf")
            .read_text()
            .replace("existing-client", "edge-peer")
            .replace("dev tun-client", "dev tun-peer")
        )
        filesystem.write_private(config, text.encode())
        process = self.start(
            "peer",
            [
                "/usr/sbin/ip",
                "netns",
                "exec",
                "p4-peer",
                "/usr/sbin/openvpn",
                "--config",
                str(config),
                "--disable-dco",
            ],
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("Disposable peer startup failed.")
            if (
                b"Initialization Sequence Completed"
                in (self.root / "peer.log").read_bytes()
            ):
                return
            time.sleep(0.1)
        raise RuntimeError("Disposable peer connection timed out.")

    def peer_ping(self) -> bool:
        """Observe real TUN-to-TUN forwarding without printing network details."""
        result = subprocess.run(
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
                "10.231.0.20",
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        return result.returncode == 0

    def unprivileged_api(self, env: dict[str, str]) -> None:
        """Run real API services with no root, capabilities, PKI, or subprocesses."""
        from tests.integration import vpn_api_probe

        jail = self.root / "api-jail"
        jail.mkdir(mode=0o755)
        jail.chmod(0o755)
        (jail / "api").mkdir(mode=0o700)
        os.chown(jail / "api", 65534, 65534)
        (jail / "run").mkdir(mode=0o755)
        (jail / "run").chmod(0o755)
        control = pathlib.Path(env["OVPNCP_AGENT_SOCKET"]).parent
        shared = jail / "run" / control.name
        shared.mkdir(mode=0o750)
        os.chown(control, 0, 65534)
        control.chmod(0o2750)
        self.run(["/usr/bin/mount", "--bind", str(control), str(shared)])
        self.run(["/usr/bin/mount", "-o", "remount,bind,ro", str(shared)])
        (jail / "dev").mkdir(mode=0o755)
        (jail / "dev").chmod(0o755)
        entropy = jail / "dev/urandom"
        entropy.touch(mode=0o444)
        self.run(["/usr/bin/mount", "--bind", "/dev/urandom", str(entropy)])
        self.run(["/usr/bin/mount", "-o", "remount,bind,ro", str(entropy)])
        child_env = {**env, "OVPNCP_API_UID": "65534"}
        agent = self.start(
            f"agent-{len(self.processes)}",
            [sys.executable, "-m", "sciaiot.ovpncp.vpn_agent"],
            child_env,
        )
        pid = os.fork()
        if pid == 0:
            try:
                os.closerange(3, 256)
                vpn_api_probe.run(jail, env["OVPNCP_AGENT_SOCKET"])
            except BaseException as error:  # noqa: BLE001 - redact child failures
                print(
                    json.dumps(
                        {
                            "api_probe": "failed",
                            "error_type": type(error).__name__,
                            "frames": [
                                (
                                    pathlib.Path(frame.filename).name,
                                    frame.lineno,
                                    frame.name,
                                )
                                for frame in traceback.extract_tb(error.__traceback__)
                            ],
                        }
                    ),
                    file=sys.stderr,
                    flush=True,
                )
                os._exit(1)
            os._exit(0)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            finished, status = os.waitpid(pid, os.WNOHANG)
            if finished:
                if status != 0:
                    raise RuntimeError("Unprivileged API proof failed.")
                break
            time.sleep(0.1)
        else:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
            raise RuntimeError("Unprivileged API proof timed out.")
        agent.terminate()
        agent.wait(timeout=5)

    def execute_mutations(self) -> dict[str, object]:
        """Exercise all families, replay, live events and VPN survival of agent loss."""
        socket_path, env = self.setup()
        # Explicitly disjoint foreign interfaces make this admin policy provably
        # unrelated to the TUN; ambiguous foreign denies correctly fail closed.
        self.run(
            [
                "/usr/sbin/iptables-nft",
                "-D",
                "FORWARD",
                "-s",
                "192.0.2.1/32",
                "-j",
                "DROP",
            ]
        )
        self.run(
            [
                "/usr/sbin/iptables-nft",
                "-A",
                "FORWARD",
                "-i",
                "foreign-in",
                "-o",
                "foreign-out",
                "-s",
                "192.0.2.1/32",
                "-j",
                "DROP",
            ]
        )
        self.run(
            [
                "/usr/sbin/iptables-nft",
                "-A",
                "OVPNCP_FORWARD",
                "-m",
                "comment",
                "--comment",
                "ovpncp:terminal-deny",
                "-j",
                "DROP",
            ]
        )
        journal = self.source / "journal"
        journal.mkdir(mode=0o700)
        env.update(
            OVPNCP_AGENT_JOURNAL=str(journal),
            OVPNCP_AGENT_MUTATIONS="assignments,routes,access,pki,events,management",
            OVPNCP_AGENT_ROUTE_PROTOCOL="200",
            OVPNCP_AGENT_EASYRSA=str(self.easyrsa),
            OVPNCP_AGENT_PROJECTION=str(self.source / "projection"),
            OVPNCP_AGENT_EVENT_SOCKET="/run/p4-events/events.sock",
        )
        self.adapter = AgentVpnControl(str(socket_path), peer_uid=0)
        agent = self.start_agent(env)
        self.start_peer()
        assert self.peer_ping()
        # A broad established/related accept after the anchors cannot bypass deny.
        self.run(
            [
                "/usr/sbin/iptables-nft",
                "-A",
                "FORWARD",
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ]
        )
        self.mutate(
            s.SetPushRoutes(
                client="existing-client", intent_id=self.access.access_id, routes=()
            )
        )
        self.mutate(s.SetAccess(intent=self.access, present=False))
        assert not self.peer_ping()
        self.mutate(s.SetAccess(intent=self.access, present=True))
        assert self.peer_ping()
        original_ca = (self.source / "pki/ca.crt").read_bytes()
        original_key = (self.source / "pki/private/existing-client.key").read_bytes()
        name = "managed-client"
        issued = self.mutate(s.ChangeClient(client=name, action="issue"))
        metadata = self.query(s.GetClient(client=name))
        assert isinstance(metadata, s.ClientResult)
        self.archive(name, metadata.item.generation)
        self.mutate(
            s.SetAssignment(client=name, assignment=s.Assignment(address="10.231.0.30"))
        )
        assert (self.source / "ccd" / name).read_bytes() == (
            self.source / "projection/ccd" / name
        ).read_bytes()
        assert (self.source / "projection/ccd" / name).stat().st_mode & 0o777 == 0o640
        route = s.ManagedRoute(
            route_id=str(uuid.uuid4()), network="10.236.0.0/24", gateway="10.231.0.20"
        )
        self.mutate(s.SetRoute(route=route, present=True))
        observed = self.query(s.ListRoutes())
        assert isinstance(observed, s.RoutesResult) and route in observed.items
        self.mutate(s.SetRoute(route=route, present=False))
        assert b"10.235.0.0/24" in self.run(
            ["/usr/sbin/ip", "-N", "-j", "-4", "route", "show", "proto", "201"]
        )
        access = s.AccessIntent(
            access_id=str(uuid.uuid4()),
            source_client=name,
            destination_client="edge-peer",
            source_address="10.231.0.30",
            destination_address="10.231.0.20",
            private_networks=("10.234.0.0/24",),
        )
        self.mutate(s.SetAccess(intent=access, present=True))
        self.mutate(
            s.SetPushRoutes(
                client=name,
                intent_id=access.access_id,
                routes=(s.PushRoute(network="10.234.0.0/24", gateway="10.231.0.20"),),
            )
        )
        self.mutate(s.SetPushRoutes(client=name, intent_id=access.access_id, routes=()))
        self.mutate(s.SetAccess(intent=access, present=False))
        rules = self.run(["/usr/sbin/iptables-nft-save", "-t", "filter"])
        assert (
            b"192.0.2.1/32" in rules
            and b"foreign-in" in rules
            and b"ovpncp:terminal-deny" in rules
        )
        self.mutate(s.ChangeClient(client=name, action="renew"))
        renewed = self.query(s.GetClient(client=name))
        assert isinstance(renewed, s.ClientResult)
        assert renewed.item.certificate_sha256 != metadata.item.certificate_sha256
        self.archive(name, renewed.item.generation)
        self.mutate(s.SetAssignment(client=name, assignment=None))
        self.mutate(s.ChangeClient(client=name, action="revoke"))
        try:
            self.archive(name, renewed.item.generation)
        except ControlError:
            pass
        else:
            raise AssertionError("Revoked credentials were downloadable.")
        self.mutate(s.ChangeClient(client=name, action="delete"))
        assert not (self.source / "pki/private" / f"{name}.key").exists()
        assert (self.source / "pki/ca.crt").read_bytes() == original_ca
        assert (
            self.source / "pki/private/existing-client.key"
        ).read_bytes() == original_key
        # Startup gap reconciles the connection which preceded agent availability.
        engine = create_engine(f"sqlite:///{self.root / 'api-history.sqlite3'}")
        SQLModel.metadata.create_all(engine)
        with Session(engine) as session:
            session.add(Client(name="existing-client"))
            session.commit()
        consumer = EventConsumer(engine, self.adapter)
        consumer.run_once()
        sessions = self.query(s.ListSessions())
        assert isinstance(sessions, s.SessionsResult) and sessions.items
        current = next(
            item for item in sessions.items if item.client == "existing-client"
        )
        self.mutate(s.Disconnect(client=current.client, session_id=current.session_id))
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            consumer.run_once()
            with Session(engine) as session:
                history = session.exec(select(Connection)).all()
                if any(item.disconnected_time is not None for item in history):
                    break
            time.sleep(0.2)
        else:
            raise AssertionError("Real disconnect event was not committed.")
        with Session(engine) as session:
            cursor = session.get(EventCursor, 1)
            assert cursor is not None and cursor.after == cursor.acknowledged
        engine.dispose()
        self.mutate(s.Reload())
        # The daemon is ready before clients finish their bounded reconnect.
        deadline = time.monotonic() + 30
        while not self.peer_ping():
            if time.monotonic() >= deadline:
                raise RuntimeError("Clients did not reconnect after soft reload.")
            time.sleep(0.1)
        self.ping()
        # SIGKILL leaves a stale socket; journal ownership permits safe restart.
        agent.kill()
        agent.wait(timeout=5)
        self.ping()
        agent = self.start_agent(env)
        assert issued.operation_id is not None
        replay = self.query(s.LookupOperation(operation_id=issued.operation_id))
        assert isinstance(replay, s.MutationResult) and replay.state == "succeeded"
        assert self.adapter.execute(issued).result == replay
        agent.terminate()
        agent.wait(timeout=5)
        self.ping()
        self.unprivileged_api(env)
        self.ping()
        return {
            "mutation_families": "passed",
            "unprivileged_api_without_protected_mounts_or_subprocesses": "passed",
            "credential_stream": "passed",
            "same_id_replay_after_restart": "passed",
            "foreign_state_preserved": "passed",
            "real_tun_to_tun_allow_deny": "passed",
            "api_history_before_ack": "passed",
            "real_disconnect_event": "passed",
            "openvpn_survived_agent_loss": True,
        }


def main() -> int:
    """Refuse host execution before creating any privileged fixture."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--easyrsa", type=pathlib.Path, required=True)
    parser.add_argument("--failure-evidence-dir", type=pathlib.Path)
    args = parser.parse_args()
    fixture.require_isolation()
    if args.failure_evidence_dir is not None:
        fixture.validate_evidence_directory(args.failure_evidence_dir)
    rehearsal = MutationRehearsal(args.easyrsa, network=True, version="2.6.19")
    try:
        print(json.dumps(rehearsal.execute_mutations(), sort_keys=True))
        return 0
    except Exception as error:  # noqa: BLE001 - private fixture diagnostics stay private
        if args.failure_evidence_dir is not None:
            rehearsal.retain_failure_evidence(args.failure_evidence_dir)
            for agent_log in rehearsal.root.glob("agent-*.log"):
                filesystem.write_private(
                    args.failure_evidence_dir / agent_log.name,
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
