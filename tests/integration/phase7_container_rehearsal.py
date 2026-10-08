"""Opt-in encrypted M0 migration, UDP, checkpoint and rollback rehearsal.

Run only on an approved rootful Linux Docker host through a maintenance guard.
All network mutations reuse Phase 6's pinned disposable namespaces; no source
OpenVPN files, application database, firewall or host network are mounted here.
"""

import argparse
import ipaddress
import json
import os
import pathlib
import re
import signal
import stat
import sys
import tempfile
import time
import traceback
import uuid

from tests.integration import vpn_container_rehearsal as phase6

REPO = pathlib.Path(__file__).resolve().parents[2]
HOOK = REPO / "deploy/containers/vpn_event.sh"
MIGRATION = REPO / "src/sciaiot/ovpncp/migration"


def _private_dir(path: pathlib.Path) -> None:
    """Require a root-owned, canonical private staging boundary."""
    info = path.lstat()
    if (
        not path.is_absolute()
        or path.resolve() != path
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ValueError("Expected a root-owned private directory.")


def _inputs(path: pathlib.Path) -> None:
    _private_dir(path)
    for name in ("migration.bundle", "migration.key", "capabilities.json"):
        info = (path / name).lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ValueError("Private migration input grants are invalid.")


class Rehearsal(phase6.Rehearsal):
    """Reuse Phase 6's isolated Docker, namespace, probes and cleanup."""

    def __init__(
        self,
        agent: str,
        openvpn: str,
        api: str,
        input_dir: pathlib.Path,
        private_parent: pathlib.Path,
    ) -> None:
        _inputs(input_dir)
        _private_dir(private_parent)
        self.images = {"agent": agent, "openvpn": openvpn, "api": api}
        for role, value in self.images.items():
            phase6.validate_image(value, role)
        capabilities = json.loads((input_dir / "capabilities.json").read_text())
        references = (
            capabilities.get("image_refs") if isinstance(capabilities, dict) else None
        )
        if not isinstance(references, dict) or references != self.images:
            raise ValueError(
                "Image references differ from observed capability evidence."
            )
        self.input_dir = input_dir
        self.token = uuid.uuid4().hex[:12]
        self.containers: list[str] = []
        self.namespaces: dict[str, int] = {}
        self.root = pathlib.Path(
            tempfile.mkdtemp(prefix=f"ovpncp-p7-{self.token}-", dir=private_parent)
        )
        self.state = self.root / "migration/active"
        self.stage = "initialized"
        self.helper_index = 0
        self._progress()

    def docker(self, *argv: str, input_data: bytes | None = None) -> bytes:
        """Allow bounded cryptographic bundle checks on a one-core host."""
        return self.command(
            ["docker", "--host=unix:///var/run/docker.sock", *argv],
            input_data=input_data,
            timeout=240,
        )

    def _progress(self) -> None:
        """Publish only a fixed stage label for the maintenance supervisor."""
        temporary = self.root / ".progress.tmp"
        temporary.write_text(json.dumps({"stage": self.stage, "run_id": self.token}))
        temporary.chmod(0o600)
        os.replace(temporary, self.root / "progress.json")

    def _stage(self, value: str) -> None:
        self.stage = value
        self._progress()

    def _admin(
        self,
        argv: list[str],
        *,
        mutate: bool = False,
        read_target: bool = False,
    ) -> dict[str, object]:
        """Run pinned Python 3.14 with narrowly scoped offline grants."""
        if mutate and read_target:
            raise ValueError("Helper cannot be read-only and mutating.")
        self.helper_index += 1
        name = f"ovpncp-p7-{self.token}-helper-{self.helper_index}"
        options = [
            "run",
            "--pull=never",
            "--rm",
            "--name",
            name,
            "--label",
            f"ovpncp.rehearsal={self.token}",
            "--network=none",
            "--read-only",
            "--user=0:65532",
            "--group-add=65531",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--pids-limit=64",
            "--memory=512m",
            "--cpus=1",
            "--log-driver=none",
            "--mount",
            f"type=bind,src={self.input_dir},dst=/input,readonly",
            "--mount",
            (
                f"type=bind,src={self.root},dst=/work"
                + (",readonly" if read_target else "")
            ),
            "--mount",
            (
                f"type=bind,src={MIGRATION},"
                "dst=/opt/app/sciaiot/ovpncp/migration,readonly"
            ),
            "--mount",
            (
                "type=bind,src="
                f"{REPO / 'tests/integration/phase7_migration_helper.py'},"
                "dst=/repo/phase7_helper.py,readonly"
            ),
            "--entrypoint=python",
        ]
        if mutate:
            options.extend(
                ["--cap-add=CHOWN", "--cap-add=FOWNER", "--cap-add=DAC_OVERRIDE"]
            )
        elif read_target:
            options.append("--cap-add=DAC_OVERRIDE")
        output = self.docker(*options, self.images["api"], *argv)
        value = json.loads(output)
        if not isinstance(value, dict):
            raise TypeError("Invalid redacted migration helper response.")
        return value

    def _helper(
        self,
        command: str,
        *,
        mutate: bool = False,
        read_target: bool = False,
    ) -> None:
        result = self._admin(
            [
                "/repo/phase7_helper.py",
                command,
                "--input-dir",
                "/input",
                "--work",
                "/work",
            ],
            mutate=mutate,
            read_target=read_target,
        )
        if result != {"phase7_helper": command, "passed": True}:
            raise RuntimeError("Private Phase 7 helper did not attest success.")

    def _migration(
        self,
        command: str,
        *,
        checkpoint: bool = False,
        restore: bool = False,
        apply: bool = False,
    ) -> dict[str, object]:
        """Use only the public encrypted M0 CLI for target operations."""
        bundle_name = "checkpoint.bundle" if checkpoint else "migration.bundle"
        key_name = "checkpoint.key" if checkpoint else "migration.key"
        policy_name = "restore-policy.json" if restore else "policy.json"
        target_path = "/work/restore" if restore else "/work/migration"
        argv = ["-m", "sciaiot.ovpncp.migration.cli", command]
        if command != "rollback":
            argv.extend(
                [
                    "--container",
                    "--bundle",
                    f"/{'work' if checkpoint else 'input'}/{bundle_name}",
                    "--key-file",
                    f"/{'work' if checkpoint else 'input'}/{key_name}",
                    "--policy",
                    f"/work/{policy_name}",
                ]
            )
        else:
            argv.append("--container")
        if command in {"import", "verify", "rollback"}:
            argv.extend(["--target", target_path])
        if apply:
            argv.extend(["--apply", "--target-stopped"])
        return self._admin(
            argv,
            mutate=apply,
            read_target=command == "verify",
        )

    def _checkpoint(self) -> None:
        """Export the stopped target via M0 with agent-only, read-only mounts."""
        private = self.root / "checkpoint-work"
        private.mkdir(mode=0o700)
        os.chown(private, 65532, 65532)
        key = private / "checkpoint.key"
        key.write_bytes(os.urandom(32))
        os.chown(key, 65532, 65532)
        key.chmod(0o600)
        spec = {
            "openvpn_root": "/var/lib/ovpn-agent/projection",
            "easyrsa_root": "/var/lib/ovpn-agent/pki",
            "server_config": "server.conf",
            "versions": {"openvpn": "2.6.19", "easyrsa": "3.1.7", "openssl": "3.5.7"},
            "serial_policy": self.serial_policy,
            "container_runtime_hooks": True,
            "external_files": {
                "/var/lib/openvpn/ipp.txt": "pool",
                "/usr/local/bin/ovpncp-vpn-event": "hook",
            },
        }
        descriptor = private / "source.json"
        descriptor.write_text(json.dumps(spec))
        os.chown(descriptor, 65532, 65532)
        descriptor.chmod(0o600)
        checkpoint_name = f"ovpncp-p7-{self.token}-checkpoint"
        options = [
            "run",
            "--pull=never",
            "--rm",
            "--name",
            checkpoint_name,
            "--label",
            f"ovpncp.rehearsal={self.token}",
            "--network=none",
            "--read-only",
            "--user=65532:65532",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--pids-limit=64",
            "--memory=512m",
            "--cpus=1",
            "--log-driver=none",
            "--mount",
            f"type=bind,src={private},dst=/checkpoint",
            "--mount",
            (
                "type=bind,src="
                f"{self.state / 'vpn-projection'},"
                "dst=/var/lib/ovpn-agent/projection,readonly"
            ),
            "--mount",
            (
                f"type=bind,src={self.state / 'vpn-pki'},"
                "dst=/var/lib/ovpn-agent/pki,readonly"
            ),
            "--mount",
            (f"type=bind,src={self.state / 'vpn-pool'},dst=/var/lib/openvpn,readonly"),
            "--mount",
            f"type=bind,src={HOOK},dst=/usr/local/bin/ovpncp-vpn-event,readonly",
            "--mount",
            (
                f"type=bind,src={MIGRATION},"
                "dst=/opt/app/sciaiot/ovpncp/migration,readonly"
            ),
            "--entrypoint=python",
            self.images["api"],
            "-m",
            "sciaiot.ovpncp.migration.cli",
            "export",
            "--source",
            "/checkpoint/source.json",
            "--bundle",
            "/checkpoint/checkpoint.bundle",
            "--key-file",
            "/checkpoint/checkpoint.key",
            "--writers-frozen",
        ]
        result = json.loads(self.docker(*options))
        if result.get("exported") is not True or result.get("encrypted") is not True:
            raise RuntimeError("Stopped target checkpoint did not complete.")
        for name in ("checkpoint.key", "checkpoint.bundle"):
            os.replace(private / name, self.root / name)
            os.chown(self.root / name, 0, 0, follow_symlinks=False)

    def _bind(
        self, path: pathlib.Path, destination: str, *, readonly: bool = False
    ) -> list[str]:
        if not path.resolve().is_relative_to(self.root):
            raise ValueError("Unowned fixture mount.")
        suffix = ",readonly" if readonly else ""
        return ["--mount", f"type=bind,src={path},dst={destination}{suffix}"]

    def _services(
        self, anchors: dict[str, str], generation: str
    ) -> tuple[str, str, str]:
        """Launch only the real VPN, agent, probe and unchanged client."""
        caps = ["--cap-add=NET_ADMIN", "--cap-add=SETUID", "--cap-add=SETGID"]
        server = self.launch(
            f"{generation}-server",
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
            "MUTATIONS": "pki,events,management",
        }
        options = ["--user=0:65532", "--group-add=65531", *caps]
        options.extend(
            f"--env=OVPNCP_AGENT_{key}={value}" for key, value in paths.items()
        )
        options.extend(
            [
                "--env=OVPNCP_MANAGEMENT_SOCKET=/run/openvpn/management.sock",
                "--env=OVPNCP_MANAGEMENT_UID=0",
                "--env=OVPNCP_MANAGEMENT_GID=65532",
                "--env=OVPNCP_OPENVPN_UID=65530",
                "--env=OVPNCP_API_UID=65531",
            ]
        )
        for local, remote, readonly in (
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
            options.extend(self.mount(local, remote, readonly=readonly))
        agent = self.launch(
            f"{generation}-agent",
            self.images["agent"],
            options,
            [],
            network=f"container:{anchors['server']}",
            healthcheck=True,
        )
        self.probe = self.launch(
            f"{generation}-probe",
            self.images["api"],
            [
                "--user=65531:65531",
                "--entrypoint=/bin/sleep",
                *self.mount("agent-socket", "/run/ovpn-agent", readonly=True),
            ],
            ["1800"],
        )
        self.wait_ready()
        client = self.launch(
            f"{generation}-client",
            self.images["openvpn"],
            [
                "--user=0:0",
                "--cap-add=NET_ADMIN",
                "--device=/dev/net/tun:/dev/net/tun:rwm",
                "--entrypoint=/usr/local/sbin/openvpn",
                *self._bind(self.root / "client", "/fixture", readonly=True),
            ],
            ["--config", "/fixture/client.conf"],
            network=f"container:{anchors['a']}",
        )
        return server, agent, client

    def _wait_client(self) -> None:
        end = time.monotonic() + 180
        while time.monotonic() < end:
            if self.ping("a", self.client_meta["gateway"]):
                addresses = json.loads(
                    self.network(
                        "a", ["ip", "-j", "-4", "address", "show", "dev", "tun-client"]
                    )
                )
                observed = {
                    item["local"] for link in addresses for item in link["addr_info"]
                }
                if self.client_meta["ccd"] not in observed:
                    raise RuntimeError("Imported CCD assignment differs on tunnel.")
                result = self.query(
                    "print(json.dumps({'active': any(item.client == "
                    f"{self.client_meta['name']!r} for item in "
                    "query(s.ListSessions()).items)}))"
                )
                if result.get("active") is True:
                    return
            time.sleep(0.5)
        raise RuntimeError("Unchanged client did not reconnect within VPN objective.")

    def _revoke_test_client(self, name: str) -> None:
        self.query(
            f"mutate(s.ChangeClient(client={name!r}, action='issue'))\n"
            "print(json.dumps({'issued': True}))"
        )
        before = (self.state / "vpn-pki/crl.pem").read_bytes()
        self.query(
            f"mutate(s.ChangeClient(client={name!r}, action='revoke'))\n"
            f"assert query(s.GetClient(client={name!r})).item.state == 'revoked'\n"
            "print(json.dumps({'revoked': True}))"
        )
        after = (self.state / "vpn-pki/crl.pem").read_bytes()
        if (
            after == before
            or after != (self.state / "vpn-projection/crl.pem").read_bytes()
        ):
            raise RuntimeError("Revocation was not durably projected.")

    def _stop_services(self, names: tuple[str, str, str]) -> None:
        server, agent, client = names
        self.docker("stop", "--time=10", client, agent, server, self.probe)
        for relative in (
            "agent-socket/agent.sock",
            "management-socket/management.sock",
            "event-socket/events.sock",
        ):
            path = self.state / relative
            if path.exists() or path.is_symlink():
                if not stat.S_ISSOCK(path.lstat().st_mode):
                    raise RuntimeError("Unexpected runtime socket node.")
                path.unlink()

    def execute(self) -> dict[str, object]:
        """Rehearse import, unchanged client, revoke, restore and exact rollback."""
        self._stage("image-cache")
        self.check_image_cache()
        self._stage("private-policy")
        self._helper("policy")
        self.serial_policy = json.loads((self.root / "policy.json").read_text())[
            "serial_policy"
        ]
        self._helper("client")
        self.client_meta = json.loads((self.root / "client-meta.json").read_text())
        vpn_network = ipaddress.IPv4Network(self.client_meta["network"])
        if any(
            vpn_network.overlaps(ipaddress.IPv4Network(f"172.31.{octet}.0/30"))
            for octet in (250, 251, 252)
        ):
            raise RuntimeError("Imported VPN subnet overlaps disposable underlay.")
        self._stage("bundle-validation")
        self._migration("validate")
        self._migration("import")
        self._stage("target-import")
        self._migration("import", apply=True)
        report = self._migration("verify")
        if report.get("matches") is not True:
            raise RuntimeError("Imported OpenVPN state did not reconcile.")
        self._stage("isolated-topology")
        anchors = self.topology()
        self._stage("unchanged-client")
        first = self._services(anchors, "initial")
        self._wait_client()
        first_start = time.monotonic()
        self.docker("stop", "--time=10", first[2], first[0])
        self.docker("start", first[0], first[2])
        self._wait_client()
        restart_seconds = round(time.monotonic() - first_start, 3)
        if restart_seconds > 300:
            raise RuntimeError("VPN restart/reconnect exceeded recovery objective.")
        self._stage("target-issuance-revocation")
        first_revoked = f"p7test{self.token}"
        self._revoke_test_client(first_revoked)
        self._stage("checkpoint-freeze")
        self._stop_services(first)
        self._stage("encrypted-checkpoint")
        self._checkpoint()
        self._helper("restore-policy")
        self._helper("seed-prior", mutate=True)
        self._stage("checkpoint-restore")
        self._migration("validate", checkpoint=True, restore=True)
        self._migration("import", checkpoint=True, restore=True)
        self._migration("import", checkpoint=True, restore=True, apply=True)
        restored = self._migration("verify", checkpoint=True, restore=True)
        if restored.get("matches") is not True:
            raise RuntimeError("Restored checkpoint did not reconcile.")
        self.state = self.root / "restore/active"
        self._stage("restored-client-and-revocation")
        restore_start = time.monotonic()
        second = self._services(anchors, "restored")
        self._wait_client()
        restore_seconds = round(time.monotonic() - restore_start, 3)
        if restore_seconds > 300:
            raise RuntimeError("Restored VPN reconnect exceeded recovery objective.")
        result = self.query(
            f"print(json.dumps({{'revoked': query(s.GetClient(client={first_revoked!r})).item.state == 'revoked'}}))"
        )
        if result.get("revoked") is not True:
            raise RuntimeError("Checkpoint restore lost acknowledged revocation.")
        self._stage("exact-rollback")
        self._stop_services(second)
        self._migration("rollback", restore=True, apply=True)
        self._helper("check-rollback", read_target=True)
        self._stage("rolled-back-revocation")
        third = self._services(anchors, "rollback")
        self._wait_client()
        result = self.query(
            f"print(json.dumps({{'revoked': query(s.GetClient(client={first_revoked!r})).item.state == 'revoked'}}))"
        )
        if result.get("revoked") is not True:
            raise RuntimeError("Rollback lost acknowledged revocation.")
        self._revoke_test_client(f"p7restore{self.token}")
        self._stop_services(third)
        self._stage("passed")
        return {
            "phase7_openvpn": "passed",
            "unchanged_client_credentials": "passed",
            "ccd_and_semantic_reconciliation": "passed",
            "new_client_revoke_and_checkpoint": "passed",
            "restored_revocation_and_new_revoke": "passed",
            "nonempty_exact_rollback": "passed",
            "vpn_restart_reconnect_seconds": restart_seconds,
            "vpn_restore_reconnect_seconds": restore_seconds,
            "vpn_reconnect_objective_seconds": 300,
            "full_vm_api_restore": "not_tested",
            "coordinated_api_agent_rpo": "not_tested",
            "evidence_root": str(self.root),
        }

    def close(self, *, remove_state: bool = False) -> None:
        """Remove every labeled container, including timed-out one-shot helpers."""
        del remove_state
        failure = False
        try:
            names = (
                self.docker(
                    "ps", "-aq", "--filter", f"label=ovpncp.rehearsal={self.token}"
                )
                .decode()
                .splitlines()
            )
            for identifier in names:
                try:
                    info = json.loads(self.docker("inspect", identifier))[0]
                    owned = info["Config"]["Labels"].get("ovpncp.rehearsal")
                    name = info["Name"].removeprefix("/")
                    if (
                        owned != self.token
                        or re.fullmatch(r"[a-f0-9]{64}", info["Id"]) is None
                        or not name.startswith(
                            (f"ovpncp-p6-{self.token}-", f"ovpncp-p7-{self.token}-")
                        )
                    ):
                        raise RuntimeError("Container cleanup ownership mismatch.")
                    self.docker("rm", "--force", info["Id"])
                except (RuntimeError, ValueError, KeyError, IndexError):
                    failure = True
        except RuntimeError:
            failure = True
        finally:
            for descriptor in self.namespaces.values():
                os.close(descriptor)
            self.namespaces.clear()
        if failure:
            raise RuntimeError("Disposable container cleanup incomplete.")


def main() -> int:
    """Run only by explicit root invocation and emit a redacted result."""
    parser = argparse.ArgumentParser(description=__doc__)
    for role in ("agent", "openvpn", "api"):
        parser.add_argument(f"--{role}-image", required=True)
    parser.add_argument("--input-dir", type=pathlib.Path, required=True)
    parser.add_argument("--private-parent", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Reviewed root execution is required.")
    os.umask(0o077)

    def interrupted(signum: int, frame: object) -> None:
        raise RuntimeError("Disposable migration rehearsal interrupted.")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    rehearsal = Rehearsal(
        args.agent_image,
        args.openvpn_image,
        args.api_image,
        args.input_dir,
        args.private_parent,
    )
    result: dict[str, object] = {}
    code = 0
    try:
        result = rehearsal.execute()
    except Exception as error:  # noqa: BLE001 - never disclose private output
        code = 1
        result = {
            "result": "failed",
            "error_type": type(error).__name__,
            "stage": rehearsal.stage,
            "last_command": getattr(rehearsal, "last_command", {}),
            "probe_failure": getattr(rehearsal, "probe_failure", {}),
            "frames": [
                (pathlib.Path(item.filename).name, item.lineno, item.name)
                for item in traceback.extract_tb(error.__traceback__)
            ],
            "evidence_root": str(rehearsal.root),
        }
    finally:
        try:
            rehearsal.close(remove_state=False)
            result["cleanup"] = "passed"
        except Exception:  # noqa: BLE001 - retain evidence on uncertain cleanup
            code = 1
            result["cleanup"] = "incomplete"
            result["run_id"] = rehearsal.token
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
