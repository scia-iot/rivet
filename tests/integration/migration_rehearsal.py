"""Explicit disposable migration rehearsal; never collected by ordinary pytest.

Offline mode runs only synthetic Easy-RSA PKI operations in private temp roots.
Network mode requires isolated mount, PID and network namespaces, private
tmpfs mounts, and a namespace-only marker; it never controls host services.
"""

import argparse
import datetime
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import BinaryIO

from cryptography import x509

from sciaiot.ovpncp.migration import bundle, filesystem, source, target
from sciaiot.ovpncp.migration.models import MigrationError, SourceSpec, TargetSpec


class Rehearsal:
    """Keep every generated credential, command log, and state in private roots."""

    def __init__(self, easyrsa: pathlib.Path, *, network: bool, version: str) -> None:
        self.easyrsa = easyrsa.absolute()
        filesystem.read_file(self.easyrsa)
        if not os.access(self.easyrsa, os.X_OK):
            raise MigrationError("reviewed Easy-RSA executable is unavailable")
        self.network = network
        self.version = version
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="ovpncp-migration-rehearsal-"))
        self.source = self.root / "source"
        self.source.mkdir(mode=0o700)
        self.log = self.root / "commands.log"
        filesystem.write_private(self.log, b"")
        self.processes: list[subprocess.Popen[bytes]] = []
        self.streams: list[BinaryIO] = []

    def run(self, argv: list[str], pki: pathlib.Path | None = None) -> bytes:
        """Run an explicit reviewed tool with bounded time and private output."""
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8"}
        if pki is not None:
            env.update(
                {
                    "EASYRSA": str(self.easyrsa.parent),
                    "EASYRSA_PKI": str(pki),
                    "EASYRSA_BATCH": "1",
                    "EASYRSA_ALGO": "ec",
                    "EASYRSA_CURVE": "prime256v1",
                    "EASYRSA_SSL_CONF": str(
                        pki / "openssl-easyrsa.cnf"
                        if (pki / "openssl-easyrsa.cnf").exists()
                        else self.source / "openssl-easyrsa.cnf"
                    ),
                }
            )
        if len(argv) > 2 and argv[2] == "build-ca":
            env["EASYRSA_REQ_CN"] = "rehearsal-ca"
        result = subprocess.run(
            argv,
            cwd=self.root,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=180,
            check=False,
        )
        with self.log.open("ab") as stream:
            stream.write(result.stdout)
        valid_help_exit = (
            result.returncode == 1
            and pathlib.Path(argv[0]).name == "openvpn"
            and argv[1:] == ["--help"]
            and re.match(rb"OpenVPN [0-9]+\.[0-9]+\.[0-9]+", result.stdout) is not None
            and b"--config " in result.stdout
            and b"--dev " in result.stdout
        )
        if result.returncode and not valid_help_exit:
            raise MigrationError(_tool_failure(argv, result.returncode, result.stdout))
        return result.stdout

    def easy(self, pki: pathlib.Path, *args: str) -> None:
        """Execute only fixed test PKI operations against an explicit temp PKI."""
        self.run([str(self.easyrsa), "--batch", *args], pki)

    def observe_capabilities(self) -> tuple[set[str], set[str]]:
        """Observe the actual target binary's option and cipher inventory."""
        executable = shutil.which("openvpn")
        if executable is None:
            raise MigrationError("OpenVPN is required on the disposable runner")
        help_text = self.run([executable, "--help"]).decode()
        cipher_text = self.run([executable, "--show-ciphers"]).decode()
        options = set(re.findall(r"--([a-z][a-z0-9-]*)", help_text))
        ciphers = set(
            re.findall(r"^([A-Z0-9][A-Za-z0-9_-]+)\s+\(", cipher_text, re.MULTILINE)
        )
        return options, ciphers

    def verify_ccd(self) -> None:
        """Require the authenticated client TUN to have its migrated CCD IP."""
        executable = shutil.which("ip")
        if executable is None:
            raise MigrationError("iproute2 is required to verify migrated CCD state")
        interfaces = json.loads(
            self.run([executable, "-json", "address", "show", "dev", "tun-client"])
        )
        addresses = {
            address.get("local")
            for interface in interfaces
            for address in interface.get("addr_info", [])
        }
        if "10.231.0.10" not in addresses:
            raise MigrationError(
                "observed client TUN address differs from migrated CCD"
            )

    def _connect(self, config: pathlib.Path, client: pathlib.Path) -> None:
        openvpn = shutil.which("openvpn")
        if openvpn is None:
            raise MigrationError("OpenVPN is required on the disposable runner")
        options, _ = self.observe_capabilities()
        extra = ["--disable-dco"] if "disable-dco" in options else []
        for name, path in (("server", config), ("client", client)):
            log = self.root / f"{name}.log"
            filesystem.write_private(log, b"")
            stream = log.open("ab")
            self.streams.append(stream)
            self.processes.append(
                subprocess.Popen(
                    [openvpn, "--config", str(path), *extra],
                    cwd=self.root,
                    stdout=stream,
                    stderr=subprocess.STDOUT,
                    env={
                        "PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"),
                        "LANG": "C.UTF-8",
                    },
                )
            )
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if any(process.poll() is not None for process in self.processes):
                raise MigrationError(
                    "disposable VPN process exited; inspect private logs"
                )
            if b"Initialization Sequence Completed" in filesystem.read_file(
                self.root / "client.log"
            ):
                self.verify_ccd()
                return
            time.sleep(0.2)
        raise MigrationError("existing-client connectivity deadline exceeded")

    def retain_failure_evidence(self, destination: pathlib.Path) -> None:
        """Copy only bounded private logs to an explicitly approved root-owned directory."""
        validate_evidence_directory(destination)
        for name in ("commands.log", "server.log", "client.log"):
            path = self.root / name
            if path.exists():
                filesystem.write_private(destination / name, filesystem.read_file(path))

    def stop(self) -> None:
        """Stop only processes created by this rehearsal, restoring stopped state."""
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
        self.processes.clear()
        for stream in self.streams:
            stream.close()
        self.streams.clear()

    def execute(self) -> dict[str, object]:
        """Prove offline PKI continuity and optional real UDP authentication."""
        openssl = shutil.which("openssl")
        if openssl is None:
            raise MigrationError("OpenSSL is required for disposable PKI operations")
        shutil.copyfile(
            self.easyrsa.parent / "openssl-easyrsa.cnf",
            self.source / "openssl-easyrsa.cnf",
        )
        (self.source / "openssl-easyrsa.cnf").chmod(0o600)
        pki = self.source / "pki"
        self.easy(pki, "init-pki")
        self.easy(pki, "build-ca", "nopass")
        self.easy(pki, "build-server-full", "server", "nopass")
        self.easy(pki, "build-client-full", "existing-client", "nopass")
        self.easy(pki, "build-client-full", "already-revoked", "nopass")
        self.easy(pki, "revoke", "already-revoked")
        self.easy(pki, "gen-crl")
        filesystem.write_private(
            pki / "vars",
            b'set_var EASYRSA_ALGO "ec"\nset_var EASYRSA_CURVE "prime256v1"\n',
        )
        self._server_configuration()
        easy_output = self.run([str(self.easyrsa), "--version"]).decode()
        easy_match = re.search(r"Version:\s*(\d+\.\d+\.\d+)", easy_output)
        openssl_match = re.search(
            r"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)", self.run([openssl, "version"]).decode()
        )
        if easy_match is None or openssl_match is None:
            raise MigrationError("unable to observe disposable crypto tool versions")
        versions = {
            "openvpn": self.version,
            "easyrsa": easy_match[1],
            "openssl": openssl_match[1],
        }
        spec = SourceSpec(
            openvpn_root=str(self.source),
            easyrsa_root=str(self.source),
            pki_subdirectory="pki",
            easyrsa_config={"openssl-easyrsa.cnf": "openssl-easyrsa.cnf"},
            server_config="server.conf",
            versions=versions,
            serial_policy="random",
        )
        before = target._hash_tree(self.source)
        snapshot = source.capture(spec, writers_frozen=True)
        key = os.urandom(32)
        encrypted = bundle.seal(snapshot, key)
        filesystem.write_private(self.root / "migration.bundle", encrypted)
        restored = bundle.open_bundle(encrypted, key)
        observed_options = {
            item.name
            for items in snapshot.manifest.configurations.values()
            for item in items
        }
        observed_ciphers = {"AES-256-GCM", "AES-128-GCM"}
        if self.network:
            observed_options, observed_ciphers = self.observe_capabilities()
        policy = TargetSpec(
            versions=versions,
            serial_policy="random",
            supported_options=sorted(observed_options),
            supported_ciphers=sorted(observed_ciphers),
        )
        destination = self.root / "target"
        target.install(restored, destination, policy)
        if destination.exists():
            raise MigrationError("dry-run unexpectedly mutated target")
        # Establish only a synthetic migration-owned prior generation. This
        # tests exact nonempty rollback without adopting any live installation.
        target._owned(destination, create=True)
        (destination / "active").mkdir(mode=0o700)
        filesystem.write_private(
            destination / "active/prior-state", b"synthetic pre-import target state\n"
        )
        previous_target = target._hash_tree(destination / "active")
        target.install(restored, destination, policy, apply=True, target_stopped=True)
        target.verify(restored, destination, policy)
        credential_hashes = {
            name: filesystem.digest(data)
            for name, data in restored.files.items()
            if "existing-client" in name
        }
        active = destination / "active"
        client = self.root / "existing-client.conf"
        filesystem.write_private(
            client,
            (
                "client\ndev tun-client\nproto udp\nremote 127.0.0.1 1194\nnobind\n"
                "remote-cert-tls server\nroute-noexec\nverb 3\n"
                f"ca {pki}/ca.crt\ncert {pki}/issued/existing-client.crt\n"
                f"key {pki}/private/existing-client.key\n"
            ).encode(),
        )
        if self.network:
            self._connect(active / restored.manifest.main_config, client)
            self.stop()
        initial_crl = x509.load_pem_x509_crl((active / "pki/crl.pem").read_bytes())
        old_revocations = {item.serial_number for item in initial_crl}
        self.easy(active / "pki", "build-client-full", "new-test-client", "nopass")
        new_cert = x509.load_pem_x509_certificate(
            (active / "pki/issued/new-test-client.crt").read_bytes()
        )
        self.easy(active / "pki", "revoke", "new-test-client")
        self.easy(active / "pki", "gen-crl")
        final_crl = x509.load_pem_x509_crl((active / "pki/crl.pem").read_bytes())
        if not old_revocations | {new_cert.serial_number} <= {
            item.serial_number for item in final_crl
        }:
            raise MigrationError("target lost pre-existing or new revocations")
        if any(
            filesystem.digest(filesystem.read_file(active / name)) != value
            for name, value in credential_hashes.items()
        ):
            raise MigrationError("existing client credentials changed")
        target.rollback(destination, apply=True, target_stopped=True)
        if (
            target._hash_tree(active) != previous_target
            or target._hash_tree(self.source) != before
        ):
            raise MigrationError("rollback or source immutability failed")
        result: dict[str, object] = {
            "schema": 1,
            "mode": "isolated-network" if self.network else "offline-pki",
            "export_validate_import_verify": True,
            "existing_credentials_unchanged": True,
            "pki_issue_revoke_crl": True,
            "prior_revocations_preserved": True,
            "source_unchanged": True,
            "rollback_hashes_and_stopped_state": True,
            "existing_client_connected": self.network,
            "migrated_ccd_address_observed": self.network,
            "nonempty_target_rollback_exact": True,
            "openvpn_metadata": "observed" if self.network else "declared-assumption",
            "completed_at": datetime.datetime.now(datetime.UTC).isoformat(),
        }
        filesystem.write_private(
            self.root / "result.json", json.dumps(result, sort_keys=True).encode()
        )
        return result

    def _server_configuration(self) -> None:
        (self.source / "ccd").mkdir(mode=0o700)
        filesystem.write_private(
            self.source / "ccd/existing-client",
            b"ifconfig-push 10.231.0.10 255.255.255.0\n",
        )
        filesystem.write_private(
            self.source / "server.conf",
            (
                b"dev tun-server\nproto udp\nlocal 127.0.0.1\nport 1194\n"
                b"server 10.231.0.0 255.255.255.0\ntopology subnet\n"
                b"ca pki/ca.crt\ncert pki/issued/server.crt\nkey pki/private/server.key\n"
                b"crl-verify pki/crl.pem\ndh none\nverb 3\nclient-config-dir ccd\n"
            ),
        )


def _tool_failure(argv: list[str], returncode: int, output: bytes) -> str:
    # Only fixed allowlisted labels reach public diagnostics, never argv,
    # exception text, paths, client names or raw subprocess output.
    executable = pathlib.Path(argv[0]).name
    tool = (
        executable
        if executable in {"easyrsa", "openssl", "openvpn", "ip"}
        else "reviewed-tool"
    )
    allowed = {
        "init-pki",
        "build-ca",
        "build-server-full",
        "build-client-full",
        "revoke",
        "gen-crl",
        "--version",
        "version",
        "--help",
        "--show-ciphers",
        "address",
    }
    stage = next((arg for arg in argv[1:] if arg in allowed), "operation")
    lowered = output.lower()
    reason = "tool_rejected_operation"
    classifications = (
        (b"option conflict", "configuration_conflict"),
        (b"permission denied", "permission_denied"),
        (b"no space left", "storage_limit"),
        (b"cannot allocate memory", "memory_limit"),
        (b"not found", "missing_prerequisite"),
    )
    for needle, label in classifications:
        if needle in lowered:
            reason = label
            break
    return f"disposable tool failed: tool={tool} stage={stage} exit={returncode} reason={reason}; inspect private evidence"


def validate_evidence_directory(path: pathlib.Path) -> None:
    """Require an existing empty root-owned private directory outside ephemeral roots."""
    if not path.is_absolute() or any(
        path == root or path.is_relative_to(root)
        for root in (
            pathlib.Path("/tmp"),
            pathlib.Path("/run"),
            pathlib.Path("/etc/openvpn"),
        )
    ):
        raise MigrationError(
            "failure evidence requires an approved persistent private directory"
        )
    with filesystem.directory(path) as descriptor:
        info = os.fstat(descriptor)
        if info.st_uid != 0 or info.st_mode & 0o7777 != 0o700 or os.listdir(descriptor):
            raise MigrationError(
                "failure evidence directory must be empty, root-owned and mode 0700"
            )


def _namespace_identity(kind: str, process: str) -> int:
    return os.stat(f"/proc/{process}/ns/{kind}").st_ino


def _mountinfo() -> str:
    with pathlib.Path("/proc/self/mountinfo").open() as stream:
        data = stream.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise MigrationError("mount inventory exceeds rehearsal limit")
    return data


def _private_mounts() -> bool:
    mounts = {}
    for line in _mountinfo().splitlines():
        fields = line.split()
        separator = fields.index("-")
        if any(
            field.startswith(("shared:", "master:", "propagate_from:"))
            for field in fields[6:separator]
        ):
            return False
        mounts[fields[4]] = fields[separator + 1]
    return all(
        mounts.get(path) == "tmpfs"
        and os.stat(path).st_dev != os.stat(f"/proc/1/root{path}").st_dev
        for path in ("/run", "/tmp")
    )


def require_isolation() -> None:
    """Refuse the live host before observing binaries or changing loopback."""
    if os.geteuid() != 0 or any(
        _namespace_identity(kind, "self") == _namespace_identity(kind, "1")
        for kind in ("net", "mnt", "pid")
    ):
        raise MigrationError("separate mount, PID and network namespaces required")
    if not _private_mounts():
        raise MigrationError(
            "private propagation and distinct /run and /tmp tmpfs mounts required"
        )
    marker = pathlib.Path("/run/ovpncp-disposable-runner")
    info = marker.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o077
        or filesystem.read_file(marker) != b"DISPOSABLE OPENVPN MIGRATION NAMESPACE\n"
    ):
        raise MigrationError("private namespace attestation is missing")
    if not pathlib.Path("/dev/net/tun").exists():
        raise MigrationError("TUN device is required inside the disposable namespace")


def main(argv: list[str] | None = None) -> int:
    """Require explicit offline or externally isolated network rehearsal mode."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--easyrsa", type=pathlib.Path, required=True)
    parser.add_argument(
        "--mode", choices=("offline", "isolated-network"), required=True
    )
    parser.add_argument("--declared-openvpn-version", default="2.6.12")
    parser.add_argument("--failure-evidence-dir", type=pathlib.Path)
    args = parser.parse_args(argv)
    rehearsal = None
    failed = True
    try:
        if args.failure_evidence_dir is not None:
            validate_evidence_directory(args.failure_evidence_dir)
        network = args.mode == "isolated-network"
        version = args.declared_openvpn_version
        if network:
            require_isolation()
            openvpn = shutil.which("openvpn")
            ip = shutil.which("ip")
            if openvpn is None or ip is None:
                raise MigrationError(
                    "disposable OpenVPN and iproute2 prerequisites missing"
                )
            result = subprocess.run(
                [openvpn, "--version"], capture_output=True, check=True, timeout=10
            )
            match = re.search(rb"OpenVPN (\d+\.\d+\.\d+)", result.stdout)
            if match is None:
                raise MigrationError("could not observe OpenVPN version")
            version = match[1].decode()
            subprocess.run(
                [ip, "link", "set", "lo", "up"],
                check=True,
                capture_output=True,
                timeout=10,
            )
        rehearsal = Rehearsal(args.easyrsa, network=network, version=version)
        print(json.dumps(rehearsal.execute(), sort_keys=True))
        failed = False
        return 0
    except MigrationError as exc:
        print(
            json.dumps({"error": "rehearsal_failed", "detail": str(exc)}),
            file=sys.stderr,
        )
        return 2
    except (OSError, ValueError, subprocess.SubprocessError):
        print(
            '{"error":"rehearsal_failed","detail":"Review prerequisites and private disposable logs."}',
            file=sys.stderr,
        )
        return 2
    finally:
        if rehearsal is not None:
            rehearsal.stop()
            if failed and args.failure_evidence_dir is not None:
                try:
                    rehearsal.retain_failure_evidence(args.failure_evidence_dir)
                except (MigrationError, OSError):
                    print('{"error":"failure_evidence_unavailable"}', file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
