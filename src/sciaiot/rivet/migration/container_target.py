"""Map an authenticated M0 bundle into stopped Phase 6 Compose VPN mounts."""

import ipaddress
import os
import pathlib
import re
import shutil
import stat
import uuid
from dataclasses import dataclass

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from sciaiot.rivet.migration import filesystem, target, validation
from sciaiot.rivet.migration.models import (
    ContainerTargetSpec,
    MigrationError,
    Snapshot,
    validate_versions,
)

PROJECTION = "/var/lib/ovpn-agent/projection"
POOL = "/var/lib/openvpn/ipp.txt"
HOOK = "/usr/local/bin/rivet-vpn-event"
HOOK_SHA256 = "2f67311779242fd6a641bb75cdc9fe6c1c0f2cbecdc916f86ea83d7f0c73019d"
HOOK_COMMAND = (
    f"{HOOK} --socket /run/ovpn-events/events.sock "
    "--management-socket /run/openvpn/management.sock --agent-uid 65532"
)
# Accept the previous hook only when capturing a stopped source deployment.
LEGACY_HOOK = "/usr/local/bin/ovpncp-vpn-event"
LEGACY_HOOK_SHA256 = "bd29220d58469db027654ff9a5468f61f5c81d877511da1e28f04dc0fe31edb3"
LEGACY_HOOK_COMMAND = (
    f"{LEGACY_HOOK} --socket /run/ovpn-events/events.sock "
    "--management-socket /run/openvpn/management.sock --agent-uid 65532"
)
ALLOWED_OPTIONS = frozenset(
    {
        "ca",
        "cert",
        "key",
        "crl-verify",
        "dh",
        "dev",
        "dev-type",
        "proto",
        "port",
        "server",
        "topology",
        "data-ciphers",
        "data-ciphers-fallback",
        "client-config-dir",
        "ccd-exclusive",
        "ifconfig-pool-persist",
        "client-connect",
        "client-disconnect",
        "script-security",
        "keepalive",
        "persist-key",
        "persist-tun",
        "verb",
        "explicit-exit-notify",
        "disable-dco",
    }
)
VPN_DIRECTORIES = frozenset(
    {
        "vpn-config",
        "vpn-pki",
        "vpn-ccd",
        "vpn-journal",
        "vpn-projection",
        "vpn-projection/ccd",
        "vpn-pool",
        "management-socket",
        "agent-socket",
        "event-socket",
    }
)


@dataclass(frozen=True)
class _File:
    data: bytes
    mode: int = 0o600


def source_hook(command: str) -> tuple[str, str]:
    """Resolve an exact reviewed source hook command to its path and checksum.

    Legacy hooks may be captured for migration; targets always use Rivet.

    Raises:
        MigrationError: The source command is not a reviewed runtime hook.
    """
    if command == HOOK_COMMAND:
        return HOOK, HOOK_SHA256
    if command == LEGACY_HOOK_COMMAND:
        return LEGACY_HOOK, LEGACY_HOOK_SHA256
    raise MigrationError("unsupported container checkpoint hook")


def _identities() -> tuple[int, int, int, int]:
    return 65532, 65530, 65532, 65531


def _compatible(state: Snapshot, policy: ContainerTargetSpec) -> None:
    validation.validate(state)
    for name, data in state.files.items():
        if not name.startswith("pki/issued/") or not name.endswith(".crt"):
            continue
        stem = pathlib.PurePosixPath(name).stem
        if re.fullmatch(r"[A-Za-z0-9_-]{1,255}", stem) is None:
            raise MigrationError("issued certificate name incompatible with agent")
        certificate = x509.load_pem_x509_certificate(data)
        try:
            usage = certificate.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage
            ).value
        except x509.ExtensionNotFound:
            raise MigrationError(
                "issued certificate lacks agent-required EKU"
            ) from None
        if ExtendedKeyUsageOID.CLIENT_AUTH in usage:
            names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if len(names) != 1 or names[0].value != stem:
                raise MigrationError("issued client identity incompatible with agent")
    validate_versions(policy.versions)
    source_versions = state.manifest.versions
    target_versions = policy.versions
    expected_target = {
        "openvpn": "2.6.19",
        "easyrsa": "3.1.7",
        "openssl": "3.5.7",
    }
    if target_versions != expected_target:
        raise MigrationError("pinned container image version mismatch")
    if policy.serial_policy != state.manifest.serial_policy:
        raise MigrationError("serial policy differs from authenticated bundle")
    if target_versions != source_versions:
        expected_source = {
            "openvpn": "2.6.19",
            "easyrsa": "3.1.7",
            "openssl": "3.0.13",
        }
        if (
            source_versions != expected_source
            or policy.openssl_transition != "3.0.13-to-3.5.7"
        ):
            raise MigrationError("unsupported version transition")
    elif policy.openssl_transition is not None:
        raise MigrationError("unnecessary version transition policy")
    if policy.owner or policy.group:
        raise MigrationError("container ownership is fixed by the image contract")
    if re.fullmatch(r"tun[0-9]{1,3}", policy.target_device) is None:
        raise MigrationError("reviewed numbered TUN device required")
    directives = [
        item for entries in state.manifest.configurations.values() for item in entries
    ]
    if {item.name for item in directives} - set(policy.supported_options):
        raise MigrationError("target option availability was not observed")
    for item in directives:
        if item.name in {
            "cipher",
            "data-ciphers",
            "data-ciphers-fallback",
            "tls-cipher",
            "tls-ciphersuites",
        } and (
            len(item.args) != 1
            or any(
                value.removeprefix("?") not in policy.supported_ciphers
                for value in item.args[0].split(":")
            )
        ):
            raise MigrationError("target cipher availability was not observed")


def _layout(
    state: Snapshot, policy: ContainerTargetSpec
) -> tuple[dict[str, _File], set[str]]:
    _compatible(state, policy)
    manifest = state.manifest
    if set(manifest.configurations) != {manifest.main_config}:
        raise MigrationError("container profile requires reviewed include conversion")
    files: dict[str, _File] = {}
    directories = set(VPN_DIRECTORIES)
    for name, data in state.files.items():
        if name.startswith("pki/"):
            files[f"vpn-pki/{name[4:]}"] = _File(data)
        elif name.startswith("ccd/"):
            files[f"vpn-ccd/{name[4:]}"] = _File(data)
            files[f"vpn-projection/ccd/{name[4:]}"] = _File(data, 0o640)
        elif name.startswith(("config/", "pool/", "assets/")):
            continue
        else:
            raise MigrationError("unmapped OpenVPN bundle artifact")
    for name in manifest.directories:
        if name.startswith("pki/"):
            directories.add(f"vpn-pki/{name[4:]}")
        elif name.startswith("ccd/"):
            directories.add(f"vpn-ccd/{name[4:]}")
    for name in files:
        for parent in pathlib.PurePosixPath(name).parents:
            if str(parent) != ".":
                directories.add(str(parent))

    projected = {
        "ca": "ca.crt",
        "cert": "server.crt",
        "key": "server.key",
        "crl-verify": "crl.pem",
        "dh": "dh.pem",
    }
    seen: set[str] = set()
    seen_options: set[str] = set()
    pool_seen = False
    used_assets: set[str] = set()
    used_pool: set[str] = set()
    lines: list[str] = []
    for item in manifest.configurations[manifest.main_config]:
        option = item.name
        args = list(item.args)
        if option == "config":
            raise MigrationError(
                "container profile requires reviewed include conversion"
            )
        if option not in ALLOWED_OPTIONS:
            raise MigrationError("unreviewed container server directive")
        if option in seen_options:
            raise MigrationError("duplicate container server directive")
        seen_options.add(option)
        if option == "server":
            if len(args) != 2:
                raise MigrationError("container server requires IPv4 subnet and mask")
            try:
                ipaddress.IPv4Network(f"{args[0]}/{args[1]}", strict=True)
            except ValueError:
                raise MigrationError(
                    "container server requires valid IPv4 subnet"
                ) from None
        if option == "port" and (
            len(args) != 1 or not args[0].isdecimal() or not 1 <= int(args[0]) <= 65535
        ):
            raise MigrationError("container server requires valid UDP port")
        if (
            option in {"persist-key", "persist-tun", "ccd-exclusive", "disable-dco"}
            and args
        ):
            raise MigrationError("invalid container server flag arguments")
        if option in {"local", "secret", "tls-auth", "tls-crypt", "tls-crypt-v2"}:
            raise MigrationError(
                "container profile rejects unreviewed network or TLS option"
            )
        if option == "dev":
            if args != ["tun"] and args != [policy.target_device]:
                raise MigrationError("container profile requires reviewed TUN device")
            args = [policy.target_device]
        if option == "dev-type" and args != ["tun"]:
            raise MigrationError("container profile requires TUN device type")
        if option == "script-security" and args != ["2"]:
            raise MigrationError("container profile requires script security two")
        if option == "proto" and args != ["udp"]:
            raise MigrationError("container profile requires reviewed UDP transport")
        if option == "topology" and args != ["subnet"]:
            raise MigrationError("container profile requires subnet topology")
        if option in projected:
            if option in seen:
                raise MigrationError("duplicate projected server asset")
            seen.add(option)
            if option == "dh" and args == ["none"]:
                pass
            else:
                reference = item.references.get("0")
                if reference is None or reference not in state.files:
                    raise MigrationError("missing projected server asset")
                target_name = projected[option]
                files[f"vpn-projection/{target_name}"] = _File(
                    state.files[reference], 0o640
                )
                if reference.startswith("assets/"):
                    used_assets.add(reference)
                args[0] = f"{PROJECTION}/{target_name}"
        elif option == "client-config-dir":
            args[0] = f"{PROJECTION}/ccd"
        elif option == "ifconfig-pool-persist":
            if pool_seen:
                raise MigrationError("duplicate pool persistence directive")
            pool_seen = True
            reference = item.references.get("0")
            if reference is None or reference not in state.files:
                raise MigrationError("missing pool persistence state")
            files["vpn-pool/ipp.txt"] = _File(state.files[reference], 0o660)
            used_pool.add(reference)
            args[0] = POOL
        elif option in {"client-connect", "client-disconnect"}:
            reference = item.references.get("0", "")
            replacement = policy.replacements.get(reference.removeprefix("hook/"))
            if (
                replacement is None
                or replacement.path != HOOK
                or replacement.sha256 != HOOK_SHA256
            ):
                raise MigrationError("reviewed container hook replacement required")
            args[0] = HOOK_COMMAND
        elif item.references:
            raise MigrationError("unmapped container file reference")
        lines.append(" ".join(target._quote(value) for value in [option, *args]))
    if used_assets != {
        name for name in state.files if name.startswith("assets/")
    } or used_pool != {name for name in state.files if name.startswith("pool/")}:
        raise MigrationError("container map leaves a source asset unmapped")
    if not {"ca", "cert", "key", "crl-verify"} <= seen:
        raise MigrationError("complete projected server identity and CRL required")
    if (
        not {"dev", "proto", "port", "server", "topology", "client-config-dir"}
        <= seen_options
    ):
        raise MigrationError("container server requires complete tunnel configuration")
    if not pool_seen:
        files["vpn-pool/ipp.txt"] = _File(b"", 0o660)
        lines.append(f'"ifconfig-pool-persist" "{POOL}"')
    if not any(
        item.name == "dev-type"
        for item in manifest.configurations[manifest.main_config]
    ):
        lines.append('"dev-type" "tun"')
    if not any(
        item.name == "script-security"
        for item in manifest.configurations[manifest.main_config]
    ):
        lines.append('"script-security" "2"')
    if not any(
        item.name == "disable-dco"
        for item in manifest.configurations[manifest.main_config]
    ):
        lines.append('"disable-dco"')
    lines.extend(
        [
            '"user" "ovpn-openvpn"',
            '"group" "ovpn-runtime"',
            '"management" "/run/openvpn/management.sock" "unix"',
            '"management-client-user" "ovpn-agent"',
            '"management-client-group" "ovpn-runtime"',
            '"status" "/run/openvpn/status.log" "10"',
            '"status-version" "3"',
            '"writepid" "/run/openvpn/openvpn.pid"',
            '"log" "/dev/null"',
        ]
    )
    rendered = ("\n".join(lines) + "\n").encode()
    files["vpn-config/server.conf"] = _File(rendered)
    files["vpn-config/ownership.json"] = _File(
        b'{"version":"1.0","routes":[],"access":[],"pushes":[]}'
    )
    files["vpn-projection/server.conf"] = _File(rendered, 0o640)
    files["management-socket/status.log"] = _File(b"", 0o660)
    return files, directories


def validate_policy(state: Snapshot, policy: ContainerTargetSpec) -> dict[str, object]:
    """Validate reviewed image capability policy and Compose file mapping."""
    files, _ = _layout(state, policy)
    return {
        "valid": True,
        "compatible": True,
        "capabilities_verified": True,
        "file_count": len(files),
    }


def _ownership(name: str) -> tuple[int, int]:
    agent, vpn, runtime, control = _identities()
    if name == "vpn-pool" or name.startswith("vpn-pool/"):
        return vpn, runtime
    if name == "management-socket" or name.startswith("management-socket/"):
        return vpn, runtime
    if name == "agent-socket" or name.startswith("agent-socket/"):
        return agent, control
    return agent, runtime


def _mode(name: str, *, directory: bool) -> int:
    if not directory:
        return (
            0o660
            if name in {"vpn-pool/ipp.txt", "management-socket/status.log"}
            else (0o640 if name.startswith("vpn-projection/") else 0o600)
        )
    if name in {"vpn-pool", "management-socket", "event-socket"}:
        return 0o2770
    if name == "agent-socket":
        return 0o2750
    if name.startswith("vpn-projection"):
        return 0o750
    return 0o700


def _write_layout(
    path: pathlib.Path, files: dict[str, _File], directories: set[str]
) -> None:
    for name in sorted(directories, key=lambda value: (value.count("/"), value)):
        item = path / name
        item.mkdir(mode=0o700)
        owner, group = _ownership(name)
        os.chown(item, owner, group, follow_symlinks=False)
        os.chmod(item, _mode(name, directory=True), follow_symlinks=False)
    for name, entry in files.items():
        item = path / name
        filesystem.write_private(item, entry.data)
        owner, group = _ownership(name)
        os.chown(item, owner, group, follow_symlinks=False)
        os.chmod(item, entry.mode, follow_symlinks=False)
    for name in sorted(directories, key=lambda value: -value.count("/")):
        target._sync(path / name)
    target._sync(path)


def _check_layout(
    path: pathlib.Path, files: dict[str, _File], directories: set[str]
) -> None:
    names, folders = filesystem.tree(path, len(files) + len(directories) + 1)
    if set(names) != set(files) or set(folders) != directories:
        raise MigrationError("container target tree differs from bundle mapping")
    root = path.stat(follow_symlinks=False)
    if root.st_uid != os.geteuid() or stat.S_IMODE(root.st_mode) != 0o700:
        raise MigrationError("container generation root ownership mismatch")
    for name in [*names, *folders]:
        item = path / name
        info = item.stat(follow_symlinks=False)
        owner, group = _ownership(name)
        expected_mode = _mode(name, directory=name in directories)
        if (
            info.st_uid != owner
            or info.st_gid != group
            or stat.S_IMODE(info.st_mode) != expected_mode
        ):
            raise MigrationError("container target ownership or mode mismatch")
        if name in files and filesystem.read_file(item) != files[name].data:
            raise MigrationError("container target file checksum mismatch")


def _check_previous(path: pathlib.Path) -> None:
    if not path.exists():
        return
    names, folders = filesystem.tree(path, 20000)
    if {name.split("/", 1)[0] for name in [*names, *folders]} - {
        item.split("/", 1)[0] for item in VPN_DIRECTORIES
    }:
        raise MigrationError("existing target contains non-VPN state")


def install(
    state: Snapshot,
    destination: pathlib.Path,
    policy: ContainerTargetSpec,
    *,
    apply: bool = False,
    target_stopped: bool = False,
) -> dict[str, object]:
    """Stage a private Compose generation and retain exact prior state."""
    destination = pathlib.Path(os.path.abspath(destination))
    files, directories = _layout(state, policy)
    target._owned(destination, profile="container")
    if not apply:
        return {"dry_run": True, "compatible": True, "file_count": len(files)}
    if not target_stopped:
        raise MigrationError("target must be stopped with all writers frozen")
    target._owned(destination, create=True, profile="container")
    with target._lock(destination):
        if (destination / target.JOURNAL).exists():
            raise MigrationError("rollback snapshot retained; roll back first")
        active = destination / "active"
        backup = destination / "rollback"
        if backup.exists():
            raise MigrationError("unrecorded rollback snapshot")
        _check_previous(active)
        stage = destination / f".stage-{uuid.uuid4().hex}"
        stage.mkdir(mode=0o700)
        journal_written = False
        try:
            _write_layout(stage, files, directories)
            _check_layout(stage, files, directories)
            validation.validate(state)
            previous = target._hash_tree(active)
            target._replace_json(
                destination / target.JOURNAL,
                {
                    "schema": 1,
                    "service_state": "stopped",
                    "previous": previous,
                    "stage": stage.name,
                },
            )
            journal_written = True
            if active.exists():
                os.replace(active, backup)
                target._sync(destination)
            os.replace(stage, active)
            target._sync(destination)
            _check_layout(active, files, directories)
        except BaseException:
            if journal_written:
                target._restore(destination)
            raise
        finally:
            if stage.exists():
                shutil.rmtree(stage)
    return {
        "dry_run": False,
        "activated": True,
        "rollback_retained": True,
        "service_state": "stopped",
    }


def verify(
    state: Snapshot, destination: pathlib.Path, policy: ContainerTargetSpec
) -> dict[str, object]:
    """Compare the complete mapped tree and protected semantic inventory."""
    destination = pathlib.Path(os.path.abspath(destination))
    files, directories = _layout(state, policy)
    target._owned(destination, profile="container")
    _check_layout(destination / "active", files, directories)
    statuses = state.manifest.semantics["serial_status"]
    ccd = state.manifest.semantics["ccd"]
    options = state.manifest.semantics["options"]
    if (
        not isinstance(statuses, dict)
        or not isinstance(ccd, dict)
        or not isinstance(options, dict)
    ):
        raise MigrationError("invalid protected semantic inventory")
    return {
        "matches": True,
        "ca_identity": True,
        "server_identity": True,
        "client_serial_status": True,
        "ccd": True,
        "server_options": True,
        "reconciliation": {
            "pki_files": sum(name.startswith("pki/") for name in state.files),
            "revoked_serials": sum(status == "R" for status in statuses.values()),
            "ccd_entries": len(ccd),
            "source_configurations": len(options),
            "target_files": len(files),
            "unexplained_drift": 0,
        },
    }


def rollback(
    destination: pathlib.Path,
    *,
    apply: bool = False,
    target_stopped: bool = False,
) -> dict[str, object]:
    """Restore the prior generation's exact files, owners, modes and absence."""
    return target.rollback(
        destination,
        apply=apply,
        target_stopped=target_stopped,
        profile="container",
    )


_hash_tree = target._hash_tree
