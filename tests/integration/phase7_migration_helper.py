"""Private Python 3.14 helper for the disposable Phase 7 Docker rehearsal.

The parent runner mounts only authenticated inputs and run-owned output roots.
No private identity, address, key, certificate, or file contents are printed.
"""

import argparse
import datetime
import hashlib
import ipaddress
import json
import os
import pathlib
import re

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from sciaiot.ovpncp.migration import (
    bundle,
    container_target,
    filesystem,
    source,
    target,
)
from sciaiot.ovpncp.migration.models import (
    ContainerTargetSpec,
    MigrationError,
    Replacement,
    parse_model,
)


def _state(input_dir: pathlib.Path):
    key = filesystem.read_file(input_dir / "migration.key", 32)
    if len(key) != 32:
        raise MigrationError("invalid private migration key")
    return bundle.open_bundle(
        filesystem.read_file(input_dir / "migration.bundle", 144 * 1024 * 1024),
        key,
    )


def _private_json(path: pathlib.Path, value: object) -> None:
    filesystem.write_private(path, json.dumps(value, sort_keys=True).encode())


def _image_digest(value: object, role: str) -> str:
    """Validate a reviewed role-specific OCI reference and return its digest."""
    registry = r"[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]+)?"
    namespace = r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
    pattern = rf"{registry}{namespace}/ovpncp-{role}@sha256:[a-f0-9]{{64}}"
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise MigrationError("pinned image capability evidence mismatch")
    return value.rsplit("@", 1)[1]


def policy(input_dir: pathlib.Path, output: pathlib.Path) -> None:
    """Bind independently observed image capabilities to authenticated hooks."""
    state = _state(input_dir)
    capabilities = json.loads(
        filesystem.read_file(input_dir / "capabilities.json", 65536)
    )
    references = (
        capabilities.get("image_refs") if isinstance(capabilities, dict) else None
    )
    if not isinstance(references, dict) or set(references) != {
        "openvpn",
        "agent",
        "api",
    }:
        raise MigrationError("pinned image capability evidence mismatch")
    digests = {
        role: _image_digest(references[role], role)
        for role in ("openvpn", "agent", "api")
    }
    if (
        capabilities["versions"]
        != {"openvpn": "2.6.19", "easyrsa": "3.1.7", "openssl": "3.5.7"}
        or capabilities["hook_sha256"] != container_target.HOOK_SHA256
        or capabilities["explicit_fallback_option_probe"] is not True
        or capabilities.get("explicit_disable_dco_option_probe") is not True
        or capabilities["network"] != "none"
        or capabilities["capabilities"] != []
    ):
        raise MigrationError("pinned image capability evidence mismatch")
    options = capabilities["supported_options"]
    ciphers = capabilities["supported_ciphers"]
    if (
        not isinstance(options, list)
        or not isinstance(ciphers, list)
        or any(not isinstance(item, str) for item in [*options, *ciphers])
        or not {"dev-type", "script-security"} <= set(options)
    ):
        raise MigrationError("invalid observed capability lists")
    policy = ContainerTargetSpec(
        image_digest=digests["openvpn"],
        versions=capabilities["versions"],
        openssl_transition=(
            None
            if state.manifest.versions == capabilities["versions"]
            else "3.0.13-to-3.5.7"
        ),
        target_device="tun0",
        serial_policy=state.manifest.serial_policy,
        supported_options=sorted(
            set(options) | {"data-ciphers-fallback", "disable-dco"}
        ),
        supported_ciphers=sorted(set(ciphers)),
        replacements={
            name: Replacement(
                path=container_target.HOOK,
                sha256=container_target.HOOK_SHA256,
            )
            for name in state.manifest.hooks
        },
    )
    container_target.validate_policy(state, policy)
    _private_json(output, policy.model_dump(mode="json"))


def client(input_dir: pathlib.Path, output: pathlib.Path) -> None:
    """Select one indexed active CCD client and copy unchanged credential bytes."""
    state = _state(input_dir)
    statuses = state.manifest.semantics["serial_status"]
    if not isinstance(statuses, dict):
        raise MigrationError("invalid protected client status inventory")
    options = state.manifest.configurations[state.manifest.main_config]
    port = next(item.args[0] for item in options if item.name == "port")
    server = next(item.args for item in options if item.name == "server")
    network = ipaddress.IPv4Network(f"{server[0]}/{server[1]}", strict=True)
    gateway = str(next(network.hosts()))
    selected: tuple[str, bytes, bytes, str] | None = None
    for filename in sorted(state.files):
        if not filename.startswith("pki/issued/") or not filename.endswith(".crt"):
            continue
        name = pathlib.PurePosixPath(filename).stem
        if re.fullmatch(r"[A-Za-z0-9_-]{1,255}", name) is None:
            continue
        key = state.files.get(f"pki/private/{name}.key")
        ccd = state.files.get(f"ccd/{name}")
        if key is None or ccd is None:
            continue
        cert = x509.load_pem_x509_certificate(state.files[filename])
        common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if (
            len(common_names) != 1
            or common_names[0].value != name
            or statuses.get(str(cert.serial_number)) != "V"
            or not (
                cert.not_valid_before_utc
                <= datetime.datetime.now(datetime.UTC)
                <= cert.not_valid_after_utc
            )
        ):
            continue
        try:
            usage = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        except x509.ExtensionNotFound:
            continue
        if ExtendedKeyUsageOID.CLIENT_AUTH not in usage.value:
            continue
        assignment = [item for item in source.parse(ccd) if item[0] == "ifconfig-push"]
        if len(assignment) != 1 or len(assignment[0]) != 3:
            continue
        address = str(ipaddress.IPv4Address(assignment[0][1]))
        if ipaddress.IPv4Address(address) not in network:
            continue
        selected = name, state.files[filename], key, address
        break
    if selected is None:
        raise MigrationError("no indexed active client with unchanged CCD credentials")
    name, cert_bytes, key, address = selected
    output.mkdir(mode=0o700)
    for filename, data in (
        ("ca.crt", state.files["pki/ca.crt"]),
        ("client.crt", cert_bytes),
        ("client.key", key),
    ):
        filesystem.write_private(output / filename, data)
    configuration = (
        "client\nremote 172.31.250.1 " + port + "\nproto udp\n"
        "dev tun-client\nnobind\nca /fixture/ca.crt\n"
        "cert /fixture/client.crt\nkey /fixture/client.key\n"
        "remote-cert-tls server\n"
        "data-ciphers AES-256-GCM:AES-128-GCM\n"
        "data-ciphers-fallback AES-256-CBC\n"
        "connect-retry 1 1\nhand-window 5\ntls-timeout 1\n"
        "disable-dco\nlog /dev/null\nverb 0\n"
    )
    filesystem.write_private(output / "client.conf", configuration.encode())
    _private_json(
        output.parent / "client-meta.json",
        {
            "name": name,
            "gateway": gateway,
            "ccd": address,
            "network": str(network),
        },
    )


def restore_policy(
    input_dir: pathlib.Path,
    checkpoint: pathlib.Path,
    key_path: pathlib.Path,
    first_policy: pathlib.Path,
    output: pathlib.Path,
) -> None:
    """Bind checkpoint hooks to the first policy's reviewed image digest."""
    del input_dir
    state = bundle.open_bundle(
        filesystem.read_file(checkpoint, 144 * 1024 * 1024),
        filesystem.read_file(key_path, 32),
    )
    previous = parse_model(
        ContainerTargetSpec, filesystem.read_file(first_policy, 65536)
    )
    current = previous.model_copy(
        update={
            "versions": state.manifest.versions,
            "openssl_transition": None,
            "replacements": {
                name: Replacement(
                    path=container_target.HOOK,
                    sha256=container_target.HOOK_SHA256,
                )
                for name in state.manifest.hooks
            },
        }
    )
    container_target.validate_policy(state, current)
    _private_json(output, current.model_dump(mode="json"))


def seed_prior(
    checkpoint: pathlib.Path,
    key_path: pathlib.Path,
    wrapper: pathlib.Path,
    policy_path: pathlib.Path,
    digest_path: pathlib.Path,
) -> None:
    """Seed a revoked-state predecessor with a harmless distinct journal marker."""
    state = bundle.open_bundle(
        filesystem.read_file(checkpoint, 144 * 1024 * 1024),
        filesystem.read_file(key_path, 32),
    )
    active = wrapper / "active"
    parsed = parse_model(ContainerTargetSpec, filesystem.read_file(policy_path, 65536))
    files, directories = container_target._layout(state, parsed)
    target._owned(wrapper, create=True, profile="container")
    active.mkdir(mode=0o700)
    container_target._write_layout(active, files, directories)
    container_target._check_layout(active, files, directories)
    sentinel = active / "vpn-journal/phase7-prior-generation"
    filesystem.write_private(sentinel, b"disposable rollback predecessor\n")
    os.chown(sentinel, 65532, 65532, follow_symlinks=False)
    digest = hashlib.sha256(
        json.dumps(target._hash_tree(active), sort_keys=True).encode()
    ).hexdigest()
    filesystem.write_private(digest_path, digest.encode())


def check_rollback(wrapper: pathlib.Path, digest_path: pathlib.Path) -> None:
    """Compare exact prior bytes, modes and owners after M0 rollback."""
    expected = filesystem.read_file(digest_path, 64).decode()
    actual = hashlib.sha256(
        json.dumps(target._hash_tree(wrapper / "active"), sort_keys=True).encode()
    ).hexdigest()
    if actual != expected or (wrapper / target.JOURNAL).exists():
        raise MigrationError("restored predecessor differs from exact snapshot")


def main() -> None:
    """Dispatch only the fixed private preparation and comparison operations."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=("policy", "client", "restore-policy", "seed-prior", "check-rollback"),
    )
    parser.add_argument("--input-dir", type=pathlib.Path, required=True)
    parser.add_argument("--work", type=pathlib.Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "policy":
            policy(args.input_dir, args.work / "policy.json")
        elif args.command == "client":
            client(args.input_dir, args.work / "client")
        elif args.command == "restore-policy":
            restore_policy(
                args.input_dir,
                args.work / "checkpoint.bundle",
                args.work / "checkpoint.key",
                args.work / "policy.json",
                args.work / "restore-policy.json",
            )
        elif args.command == "seed-prior":
            seed_prior(
                args.work / "checkpoint.bundle",
                args.work / "checkpoint.key",
                args.work / "restore",
                args.work / "restore-policy.json",
                args.work / "prior-digest",
            )
        else:
            check_rollback(args.work / "restore", args.work / "prior-digest")
    except OSError, ValueError, KeyError, TypeError:
        raise SystemExit("Phase 7 helper failed; review private inputs.") from None
    print(json.dumps({"phase7_helper": args.command, "passed": True}))


if __name__ == "__main__":
    main()
