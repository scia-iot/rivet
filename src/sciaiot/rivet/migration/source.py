"""Capture only approved OpenVPN configuration and complete Easy-RSA state."""

import os
import pathlib
import shlex

from sciaiot.rivet.migration import filesystem, validation
from sciaiot.rivet.migration.models import (
    MAX_FILES,
    MAX_TOTAL_BYTES,
    Directive,
    Entry,
    Manifest,
    MigrationError,
    Snapshot,
    SourceSpec,
    logical_path,
    validate_versions,
)

FILE_OPTIONS = frozenset(
    {
        "ca",
        "cert",
        "key",
        "dh",
        "crl-verify",
        "tls-auth",
        "tls-crypt",
        "tls-crypt-v2",
        "extra-certs",
        "secret",
    }
)
HOOK_OPTIONS = frozenset(
    {
        "up",
        "down",
        "route-up",
        "route-pre-down",
        "client-connect",
        "client-disconnect",
        "learn-address",
        "auth-user-pass-verify",
        "tls-verify",
    }
)
RUNTIME_OPTIONS = frozenset(
    {
        "user",
        "group",
        "log",
        "log-append",
        "status",
        "writepid",
        "daemon",
        "management",
        "management-client-user",
        "management-client-group",
        "status-version",
    }
)
PLAIN_OPTIONS = frozenset(
    {
        "dev",
        "dev-type",
        "proto",
        "port",
        "local",
        "server",
        "server-ipv6",
        "topology",
        "mode",
        "tls-server",
        "tls-client",
        "client",
        "remote",
        "nobind",
        "persist-key",
        "persist-tun",
        "disable-dco",
        "keepalive",
        "ping",
        "ping-restart",
        "ping-timer-rem",
        "reneg-sec",
        "hand-window",
        "tran-window",
        "auth",
        "cipher",
        "data-ciphers",
        "data-ciphers-fallback",
        "tls-version-min",
        "tls-version-max",
        "tls-cipher",
        "tls-ciphersuites",
        "remote-cert-tls",
        "verify-client-cert",
        "verify-x509-name",
        "remote-cert-ku",
        "remote-cert-eku",
        "tls-cert-profile",
        "key-direction",
        "push",
        "push-reset",
        "push-remove",
        "route",
        "route-ipv6",
        "route-gateway",
        "route-metric",
        "route-delay",
        "route-nopull",
        "ifconfig",
        "ifconfig-ipv6",
        "ifconfig-pool",
        "ifconfig-pool-linear",
        "ifconfig-ipv6-pool",
        "ifconfig-push",
        "ifconfig-ipv6-push",
        "iroute",
        "iroute-ipv6",
        "disable",
        "ccd-exclusive",
        "client-to-client",
        "duplicate-cn",
        "username-as-common-name",
        "max-clients",
        "max-routes-per-client",
        "verb",
        "mute",
        "mute-replay-warnings",
        "explicit-exit-notify",
        "sndbuf",
        "rcvbuf",
        "txqueuelen",
        "tun-mtu",
        "mssfix",
        "fragment",
        "float",
        "fast-io",
        "tcp-nodelay",
        "socket-flags",
        "replay-window",
        "allow-compression",
        "compress",
        "comp-lzo",
        "script-security",
        "auth-nocache",
        "auth-gen-token",
        "auth-gen-token-lifetime",
        "client-config-dir",
        "ifconfig-pool-persist",
        "config",
    }
)
CCD_OPTIONS = frozenset(
    {
        "ifconfig-push",
        "ifconfig-ipv6-push",
        "iroute",
        "iroute-ipv6",
        "push",
        "push-reset",
        "push-remove",
        "disable",
    }
)


def parse(data: bytes) -> list[list[str]]:
    """Parse bounded, explicit single-line OpenVPN directives."""
    try:
        lines = data.decode("utf-8").splitlines()
        result = []
        for line in lines:
            if len(line) > 8192 or "\x00" in line or line.rstrip().endswith("\\"):
                raise MigrationError("unsupported configuration syntax")
            lexer = shlex.shlex(line, posix=True)
            lexer.whitespace_split = True
            lexer.commenters = "#;"
            tokens = list(lexer)
            if tokens:
                tokens[0] = tokens[0].removeprefix("--")
                if tokens[0].startswith("<"):
                    raise MigrationError(
                        "inline configuration needs reviewed conversion"
                    )
                result.append(tokens)
        return result
    except (UnicodeError, ValueError) as exc:
        if isinstance(exc, MigrationError):
            raise
        raise MigrationError("invalid configuration syntax") from None


def capture(
    spec: SourceSpec,
    *,
    writers_frozen: bool = False,
    key_passwords: dict[str, bytes] | None = None,
) -> Snapshot:
    """Take two identical bounded reads while operator-frozen writers stop.

    Args:
        spec: Explicit approved roots and observed compatibility metadata.
        writers_frozen: Attestation that *all* external writers are frozen.
    Returns:
        A validated sensitive snapshot, never suitable for logging.
    Raises:
        MigrationError: Unsafe, inconsistent, unsupported, or incomplete state.
    """
    if not writers_frozen:
        raise MigrationError("writer freeze required before consistent snapshot")
    validate_versions(spec.versions)
    first = _collect(spec, key_passwords)
    second = _collect(spec, key_passwords)
    if first != second:
        raise MigrationError("source changed during snapshot; restore writer freeze")
    validation.validate(first)
    return first


def inventory(spec: SourceSpec) -> dict[str, object]:
    """Return redacted discovery only; never claim a consistent backup."""
    validate_versions(spec.versions)
    state = _collect(spec, with_semantics=False)
    return {
        "schema_version": 1,
        "consistent_snapshot": False,
        "file_count": len(state.files),
        "total_bytes": sum(len(data) for data in state.files.values()),
        "versions": state.manifest.versions,
        "directives": sorted(
            {
                item.name
                for items in state.manifest.configurations.values()
                for item in items
            }
        ),
        "reviewed_hook_replacements_required": len(state.manifest.hooks),
        "excluded_runtime_directives": sorted(set(state.manifest.excluded_runtime)),
        "network_state_captured": False,
    }


def _collect(
    spec: SourceSpec,
    key_passwords: dict[str, bytes] | None = None,
    *,
    with_semantics: bool = True,
) -> Snapshot:
    vpn = pathlib.Path(os.path.abspath(spec.openvpn_root))
    easyrsa = pathlib.Path(os.path.abspath(spec.easyrsa_root))
    if (
        pathlib.Path(spec.pki_subdirectory).is_absolute()
        or ".." in pathlib.Path(spec.pki_subdirectory).parts
    ):
        raise MigrationError("unsafe PKI subdirectory")
    pki = easyrsa / spec.pki_subdirectory
    files: dict[str, bytes] = {}
    directories = {"pki", "config", "assets", "ccd", "pool"}
    configs: dict[str, list[Directive]] = {}
    hooks: dict[str, str] = {}
    runtime: list[str] = []
    used_external: set[str] = set()
    total = 0

    def add(name: str, data: bytes) -> str:
        nonlocal total
        logical_path(name)
        if name not in files:
            total += len(data)
            if len(files) >= MAX_FILES or total > MAX_TOTAL_BYTES:
                raise MigrationError("snapshot size limit exceeded")
            files[name] = data
        elif files[name] != data:
            raise MigrationError("source changed during snapshot")
        return name

    names, folders = filesystem.tree(pki, MAX_FILES)
    directories.update(f"pki/{name}" for name in folders)
    for name in names:
        validation.pki_path(name)
        add(f"pki/{name}", filesystem.read_file(pki / name))
    for name, value in spec.easyrsa_config.items():
        if name not in {"vars", "openssl-easyrsa.cnf", "safessl-easyrsa.cnf"}:
            raise MigrationError("unsupported Easy-RSA configuration file")
        path = pathlib.Path(value)
        if path.is_absolute() or ".." in path.parts:
            raise MigrationError("unsafe Easy-RSA configuration path")
        add(f"pki/{name}", filesystem.read_file(easyrsa / path))

    def resolve(value: str, *, role: str = "") -> pathlib.Path:
        candidate = pathlib.Path(value)
        if ".." in candidate.parts or "\\" in value:
            raise MigrationError("unsafe source path")
        path = candidate if candidate.is_absolute() else vpn / candidate
        if not (path.is_relative_to(vpn) or path.is_relative_to(pki)):
            if spec.external_files.get(str(path)) != role or role not in {
                "pool",
                "hook",
            }:
                raise MigrationError("file reference outside approved roots")
            used_external.add(str(path))
        return path

    def reference(value: str, kind: str = "assets") -> str:
        path = resolve(value, role=kind)
        if path.is_relative_to(pki):
            name = f"pki/{path.relative_to(pki).as_posix()}"
        elif not path.is_relative_to(vpn) and kind == "pool":
            name = "pool/ipp.txt"
        else:
            name = f"{kind}/{path.relative_to(vpn).as_posix()}"
        return add(name, filesystem.read_file(path))

    def configuration(value: str, stack: tuple[str, ...] = ()) -> str:
        name = reference(value, "config")
        if name in stack or len(stack) >= 16:
            raise MigrationError("configuration include cycle or depth limit")
        if name in configs:
            return name
        directives = []
        for tokens in parse(files[name]):
            option, args = tokens[0], tokens[1:]
            refs: dict[str, str] = {}
            if option in RUNTIME_OPTIONS:
                runtime.append(option)
                # Source service identities and runtime files never transfer.
                continue
            if option in FILE_OPTIONS:
                if not args or len(args) > (2 if option == "tls-auth" else 1):
                    raise MigrationError("unsupported file directive variant")
                if not (option == "dh" and args == ["none"]):
                    refs["0"] = reference(args[0])
                    args[0] = refs["0"]
            elif option == "config":
                if len(args) != 1:
                    raise MigrationError("invalid include directive")
                refs["0"] = configuration(args[0], (*stack, name))
                args[0] = refs["0"]
            elif option in ("client-config-dir", "ifconfig-pool-persist"):
                if not args or len(args) > (
                    2 if option == "ifconfig-pool-persist" else 1
                ):
                    raise MigrationError("invalid state-file directive")
                if option == "client-config-dir":
                    root = resolve(args[0])
                    children, nested = filesystem.tree(root, MAX_FILES)
                    if nested:
                        raise MigrationError("nested CCD directories are unsupported")
                    for child in children:
                        data = filesystem.read_file(root / child)
                        if any(item[0] not in CCD_OPTIONS for item in parse(data)):
                            raise MigrationError("unsupported CCD directive")
                        add(f"ccd/{child}", data)
                    refs["0"] = "ccd"
                else:
                    refs["0"] = reference(args[0], "pool")
                args[0] = refs["0"]
            elif option in HOOK_OPTIONS:
                if not args or len(args) > (
                    2 if option == "auth-user-pass-verify" else 1
                ):
                    raise MigrationError("hook arguments require reviewed conversion")
                hook_path = args[0]
                if spec.container_runtime_hooks:
                    from sciaiot.rivet.migration import container_target

                    if option not in {
                        "client-connect",
                        "client-disconnect",
                    } or spec.versions != {
                        "openvpn": "2.6.19",
                        "easyrsa": "3.1.7",
                        "openssl": "3.5.7",
                    }:
                        raise MigrationError("unsupported container checkpoint hook")
                    hook_path, expected_hook_hash = container_target.source_hook(
                        hook_path
                    )
                code_hash = filesystem.digest(
                    filesystem.read_file(resolve(hook_path, role="hook"))
                )
                if spec.container_runtime_hooks and (code_hash != expected_hook_hash):
                    raise MigrationError("container checkpoint hook hash mismatch")
                hook_id = f"{option}:{code_hash}"
                hooks[hook_id] = code_hash
                refs["0"] = f"hook/{hook_id}"
                args[0] = refs["0"]
            elif option not in PLAIN_OPTIONS:
                raise MigrationError(
                    "unsupported directive; reviewed conversion required"
                )
            directives.append(Directive(name=option, args=args, references=refs))
        configs[name] = directives
        return name

    main = configuration(spec.server_config)
    if used_external != set(spec.external_files):
        raise MigrationError("unused or unsupported external file approval")
    manifest = Manifest(
        versions=spec.versions,
        serial_policy=spec.serial_policy,
        main_config=main,
        files={
            name: Entry(sha256=filesystem.digest(data), size=len(data))
            for name, data in files.items()
        },
        directories=sorted(directories),
        configurations=configs,
        hooks=hooks,
        excluded_runtime=runtime,
        semantics={},
    )
    state = Snapshot(manifest, files, key_passwords or {})
    if with_semantics:
        manifest.semantics = validation.semantic_state(state)
    return state
