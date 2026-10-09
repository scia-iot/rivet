"""Independent checksum, certificate, revocation, and semantic validation."""

import datetime
import pathlib
import re
import shlex
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization

from sciaiot.rivet.migration import filesystem
from sciaiot.rivet.migration.models import (
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_TOTAL_BYTES,
    MigrationError,
    Snapshot,
    logical_path,
    validate_versions,
)


def pki_path(name: str) -> None:
    """Reject application, executable, runtime, and archive artifacts in PKI."""
    logical_path(f"pki/{name}")
    path = pathlib.PurePosixPath(name)
    allowed_roots = {
        "private",
        "issued",
        "reqs",
        "certs_by_serial",
        "revoked",
        "renewed",
        "expired",
        "inline",
        "ecparams",
    }
    allowed_files = {
        "ca.crt",
        "crl.pem",
        "crl.der",
        "dh.pem",
        "serial",
        "serial.old",
        "crlnumber",
        "crlnumber.old",
        "index.txt",
        "index.txt.old",
        "index.txt.attr",
        "index.txt.attr.old",
        "vars",
        "openssl-easyrsa.cnf",
        "safessl-easyrsa.cnf",
        ".rnd",
        "README",
        "RAND_SEED",
        "vars.example",
    }
    if len(path.parts) == 1:
        allowed = name in allowed_files
    else:
        allowed = path.parts[0] in allowed_roots and (
            path.suffix in {".crt", ".key", ".req", ".pem", ".creds"}
            or path.suffix == ".inline"
            or name == "inline/private/README.inline.private"
        )
    if not allowed:
        raise MigrationError("unexpected PKI artifact; backend/UI files are forbidden")


def _certificate(data: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(data)


def _key_matches(
    data: bytes, cert: x509.Certificate, password: bytes | None = None
) -> None:
    key = serialization.load_pem_private_key(data, password=password)
    options = (
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if key.public_key().public_bytes(*options) != cert.public_key().public_bytes(
        *options
    ):
        raise MigrationError("certificate/private-key mismatch")


def _index(data: bytes) -> dict[int, tuple[str, str, str, str]]:
    records = {}
    for line in data.decode("utf-8").splitlines():
        parts = line.split("\t")
        if len(parts) != 6 or parts[0] not in {"V", "R", "E"}:
            raise MigrationError("invalid Easy-RSA index record")
        status, expiry, revoked, serial, _, subject = parts
        for date in (expiry, revoked.split(",", 1)[0]):
            if not date:
                continue
            pattern = "%y%m%d%H%M%SZ" if len(date) == 13 else "%Y%m%d%H%M%SZ"
            datetime.datetime.strptime(date, pattern).replace(tzinfo=datetime.UTC)
        number = int(serial, 16)
        if (
            number <= 0
            or number in records
            or not re.fullmatch(r"[0-9A-Fa-f]+", serial)
        ):
            raise MigrationError("duplicate or invalid Easy-RSA serial")
        if (status == "R") != bool(revoked):
            raise MigrationError("inconsistent Easy-RSA revocation record")
        records[number] = (status, expiry, revoked, subject)
    return records


def _index_common_name(subject: str) -> str:
    if not subject.startswith("/") or "\\" in subject:
        raise MigrationError("unsupported Easy-RSA index subject encoding")
    names: list[str] = []
    for part in subject[1:].split("/"):
        name, separator, value = part.partition("=")
        if (
            not separator
            or not value
            or re.fullmatch(r"[A-Za-z][A-Za-z0-9.]*", name) is None
            or any(ord(char) < 32 for char in value)
        ):
            raise MigrationError("invalid Easy-RSA index subject")
        if name == "CN":
            names.append(value)
    if len(names) != 1:
        raise MigrationError("ambiguous Easy-RSA index common name")
    return names[0]


def semantic_state(state: Snapshot) -> dict[str, object]:
    """Verify cryptographic PKI and return protected semantic comparison data."""
    try:
        return _semantic_state(state)
    except (
        ValueError,
        KeyError,
        TypeError,
        InvalidSignature,
        x509.ExtensionNotFound,
    ) as exc:
        if isinstance(exc, MigrationError):
            raise
        raise MigrationError(
            "invalid or incomplete PKI; inspect source privately"
        ) from None


def _semantic_state(state: Snapshot) -> dict[str, object]:
    files, manifest = state.files, state.manifest
    for required in (
        "ca.crt",
        "private/ca.key",
        "index.txt",
        "serial",
        "crl.pem",
        "openssl-easyrsa.cnf",
    ):
        if f"pki/{required}" not in files:
            raise MigrationError("incomplete Easy-RSA PKI snapshot")
    now = datetime.datetime.now(datetime.UTC)
    ca = _certificate(files["pki/ca.crt"])
    if not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise MigrationError("CA certificate is not a certificate authority")
    ca.verify_directly_issued_by(ca)
    _key_matches(
        files["pki/private/ca.key"], ca, state.key_passwords.get("pki/private/ca.key")
    )
    if not ca.not_valid_before_utc <= now <= ca.not_valid_after_utc:
        raise MigrationError("CA certificate is not currently valid")
    records = _index(files["pki/index.txt"])
    next_serial = int(files["pki/serial"].strip(), 16)
    if (
        next_serial <= 0
        or next_serial in records
        or (
            manifest.serial_policy == "sequential"
            and records
            and next_serial <= max(records)
        )
    ):
        raise MigrationError("Easy-RSA serial allocation is inconsistent")
    crl = x509.load_pem_x509_crl(files["pki/crl.pem"])
    public_key: Any = ca.public_key()
    if crl.issuer != ca.subject or not crl.is_signature_valid(public_key):
        raise MigrationError("CRL signature or issuer mismatch")
    if (
        crl.next_update_utc is None
        or not crl.last_update_utc <= now <= crl.next_update_utc
    ):
        raise MigrationError("CRL is stale or not yet valid; regenerate before export")
    revoked = {entry.serial_number: entry for entry in crl}
    if len(revoked) != len(crl) or set(revoked) != {
        serial for serial, record in records.items() if record[0] == "R"
    }:
        raise MigrationError("CRL and index revocations disagree")
    identities: dict[str, dict[str, str]] = {}
    for name, data in files.items():
        if not name.startswith("pki/") or name == "pki/ca.crt":
            continue
        if not (
            name.endswith(".crt")
            or name.startswith("pki/certs_by_serial/")
            and name.endswith(".pem")
        ):
            continue
        cert = _certificate(data)
        cert.verify_directly_issued_by(ca)
        record = records[cert.serial_number]
        status, expiry, _, subject = record
        expected_expiry = cert.not_valid_after_utc.strftime("%y%m%d%H%M%SZ")
        if expiry not in (
            expected_expiry,
            cert.not_valid_after_utc.strftime("%Y%m%d%H%M%SZ"),
        ):
            raise MigrationError("certificate and index expiry disagree")
        common_names = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if len(common_names) != 1 or _index_common_name(subject) != str(
            common_names[0].value
        ):
            raise MigrationError("certificate and index subject disagree")
        if status == "E" and cert.not_valid_after_utc >= now:
            raise MigrationError("index expiry status disagrees with certificate")
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        previous = identities.get(str(cert.serial_number))
        if previous is not None and previous["fingerprint"] != fingerprint:
            raise MigrationError("different certificates share one serial")
        identities[str(cert.serial_number)] = {
            "fingerprint": fingerprint,
            "status": status,
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
        }
        if name.startswith("pki/issued/"):
            key = f"pki/private/{pathlib.PurePosixPath(name).stem}.key"
            if key in files:
                _key_matches(files[key], cert, state.key_passwords.get(key))
    if any(
        str(serial) not in identities
        for serial, record in records.items()
        if record[0] != "R"
    ):
        raise MigrationError("non-revoked indexed certificate missing from PKI")
    # Deleted revoked clients retain their complete index/CRL history.
    for serial, record in records.items():
        if record[0] == "R":
            date = record[2].split(",", 1)[0]
            expected = revoked[serial].revocation_date_utc
            if date not in (
                expected.strftime("%y%m%d%H%M%SZ"),
                expected.strftime("%Y%m%d%H%M%SZ"),
            ):
                raise MigrationError("CRL and index revocation dates disagree")
    directives = [item for items in manifest.configurations.values() for item in items]
    required_options = {}
    for item in directives:
        if item.name in {"ca", "cert", "key", "crl-verify"}:
            if item.name in required_options or "0" not in item.references:
                raise MigrationError("ambiguous PKI configuration directive")
            required_options[item.name] = item.references["0"]
    if set(required_options) != {"ca", "cert", "key", "crl-verify"}:
        raise MigrationError("server CA, certificate, key, and CRL are required")
    if _certificate(files[required_options["ca"]]).fingerprint(
        hashes.SHA256()
    ) != ca.fingerprint(hashes.SHA256()):
        raise MigrationError("server references a different CA")
    server = _certificate(files[required_options["cert"]])
    server.verify_directly_issued_by(ca)
    _key_matches(
        files[required_options["key"]],
        server,
        state.key_passwords.get(required_options["key"]),
    )
    if not server.not_valid_before_utc <= now <= server.not_valid_after_utc:
        raise MigrationError("server certificate is not currently valid")
    indexed_server = identities.get(str(server.serial_number))
    if indexed_server is None:
        raise MigrationError("configured server certificate absent from PKI inventory")
    if indexed_server["fingerprint"] != server.fingerprint(hashes.SHA256()).hex():
        raise MigrationError("server certificate differs from indexed identity")
    try:
        if server.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise MigrationError("server certificate must not be a CA")
    except x509.ExtensionNotFound:
        pass
    try:
        if (
            x509.ExtendedKeyUsageOID.SERVER_AUTH
            not in server.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage
            ).value
        ):
            raise MigrationError("server certificate lacks server authentication usage")
    except x509.ExtensionNotFound:
        pass
    if records[server.serial_number][0] != "V":
        raise MigrationError("server certificate is not active")
    active_crl = x509.load_pem_x509_crl(files[required_options["crl-verify"]])
    if active_crl.public_bytes(serialization.Encoding.DER) != crl.public_bytes(
        serialization.Encoding.DER
    ):
        raise MigrationError("active CRL differs from PKI CRL")
    for item in directives:
        if item.name == "dh" and item.args != ["none"]:
            serialization.load_pem_parameters(files[item.references["0"]])
    return {
        "ca_fingerprint": ca.fingerprint(hashes.SHA256()).hex(),
        "server_fingerprint": server.fingerprint(hashes.SHA256()).hex(),
        "certificates": identities,
        "serial_status": {str(serial): record[0] for serial, record in records.items()},
        "ccd": {
            name: filesystem.digest(data)
            for name, data in files.items()
            if name.startswith("ccd/")
        },
        "options": {
            name: [item.model_dump() for item in items]
            for name, items in manifest.configurations.items()
        },
    }


def validate(state: Snapshot) -> None:
    """Validate all protected metadata before staging or activating anything."""
    from sciaiot.rivet.migration import source

    manifest, files = state.manifest, state.files
    validate_versions(manifest.versions)
    if len(files) > MAX_FILES or set(files) != set(manifest.files):
        raise MigrationError("manifest file inventory mismatch")
    if sum(len(data) for data in files.values()) > MAX_TOTAL_BYTES:
        raise MigrationError("bundle size limit exceeded")
    if len(manifest.directories) > MAX_FILES or len(set(manifest.directories)) != len(
        manifest.directories
    ):
        raise MigrationError("invalid directory inventory")
    for name in manifest.directories:
        logical_path(name)
        if name in files:
            raise MigrationError("file/directory collision")
    for name, data in files.items():
        logical_path(name)
        if name.startswith("pki/"):
            pki_path(name[4:])
        if any(
            parent.as_posix() in files for parent in pathlib.PurePosixPath(name).parents
        ):
            raise MigrationError("file/directory collision")
        entry = manifest.files[name]
        if (
            len(data) > MAX_FILE_BYTES
            or entry.size != len(data)
            or entry.sha256 != filesystem.digest(data)
        ):
            raise MigrationError("manifest hash or size mismatch")
        if name.startswith("ccd/") and any(
            item[0] not in source.CCD_OPTIONS for item in source.parse(data)
        ):
            raise MigrationError("unexpected CCD content")
    if manifest.main_config not in manifest.configurations:
        raise MigrationError("main configuration is missing")
    referenced = set()
    for name, items in manifest.configurations.items():
        if not name.startswith("config/") or name not in files:
            raise MigrationError("invalid configuration inventory")
        for item in items:
            if (
                item.name
                not in source.FILE_OPTIONS | source.HOOK_OPTIONS | source.PLAIN_OPTIONS
            ):
                raise MigrationError("unsupported configuration directive")
            for index, reference in item.references.items():
                if index != "0" or not item.args or item.args[0] != reference:
                    raise MigrationError("invalid logical file reference")
                if reference.startswith("hook/"):
                    if (
                        item.name not in source.HOOK_OPTIONS
                        or reference[5:] not in manifest.hooks
                    ):
                        raise MigrationError("unreviewed executable dependency")
                elif reference not in files and reference not in manifest.directories:
                    raise MigrationError("missing logical file reference")
                referenced.add(reference)
            if (
                item.name
                in source.FILE_OPTIONS
                | source.HOOK_OPTIONS
                | {
                    "config",
                    "client-config-dir",
                    "ifconfig-pool-persist",
                }
                and not item.references
                and not (item.name == "dh" and item.args == ["none"])
            ):
                raise MigrationError("unmapped source file directive")
    for name in files:
        if not name.startswith(("pki/", "ccd/", "config/")) and name not in referenced:
            raise MigrationError("unexpected non-OpenVPN artifact")
    _validate_configuration(state)
    _validate_easyrsa_configuration(files)
    _validate_auxiliary_pki(state)
    if semantic_state(state) != manifest.semantics:
        raise MigrationError("protected semantic inventory mismatch")


def _validate_configuration(state: Snapshot) -> None:
    from sciaiot.rivet.migration import source

    manifest, files = state.manifest, state.files
    if {name for name in files if name.startswith("config/")} != set(
        manifest.configurations
    ):
        raise MigrationError("unexpected configuration artifact")
    visited: set[str] = set()

    def visit(name: str, stack: tuple[str, ...]) -> None:
        if name in stack or len(stack) >= 16:
            raise MigrationError("configuration include cycle or depth limit")
        if name not in manifest.configurations:
            raise MigrationError("missing included configuration")
        if name in visited:
            return
        visited.add(name)
        for item in manifest.configurations[name]:
            if any(
                len(arg) > 8192 or any(ord(char) < 32 for char in arg)
                for arg in item.args
            ):
                raise MigrationError("unsafe configuration argument")
            if item.name == "config":
                if len(item.args) != 1:
                    raise MigrationError("invalid include directive")
                visit(item.references["0"], (*stack, name))
            if item.name in source.FILE_OPTIONS | source.HOOK_OPTIONS | {
                "client-config-dir",
                "ifconfig-pool-persist",
            }:
                maximum = (
                    2
                    if item.name
                    in {"tls-auth", "ifconfig-pool-persist", "auth-user-pass-verify"}
                    else 1
                )
                if not 1 <= len(item.args) <= maximum:
                    raise MigrationError("unsupported file directive variant")
            if item.name == "client-config-dir" and item.references != {"0": "ccd"}:
                raise MigrationError("invalid CCD directory reference")
            if item.name in {"tls-auth", "tls-crypt", "secret"}:
                content = files[item.references["0"]].decode("ascii")
                lines = [
                    line.strip()
                    for line in content.splitlines()
                    if line.strip() and not line.startswith("#")
                ]
                if (
                    len(lines) < 3
                    or lines[0] != "-----BEGIN OpenVPN Static key V1-----"
                    or lines[-1] != "-----END OpenVPN Static key V1-----"
                    or re.fullmatch(r"[a-fA-F0-9]{512}", "".join(lines[1:-1])) is None
                ):
                    raise MigrationError("invalid OpenVPN TLS static key")
                if (
                    item.name == "tls-auth"
                    and len(item.args) == 2
                    and item.args[1] not in {"0", "1"}
                ):
                    raise MigrationError("invalid TLS key direction")
            if item.name == "tls-crypt-v2":
                raise MigrationError("TLS-crypt-v2 requires reviewed target conversion")
            if item.name == "extra-certs":
                chain = x509.load_pem_x509_certificates(files[item.references["0"]])
                if not chain:
                    raise MigrationError("empty extra certificate chain")
            if item.name == "push" and item.args:
                pushed = source.parse(item.args[0].encode())
                if len(pushed) != 1 or pushed[0][
                    0
                ] in source.FILE_OPTIONS | source.HOOK_OPTIONS | {
                    "config",
                    "plugin",
                    "cd",
                }:
                    raise MigrationError("unsafe pushed configuration directive")

    visit(manifest.main_config, ())
    if visited != set(manifest.configurations):
        raise MigrationError("unreachable configuration artifact")
    if any(name not in source.RUNTIME_OPTIONS for name in manifest.excluded_runtime):
        raise MigrationError("invalid excluded runtime inventory")


def _validate_easyrsa_configuration(files: dict[str, bytes]) -> None:
    allowed_vars = {
        "EASYRSA_ALGO",
        "EASYRSA_CURVE",
        "EASYRSA_KEY_SIZE",
        "EASYRSA_DIGEST",
        "EASYRSA_CA_EXPIRE",
        "EASYRSA_CERT_EXPIRE",
        "EASYRSA_CRL_DAYS",
        "EASYRSA_DN",
        "EASYRSA_REQ_COUNTRY",
        "EASYRSA_REQ_PROVINCE",
        "EASYRSA_REQ_CITY",
        "EASYRSA_REQ_ORG",
        "EASYRSA_REQ_EMAIL",
        "EASYRSA_REQ_OU",
        "EASYRSA_REQ_CN",
        "EASYRSA_BATCH",
        "EASYRSA_NO_PASS",
    }
    if "pki/vars" in files:
        for line in files["pki/vars"].decode().splitlines():
            tokens = shlex.split(line, comments=True)
            if not tokens:
                continue
            if (
                len(tokens) != 3
                or tokens[0] != "set_var"
                or tokens[1] not in allowed_vars
                or any(char in line.split("#", 1)[0] for char in "$`;\\\n\r|&<>()")
            ):
                raise MigrationError(
                    "Easy-RSA vars requires reviewed declarative conversion"
                )
    # Easy-RSA's stock config uses $dir and $ENV::EASYRSA_PKI. Other file
    # roots, .include, engine and provider loading require reviewed conversion.
    for name in ("pki/openssl-easyrsa.cnf", "pki/safessl-easyrsa.cnf"):
        if name not in files:
            continue
        for line in files[name].decode().splitlines():
            text = line.strip()
            if not text or text.startswith(("#", ";")):
                continue
            if text.startswith(".") or any(
                word in text.lower()
                for word in ("engine", "module", "provider", "openssl_conf")
            ):
                raise MigrationError(
                    "OpenSSL configuration requires reviewed conversion"
                )
            if "=" in text:
                _, value = text.split("=", 1)
                value = value.strip().split("#", 1)[0].strip().strip("\"'")
                if (
                    value.startswith(("/", "~"))
                    or ".." in pathlib.PurePosixPath(value).parts
                ):
                    raise MigrationError("host-specific OpenSSL configuration path")
                for variable in re.findall(
                    r"\$(?:\{([^}]+)\}|([A-Za-z_][A-Za-z0-9_:]*))", value
                ):
                    symbol = variable[0] or variable[1]
                    if symbol != "dir" and not symbol.startswith("ENV::EASYRSA_"):
                        raise MigrationError(
                            "unreviewed OpenSSL environment dependency"
                        )


def _validate_auxiliary_pki(state: Snapshot) -> None:
    try:
        for name, data in state.files.items():
            if not name.startswith("pki/"):
                continue
            if name.endswith(".req"):
                request = x509.load_pem_x509_csr(data)
                if not request.is_signature_valid:
                    raise MigrationError("invalid certificate request signature")
            elif name.endswith(".key"):
                serialization.load_pem_private_key(
                    data, password=state.key_passwords.get(name)
                )
            elif name == "pki/crl.der":
                crl = x509.load_der_x509_crl(data)
                current = x509.load_pem_x509_crl(state.files["pki/crl.pem"])
                if crl.public_bytes(serialization.Encoding.DER) != current.public_bytes(
                    serialization.Encoding.DER
                ):
                    raise MigrationError("DER and PEM CRLs disagree")
            elif name in {"pki/serial.old", "pki/crlnumber", "pki/crlnumber.old"}:
                if int(data.strip(), 16) <= 0:
                    raise MigrationError("invalid historical serial or CRL number")
            elif name == "pki/index.txt.old":
                _index(data)
    except ValueError, TypeError:
        raise MigrationError("invalid auxiliary PKI state") from None
