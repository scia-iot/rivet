"""Bounded sanitized config, certificate and CCD observations."""

import ipaddress
import json
import os
import re
import shlex
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from sciaiot.rivet.application.vpn_control import schemas as s
from sciaiot.rivet.application.vpn_control.errors import ControlError, ErrorCode

from . import bounded
from .settings import Settings


def directives(content: bytes) -> dict[str, list[list[str]]]:
    """Parse bounded single-file OpenVPN syntax without evaluating includes."""
    result: dict[str, list[list[str]]] = {}
    for line in content.decode("utf-8").splitlines():
        if len(line) > 8192:
            raise ControlError(ErrorCode.EXHAUSTED)
        words = shlex.split(line, comments=True)
        if not words:
            continue
        if words[0].startswith("<") or words[0] in {"config", "include"}:
            raise ControlError(ErrorCode.UNAVAILABLE)
        result.setdefault(words[0], []).append(words[1:])
    return result


def configuration(settings: Settings, deadline: float) -> s.ConfigResult:
    """Project only typed public options, retaining the configured address."""
    raw = bounded.read_file(settings.config_path, deadline)
    options = directives(raw)

    def value(name: str, default: str | None = None) -> str:
        entries = options.get(name)
        if entries is None and default is not None:
            return default
        if entries is None or len(entries) != 1:
            raise ControlError(ErrorCode.UNAVAILABLE)
        return " ".join(entries[0])

    network_address, mask = value("server").split()
    network = ipaddress.IPv4Network(f"{network_address}/{mask}")
    device = value("dev")
    if device in {"tun", "tap"}:
        raise ControlError(ErrorCode.UNAVAILABLE)
    keepalive = value("keepalive", "10 120").split()
    address = value("ifconfig", f"{next(network.hosts())} {mask}").split()[0]
    if ipaddress.IPv4Address(address) not in network:
        raise ControlError(ErrorCode.UNAVAILABLE)
    result = s.ConfigResult.model_validate(
        {
            "generation": 0,
            "device": device,
            "network": str(network),
            "server_address": address,
            "device_type": value(
                "dev-type", "tun" if device.startswith("tun") else "tap"
            ),
            "ccd_exclusive": "ccd-exclusive" in options,
            "keepalive": (int(keepalive[0]), int(keepalive[1])),
            "port": int(value("port", "1194")),
            "protocol": value("proto", "udp"),
            "topology": value("topology", "net30"),
            "persist_key": "persist-key" in options,
            "persist_tun": "persist-tun" in options,
            "data_ciphers": tuple(value("data-ciphers").split(":"))
            if "data-ciphers" in options
            else None,
            "fallback_cipher": value("data-ciphers-fallback")
            if "data-ciphers-fallback" in options
            else None,
            "verbosity": int(value("verb")) if "verb" in options else None,
            "explicit_exit_notify": int(value("explicit-exit-notify") or "1")
            if "explicit-exit-notify" in options
            else None,
        }
    )
    return result.model_copy(
        update={"generation": bounded.revision(result.model_dump_json().encode())}
    )


def ccd(settings: Settings, client: str, deadline: float) -> dict[str, list[list[str]]]:
    """Read one validated client CCD, distinguishing absent optional state."""
    s.GetClient(client=client)
    try:
        return directives(bounded.read_file(settings.ccd_path / client, deadline))
    except FileNotFoundError:
        return {}


def clients(settings: Settings, deadline: float) -> tuple[s.ClientMetadata, ...]:
    """Reject cross-file drift by requiring two identical bounded observations."""
    first = _clients_once(settings, deadline)
    if first != _clients_once(settings, deadline):
        raise ControlError(ErrorCode.CONFLICT)
    return first


def _clients_once(settings: Settings, deadline: float) -> tuple[s.ClientMetadata, ...]:
    """Discover verified leaf certificates without reading any private keys."""
    index = bounded.read_file(settings.pki_path / "index.txt", deadline)
    ca = x509.load_pem_x509_certificate(
        bounded.read_file(settings.pki_path / "ca.crt", deadline)
    )
    revoked: dict[int, str] = {}
    historical: dict[str, str] = {}
    for line in index.decode("utf-8").splitlines():
        fields = line.split("\t")
        if len(fields) != 6 or fields[0] not in {"V", "R", "E"}:
            raise ControlError(ErrorCode.INTEGRITY)
        if re.fullmatch(r"[0-9A-Fa-f]{1,128}", fields[3]) is None:
            raise ControlError(ErrorCode.INTEGRITY)
        serial = int(fields[3], 16)
        common_name = re.search(r"(?:^|/)CN=([A-Za-z0-9_-]{1,255})(?:/|$)", fields[5])
        if fields[0] == "R" and common_name is not None:
            historical[common_name.group(1)] = fields[3]
        if serial in revoked:
            raise ControlError(ErrorCode.INTEGRITY)
        revoked[serial] = fields[0]
        if len(revoked) > bounded.MAX_RECORDS:
            raise ControlError(ErrorCode.EXHAUSTED)
    issued = settings.pki_path / "issued"
    if issued.is_symlink():
        raise ControlError(ErrorCode.INTEGRITY)
    names: list[str] = []
    count = 0
    with os.scandir(issued) as directory_entries:
        for entry in directory_entries:
            bounded.remaining(deadline)
            count += 1
            if count > bounded.MAX_RECORDS:
                raise ControlError(ErrorCode.EXHAUSTED)
            if entry.name.endswith(".crt"):
                names.append(entry.name[:-4])
    sources = {name: issued / f"{name}.crt" for name in names}
    deleted = deleted_clients(settings, deadline)
    for name, serial_text in historical.items():
        if name not in sources and deleted.get(name) != serial_text:
            candidate = (
                settings.pki_path / "revoked" / "certs_by_serial" / f"{serial_text}.crt"
            )
            if candidate.exists() or candidate.is_symlink():
                sources[name] = candidate
    if len(sources) > bounded.MAX_RECORDS:
        raise ControlError(ErrorCode.EXHAUSTED)
    result: list[s.ClientMetadata] = []
    total = 0
    for name in sorted(sources):
        s.GetClient(client=name)
        raw = bounded.read_file(sources[name], deadline, 65536)
        total += len(raw)
        if total > 16 * bounded.MAX_BYTES:
            raise ControlError(ErrorCode.EXHAUSTED)
        certificate = x509.load_pem_x509_certificate(raw)
        certificate.verify_directly_issued_by(ca)
        eku = certificate.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
        if ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
            continue
        common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(common_names) != 1 or common_names[0].value != name:
            raise ControlError(ErrorCode.INTEGRITY)
        if certificate.serial_number not in revoked:
            raise ControlError(ErrorCode.INTEGRITY)
        options = ccd(settings, name, deadline)
        assignment = None
        if "ifconfig-push" in options:
            entries = options["ifconfig-push"]
            if len(entries) != 1 or len(entries[0]) != 2:
                raise ControlError(ErrorCode.INTEGRITY)
            networks = options.get("iroute", [])
            if len(networks) > 1:
                raise ControlError(ErrorCode.UNAVAILABLE)
            network = (
                str(ipaddress.IPv4Network("/".join(networks[0]))) if networks else None
            )
            assignment = s.Assignment(address=entries[0][0], network=network)
        item = s.ClientMetadata(
            client=name,
            generation=0,
            state="revoked" if revoked[certificate.serial_number] == "R" else "active",
            issuer=str(ca.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value),
            subject=name,
            certificate_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
            not_before=int(certificate.not_valid_before_utc.timestamp() * 1_000_000),
            not_after=int(certificate.not_valid_after_utc.timestamp() * 1_000_000),
            assignment=assignment,
        )
        result.append(
            item.model_copy(
                update={"generation": bounded.revision(item.model_dump_json().encode())}
            )
        )
    bounded.remaining(deadline)
    return tuple(result)


def deleted_clients(settings: Settings, deadline: float) -> dict[str, str]:
    """Read only serial-scoped deletion markers, preserving CA audit history."""
    try:
        value = json.loads(
            bounded.read_file(settings.pki_path / "ovpncp-deleted.json", deadline)
        )
    except FileNotFoundError:
        return {}
    if not isinstance(value, dict) or len(value) > bounded.MAX_RECORDS:
        raise ControlError(ErrorCode.INTEGRITY)
    for name, serial in value.items():
        s.GetClient(client=name)
        if (
            not isinstance(serial, str)
            or re.fullmatch(r"[0-9A-Fa-f]{1,128}", serial) is None
        ):
            raise ControlError(ErrorCode.INTEGRITY)
    return value


def certificate_path(settings: Settings, name: str, deadline: float) -> Path:
    """Resolve the current issued or latest revoked leaf through the CA index."""
    s.GetClient(client=name)
    issued = settings.pki_path / "issued" / f"{name}.crt"
    if issued.exists() or issued.is_symlink():
        return issued
    found: str | None = None
    for line in (
        bounded.read_file(settings.pki_path / "index.txt", deadline)
        .decode()
        .splitlines()
    ):
        fields = line.split("\t")
        if (
            len(fields) == 6
            and fields[0] == "R"
            and re.search(rf"(?:^|/)CN={re.escape(name)}(?:/|$)", fields[5])
        ):
            if re.fullmatch(r"[0-9A-Fa-f]{1,128}", fields[3]) is None:
                raise ControlError(ErrorCode.INTEGRITY)
            found = fields[3]
    if found is None:
        raise ControlError(ErrorCode.NOT_FOUND)
    return settings.pki_path / "revoked" / "certs_by_serial" / f"{found}.crt"
