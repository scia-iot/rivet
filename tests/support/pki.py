"""Signed synthetic Easy-RSA fixture for agent mutation tests."""

import dataclasses
import datetime
from collections.abc import Generator
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from sciaiot.ovpncp.application.vpn_control import schemas as s
from sciaiot.ovpncp.vpn_agent import bounded
from sciaiot.ovpncp.vpn_agent.writer import MutationVpnControl
from tests.support.agent import request, settings


@pytest.fixture
def pki_control(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Generator[tuple[MutationVpnControl, list[list[str]]]]:
    """Mock only Easy-RSA processes while writing signed synthetic PKI artifacts."""
    configured = dataclasses.replace(
        settings(tmp_path),
        journal_path=tmp_path,
        projection_path=tmp_path / "projection",
        mutation_families=frozenset({"pki"}),
    )
    configured.pki_path.mkdir()
    configured.ccd_path.mkdir()
    assert configured.projection_path is not None
    configured.projection_path.mkdir()
    for name in ("issued", "private", "reqs"):
        (configured.pki_path / name).mkdir()
    configured.config_path.write_text(
        f"dev tun0\nserver 10.8.0.0 255.255.255.0\ntopology subnet\ndisable-dco\ncrl-verify {configured.projection_path / 'crl.pem'}\n"
    )
    now = datetime.datetime.now(datetime.UTC).replace(microsecond=0)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ca")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(ca_key, hashes.SHA256())
    )
    (configured.pki_path / "ca.crt").write_bytes(
        ca.public_bytes(serialization.Encoding.PEM)
    )
    (configured.pki_path / "index.txt").write_text("")
    records: dict[int, tuple[str, bool]] = {}
    prior: dict[str, int] = {}
    commands: list[list[str]] = []

    def run(
        arguments: list[str], deadline: float, input_data: bytes | None = None
    ) -> bytes:
        commands.append(arguments)
        if arguments[-1] == "--version":
            return b"EasyRSA Version: 3.1.7"
        verb = arguments[3]
        name = arguments[4] if len(arguments) > 4 else ""
        if verb in {"build-client-full", "renew"}:
            if verb == "renew":
                previous = x509.load_pem_x509_certificate(
                    (configured.pki_path / "issued" / f"{name}.crt").read_bytes()
                )
                prior[name] = previous.serial_number
            key = ec.generate_private_key(ec.SECP256R1())
            serial = len(records) + 2
            leaf = (
                x509.CertificateBuilder()
                .subject_name(
                    x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
                )
                .issuer_name(ca_name)
                .public_key(key.public_key())
                .serial_number(serial)
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=30))
                .add_extension(
                    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False
                )
                .sign(ca_key, hashes.SHA256())
            )
            (configured.pki_path / "issued" / f"{name}.crt").write_bytes(
                leaf.public_bytes(serialization.Encoding.PEM)
            )
            (configured.pki_path / "private" / f"{name}.key").write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            (configured.pki_path / "reqs" / f"{name}.req").write_bytes(b"synthetic")
            records[serial] = name, False
        elif verb in {"revoke", "revoke-renewed"}:
            serial = (
                prior[name]
                if verb == "revoke-renewed"
                else x509.load_pem_x509_certificate(
                    (configured.pki_path / "issued" / f"{name}.crt").read_bytes()
                ).serial_number
            )
            records[serial] = name, True
            if verb == "revoke":
                for directory, suffix, target_directory in (
                    ("issued", "crt", "certs_by_serial"),
                    ("private", "key", "private_by_serial"),
                    ("reqs", "req", "reqs_by_serial"),
                ):
                    destination = configured.pki_path / "revoked" / target_directory
                    destination.mkdir(parents=True, exist_ok=True)
                    source = configured.pki_path / directory / f"{name}.{suffix}"
                    source.rename(destination / f"{serial:X}.{suffix}")
        elif verb == "gen-crl":
            builder = (
                x509.CertificateRevocationListBuilder()
                .issuer_name(ca_name)
                .last_update(now)
                .next_update(now + datetime.timedelta(days=7))
            )
            for serial, (_, revoked) in records.items():
                if revoked:
                    builder = builder.add_revoked_certificate(
                        x509.RevokedCertificateBuilder()
                        .serial_number(serial)
                        .revocation_date(now)
                        .build()
                    )
            (configured.pki_path / "crl.pem").write_bytes(
                builder.sign(ca_key, hashes.SHA256()).public_bytes(
                    serialization.Encoding.PEM
                )
            )
        else:
            pytest.fail("Unexpected privileged verb")
        (configured.pki_path / "index.txt").write_text(
            "".join(
                f"{'R' if revoked else 'V'}\t270101000000Z\t\t{serial:X}\tunknown\t/CN={name}\n"
                for serial, (name, revoked) in records.items()
            )
        )
        return b""

    monkeypatch.setattr(bounded, "command", run)
    control = MutationVpnControl(configured)
    yield control, commands
    control.close()


def change(
    control: MutationVpnControl, action: str, client: str = "device"
) -> s.MutationResult:
    """Run one synthetic lifecycle intent at the authoritative generation."""
    command = s.ChangeClient.model_validate({"client": client, "action": action})
    intent = request(command).model_copy(
        update={"expected_generation": control.journal.generation}
    )
    result = control.execute(intent).result
    assert isinstance(result, s.MutationResult)
    return result
