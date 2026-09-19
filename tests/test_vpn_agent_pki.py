"""Synthetic Easy-RSA boundary fixtures and real certificate/archive validation."""

import dataclasses
import datetime
import io
import time
import zipfile
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from sciaiot.ovpncp.application.vpn_control import schemas as s
from sciaiot.ovpncp.application.vpn_control.errors import ControlError
from sciaiot.ovpncp.vpn_agent import bounded, files
from sciaiot.ovpncp.vpn_agent.writer import MutationVpnControl
from tests.test_vpn_agent import request, settings


@pytest.fixture
def pki_control(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
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


def test_lifecycle_archive_renew_revoke_delete(pki_control) -> None:
    control, commands = pki_control
    assert change(control, "issue").state == "succeeded"
    before = files.clients(control.settings, time.monotonic() + 2)[0]
    archive_request = request(s.Archive(client="device", generation=before.generation))
    with control.open_archive(archive_request) as stream:
        data = b"".join(stream)
        assert stream.verified
    assert set(zipfile.ZipFile(io.BytesIO(data)).namelist()) == {
        "ca.crt",
        "issued/device.crt",
        "private/device.key",
    }
    unread = control.open_archive(archive_request)
    assert change(control, "renew").state == "succeeded"
    with pytest.raises(ControlError):
        next(unread)
    assert any("revoke-renewed" in command for command in commands)
    assert change(control, "revoke").state == "succeeded"
    assert change(control, "delete").state == "succeeded"
    assert files.clients(control.settings, time.monotonic() + 2) == ()
    assert len((control.settings.pki_path / "index.txt").read_text().splitlines()) == 2


def test_archive_quota_and_unread_close(pki_control) -> None:
    control, _ = pki_control
    change(control, "issue")
    generation = files.clients(control.settings, time.monotonic() + 2)[0].generation
    intent = request(s.Archive(client="device", generation=generation))
    streams = [control.open_archive(intent) for _ in range(4)]
    with pytest.raises(ControlError):
        control.open_archive(intent)
    streams.pop().close()
    control.open_archive(intent).close()
    for stream in streams:
        stream.close()


def test_interrupted_issue_is_not_blindly_repeated(
    pki_control, monkeypatch: pytest.MonkeyPatch
) -> None:
    control, commands = pki_control
    original = bounded.command

    def interrupted(
        arguments: list[str], deadline: float, input_data: bytes | None = None
    ) -> bytes:
        original(arguments, deadline, input_data)
        raise OSError("lost response after complete effect")

    monkeypatch.setattr(bounded, "command", interrupted)
    intent = request(s.ChangeClient(client="device", action="issue"))
    with pytest.raises(ControlError):
        control.execute(intent)
    count = len(commands)
    control.reconcile()
    assert control.journal.lookup(str(intent.operation_id)).state == "succeeded"
    assert len(commands) == count


def test_reissue_deleted_name_and_revoke_new_serial_remain_observable(
    pki_control,
) -> None:
    control, _ = pki_control
    assert change(control, "issue").state == "succeeded"
    assert change(control, "delete").state == "succeeded"
    assert change(control, "issue").state == "succeeded"
    assert change(control, "revoke").state == "succeeded"
    clients = files.clients(control.settings, time.monotonic() + 2)
    assert len(clients) == 1 and clients[0].state == "revoked"
