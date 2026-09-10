"""Portable migration boundary and cryptographic fixture tests."""

import datetime
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sciaiot.ovpncp.migration import bundle, source, target
from sciaiot.ovpncp.migration.models import MigrationError, SourceSpec, TargetSpec


def _target_policy(**kwargs):
    return TargetSpec(
        supported_options=sorted(
            source.PLAIN_OPTIONS | source.FILE_OPTIONS | source.HOOK_OPTIONS
        ),
        **kwargs,
    )


@pytest.fixture
def legacy(tmp_path):
    """Make a real signed Easy-RSA-shaped PKI without system commands."""
    root = tmp_path / "legacy"
    pki = root / "pki"
    for directory in ("private", "issued", "reqs", "certs_by_serial"):
        (pki / directory).mkdir(parents=True, mode=0o700)
    now = datetime.datetime.now(datetime.UTC)
    ca_key = rsa.generate_private_key(65537, 2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture-ca")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=2))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(ca_key, hashes.SHA256())
    )
    (pki / "ca.crt").write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    def write_key(path, key):
        path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

    write_key(pki / "private/ca.key", ca_key)
    entries = []
    for serial, name in ((2, "server"), (3, "client")):
        key = rsa.generate_private_key(65537, 2048)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=20))
            .sign(ca_key, hashes.SHA256())
        )
        (pki / f"issued/{name}.crt").write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )
        write_key(pki / f"private/{name}.key", key)
        request = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(cert.subject)
            .sign(key, hashes.SHA256())
        )
        (pki / f"reqs/{name}.req").write_bytes(
            request.public_bytes(serialization.Encoding.PEM)
        )
        (pki / f"certs_by_serial/{serial:02X}.pem").write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )
        expiry = cert.not_valid_after_utc.strftime("%y%m%d%H%M%SZ")
        entries.append(f"V\t{expiry}\t\t{serial:02X}\tunknown\t/CN={name}\n")
    revoked = (
        x509.RevokedCertificateBuilder()
        .serial_number(4)
        .revocation_date(now - datetime.timedelta(hours=1))
        .build()
    )
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_name)
        .last_update(now - datetime.timedelta(hours=1))
        .next_update(now + datetime.timedelta(days=7))
        .add_revoked_certificate(revoked)
        .sign(ca_key, hashes.SHA256())
    )
    (pki / "crl.pem").write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    (pki / "crl.der").write_bytes(crl.public_bytes(serialization.Encoding.DER))
    expiry = (now + datetime.timedelta(days=20)).strftime("%y%m%d%H%M%SZ")
    revoked_at = revoked.revocation_date_utc.strftime("%y%m%d%H%M%SZ")
    entries.append(f"R\t{expiry}\t{revoked_at}\t04\tunknown\t/CN=removed\n")
    (pki / "index.txt").write_text("".join(entries))
    (pki / "serial").write_text("05\n")
    (pki / "serial.old").write_text("04\n")
    (pki / "crlnumber").write_text("01\n")
    (pki / "index.txt.old").write_text("".join(entries[:2]))
    (pki / "vars").write_text('set_var EASYRSA_ALGO "rsa"\n')
    (pki / "openssl-easyrsa.cnf").write_text("# fixture\n")
    (root / "ccd").mkdir()
    (root / "ccd/client").write_text("ifconfig-push 10.9.0.2 255.255.255.0\n")
    (root / "server.conf").write_text(
        "dev tun\nproto udp\nport 1194\nserver 10.9.0.0 255.255.255.0\n"
        "ca pki/ca.crt\ncert pki/issued/server.crt\n"
        "key pki/private/server.key\ncrl-verify pki/crl.pem\n"
        "dh none\nclient-config-dir ccd\n"
    )
    spec = SourceSpec(
        openvpn_root=str(root),
        easyrsa_root=str(pki),
        server_config="server.conf",
        versions={"openvpn": "2.6.12", "easyrsa": "3.2.1", "openssl": "3.4.0"},
        serial_policy="sequential",
    )
    return root, spec


def test_complete_roundtrip_and_rollback(legacy, tmp_path):
    root, spec = legacy
    before = {
        p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()
    }
    state = source.capture(spec, writers_frozen=True)
    key = b"k" * 32
    encoded = bundle.seal(state, key)
    assert b"fixture-ca" not in encoded
    restored = bundle.open_bundle(encoded, key)
    destination = tmp_path / "target"
    policy = _target_policy(versions=spec.versions, serial_policy="sequential")
    assert target.install(restored, destination, policy)["dry_run"]
    assert not destination.exists()
    target.install(restored, destination, policy, apply=True, target_stopped=True)
    assert target.verify(restored, destination)["matches"]
    target.rollback(destination, apply=True, target_stopped=True)
    assert not (destination / "active").exists()
    after = {
        p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()
    }
    assert before == after


def test_freeze_required(legacy):
    with pytest.raises(MigrationError, match="freeze"):
        source.capture(legacy[1])


@pytest.mark.parametrize("attack", ["symlink", "hardlink", "fifo", "traversal"])
def test_source_attacks(legacy, attack):
    root, spec = legacy
    path = root / "pki/attack"
    if attack == "symlink":
        path.symlink_to("/etc/passwd")
    elif attack == "hardlink":
        path.hardlink_to(root / "pki/ca.crt")
    elif attack == "fifo":
        import os

        os.mkfifo(path)
    else:
        (root / "server.conf").write_text("ca ../outside\n")
    with pytest.raises(MigrationError):
        source.capture(spec, writers_frozen=True)


def test_tamper_and_wrong_key(legacy):
    state = source.capture(legacy[1], writers_frozen=True)
    encoded = bundle.seal(state, b"a" * 32)
    for blob, key in (
        (encoded, b"b" * 32),
        (encoded[:-1] + bytes([encoded[-1] ^ 1]), b"a" * 32),
    ):
        with pytest.raises(MigrationError):
            bundle.open_bundle(blob, key)


def test_compatibility_and_nonempty_target_fail_closed(legacy, tmp_path):
    state = source.capture(legacy[1], writers_frozen=True)
    policy = _target_policy(
        versions={**legacy[1].versions, "openvpn": "2.5.0"}, serial_policy="sequential"
    )
    with pytest.raises(MigrationError, match="compatibility"):
        target.install(state, tmp_path / "target", policy)
    destination = tmp_path / "target"
    destination.mkdir()
    (destination / "unrelated").write_text("preserve")
    policy = _target_policy(versions=legacy[1].versions, serial_policy="sequential")
    with pytest.raises(MigrationError, match="owned"):
        target.install(state, destination, policy, apply=True, target_stopped=True)
    assert (destination / "unrelated").read_text() == "preserve"


def test_cli_redacts_failures(tmp_path, capsys):
    from sciaiot.ovpncp.migration.cli import main

    spec = tmp_path / "private-client-address.json"
    spec.write_text(json.dumps({"openvpn_root": "secret-host-address"}))
    assert main(["inventory", "--source", str(spec)]) == 2
    output = capsys.readouterr()
    assert "secret-host-address" not in output.err
    assert str(spec) not in output.err


def test_missing_pki_state_fails(legacy):
    (legacy[0] / "pki/serial").unlink()
    with pytest.raises(MigrationError):
        source.capture(legacy[1], writers_frozen=True)


def _archive(entries):
    import io
    import tarfile

    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data, kind in entries:
            entry = tarfile.TarInfo(name)
            entry.type = kind
            entry.mode = 0o600
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
    return stream.getvalue()


@pytest.mark.parametrize(
    "name",
    [
        "/absolute",
        "files/../escape",
        "files/pki/../escape",
        "files/pki//key",
        "files/pki/./key",
        "files/pki\\key",
        "backend.db",
        "files/ui/index.html",
    ],
)
def test_archive_path_boundaries(name):
    import tarfile

    with pytest.raises(MigrationError):
        bundle.decode_archive(_archive([(name, b"data", tarfile.REGTYPE)]))


@pytest.mark.parametrize(
    "kind", [b"1", b"2", b"3", b"4", b"5", b"6", b"x", b"g", b"L", b"K"]
)
def test_archive_rejects_links_special_nodes_and_extensions(kind):
    with pytest.raises(MigrationError):
        bundle.decode_archive(_archive([("files/pki/ca.crt", b"", kind)]))


def test_archive_duplicate_entries_and_trailing_payload():
    import tarfile

    entry = ("files/pki/ca.crt", b"data", tarfile.REGTYPE)
    for payload in (_archive([entry, entry]), _archive([entry]) + b"hidden-payload"):
        with pytest.raises(MigrationError):
            bundle.decode_archive(payload)


def test_unknown_schema_and_duplicate_json_keys():
    import tarfile

    for data in (b'{"schema_version":99}', b'{"schema_version":1,"schema_version":1}'):
        with pytest.raises(MigrationError):
            bundle.decode_archive(_archive([("manifest.json", data, tarfile.REGTYPE)]))


def test_manifest_checksum_tampering(legacy):
    from sciaiot.ovpncp.migration import validation

    state = source.capture(legacy[1], writers_frozen=True)
    state.files["pki/serial"] = b"09\n"
    with pytest.raises(MigrationError, match="hash"):
        validation.validate(state)


def test_includes_tls_keys_and_redacted_inventory(legacy):
    root, spec = legacy
    (root / "tls.key").write_text(
        "-----BEGIN OpenVPN Static key V1-----\n"
        + "a" * 512
        + "\n-----END OpenVPN Static key V1-----\n"
    )
    config = root / "server.conf"
    (root / "fragment.conf").write_text("tls-auth tls.key 0\n")
    config.write_text(
        config.read_text() + "config fragment.conf\nlog /private/runtime.log\n"
    )
    state = source.capture(spec, writers_frozen=True)
    assert "assets/tls.key" in state.files
    assert "config/fragment.conf" in state.files
    report = json.dumps(source.inventory(spec))
    assert str(root) not in report
    assert "10.9." not in report
    assert "client" not in report.replace("client-config-dir", "")
    assert "log" in report


@pytest.mark.parametrize(
    "option",
    [
        "config server.conf",
        "plugin /outside/plugin.so",
        "cd /etc/openvpn",
        "<ca>",
        "crl-verify pki/crl.pem dir",
        "tls-auth missing.key",
        "tls-crypt pki/vars",
    ],
)
def test_unsupported_or_inconsistent_source_options(legacy, option):
    config = legacy[0] / "server.conf"
    config.write_text(config.read_text() + option + "\n")
    with pytest.raises(MigrationError):
        source.capture(legacy[1], writers_frozen=True)


def test_source_race_detected(legacy, monkeypatch):
    from sciaiot.ovpncp.migration import filesystem

    original = filesystem.read_file
    calls = 0

    def changing(path, limit=filesystem.MAX_FILE_BYTES):
        nonlocal calls
        content = original(path, limit)
        if path.name == "serial":
            calls += 1
            if calls == 2:
                return b"06\n"
        return content

    monkeypatch.setattr(filesystem, "read_file", changing)
    with pytest.raises(MigrationError, match="changed"):
        source.capture(legacy[1], writers_frozen=True)


def test_source_count_and_size_limits(legacy, monkeypatch):
    monkeypatch.setattr(source, "MAX_FILES", 2)
    with pytest.raises(MigrationError, match="limit"):
        source.capture(legacy[1], writers_frozen=True)


def test_encrypted_ca_preserved(legacy):
    root, spec = legacy
    path = root / "pki/private/ca.key"
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    encrypted = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"private-passphrase"),
    )
    path.write_bytes(encrypted)
    with pytest.raises(MigrationError):
        source.capture(spec, writers_frozen=True)
    passwords = {"pki/private/ca.key": b"private-passphrase"}
    state = source.capture(spec, writers_frozen=True, key_passwords=passwords)
    restored = bundle.open_bundle(
        bundle.seal(state, b"k" * 32), b"k" * 32, key_passwords=passwords
    )
    assert restored.files["pki/private/ca.key"] == encrypted
    assert b"private-passphrase" not in restored.manifest.model_dump_json().encode()


@pytest.mark.parametrize(
    "name,content",
    [
        ("vars", 'set_var EASYRSA_ALGO "$(touch /tmp/unsafe)"\n'),
        ("vars", "echo unreviewed\n"),
        ("openssl-easyrsa.cnf", ".include /etc/private.cnf\n"),
        ("openssl-easyrsa.cnf", "module = /etc/module.so\n"),
        ("openssl-easyrsa.cnf", "private_key = /outside/key\n"),
    ],
)
def test_easyrsa_configuration_cannot_execute_source_code(legacy, name, content):
    (legacy[0] / "pki" / name).write_text(content)
    with pytest.raises(MigrationError):
        source.capture(legacy[1], writers_frozen=True)


def test_rollback_exact_existing_owned_tree(legacy, tmp_path):
    state = source.capture(legacy[1], writers_frozen=True)
    destination = tmp_path / "target"
    target._owned(destination, create=True)
    active = destination / "active"
    active.mkdir(mode=0o700)
    (active / "prior-state").write_bytes(b"unchanged pre-import bytes")
    (active / "prior-state").chmod(0o640)
    before = target._hash_tree(active)
    policy = _target_policy(versions=legacy[1].versions, serial_policy="sequential")
    target.install(state, destination, policy, apply=True, target_stopped=True)
    assert target.rollback(destination)["dry_run"]
    assert (destination / "rollback/prior-state").exists()
    with pytest.raises(MigrationError, match="retained"):
        target.install(state, destination, policy, apply=True, target_stopped=True)
    target.rollback(destination, apply=True, target_stopped=True)
    assert target._hash_tree(active) == before


def test_atomic_activation_failure_restores_previous_tree(
    legacy, tmp_path, monkeypatch
):
    state = source.capture(legacy[1], writers_frozen=True)
    destination = tmp_path / "target"
    target._owned(destination, create=True)
    (destination / "active").mkdir(mode=0o700)
    (destination / "active/prior").write_bytes(b"retained")
    before = target._hash_tree(destination / "active")
    original = target.os.replace

    def fail_activation(src, dst):
        if src.name.startswith(".stage-") and dst.name == "active":
            raise OSError("injected replacement failure")
        return original(src, dst)

    monkeypatch.setattr(target.os, "replace", fail_activation)
    policy = _target_policy(versions=legacy[1].versions, serial_policy="sequential")
    with pytest.raises(MigrationError):
        target.install(state, destination, policy, apply=True, target_stopped=True)
    assert target._hash_tree(destination / "active") == before
    assert not (destination / target.JOURNAL).exists()


def test_target_tamper_and_missing_stop_refused(legacy, tmp_path):
    state = source.capture(legacy[1], writers_frozen=True)
    destination = tmp_path / "target"
    policy = _target_policy(versions=legacy[1].versions, serial_policy="sequential")
    with pytest.raises(MigrationError, match="stopped"):
        target.install(state, destination, policy, apply=True)
    target.install(state, destination, policy, apply=True, target_stopped=True)
    (destination / "active/pki/serial").write_text("FF\n")
    with pytest.raises(MigrationError, match="hash"):
        target.verify(state, destination)
    with pytest.raises(MigrationError, match="stopped"):
        target.rollback(destination, apply=True)


def test_cli_all_commands(legacy, tmp_path, capsys):
    from sciaiot.ovpncp.migration.cli import main

    spec = tmp_path / "source.json"
    spec.write_text(legacy[1].model_dump_json())
    policy = tmp_path / "target.json"
    policy.write_text(
        _target_policy(
            versions=legacy[1].versions, serial_policy="sequential"
        ).model_dump_json()
    )
    key = tmp_path / "key"
    key.write_bytes(b"k" * 32)
    key.chmod(0o600)
    artifact = tmp_path / "migration.bundle"
    destination = tmp_path / "target"
    args = ["--bundle", str(artifact), "--key-file", str(key)]
    assert main(["inventory", "--source", str(spec)]) == 0
    assert main(["export", "--source", str(spec), "--writers-frozen", *args]) == 0
    assert artifact.stat().st_mode & 0o777 == 0o600
    assert main(["validate", "--policy", str(policy), *args]) == 0
    assert (
        main(["import", "--policy", str(policy), "--target", str(destination), *args])
        == 0
    )
    assert not destination.exists()
    assert (
        main(
            [
                "import",
                "--apply",
                "--target-stopped",
                "--policy",
                str(policy),
                "--target",
                str(destination),
                *args,
            ]
        )
        == 0
    )
    assert (
        main(["verify", "--policy", str(policy), "--target", str(destination), *args])
        == 0
    )
    assert (
        main(["rollback", "--target", str(destination), "--apply", "--target-stopped"])
        == 0
    )
    output = capsys.readouterr()
    assert str(legacy[0]) not in output.out
    assert "10.9.0." not in output.out
    assert not output.err


def test_inventory_does_not_require_encrypted_ca_password(legacy):
    path = legacy[0] / "pki/private/ca.key"
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"offline-password"),
        )
    )
    assert source.inventory(legacy[1])["consistent_snapshot"] is False


@pytest.mark.parametrize(
    "mutation",
    [
        "invalid-index",
        "duplicate-serial",
        "revocation-status",
        "serial-collision",
        "serial-backwards",
        "missing-issued",
        "server-key",
        "missing-server-ca",
        "stale-crl",
        "crl-disagreement",
        "index-expiry",
        "index-subject",
    ],
)
def test_pki_consistency_failures(legacy, mutation):
    pki = legacy[0] / "pki"
    index = pki / "index.txt"
    if mutation == "invalid-index":
        index.write_text("invalid\n")
    elif mutation == "duplicate-serial":
        index.write_text(index.read_text() + index.read_text().splitlines()[0] + "\n")
    elif mutation == "revocation-status":
        index.write_text(index.read_text().replace("R\t", "V\t"))
    elif mutation == "serial-collision":
        (pki / "serial").write_text("03\n")
    elif mutation == "serial-backwards":
        (pki / "serial").write_text("01\n")
    elif mutation == "missing-issued":
        (pki / "issued/client.crt").unlink()
        (pki / "certs_by_serial/03.pem").unlink()
    elif mutation == "server-key":
        (pki / "private/server.key").write_bytes(
            (pki / "private/client.key").read_bytes()
        )
    elif mutation == "missing-server-ca":
        config = legacy[0] / "server.conf"
        config.write_text(config.read_text().replace("ca pki/ca.crt\n", ""))
    elif mutation in ("stale-crl", "crl-disagreement"):
        now = datetime.datetime.now(datetime.UTC)
        ca = x509.load_pem_x509_certificate((pki / "ca.crt").read_bytes())
        key = serialization.load_pem_private_key(
            (pki / "private/ca.key").read_bytes(), password=None
        )
        next_update = (
            now - datetime.timedelta(days=1)
            if mutation == "stale-crl"
            else now + datetime.timedelta(days=1)
        )
        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca.subject)
            .last_update(now - datetime.timedelta(days=2))
            .next_update(next_update)
            .sign(key, hashes.SHA256())
        )
        (pki / "crl.pem").write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    elif mutation == "index-expiry":
        records = index.read_text().splitlines()
        fields = records[0].split("\t")
        fields[1] = "300101000000Z"
        records[0] = "\t".join(fields)
        index.write_text("\n".join(records) + "\n")
    else:
        index.write_text(index.read_text().replace("/CN=server", "/CN=other"))
    with pytest.raises(MigrationError):
        source.capture(legacy[1], writers_frozen=True)


def test_observed_target_cipher_policy_required(legacy, tmp_path):
    config = legacy[0] / "server.conf"
    config.write_text(config.read_text() + "data-ciphers AES-256-GCM:AES-128-GCM\n")
    state = source.capture(legacy[1], writers_frozen=True)
    policy = _target_policy(versions=legacy[1].versions, serial_policy="sequential")
    with pytest.raises(MigrationError, match="ciphers"):
        target.install(state, tmp_path / "target", policy)
    policy.supported_ciphers = ["AES-256-GCM", "AES-128-GCM"]
    assert target.validate_policy(state, policy)["capabilities_verified"]
    policy.supported_options = []
    with pytest.raises(MigrationError, match="options"):
        target.validate_policy(state, policy)


def test_hook_excluded_and_reviewed_target_replacement(legacy, tmp_path):
    from sciaiot.ovpncp.migration import filesystem
    from sciaiot.ovpncp.migration.models import Replacement

    root, spec = legacy
    hook = root / "connect.sh"
    hook.write_text("#!/bin/sh\nexit 0\n")
    config = root / "server.conf"
    config.write_text(config.read_text() + "client-connect connect.sh\n")
    state = source.capture(spec, writers_frozen=True)
    assert all("connect.sh" not in name for name in state.files)
    policy = _target_policy(versions=spec.versions, serial_policy="sequential")
    with pytest.raises(MigrationError, match="replacement"):
        target.install(state, tmp_path / "target", policy)
    replacement = tmp_path / "reviewed-hook"
    replacement.write_text("#!/bin/sh\nexit 0\n")
    hook_id = next(iter(state.manifest.hooks))
    policy.replacements[hook_id] = Replacement(
        path=str(replacement), sha256=filesystem.digest(replacement.read_bytes())
    )
    assert target.install(state, tmp_path / "target", policy)["dry_run"]
    replacement.write_text("#!/bin/sh\nexit 1\n")
    with pytest.raises(MigrationError, match="hash"):
        target.install(state, tmp_path / "target", policy)


def test_target_lock_conflict_and_unsafe_lock(legacy, tmp_path):
    import os

    state = source.capture(legacy[1], writers_frozen=True)
    destination = tmp_path / "target"
    target._owned(destination, create=True)
    policy = _target_policy(versions=legacy[1].versions, serial_policy="sequential")
    with target._lock(destination), pytest.raises(MigrationError, match="conflicting"):
        target.install(state, destination, policy, apply=True, target_stopped=True)
    (destination / ".lock").unlink()
    os.mkfifo(destination / ".lock", 0o600)
    with pytest.raises(MigrationError, match="lock"):
        target.install(state, destination, policy, apply=True, target_stopped=True)


def test_cli_passphrase_file(legacy, tmp_path, capsys):
    from sciaiot.ovpncp.migration.cli import main

    path = legacy[0] / "pki/private/ca.key"
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"protected-password"),
        )
    )
    passwords = tmp_path / "passwords.json"
    passwords.write_text(
        json.dumps({"keys": {"pki/private/ca.key": "protected-password"}})
    )
    passwords.chmod(0o600)
    source_file = tmp_path / "source.json"
    source_file.write_text(legacy[1].model_dump_json())
    key_file = tmp_path / "bundle.key"
    key_file.write_bytes(b"k" * 32)
    key_file.chmod(0o600)
    assert (
        main(
            [
                "export",
                "--source",
                str(source_file),
                "--key-file",
                str(key_file),
                "--bundle",
                str(tmp_path / "bundle"),
                "--writers-frozen",
                "--pki-passphrases-file",
                str(passwords),
            ]
        )
        == 0
    )
    assert "protected-password" not in capsys.readouterr().out


def test_offline_target_rejects_inaccessible_owner_mapping(legacy, monkeypatch):
    import types

    state = source.capture(legacy[1], writers_frozen=True)
    policy = _target_policy(
        versions=legacy[1].versions, serial_policy="sequential", owner="anotheruser"
    )
    monkeypatch.setattr(
        target.pwd,
        "getpwnam",
        lambda name: types.SimpleNamespace(pw_uid=target.os.geteuid() + 1),
    )
    with pytest.raises(MigrationError, match="migration operator"):
        target.validate_policy(state, policy)


def test_verify_rejects_weakened_target_modes(legacy, tmp_path):
    state = source.capture(legacy[1], writers_frozen=True)
    policy = _target_policy(versions=legacy[1].versions, serial_policy="sequential")
    destination = tmp_path / "target"
    target.install(state, destination, policy, apply=True, target_stopped=True)
    (destination / "active/pki/private/ca.key").chmod(0o644)
    with pytest.raises(MigrationError, match="mode"):
        target.verify(state, destination, policy)
