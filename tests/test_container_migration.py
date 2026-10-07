"""Stopped Compose target adapter and retained rollback behavior."""

import os
import stat
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from sciaiot.ovpncp.migration import bundle, container_target, source, target
from sciaiot.ovpncp.migration.cli import main
from sciaiot.ovpncp.migration.models import (
    ContainerTargetSpec,
    MigrationError,
    Replacement,
    SourceSpec,
)
from tests.test_migration import legacy as legacy  # noqa: PLC0414


@pytest.fixture
def policy(legacy):
    """Use observed fixture capabilities with the exact fixture versions."""
    legacy[1].versions.update(
        {"openvpn": "2.6.19", "easyrsa": "3.1.7", "openssl": "3.5.7"}
    )
    config = legacy[0] / "server.conf"
    config.write_text(config.read_text() + "topology subnet\n")
    return ContainerTargetSpec(
        versions=legacy[1].versions,
        serial_policy=legacy[1].serial_policy,
        supported_options=sorted(source.PLAIN_OPTIONS | source.FILE_OPTIONS),
        supported_ciphers=["AES-256-GCM", "AES-128-GCM"],
        image_digest=(
            "sha256:5027eba02fbb4872c1b9c1ff8f084d41431dd671870ee7f48ba03877683253fa"
        ),
        target_device="tun9",
    )


@pytest.fixture
def local_identity(monkeypatch):
    """Exercise the target map under the unprivileged test identity."""
    monkeypatch.setattr(
        container_target,
        "_identities",
        lambda: (os.geteuid(), os.geteuid(), os.getegid(), os.getegid()),
    )


def test_container_import_verify_and_exact_nonempty_rollback(
    legacy, policy, local_identity, tmp_path
):
    """A second generation restores the previous bytes, modes and ownership."""
    state = source.capture(legacy[1], writers_frozen=True)
    wrapper = tmp_path / "migration"
    assert container_target.install(state, wrapper, policy)["dry_run"]
    assert not wrapper.exists()
    target._owned(wrapper, create=True, profile="container")
    prior = wrapper / "active/vpn-pki"
    prior.mkdir(parents=True, mode=0o700)
    (prior / "preexisting.crt").write_bytes(b"prior-state")
    os.chmod(prior / "preexisting.crt", 0o600)
    before = container_target._hash_tree(wrapper / "active")
    container_target.install(state, wrapper, policy, apply=True, target_stopped=True)
    active = wrapper / "active"
    report = container_target.verify(state, wrapper, policy)
    assert report["matches"]
    assert report["reconciliation"]["unexplained_drift"] == 0
    assert report["reconciliation"]["revoked_serials"] == 1
    assert (active / "vpn-pki/private/ca.key").exists()
    assert not (active / "vpn-projection/private/ca.key").exists()
    assert (active / "vpn-projection/ca.crt").exists()
    assert (active / "vpn-projection/ccd/client").exists()
    assert stat.S_IMODE((active / "vpn-pool/ipp.txt").stat().st_mode) == 0o660
    assert not any(
        (active / name).exists()
        for name in ("api-data", "api-archives", "api-profile", "web")
    )
    assert container_target._hash_tree(wrapper / "rollback") == before
    container_target.rollback(wrapper, apply=True, target_stopped=True)
    assert container_target._hash_tree(active) == before


def test_container_adapter_rejects_unsafe_profiles(
    legacy, policy, local_identity, tmp_path
):
    """An include, unknown target, or live-target claim cannot be activated."""
    state = source.capture(legacy[1], writers_frozen=True)
    wrapper = tmp_path / "migration"
    with pytest.raises(MigrationError, match="stopped"):
        container_target.install(state, wrapper, policy, apply=True)
    assert not wrapper.exists()
    (legacy[0] / "fragment.conf").write_text("verb 0\n")
    config = legacy[0] / "server.conf"
    config.write_text(config.read_text() + "config fragment.conf\n")
    included = source.capture(legacy[1], writers_frozen=True)
    with pytest.raises(MigrationError, match="include"):
        container_target.install(included, wrapper, policy)
    assert not wrapper.exists()


@pytest.mark.parametrize(
    "directive",
    [
        "client-to-client",
        "duplicate-cn",
        "verify-client-cert none",
        "server-ipv6 fd00::/64",
        "comp-lzo",
        'push "redirect-gateway def1"',
        "dev-type tap",
        "script-security 3",
    ],
)
def test_container_rejects_unreviewed_or_bypass_options(
    legacy, policy, local_identity, tmp_path, directive
):
    """The image/agent access model accepts only reviewed server directives."""
    config = legacy[0] / "server.conf"
    config.write_text(config.read_text() + directive + "\n")
    state = source.capture(legacy[1], writers_frozen=True)
    policy = policy.model_copy(
        update={"supported_options": sorted(source.PLAIN_OPTIONS | source.FILE_OPTIONS)}
    )
    with pytest.raises(MigrationError):
        container_target.install(state, tmp_path / "target", policy)


def _resign_client(root: Path, *, common_name: str, eku: bool) -> None:
    """Keep valid CA/index/leaf material while changing runtime leaf metadata."""
    pki = root / "pki"
    ca_key = serialization.load_pem_private_key(
        (pki / "private/ca.key").read_bytes(), password=None
    )
    client_key = serialization.load_pem_private_key(
        (pki / "private/client.key").read_bytes(), password=None
    )
    assert isinstance(ca_key, rsa.RSAPrivateKey)
    assert isinstance(client_key, rsa.RSAPrivateKey)
    ca = x509.load_pem_x509_certificate((pki / "ca.crt").read_bytes())
    original = x509.load_pem_x509_certificate((pki / "issued/client.crt").read_bytes())
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca.subject)
        .public_key(client_key.public_key())
        .serial_number(original.serial_number)
        .not_valid_before(original.not_valid_before_utc)
        .not_valid_after(original.not_valid_after_utc)
    )
    if eku:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False
        )
    pem = builder.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
    (pki / "issued/client.crt").write_bytes(pem)
    (pki / "certs_by_serial/03.pem").write_bytes(pem)
    index = pki / "index.txt"
    index.write_text(index.read_text().replace("/CN=client\n", f"/CN={common_name}\n"))


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ("missing_eku", "agent-required EKU"),
        ("different_cn", "identity incompatible"),
        ("invalid_name", "name incompatible"),
    ],
)
def test_container_rejects_m0_valid_agent_incompatible_leaf(
    legacy, policy, local_identity, tmp_path, change: str, message: str
):
    """An M0-valid certificate can still violate the agent runtime contract."""
    root = legacy[0]
    if change == "missing_eku":
        _resign_client(root, common_name="client", eku=False)
    elif change == "different_cn":
        _resign_client(root, common_name="other", eku=True)
    else:
        (root / "pki/issued/client.crt").rename(root / "pki/issued/client.bad.crt")
    state = source.capture(legacy[1], writers_frozen=True)
    with pytest.raises(MigrationError, match=message):
        container_target.install(state, tmp_path / "target", policy)


@pytest.mark.parametrize(
    "change",
    ["port 1195\n", "proto udp\n", "server 10.10.0.0 255.255.255.0\n"],
)
def test_container_rejects_duplicate_tunnel_options(
    legacy, policy, local_identity, tmp_path, change
):
    """A second network option cannot silently replace the reviewed first."""
    config = legacy[0] / "server.conf"
    config.write_text(config.read_text() + change)
    state = source.capture(legacy[1], writers_frozen=True)
    with pytest.raises(MigrationError, match="duplicate"):
        container_target.install(state, tmp_path / "target", policy)


def test_container_rejects_missing_explicit_udp_port(
    legacy, policy, local_identity, tmp_path
):
    """The target does not inherit a daemon default that was not inventoried."""
    config = legacy[0] / "server.conf"
    config.write_text(config.read_text().replace("port 1194\n", ""))
    state = source.capture(legacy[1], writers_frozen=True)
    with pytest.raises(MigrationError, match="complete tunnel"):
        container_target.install(state, tmp_path / "target", policy)


def test_container_rollback_refuses_modified_prior_snapshot(
    legacy, policy, local_identity, tmp_path
):
    """An altered previous generation is retained for investigation."""
    state = source.capture(legacy[1], writers_frozen=True)
    wrapper = tmp_path / "migration"
    target._owned(wrapper, create=True, profile="container")
    prior = wrapper / "active/vpn-pki"
    prior.mkdir(parents=True, mode=0o700)
    (prior / "index.txt").write_text("previous")
    container_target.install(state, wrapper, policy, apply=True, target_stopped=True)
    prior = wrapper / "rollback/vpn-pki/index.txt"
    prior.write_text("tampered")
    with pytest.raises(MigrationError, match="hash mismatch"):
        container_target.rollback(wrapper, apply=True, target_stopped=True)
    assert prior.read_text() == "tampered"


def test_exact_external_pool_and_hook_references(legacy, tmp_path):
    """Only explicitly approved file roles cross the source root boundary."""
    root, spec = legacy
    external = tmp_path / "external"
    external.mkdir()
    pool = external / "ipp.txt"
    hook = external / "client-connect.sh"
    pool.write_text("client,10.9.0.2\n")
    hook.write_text("#!/bin/sh\nexit 0\n")
    config = root / "server.conf"
    config.write_text(
        config.read_text() + f"ifconfig-pool-persist {pool}\nclient-connect {hook}\n"
    )
    with pytest.raises(MigrationError, match="outside approved"):
        source.capture(spec, writers_frozen=True)
    approved = spec.model_copy(
        update={"external_files": {str(pool): "pool", str(hook): "hook"}}
    )
    state = source.capture(approved, writers_frozen=True)
    assert state.files["pool/ipp.txt"] == pool.read_bytes()
    assert hook.read_bytes() not in state.files.values()
    with pytest.raises(MigrationError, match="outside approved"):
        source.capture(
            spec.model_copy(update={"external_files": {str(pool): "pool"}}),
            writers_frozen=True,
        )


def test_container_hook_requires_exact_reviewed_image_bytes(
    legacy, policy, local_identity, tmp_path
):
    """A shaped hash cannot substitute for the pinned image hook bytes."""
    root, spec = legacy
    hook = root / "hook.sh"
    hook.write_text("#!/bin/sh\nexit 0\n")
    config = root / "server.conf"
    config.write_text(config.read_text() + "client-connect hook.sh\n")
    state = source.capture(spec, writers_frozen=True)
    hook_id = next(iter(state.manifest.hooks))
    options = [*policy.supported_options, "client-connect"]
    wrong = policy.model_copy(
        update={
            "supported_options": options,
            "replacements": {
                hook_id: Replacement(path=container_target.HOOK, sha256="a" * 64)
            },
        }
    )
    with pytest.raises(MigrationError, match="replacement"):
        container_target.install(state, tmp_path / "target", wrong)
    correct = wrong.model_copy(
        update={
            "replacements": {
                hook_id: Replacement(
                    path=container_target.HOOK,
                    sha256=container_target.HOOK_SHA256,
                )
            }
        }
    )
    assert container_target.install(state, tmp_path / "target", correct)["compatible"]


def test_narrow_openssl_transition(legacy, policy, local_identity, tmp_path):
    """Only the reviewed pair and pinned image can enable a version change."""
    state = source.capture(legacy[1], writers_frozen=True)
    changed = policy.model_copy(
        update={"versions": {**policy.versions, "openvpn": "2.5.0"}}
    )
    with pytest.raises(MigrationError, match="version"):
        container_target.install(state, tmp_path / "target", changed)
    bad = policy.model_copy(update={"openssl_transition": "3.0.13-to-3.5.7"})
    with pytest.raises(MigrationError, match="transition"):
        container_target.install(state, tmp_path / "target", bad)
    source_versions = {
        "openvpn": "2.6.19",
        "easyrsa": "3.1.7",
        "openssl": "3.0.13",
    }
    reviewed = source.capture(
        legacy[1].model_copy(update={"versions": source_versions}),
        writers_frozen=True,
    )
    allowed = policy.model_copy(
        update={
            "versions": {**source_versions, "openssl": "3.5.7"},
            "openssl_transition": "3.0.13-to-3.5.7",
        }
    )
    assert container_target.install(reviewed, tmp_path / "target", allowed)[
        "compatible"
    ]


def test_container_cli_uses_encrypted_m0_bundle(
    legacy, policy, local_identity, tmp_path, capsys
):
    """The public CLI selects the container map and retains M0 encryption."""
    state = source.capture(legacy[1], writers_frozen=True)
    bundle_path = tmp_path / "migration.bundle"
    key_path = tmp_path / "migration.key"
    policy_path = tmp_path / "policy.json"
    wrapper = tmp_path / "target"
    key_path.write_bytes(b"k" * 32)
    os.chmod(key_path, 0o600)
    bundle_path.write_bytes(bundle.seal(state, key_path.read_bytes()))
    policy_path.write_text(policy.model_dump_json())
    common = [
        "--container",
        "--bundle",
        str(bundle_path),
        "--key-file",
        str(key_path),
        "--policy",
        str(policy_path),
    ]
    assert main(["validate", *common]) == 0
    assert main(["import", *common, "--target", str(wrapper)]) == 0
    assert not wrapper.exists()
    assert (
        main(
            [
                "import",
                *common,
                "--target",
                str(wrapper),
                "--apply",
                "--target-stopped",
            ]
        )
        == 0
    )
    assert main(["verify", *common, "--target", str(wrapper)]) == 0
    assert (
        main(
            [
                "rollback",
                "--container",
                "--target",
                str(wrapper),
                "--apply",
                "--target-stopped",
            ]
        )
        == 0
    )
    report = capsys.readouterr()
    assert "fixture-ca" not in report.out + report.err
    assert "private/ca.key" not in report.out + report.err


def test_container_generation_exports_as_m0_recovery_bundle(
    legacy, policy, local_identity, tmp_path, monkeypatch
):
    """A stopped target can checkpoint and restore via the same M0 schema."""
    initial = source.capture(legacy[1], writers_frozen=True)
    first = tmp_path / "first"
    projection = first / "active/vpn-projection"
    pool = first / "active/vpn-pool/ipp.txt"
    monkeypatch.setattr(container_target, "PROJECTION", str(projection))
    monkeypatch.setattr(container_target, "POOL", str(pool))
    container_target.install(initial, first, policy, apply=True, target_stopped=True)
    checkpoint_spec = SourceSpec(
        openvpn_root=str(projection),
        easyrsa_root=str(first / "active/vpn-pki"),
        server_config="server.conf",
        external_files={str(pool): "pool"},
        versions=policy.versions,
        serial_policy=policy.serial_policy,
    )
    checkpoint = source.capture(checkpoint_spec, writers_frozen=True)
    sealed = bundle.seal(checkpoint, b"r" * 32)
    recovered = bundle.open_bundle(sealed, b"r" * 32)
    second = tmp_path / "second"
    container_target.install(recovered, second, policy, apply=True, target_stopped=True)
    assert container_target.verify(recovered, second, policy)["matches"]
    assert (first / "active/vpn-pki/crl.pem").read_bytes() == (
        second / "active/vpn-pki/crl.pem"
    ).read_bytes()


def test_container_hook_checkpoint_preserves_exact_replacement(
    legacy, policy, local_identity, tmp_path, monkeypatch
):
    """A target checkpoint accepts only its reviewed runtime hook command."""
    root, original = legacy
    source_hook = root / "source-hook.sh"
    source_hook.write_text("#!/bin/sh\nexit 0\n")
    config = root / "server.conf"
    config.write_text(config.read_text() + "client-connect source-hook.sh\n")
    source_versions = {
        "openvpn": "2.6.19",
        "easyrsa": "3.1.7",
        "openssl": "3.0.13",
    }
    state = source.capture(
        original.model_copy(update={"versions": source_versions}),
        writers_frozen=True,
    )
    source_hook_id = next(iter(state.manifest.hooks))
    reviewed = tmp_path / "reviewed-hook"
    reviewed.write_bytes(
        (
            Path(__file__).resolve().parents[1] / "deploy/containers/vpn_event.sh"
        ).read_bytes()
    )
    monkeypatch.setattr(container_target, "HOOK", str(reviewed))
    monkeypatch.setattr(
        container_target,
        "HOOK_COMMAND",
        f"{reviewed} --socket /run/ovpn-events/events.sock "
        "--management-socket /run/openvpn/management.sock --agent-uid 65532",
    )
    first = tmp_path / "first"
    projection = first / "active/vpn-projection"
    pool = first / "active/vpn-pool/ipp.txt"
    monkeypatch.setattr(container_target, "PROJECTION", str(projection))
    monkeypatch.setattr(container_target, "POOL", str(pool))
    target_versions = {**source_versions, "openssl": "3.5.7"}
    allowed = policy.model_copy(
        update={
            "versions": target_versions,
            "openssl_transition": "3.0.13-to-3.5.7",
            "supported_options": [*policy.supported_options, "client-connect"],
            "replacements": {
                source_hook_id: Replacement(
                    path=str(reviewed), sha256=container_target.HOOK_SHA256
                )
            },
        }
    )
    container_target.install(state, first, allowed, apply=True, target_stopped=True)
    checkpoint_spec = SourceSpec(
        openvpn_root=str(projection),
        easyrsa_root=str(first / "active/vpn-pki"),
        server_config="server.conf",
        external_files={str(pool): "pool", str(reviewed): "hook"},
        container_runtime_hooks=True,
        versions=target_versions,
        serial_policy=allowed.serial_policy,
    )
    checkpoint = source.capture(checkpoint_spec, writers_frozen=True)
    assert set(checkpoint.manifest.hooks) == {
        f"client-connect:{container_target.HOOK_SHA256}"
    }
    restored = allowed.model_copy(
        update={
            "openssl_transition": None,
            "replacements": {
                next(iter(checkpoint.manifest.hooks)): Replacement(
                    path=str(reviewed), sha256=container_target.HOOK_SHA256
                )
            },
        }
    )
    second = tmp_path / "second"
    container_target.install(
        checkpoint, second, restored, apply=True, target_stopped=True
    )
    assert container_target.verify(checkpoint, second, restored)["matches"]
