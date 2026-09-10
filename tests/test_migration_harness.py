"""Unit checks for disposable rehearsal isolation; never start system tools."""

import types

import pytest

from sciaiot.ovpncp.migration.models import MigrationError
from tests.integration import migration_rehearsal as harness


def test_live_namespace_is_refused_before_network_operation(monkeypatch):
    monkeypatch.setattr(harness.os, "geteuid", lambda: 0)
    monkeypatch.setattr(harness, "_namespace_identity", lambda kind, process: 1)
    with pytest.raises(MigrationError, match="namespace"):
        harness.require_isolation()


def test_private_mounts_are_mandatory(monkeypatch):
    monkeypatch.setattr(harness.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        harness,
        "_namespace_identity",
        lambda kind, process: 2 if process == "self" else 1,
    )
    monkeypatch.setattr(harness, "_private_mounts", lambda: False)
    with pytest.raises(MigrationError, match="private"):
        harness.require_isolation()


def test_host_mount_devices_are_refused(monkeypatch):
    text = "1 0 0:1 / / rw - ext4 /dev/root rw\n2 1 0:2 / /run rw - tmpfs tmpfs rw\n3 1 0:3 / /tmp rw - tmpfs tmpfs rw\n"
    monkeypatch.setattr(harness, "_mountinfo", lambda: text)
    monkeypatch.setattr(
        harness.os, "stat", lambda path: types.SimpleNamespace(st_dev=1)
    )
    assert not harness._private_mounts()


def test_shared_propagation_is_refused(monkeypatch):
    monkeypatch.setattr(
        harness, "_mountinfo", lambda: "1 0 0:1 / / rw shared:1 - ext4 /dev/root rw\n"
    )
    assert not harness._private_mounts()


def test_ccd_address_must_be_observed(monkeypatch, tmp_path):
    rehearsal = object.__new__(harness.Rehearsal)
    rehearsal.root = tmp_path
    monkeypatch.setattr(harness.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        rehearsal,
        "run",
        lambda args, pki=None: b'[{"addr_info":[{"local":"10.231.0.99"}]}]',
    )
    with pytest.raises(MigrationError, match="CCD"):
        rehearsal.verify_ccd()
    monkeypatch.setattr(
        rehearsal,
        "run",
        lambda args, pki=None: b'[{"addr_info":[{"local":"10.231.0.10"}]}]',
    )
    rehearsal.verify_ccd()


def test_observed_options_are_not_copied_from_source(monkeypatch):
    rehearsal = object.__new__(harness.Rehearsal)
    monkeypatch.setattr(harness.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        rehearsal,
        "run",
        lambda args, pki=None: (
            b"--dev device\n--proto protocol\n"
            if args[-1] == "--help"
            else b"AES-256-GCM (256 bit key)\n"
        ),
    )
    options, ciphers = rehearsal.observe_capabilities()
    assert options == {"dev", "proto"}
    assert ciphers == {"AES-256-GCM"}


def test_failed_tool_has_only_safe_diagnostic_context(monkeypatch, tmp_path):
    rehearsal = object.__new__(harness.Rehearsal)
    rehearsal.root = tmp_path
    rehearsal.log = tmp_path / "commands.log"
    rehearsal.easyrsa = tmp_path / "private-tool-path/easyrsa"
    rehearsal.source = tmp_path
    monkeypatch.setattr(
        harness.subprocess,
        "run",
        lambda *args, **kwargs: types.SimpleNamespace(
            returncode=1,
            stdout=b"Option conflict: externally set commonName /private/key secret-value\n",
        ),
    )
    with pytest.raises(MigrationError) as caught:
        rehearsal.run(
            [
                str(rehearsal.easyrsa),
                "--batch",
                "build-server-full",
                "private-client-name",
            ]
        )
    detail = str(caught.value)
    assert "build-server-full" in detail
    assert "exit=1" in detail
    assert "configuration_conflict" in detail
    assert "private-client-name" not in detail
    assert "secret-value" not in detail
    assert "/private" not in detail


def test_failure_evidence_is_private_and_excludes_pki(monkeypatch, tmp_path):
    rehearsal = object.__new__(harness.Rehearsal)
    rehearsal.root = tmp_path / "run"
    rehearsal.root.mkdir()
    (rehearsal.root / "commands.log").write_text("private diagnostics")
    (rehearsal.root / "secret.key").write_text("never export arbitrary state")
    evidence = tmp_path / "evidence"
    evidence.mkdir(mode=0o700)
    monkeypatch.setattr(harness, "validate_evidence_directory", lambda path: None)
    rehearsal.retain_failure_evidence(evidence)
    assert {path.name for path in evidence.iterdir()} == {"commands.log"}
    assert (evidence / "commands.log").stat().st_mode & 0o777 == 0o600
    assert (evidence / "commands.log").read_text() == "private diagnostics"


@pytest.mark.parametrize(
    "stage,requires_cn",
    [
        ("build-ca", True),
        ("build-server-full", False),
        ("build-client-full", False),
        ("revoke", False),
    ],
)
def test_common_name_override_is_only_for_ca(stage, requires_cn, monkeypatch, tmp_path):
    rehearsal = object.__new__(harness.Rehearsal)
    rehearsal.root = tmp_path
    rehearsal.source = tmp_path
    rehearsal.easyrsa = tmp_path / "easyrsa"
    rehearsal.log = tmp_path / "commands.log"
    observed = {}

    def run(*args, **kwargs):
        observed.update(kwargs["env"])
        return types.SimpleNamespace(returncode=0, stdout=b"")

    monkeypatch.setattr(harness.subprocess, "run", run)
    rehearsal.run(["/usr/share/easy-rsa/easyrsa", "--batch", stage], tmp_path / "pki")
    assert ("EASYRSA_REQ_CN" in observed) is requires_cn


@pytest.mark.parametrize(
    "flag,output,accepted",
    [
        (
            "--help",
            b"OpenVPN 2.6.19 x86_64\nGeneral Options:\n--config file\n--dev tun\n",
            True,
        ),
        ("--help", b"permission denied\n", False),
        ("--help", b"OpenVPN 2.6.19\ntruncated usage", False),
        ("--version", b"OpenVPN 2.6.19\n--config file\n--dev tun\n", False),
    ],
)
def test_only_complete_openvpn_help_accepts_exit_one(
    flag, output, accepted, monkeypatch, tmp_path
):
    rehearsal = object.__new__(harness.Rehearsal)
    rehearsal.root = tmp_path
    rehearsal.log = tmp_path / "commands.log"
    monkeypatch.setattr(
        harness.subprocess,
        "run",
        lambda *args, **kwargs: types.SimpleNamespace(returncode=1, stdout=output),
    )
    if accepted:
        assert rehearsal.run(["/usr/sbin/openvpn", flag]) == output
    else:
        with pytest.raises(MigrationError):
            rehearsal.run(["/usr/sbin/openvpn", flag])
