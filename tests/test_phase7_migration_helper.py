"""Regressions for independently observed Phase 7 image capability policy."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from sciaiot.ovpncp.migration import container_target
from sciaiot.ovpncp.migration.models import ContainerTargetSpec, MigrationError
from tests.integration import phase7_container_rehearsal as runner
from tests.integration import phase7_migration_helper as helper

OPENVPN = "registry.example/team/ovpncp-openvpn@sha256:" + "a" * 64
AGENT = "registry.example/team/ovpncp-agent@sha256:" + "b" * 64
API = "registry.example/team/ovpncp-api@sha256:" + "c" * 64
SOURCE_VERSIONS = {
    "openvpn": "2.6.19",
    "easyrsa": "3.1.7",
    "openssl": "3.0.13",
}
TARGET_VERSIONS = {
    "openvpn": "2.6.19",
    "easyrsa": "3.1.7",
    "openssl": "3.5.7",
}


def _snapshot(versions: dict[str, str]) -> SimpleNamespace:
    return SimpleNamespace(
        manifest=SimpleNamespace(
            versions=versions,
            serial_policy="random",
            hooks={},
        )
    )


def _capabilities() -> dict[str, object]:
    return {
        "image_refs": {
            "openvpn": OPENVPN,
            "agent": AGENT,
            "api": API,
        },
        "versions": TARGET_VERSIONS,
        "hook_sha256": container_target.HOOK_SHA256,
        "explicit_fallback_option_probe": True,
        "network": "none",
        "capabilities": [],
        "supported_options": ["dev-type", "script-security"],
        "supported_ciphers": ["AES-256-CBC"],
    }


def test_checkpoint_generated_dco_requires_explicit_image_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The preflight policy must cover a directive added after first import."""
    state = _snapshot(SOURCE_VERSIONS)
    monkeypatch.setattr(helper, "_state", lambda path: state)
    observed: list[ContainerTargetSpec] = []
    monkeypatch.setattr(
        container_target,
        "validate_policy",
        lambda snapshot, policy: observed.append(policy),
    )
    capabilities = _capabilities()
    path = tmp_path / "capabilities.json"
    output = tmp_path / "policy.json"
    path.write_text(json.dumps(capabilities))

    with pytest.raises(MigrationError, match="capability evidence mismatch"):
        helper.policy(tmp_path, output)
    assert not output.exists()

    capabilities["explicit_disable_dco_option_probe"] = True
    path.write_text(json.dumps(capabilities))
    helper.policy(tmp_path, output)
    assert len(observed) == 1
    saved = ContainerTargetSpec.model_validate_json(output.read_bytes())
    assert saved.image_digest == "sha256:" + "a" * 64
    assert saved.openssl_transition == "3.0.13-to-3.5.7"
    assert {"disable-dco", "data-ciphers-fallback"} <= set(saved.supported_options)


def test_policy_omits_transition_for_matching_source_versions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A same-version source needs no historical OpenSSL transition."""
    monkeypatch.setattr(helper, "_state", lambda path: _snapshot(TARGET_VERSIONS))
    observed: list[ContainerTargetSpec] = []
    monkeypatch.setattr(
        container_target,
        "validate_policy",
        lambda snapshot, policy: observed.append(policy),
    )
    capabilities = _capabilities()
    capabilities["explicit_disable_dco_option_probe"] = True
    (tmp_path / "capabilities.json").write_text(json.dumps(capabilities))
    output = tmp_path / "policy.json"

    helper.policy(tmp_path, output)

    assert len(observed) == 1
    saved = ContainerTargetSpec.model_validate_json(output.read_bytes())
    assert saved.openssl_transition is None
    assert saved.versions == TARGET_VERSIONS


@pytest.mark.parametrize(
    ("role", "reference"),
    [
        ("openvpn", "registry.example/team/ovpncp-openvpn:latest"),
        ("agent", "registry.example/team/ovpncp-agent@sha256:" + "g" * 64),
        ("agent", "registry.example/team/ovpncp-api@sha256:" + "b" * 64),
        ("api", "registry.example/team/ovpncp-api@sha256:" + "c" * 63),
        ("api", "registry.example/team/ovpncp-api@sha256:" + "c" * 64 + "\n"),
    ],
)
def test_policy_rejects_malformed_or_mutable_image_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    role: str,
    reference: str,
) -> None:
    """Capability records must identify exact role-specific OCI digests."""
    monkeypatch.setattr(
        helper,
        "_state",
        lambda path: _snapshot(SOURCE_VERSIONS),
    )
    capabilities = _capabilities()
    capabilities["explicit_disable_dco_option_probe"] = True
    refs = capabilities["image_refs"]
    assert isinstance(refs, dict)
    refs[role] = reference
    (tmp_path / "capabilities.json").write_text(json.dumps(capabilities))
    output = tmp_path / "policy.json"
    with pytest.raises(MigrationError, match="capability evidence mismatch"):
        helper.policy(tmp_path, output)
    assert not output.exists()


@pytest.mark.parametrize("extra_role", [False, True])
def test_policy_requires_exact_image_roles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, extra_role: bool
) -> None:
    """Missing or unreviewed image roles cannot enter migration policy."""
    monkeypatch.setattr(
        helper,
        "_state",
        lambda path: _snapshot(SOURCE_VERSIONS),
    )
    capabilities = _capabilities()
    references = capabilities["image_refs"]
    assert isinstance(references, dict)
    if extra_role:
        references["web"] = "registry.example/team/ovpncp-web@sha256:" + "d" * 64
    else:
        references.pop("api")
    (tmp_path / "capabilities.json").write_text(json.dumps(capabilities))
    output = tmp_path / "policy.json"
    with pytest.raises(MigrationError, match="capability evidence mismatch"):
        helper.policy(tmp_path, output)
    assert not output.exists()


def test_rehearsal_requires_all_three_images_to_match_observed_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Explicit image arguments must equal independent capability evidence."""
    monkeypatch.setattr(runner, "_inputs", lambda path: None)
    monkeypatch.setattr(runner, "_private_dir", lambda path: None)
    (tmp_path / "capabilities.json").write_text(json.dumps(_capabilities()))
    private_parent = tmp_path / "runs"
    private_parent.mkdir()
    rehearsal = runner.Rehearsal(AGENT, OPENVPN, API, tmp_path, private_parent)
    assert rehearsal.images == {"agent": AGENT, "openvpn": OPENVPN, "api": API}
    roots_before = set(private_parent.iterdir())
    with pytest.raises(ValueError, match="Image references differ"):
        runner.Rehearsal(
            AGENT,
            OPENVPN,
            "registry.example/team/ovpncp-api@sha256:" + "d" * 64,
            tmp_path,
            private_parent,
        )
    assert set(private_parent.iterdir()) == roots_before


def test_rehearsal_rejects_missing_api_evidence_without_creating_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Incomplete evidence must fail before a private rehearsal root exists."""
    monkeypatch.setattr(runner, "_inputs", lambda path: None)
    monkeypatch.setattr(runner, "_private_dir", lambda path: None)
    capabilities = _capabilities()
    references = capabilities["image_refs"]
    assert isinstance(references, dict)
    references.pop("api")
    (tmp_path / "capabilities.json").write_text(json.dumps(capabilities))
    private_parent = tmp_path / "runs"
    private_parent.mkdir()

    with pytest.raises(ValueError, match="Image references differ"):
        runner.Rehearsal(AGENT, OPENVPN, API, tmp_path, private_parent)

    assert list(private_parent.iterdir()) == []
