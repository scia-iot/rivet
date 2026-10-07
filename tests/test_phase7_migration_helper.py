"""Regressions for independently observed Phase 7 image capability policy."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from sciaiot.ovpncp.migration import container_target
from sciaiot.ovpncp.migration.models import ContainerTargetSpec, MigrationError
from tests.integration import phase7_migration_helper as helper


def _capabilities() -> dict[str, object]:
    return {
        "image_refs": {
            "openvpn": f"registry/ovpncp-openvpn@{helper.PINNED_OPENVPN}",
            "agent": f"ovpncp.local/ovpncp-agent@{helper.PINNED_AGENT}",
        },
        "versions": {"openvpn": "2.6.19", "easyrsa": "3.1.7", "openssl": "3.5.7"},
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
    state = SimpleNamespace(manifest=SimpleNamespace(serial_policy="random", hooks={}))
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
    assert {"disable-dco", "data-ciphers-fallback"} <= set(saved.supported_options)
