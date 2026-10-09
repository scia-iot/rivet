"""Container CI publication boundaries without a registry or Docker daemon."""

import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/containers.yml"


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())


def test_builds_are_read_only_and_publication_is_explicit() -> None:
    """Untrusted events cannot authenticate or acquire package write access."""
    workflow = _workflow()
    assert workflow["permissions"] == {"contents": "read"}
    events = workflow.get("on", workflow.get(True))
    assert isinstance(events, dict)
    assert set(events) == {"pull_request", "push", "workflow_dispatch"}
    assert events["workflow_dispatch"]["inputs"]["publish"]["default"] is False
    jobs = workflow["jobs"]
    publish = jobs["publish"]
    assert "github.event_name == 'workflow_dispatch'" in publish["if"]
    assert "inputs.publish" in publish["if"]
    assert "github.event.repository.default_branch" in publish["if"]
    assert publish["needs"] == ["target", "build"]
    assert publish["permissions"] == {"contents": "read", "packages": "write"}
    build = jobs["build"]
    assert "permissions" not in build
    assert not any("login-action" in s.get("uses", "") for s in build["steps"])
    build_text = yaml.safe_dump(build)
    assert "secrets." not in build_text
    assert "--push" not in build_text
    assert "type=oci,dest=artifacts/image.oci.tar" in build_text
    assert "--metadata-file artifacts/metadata.json" in build_text
    for job in (build, publish):
        matrix = job["strategy"]["matrix"]["include"]
        assert {m["component"] for m in matrix} == {"openvpn", "agent", "api", "web"}
        for row in matrix:
            assert (ROOT / row["dockerfile"]).is_file()
        for step in job["steps"]:
            if "uses" in step:
                assert re.fullmatch(r"[\w/-]+@[0-9a-f]{40}", step["uses"])
    logins = [s for s in publish["steps"] if "login-action" in s.get("uses", "")]
    assert len(logins) == 2
    ghcr, external = logins
    assert "== 'ghcr.io'" in ghcr["if"]
    assert ghcr["with"]["password"] == "${{ secrets.GITHUB_TOKEN }}"
    assert "!= 'ghcr.io'" in external["if"]
    assert external["with"]["password"] == "${{ secrets.CONTAINER_REGISTRY_PASSWORD }}"
    assert "GITHUB_TOKEN" not in yaml.safe_dump(external)


@pytest.mark.parametrize(
    ("registry", "namespace", "success", "expected"),
    [
        ("", "", True, "ghcr.io/example/rivet-api"),
        (
            "registry.example:5000",
            "team/vpn",
            True,
            "registry.example:5000/team/vpn/rivet-api",
        ),
        ("example.azurecr.io", "team", True, "example.azurecr.io/team/rivet-api"),
        ("https://registry.example", "team", False, ""),
        ("registry.example/path", "team", False, ""),
        ("GHCR.IO", "team", False, ""),
        ("registry.example", "", True, "registry.example/rivet-api"),
        ("example.azurecr.io", "", True, "example.azurecr.io/rivet-api"),
        ("docker.io", "", False, ""),
        ("ghcr.io", "../team", False, ""),
        ("ghcr.io", "$(touch marker)", False, ""),
        ("ghcr.io\nother.example", "team", False, ""),
    ],
)
def test_registry_target_validation(
    tmp_path: Path,
    registry: str,
    namespace: str,
    success: bool,
    expected: str,
) -> None:
    """Safe image paths support root registries and required Hub namespaces."""
    step = _workflow()["jobs"]["target"]["steps"][0]
    output = tmp_path / "output"
    result = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", step["run"]],
        cwd=tmp_path,
        env={
            **os.environ,
            "REGISTRY": registry,
            "NAMESPACE": namespace,
            "OWNER": "Example",
            "GITHUB_OUTPUT": str(output),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert (result.returncode == 0) is success
    if success:
        values = dict(line.split("=", 1) for line in output.read_text().splitlines())
        assert f"{values['prefix']}/rivet-api" == expected
    assert not (tmp_path / "marker").exists()


@pytest.mark.parametrize(
    ("username", "password", "success"),
    [
        ("", "", False),
        ("operator", "", False),
        ("", "test-secret", False),
        ("operator", "test-secret", True),
    ],
)
def test_external_credentials_never_fall_back(
    username: str,
    password: str,
    success: bool,
) -> None:
    """Missing external credentials fail even when a GitHub token exists."""
    steps = _workflow()["jobs"]["publish"]["steps"]
    step = next(
        s for s in steps if s.get("name") == "Validate external registry credentials"
    )
    result = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", step["run"]],
        env={
            **os.environ,
            "USERNAME": username,
            "PASSWORD": password,
            "GITHUB_TOKEN": "must-not-be-used",
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert (result.returncode == 0) is success
    assert "test-secret" not in result.stdout + result.stderr
    assert "must-not-be-used" not in result.stdout + result.stderr
