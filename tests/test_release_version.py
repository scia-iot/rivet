"""Release tags drive native distribution metadata without manual bumps."""

import email
import os
import runpy
import shutil
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy/release_version.py"


def _run(monkeypatch: pytest.MonkeyPatch, *arguments: str) -> None:
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), *arguments])
    runpy.run_path(str(SCRIPT), run_name="__main__")


def _copy_metadata(target: Path) -> None:
    for relative in ("pyproject.toml", "packages/agent/pyproject.toml"):
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)


@pytest.mark.parametrize(
    ("tag", "image", "package"),
    [
        ("v2.3.4", "2.3.4", "2.3.4"),
        ("2.3.4", "2.3.4", "2.3.4"),
        ("v2.3.4-alpha.1", "2.3.4-alpha.1", "2.3.4a1"),
        ("v2.3.4-beta-2", "2.3.4-beta-2", "2.3.4b2"),
        ("v2.3.4-rc.1", "2.3.4-rc.1", "2.3.4rc1"),
    ],
)
def test_tag_updates_both_packages_and_exact_dependency(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    tag: str,
    image: str,
    package: str,
) -> None:
    """A tag overrides checked-in versions and survives repeated preparation."""
    _copy_metadata(tmp_path)
    output = tmp_path / "output"
    for _ in range(2):
        _run(monkeypatch, "--tag", tag, "--write", "--root", str(tmp_path))
    _run(monkeypatch, "--tag", tag, "--github-output", str(output))
    assert output.read_text() == (f"version={image}\npython_version={package}\n")
    core = tomllib.loads((tmp_path / "pyproject.toml").read_text())["project"]
    agent = tomllib.loads((tmp_path / "packages/agent/pyproject.toml").read_text())[
        "project"
    ]
    assert core["version"] == agent["version"] == package
    assert agent["dependencies"] == [f"sciaiot-rivet=={package}"]
    original = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert core["optional-dependencies"] == original["optional-dependencies"]


@pytest.mark.parametrize(
    "tag",
    [
        "",
        "latest",
        "v01.2.3",
        "v1.2",
        "v1.2.3+build.4",
        "v1.2.3-preview.1",
        "v1.2.3-rc.01",
        "v1.2.3-rc..1",
        "v1.2.3\nversion=latest",
        "$(touch marker)",
        "v" + "1" * 128 + ".2.3",
    ],
)
def test_invalid_release_leaves_metadata_and_outputs_untouched(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, tag: str
) -> None:
    """Unsupported or malicious tags fail before artifact metadata changes."""
    _copy_metadata(tmp_path)
    before = {p: p.read_bytes() for p in tmp_path.rglob("*.toml")}
    output = tmp_path / "output"
    with pytest.raises(SystemExit):
        _run(
            monkeypatch,
            "--tag",
            tag,
            "--write",
            "--root",
            str(tmp_path),
            "--github-output",
            str(output),
        )
    assert all(p.read_bytes() == content for p, content in before.items())
    assert not output.exists()


def test_inconsistent_dependency_fails_before_any_write(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Unexpected packaging layout cannot silently produce mismatched wheels."""
    _copy_metadata(tmp_path)
    agent = tmp_path / "packages/agent/pyproject.toml"
    agent.write_text(agent.read_text().replace("sciaiot-rivet==", "other=="))
    before = {p: p.read_bytes() for p in tmp_path.rglob("*.toml")}
    with pytest.raises(SystemExit):
        _run(monkeypatch, "--tag", "v2.3.4", "--write", "--root", str(tmp_path))
    assert all(p.read_bytes() == content for p, content in before.items())


def test_release_sdists_rebuild_matching_wheels(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Release metadata persists in both sdists and wheels without Git state."""
    source = tmp_path / "source"
    _copy_metadata(source)
    shutil.copy2(ROOT / "README.md", source / "README.md")
    shutil.copy2(ROOT / "packages/agent/README.md", source / "packages/agent/README.md")
    shutil.copytree(
        ROOT / "src",
        source / "src",
        ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"),
    )
    _run(monkeypatch, "--tag", "v2.3.4-rc.1", "--write", "--root", str(source))
    wheels = tmp_path / "wheels"
    for project in (source, source / "packages/agent"):
        subprocess.run(
            [
                sys.executable,
                "-c",
                "from setuptools import build_meta; build_meta.build_sdist('dist')",
            ],
            cwd=project,
            check=True,
            capture_output=True,
        )
        sdist = next((project / "dist").glob("*.tar.gz"))
        with tarfile.open(sdist) as archive:
            member = next(
                m
                for m in archive.getmembers()
                if m.name.count("/") == 1 and m.name.endswith("/PKG-INFO")
            )
            stream = archive.extractfile(member)
            assert stream is not None
            assert email.message_from_bytes(stream.read())["Version"] == "2.3.4rc1"
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "--no-build-isolation",
                "--no-index",
                "--wheel-dir",
                str(wheels),
                str(sdist),
            ],
            check=True,
            capture_output=True,
            env={**os.environ, "PIP_DISABLE_PIP_VERSION_CHECK": "1"},
        )
    built = list(wheels.glob("*.whl"))
    assert len(built) == 2
    for wheel in built:
        with zipfile.ZipFile(wheel) as archive:
            name = next(n for n in archive.namelist() if n.endswith("/METADATA"))
            metadata = email.message_from_bytes(archive.read(name))
            assert metadata["Version"] == "2.3.4rc1"
            if metadata["Name"] == "sciaiot-rivet-agent":
                assert metadata.get_all("Requires-Dist") == ["sciaiot-rivet==2.3.4rc1"]


def test_pypi_workflow_stamps_release_before_building() -> None:
    """Publishing derives both distributions from the event's tag and commit."""
    workflow = yaml.safe_load((ROOT / ".github/workflows/package.yml").read_text())
    steps = workflow["jobs"]["release-build"]["steps"]
    checkout = next(s for s in steps if "checkout@" in s.get("uses", ""))
    assert checkout["with"]["ref"] == "${{ github.sha }}"
    prepare = next(s for s in steps if s.get("name") == "Prepare release version")
    assert prepare["env"]["RELEASE_TAG"] == "${{ github.event.release.tag_name }}"
    assert 'deploy/release_version.py --tag "$RELEASE_TAG" --write' in prepare["run"]
    build = next(s for s in steps if s.get("name") == "Build release distributions")
    assert steps.index(prepare) < steps.index(build)
