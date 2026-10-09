"""Public UI settings are runtime-only and cannot inject executable content."""

import json
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "deploy/containers/web_entrypoint.sh"
VALID = {
    "RIVET_UI_ENTRA_TENANT_ID": "11111111-1111-4111-8111-111111111111",
    "RIVET_UI_ENTRA_CLIENT_ID": "22222222-2222-4222-8222-222222222222",
    "RIVET_UI_ENTRA_API_SCOPE": (
        "api://33333333-3333-4333-8333-333333333333/access_as_user"
    ),
}


def render(environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Exercise the real POSIX entrypoint without starting a server."""
    return subprocess.run(
        ["/bin/sh", str(ENTRYPOINT), "--print-config"],
        env={"PATH": "/usr/bin:/bin", **environment},
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )


def test_settings_change_without_rebuilding() -> None:
    """One image emits different public config for different deployments."""
    first = render(VALID)
    assert first.returncode == 0, first.stderr
    prefix = "window.__RIVET_CONFIG__ = "
    assert first.stdout.startswith(prefix)
    settings = json.loads(first.stdout.removeprefix(prefix).rstrip(";\n"))
    assert settings == {
        "tenantId": VALID["RIVET_UI_ENTRA_TENANT_ID"],
        "clientId": VALID["RIVET_UI_ENTRA_CLIENT_ID"],
        "apiScope": VALID["RIVET_UI_ENTRA_API_SCOPE"],
    }
    alternate = dict(VALID, RIVET_UI_ENTRA_CLIENT_ID=VALID["RIVET_UI_ENTRA_TENANT_ID"])
    second = render(alternate)
    assert second.returncode == 0
    assert second.stdout != first.stdout
    https_scope = render(
        dict(VALID, RIVET_UI_ENTRA_API_SCOPE="https://api.example/access")
    )
    assert https_scope.returncode == 0


@pytest.mark.parametrize("missing", list(VALID))
def test_missing_settings_fail_startup(missing: str) -> None:
    """No config is emitted until every required field is valid."""
    environment = {name: value for name, value in VALID.items() if name != missing}
    result = render(environment)
    assert result.returncode != 0
    assert not result.stdout
    assert "public Entra configuration" in result.stderr


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("RIVET_UI_ENTRA_TENANT_ID", "common"),
        ("RIVET_UI_ENTRA_CLIENT_ID", VALID["RIVET_UI_ENTRA_CLIENT_ID"] + "\nunsafe"),
        ("RIVET_UI_ENTRA_API_SCOPE", 'api://example/x"};alert(1);//'),
        ("RIVET_UI_ENTRA_API_SCOPE", "api://example/x\ninvalid"),
        ("RIVET_UI_ENTRA_API_SCOPE", "https://user:secret@example/x"),
        ("RIVET_UI_ENTRA_API_SCOPE", "http://example/x"),
        ("RIVET_UI_ENTRA_API_SCOPE", "api://example/"),
        ("RIVET_UI_ENTRA_API_SCOPE", "api://example/" + "x" * 2048),
    ],
)
def test_invalid_values_are_rejected_without_echoing(name: str, value: str) -> None:
    """Malformed and executable-looking settings never enter browser code."""
    result = render({**VALID, name: value})
    assert result.returncode != 0
    assert not result.stdout
    assert value not in result.stderr


def test_only_public_allowlisted_values_are_exposed() -> None:
    """Unrelated secrets and auth-bypass requests stay outside public config."""
    result = render(
        {**VALID, "CLIENT_SECRET": "private-sentinel", "VITE_AUTH_DISABLED": "true"}
    )
    assert result.returncode == 0
    assert "private-sentinel" not in result.stdout
    assert "authDisabled" not in result.stdout


def test_image_build_is_independent_of_entra_values() -> None:
    """Entra settings belong to runtime Compose, never Docker build args."""
    dockerfile = (ROOT / "deploy/nginx/Dockerfile").read_text()
    assert "ARG VITE_ENTRA" not in dockerfile
    build = yaml.safe_load((ROOT / "deploy/compose.build.yml").read_text())
    assert not build["services"]["web"]["build"].get("args")
    runtime = yaml.safe_load((ROOT / "deploy/compose.yml").read_text())
    assert set(runtime["services"]["web"]["environment"]) == set(VALID)
    config = (ROOT / "deploy/nginx/container.conf").read_text()
    assert "location = /runtime-config.js" in config
    assert "alias /tmp/rivet-runtime-config.js;" in config
    assert 'default "no-store";' in config


def test_startup_writes_private_config_then_executes(tmp_path: Path) -> None:
    """Render atomically under tmpfs before handing control to the web server."""
    # Relocate the image's fixed tmpfs prefix into an isolated host test tree.
    destination = tmp_path / "runtime-config"
    launcher = tmp_path / "entrypoint.sh"
    launcher.write_text(
        ENTRYPOINT.read_text().replace("/tmp/rivet-runtime-config", str(destination))
    )
    result = subprocess.run(
        ["/bin/sh", str(launcher), "/usr/bin/true"],
        env={"PATH": "/usr/bin:/bin", **VALID},
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    generated = destination.with_suffix(".js")
    assert generated.read_text() == render(VALID).stdout
    assert generated.stat().st_mode & 0o777 == 0o600
    assert set(tmp_path.iterdir()) == {launcher, generated}
