"""Pure boundary checks for the opt-in native host rehearsal."""

import json
import os
from pathlib import Path
from unittest import mock

import pytest

from sciaiot.ovpncp.migration import container_target
from sciaiot.ovpncp.native_assets import export
from tests.integration import native_host_rehearsal as host


def test_render_server_config_uses_installed_hook_and_reviewed_bind() -> None:
    """A copied server config points to the wheel hook and local listener."""
    source = (
        Path(__file__).resolve().parents[1] / "deploy/containers/server.conf.example"
    ).read_text()
    actual = host.render_server_config(source, "198.51.100.22")
    assert actual.count(str(host.AGENT_VENV / "bin/ovpncp-vpn-event")) == 2
    assert "/usr/local/bin/ovpncp-vpn-event" not in actual
    assert "local 198.51.100.22\n" in actual


def test_render_server_config_accepts_quoted_m0_directives() -> None:
    """The M0 target serializer quotes option names and their arguments."""
    hook = container_target.HOOK_COMMAND
    source = "\n".join(
        (
            '"dev" "tun0"',
            '"user" "ovpn-openvpn"',
            '"group" "ovpn-runtime"',
            '"management" "/run/openvpn/management.sock" "unix"',
            '"client-config-dir" "/var/lib/ovpn-agent/projection/ccd"',
            f'"client-connect" "{hook}"',
            f'"client-disconnect" "{hook}"',
            "",
        )
    )
    actual = host.render_server_config(source, None)
    assert actual.count(str(host.AGENT_VENV / "bin/ovpncp-vpn-event")) == 2
    assert '"dev" "tun0"' in actual


@pytest.mark.parametrize(
    "change",
    [
        lambda value: value.replace("dev tun0", "dev tun1"),
        lambda value: value.replace("--agent-uid 65532", "--agent-uid 0", 1),
        lambda value: value.replace("local <vpn-bind-ip>", ""),
    ],
)
def test_render_server_config_rejects_incompatible_source(change: object) -> None:
    """A source drift must stop before any privileged host mutation."""
    source = (
        Path(__file__).resolve().parents[1] / "deploy/containers/server.conf.example"
    ).read_text()
    assert callable(change)
    with pytest.raises(ValueError):
        host.render_server_config(change(source), "198.51.100.22")


def test_source_tree_rejects_symlinks_and_hardlinks(tmp_path: Path) -> None:
    """A private copy cannot redirect staging outside its trusted tree."""
    source = tmp_path / "frozen"
    source.mkdir()
    (source / "file").write_bytes(b"test")
    host._tree(source)
    (source / "link").symlink_to(source / "file")
    with pytest.raises(ValueError):
        host._tree(source)
    (source / "link").unlink()
    os.link(source / "file", source / "second")
    with pytest.raises(ValueError):
        host._tree(source)


def test_canary_mutations_use_api_identity_and_validate_run_id(tmp_path: Path) -> None:
    """The helper only sends an allowed client mutation as ovpn-api."""
    root = tmp_path / "012345abcdef"
    root.mkdir()
    with (
        mock.patch.object(host, "_manifest", return_value={}),
        mock.patch.object(
            host,
            "_command",
            return_value=json.dumps(
                {"action": "assign", "state": "succeeded", "generation": 3}
            ).encode(),
        ) as command,
    ):
        result = host.mutate(root, "assign", "native-012345abcdef", "10.231.0.30")
        assert result == {"canary_action": "assign", "result": "succeeded"}
        argv = command.call_args.args
        assert argv[:4] == ("/usr/sbin/runuser", "-u", "ovpn-api", "--")
        assert argv[-3:] == ("assign", "native-012345abcdef", "10.231.0.30")
        with pytest.raises(ValueError):
            host.mutate(root, "revoke", "existing-client")
        with pytest.raises(ValueError):
            host.mutate(root, "assign", "native-012345abcdef", "not-an-ip")
        assert command.call_count == 1


def test_http_header_lookup_is_case_insensitive() -> None:
    """Uvicorn and Nginx may spell HTTP response header names differently."""
    assert (
        host._header({"content-type": "application/problem+json"}, "Content-Type")
        == "application/problem+json"
    )
    assert host._header({"Cache-Control": "no-store"}, "cache-control") == "no-store"


def test_staging_uses_wheel_templates_and_public_runtime_ui(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both service identities can traverse config, while env files stay private."""
    assets = tmp_path / "assets"
    export(assets)
    ui = tmp_path / "dist"
    ui.mkdir()
    (ui / "index.html").write_text('<script src="/assets/app.js"></script>')
    (ui / "assets").mkdir()
    (ui / "assets/app.js").write_text("app")
    target = tmp_path / "target"
    target.mkdir()
    for name in ("ETC", "SYSTEMD", "FRONTEND"):
        path = (
            target / "public" / "frontend"
            if name == "FRONTEND"
            else target / name.lower()
        )
        if name == "SYSTEMD":
            path.mkdir()
        monkeypatch.setattr(host, name, path)
    monkeypatch.setattr(host, "TMPFILES", target / "tmpfiles.conf")
    monkeypatch.setattr(host, "NGINX", target / "nginx.conf")
    previous = os.umask(0o077)
    try:
        with mock.patch.object(host.os, "chown") as chown:
            installed = host._stage_config(assets, "012345abcdef", ui)
    finally:
        os.umask(previous)
    assert (host.ETC.stat().st_mode & 0o777) == 0o755
    assert (host.FRONTEND.stat().st_mode & 0o777) == 0o755
    assert (host.FRONTEND.parent.stat().st_mode & 0o777) == 0o755
    assert (host.FRONTEND / "releases").stat().st_mode & 0o777 == 0o755
    assert (host.ETC / "agent.env").stat().st_mode & 0o777 == 0o640
    assert (host.ETC / "api.env").stat().st_mode & 0o777 == 0o600
    assert mock.call(host.ETC / "api.env", 0, 0) in chown.call_args_list
    agent = (host.ETC / "agent.env").read_text()
    assert "OVPNCP_AGENT_MUTATIONS=assignments,pki,events,management" in agent
    assert "REPLACE_WITH_" not in agent
    assert (
        b"window.__OVPNCP_CONFIG__"
        in (host.FRONTEND / "runtime-config.js").read_bytes()
    )
    assert (host.FRONTEND / "current/index.html").read_text() == (
        ui / "index.html"
    ).read_text()
    assert host.NGINX in installed


def test_staging_resets_journal_identity_and_ownership(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The host rehearsal cannot inherit Compose mutation ownership."""
    source = tmp_path / "source"
    for name in host.SOURCE_NAMES:
        (source / name).mkdir(parents=True)
    projection = source / "vpn-projection"
    (projection / "ccd").mkdir()
    for name in ("ca.crt", "server.crt", "server.key", "crl.pem"):
        (projection / name).write_text(name)
    (projection / "server.conf").write_text(
        (
            Path(__file__).resolve().parents[1]
            / "deploy/containers/server.conf.example"
        ).read_text()
    )
    (projection / ".ovpncp-journal-identity").write_text("old")
    for name in ("AGENT_STATE", "API_STATE", "OPENVPN_STATE"):
        monkeypatch.setattr(host, name, tmp_path / name.lower())
    previous = os.umask(0o077)
    try:
        with mock.patch.object(host.os, "chown"):
            host._stage_state(source, "198.51.100.22", "012345abcdef")
    finally:
        os.umask(previous)
    assert (host.AGENT_STATE.stat().st_mode & 0o777) == 0o750
    assert (host.API_STATE.stat().st_mode & 0o777) == 0o750
    assert (host.OPENVPN_STATE.stat().st_mode & 0o777) == 0o770
    assert not (host.AGENT_STATE / "projection/.ovpncp-journal-identity").exists()
    assert json.loads((host.AGENT_STATE / "config/ownership.json").read_text()) == {
        "version": "1.0",
        "routes": [],
        "access": [],
        "pushes": [],
    }
    assert list((host.AGENT_STATE / "journal").iterdir()) == []
    assert list(host.API_STATE.glob("*.sqlite*")) == []
    assert (host.AGENT_STATE / "projection/server.conf").stat().st_mode & 0o777 == 0o640
