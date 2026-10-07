"""Coordinated API and agent recovery artifacts remain separate from M0."""

import json
import os
import sqlite3
from copy import deepcopy
from pathlib import Path

import pytest

from sciaiot.ovpncp import recovery_set


def _images() -> dict[str, str]:
    return {
        "api": "b" * 64,
        "agent": "c" * 64,
        "openvpn": "d" * 64,
        "web": "e" * 64,
    }


@pytest.fixture
def recovery_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Create only the fixed synthetic API and agent persistent roles."""
    identity = (os.geteuid(), os.getegid())
    monkeypatch.setattr(
        recovery_set,
        "ROLE_IDENTITIES",
        {role: identity for role in recovery_set.ROLES},
    )
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    for role in recovery_set.ROLES:
        (root / role).mkdir(mode=0o700)
    database = root / "api-data/ovpncp.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE operations (id TEXT PRIMARY KEY)")
        connection.execute("INSERT INTO operations VALUES ('acknowledged')")
    database.chmod(0o600)
    (root / "api-profile/client.ovpn").write_bytes(b"synthetic profile\n")
    (root / "api-profile/client.ovpn").chmod(0o600)
    (root / "api-archives/client.zip").write_bytes(b"synthetic archive\n")
    (root / "api-archives/client.zip").chmod(0o600)
    (root / "vpn-config/ownership.json").write_text(
        json.dumps({"version": "1.0", "routes": [], "access": [], "pushes": []})
    )
    (root / "vpn-config/ownership.json").chmod(0o600)
    (root / "vpn-config/.ovpncp-journal-identity").write_text(
        '{"identity":"synthetic","revision":1}'
    )
    (root / "vpn-config/.ovpncp-journal-identity").chmod(0o600)
    with sqlite3.connect(root / "vpn-journal/operations.sqlite3") as connection:
        connection.execute("CREATE TABLE generations (value INTEGER)")
        connection.execute("INSERT INTO generations VALUES (1)")
    (root / "vpn-journal/operations.sqlite3").chmod(0o600)
    return root


def test_encrypted_recovery_roundtrip_and_exact_owned_restore(
    recovery_tree: Path, tmp_path: Path
) -> None:
    """Recover API persistence and agent intent without exposing M0 secrets."""
    key = b"r" * 32
    artifact = recovery_set.capture(
        recovery_tree,
        key,
        generation="test-generation-1",
        m0_sha256="a" * 64,
        image_digests=_images(),
        writers_frozen=True,
    )
    assert b"acknowledged" not in artifact
    verified = recovery_set.open_set(
        artifact, key, m0_sha256="a" * 64, expected_images=_images()
    )
    assert verified.manifest["generation"] == "test-generation-1"
    destination = tmp_path / "restored"
    recovery_set.restore(verified, destination, expected_images=_images())
    assert (destination / "api-profile/client.ovpn").read_bytes() == (
        recovery_tree / "api-profile/client.ovpn"
    ).read_bytes()
    with sqlite3.connect(destination / "api-data/ovpncp.db") as connection:
        assert connection.execute("SELECT id FROM operations").fetchone() == (
            "acknowledged",
        )
    with sqlite3.connect(destination / "vpn-journal/operations.sqlite3") as connection:
        assert connection.execute("SELECT value FROM generations").fetchone() == (1,)
    assert not any(path.name.startswith("migration") for path in destination.rglob("*"))


@pytest.mark.parametrize("attack", ["wrong_key", "tamper", "wrong_m0", "wrong_image"])
def test_recovery_rejects_authentication_or_m0_mismatch(
    recovery_tree: Path, attack: str
) -> None:
    """No recovery member is visible before both artifacts are authenticated."""
    artifact = recovery_set.capture(
        recovery_tree,
        b"r" * 32,
        generation="test-generation-1",
        m0_sha256="a" * 64,
        image_digests=_images(),
        writers_frozen=True,
    )
    key = b"x" * 32 if attack == "wrong_key" else b"r" * 32
    if attack == "tamper":
        artifact = artifact[:-1] + bytes([artifact[-1] ^ 1])
    with pytest.raises(recovery_set.RecoveryError):
        recovery_set.open_set(
            artifact,
            key,
            m0_sha256="f" * 64 if attack == "wrong_m0" else "a" * 64,
            expected_images=(
                {**_images(), "api": "f" * 64} if attack == "wrong_image" else _images()
            ),
        )


@pytest.mark.parametrize("attack", ["symlink", "hardlink", "extra_intent"])
def test_recovery_rejects_unsafe_or_unowned_source(
    recovery_tree: Path, tmp_path: Path, attack: str
) -> None:
    """The operator cannot accidentally back up links or broad config trees."""
    if attack == "symlink":
        (recovery_tree / "api-profile/unsafe").symlink_to("/etc/passwd")
    elif attack == "hardlink":
        (recovery_tree / "api-profile/unsafe").hardlink_to(
            recovery_tree / "api-profile/client.ovpn"
        )
    else:
        (recovery_tree / "vpn-config/unreviewed.json").write_text("unowned")
    with pytest.raises(recovery_set.RecoveryError):
        recovery_set.capture(
            recovery_tree,
            b"r" * 32,
            generation="test-generation-1",
            m0_sha256="a" * 64,
            image_digests=_images(),
            writers_frozen=True,
        )
    assert not (tmp_path / "recovered").exists()


def test_recovery_refuses_live_capture_and_nonempty_restore(
    recovery_tree: Path, tmp_path: Path
) -> None:
    """Both sides require a stopped, explicitly owned generation boundary."""
    with pytest.raises(recovery_set.RecoveryError, match="frozen"):
        recovery_set.capture(
            recovery_tree,
            b"r" * 32,
            generation="test-generation-1",
            m0_sha256="a" * 64,
            image_digests=_images(),
            writers_frozen=False,
        )
    artifact = recovery_set.capture(
        recovery_tree,
        b"r" * 32,
        generation="test-generation-1",
        m0_sha256="a" * 64,
        image_digests=_images(),
        writers_frozen=True,
    )
    state = recovery_set.open_set(
        artifact, b"r" * 32, m0_sha256="a" * 64, expected_images=_images()
    )
    destination = tmp_path / "restored"
    destination.mkdir()
    (destination / "unrelated").write_text("preserve")
    with pytest.raises(recovery_set.RecoveryError):
        recovery_set.restore(state, destination, expected_images=_images())
    assert (destination / "unrelated").read_text() == "preserve"


def test_recovery_backs_up_committed_agent_journal_wal(
    recovery_tree: Path, tmp_path: Path
) -> None:
    """A stopped journal checkpoint includes committed data still in WAL."""
    journal = recovery_tree / "vpn-journal/operations.sqlite3"
    with sqlite3.connect(journal) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("INSERT INTO generations VALUES (2)")
        connection.commit()
        artifact = recovery_set.capture(
            recovery_tree,
            b"r" * 32,
            generation="test-generation-2",
            m0_sha256="a" * 64,
            image_digests=_images(),
            writers_frozen=True,
        )
    state = recovery_set.open_set(
        artifact, b"r" * 32, m0_sha256="a" * 64, expected_images=_images()
    )
    destination = tmp_path / "restored"
    recovery_set.restore(state, destination, expected_images=_images())
    with sqlite3.connect(destination / "vpn-journal/operations.sqlite3") as connection:
        assert connection.execute(
            "SELECT value FROM generations ORDER BY value"
        ).fetchall() == [(1,), (2,)]


def test_recovery_rejects_forged_m0_configuration_member(
    recovery_tree: Path, tmp_path: Path
) -> None:
    """An outer recovery artifact cannot overwrite M0's server config."""
    artifact = recovery_set.capture(
        recovery_tree,
        b"r" * 32,
        generation="test-generation-1",
        m0_sha256="a" * 64,
        image_digests=_images(),
        writers_frozen=True,
    )
    state = recovery_set.open_set(
        artifact, b"r" * 32, m0_sha256="a" * 64, expected_images=_images()
    )
    manifest = deepcopy(state.manifest)
    manifest["files"]["vpn-config/server.conf"] = {
        "uid": recovery_set.ROLE_IDENTITIES["vpn-config"][0],
        "gid": recovery_set.ROLE_IDENTITIES["vpn-config"][1],
        "mode": 0o600,
        "size": 0,
        "sha256": recovery_set._digest(b""),
    }
    forged = recovery_set.RecoverySnapshot(
        manifest, {**state.files, "vpn-config/server.conf": b""}
    )
    destination = tmp_path / "restored"
    with pytest.raises(recovery_set.RecoveryError):
        recovery_set.restore(forged, destination, expected_images=_images())
    assert not destination.exists()


def test_sqlite_backup_uses_private_scratch_for_readonly_source(
    recovery_tree: Path,
) -> None:
    """A frozen read-only volume still yields a backed-up SQLite image."""
    source = recovery_tree / "api-data/ovpncp.db"
    with sqlite3.connect(source) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
    parent = source.parent
    parent.chmod(0o500)
    try:
        contents = recovery_set._sqlite_backup(source)
    finally:
        parent.chmod(0o700)
    restored = sqlite3.connect(":memory:")
    try:
        restored.deserialize(contents)
        assert restored.execute("SELECT id FROM operations").fetchone() == (
            "acknowledged",
        )
    finally:
        restored.close()
