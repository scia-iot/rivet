"""Operator-only encrypted API and agent intent recovery beside an M0 bundle.

This module has no API endpoint or runtime service hook. The operator must
freeze all persistent writers and authenticate the linked OpenVPN M0 bundle
separately before it can assemble or restore a coordinated generation.
"""

import datetime
import hashlib
import io
import json
import os
import pathlib
import re
import sqlite3
import stat
import tarfile
import tempfile
import time
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sciaiot.ovpncp.migration import filesystem

MAGIC = b"OVPNCP-RECOVERY\x00\x01AES256GCM\x00"
ROLES = ("api-data", "api-profile", "api-archives", "vpn-config", "vpn-journal")
ROLE_IDENTITIES = {
    "api-data": (65531, 65531),
    "api-profile": (65531, 65531),
    "api-archives": (65531, 65531),
    "vpn-config": (65532, 65532),
    "vpn-journal": (65532, 65532),
}
CONFIG_INTENT = frozenset({"ownership.json", ".ovpncp-journal-identity"})
CONFIG_M0 = frozenset({"server.conf"})
SQLITE_SIDEFILES = {
    "api-data": frozenset({"ovpncp.db-wal", "ovpncp.db-shm"}),
    "vpn-journal": frozenset(
        {"operations.sqlite3-wal", "operations.sqlite3-shm", "writer.lock"}
    ),
}
MAX_FILES = 1024
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024


class RecoveryError(ValueError):
    """A redacted refusal to capture or restore a recovery generation."""


@dataclass(frozen=True)
class RecoverySnapshot:
    """Authenticated private state, never suitable for logging or API output."""

    manifest: dict[str, Any]
    files: dict[str, bytes]


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _generation(value: str) -> None:
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value) is None:
        raise RecoveryError("invalid recovery generation identifier")


def _hash(value: str) -> None:
    if re.fullmatch(r"[a-f0-9]{64}", value) is None:
        raise RecoveryError("invalid recovery artifact digest")


def _metadata(path: pathlib.Path, role: str, *, directory: bool) -> dict[str, int]:
    info = path.stat(follow_symlinks=False)
    expected = ROLE_IDENTITIES[role]
    mode = stat.S_IMODE(info.st_mode)
    if (
        info.st_uid != expected[0]
        or info.st_gid != expected[1]
        or (directory and (not stat.S_ISDIR(info.st_mode) or mode != 0o700))
        or (
            not directory
            and (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or mode not in {0o400, 0o600}
            )
        )
    ):
        raise RecoveryError("recovery source owner, mode or file type mismatch")
    return {"uid": info.st_uid, "gid": info.st_gid, "mode": mode}


def _sqlite_backup(path: pathlib.Path) -> bytes:
    """Back up a frozen DB and optional WAL from private writable scratch."""
    try:
        database = filesystem.read_file(path, MAX_FILE_BYTES)
        wal_path = path.with_name(f"{path.name}-wal")
        wal = None
        if wal_path.exists() or wal_path.is_symlink():
            wal = filesystem.read_file(wal_path, MAX_FILE_BYTES)
        if len(database) + len(wal or b"") > MAX_TOTAL_BYTES:
            raise RecoveryError("SQLite source exceeds recovery bound")
        with tempfile.TemporaryDirectory(prefix="ovpncp-recovery-sqlite-") as name:
            scratch = pathlib.Path(name) / path.name
            filesystem.write_private(scratch, database)
            if wal is not None:
                filesystem.write_private(scratch.with_name(f"{path.name}-wal"), wal)
            source = sqlite3.connect(f"{scratch.as_uri()}?mode=ro", uri=True)
            backup_path = scratch.with_name("backup.db")
            backup = sqlite3.connect(backup_path)
            os.chmod(backup_path, 0o600)
            try:
                page_count = source.execute("PRAGMA page_count").fetchone()[0]
                page_size = source.execute("PRAGMA page_size").fetchone()[0]
                if page_count * page_size > MAX_FILE_BYTES:
                    raise RecoveryError("SQLite snapshot exceeds recovery bound")
                deadline = time.monotonic() + 30

                def progress(_: int, remaining: int, total: int) -> None:
                    if (
                        time.monotonic() > deadline
                        or total * page_size > MAX_FILE_BYTES
                        or remaining < 0
                    ):
                        raise RecoveryError("SQLite backup deadline or size exceeded")

                source.backup(backup, pages=256, progress=progress)
                backup.execute("PRAGMA journal_mode=DELETE")
                if backup.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                    raise RecoveryError("SQLite backup failed integrity check")
            finally:
                backup.close()
                source.close()
            return filesystem.read_file(backup_path, MAX_FILE_BYTES)
    except RecoveryError:
        raise
    except OSError, sqlite3.Error, ValueError:
        raise RecoveryError("API SQLite backup failed") from None


def _capture_files(root: pathlib.Path) -> tuple[dict[str, bytes], dict[str, object]]:
    files: dict[str, bytes] = {}
    file_metadata: dict[str, object] = {}
    directories: dict[str, object] = {}
    total = 0
    for role in ROLES:
        path = root / role
        directories[role] = _metadata(path, role, directory=True)
        try:
            names, folders = filesystem.tree(path, MAX_FILES)
        except OSError, ValueError:
            raise RecoveryError("unsafe recovery source tree") from None
        for name in folders:
            directories[f"{role}/{name}"] = _metadata(path / name, role, directory=True)
        for name in names:
            if role == "vpn-config":
                if name in CONFIG_M0:
                    continue
                if name not in CONFIG_INTENT:
                    raise RecoveryError("unreviewed agent configuration artifact")
            if name in SQLITE_SIDEFILES.get(role, ()):
                continue
            logical = f"{role}/{name}"
            metadata = _metadata(path / name, role, directory=False)
            try:
                data = (
                    _sqlite_backup(path / name)
                    if logical
                    in {"api-data/ovpncp.db", "vpn-journal/operations.sqlite3"}
                    else filesystem.read_file(path / name, MAX_FILE_BYTES)
                )
            except OSError, ValueError:
                raise RecoveryError(
                    "recovery source changed or cannot be read"
                ) from None
            total += len(data)
            if (
                len(files) >= MAX_FILES
                or len(data) > MAX_FILE_BYTES
                or total > MAX_TOTAL_BYTES
            ):
                raise RecoveryError("recovery file count or size limit exceeded")
            files[logical] = data
            file_metadata[logical] = {
                **metadata,
                "size": len(data),
                "sha256": _digest(data),
            }
    for required in (
        "api-data/ovpncp.db",
        "vpn-config/ownership.json",
        "vpn-config/.ovpncp-journal-identity",
        "vpn-journal/operations.sqlite3",
    ):
        if required not in files:
            raise RecoveryError("required coordinated recovery state missing")
    return files, {"files": file_metadata, "directories": directories}


def _fingerprint(root: pathlib.Path) -> dict[str, tuple[int, ...]]:
    """Detect a mutation anywhere in the approved roles during capture."""
    observed: dict[str, tuple[int, ...]] = {}
    try:
        for role in ROLES:
            base = root / role
            files, directories = filesystem.tree(base, MAX_FILES)
            for name in ["", *directories, *files]:
                path = base / name
                info = path.stat(follow_symlinks=False)
                observed[f"{role}/{name}"] = (
                    info.st_dev,
                    info.st_ino,
                    info.st_size,
                    info.st_mtime_ns,
                    info.st_ctime_ns,
                    info.st_mode,
                    info.st_uid,
                    info.st_gid,
                )
    except OSError, ValueError:
        raise RecoveryError("unsafe or changing recovery source") from None
    return observed


def capture(
    root: pathlib.Path,
    key: bytes,
    *,
    generation: str,
    m0_sha256: str,
    image_digests: dict[str, str],
    writers_frozen: bool,
) -> bytes:
    """Seal a bounded separate API/agent recovery set while writers are frozen."""
    if not writers_frozen:
        raise RecoveryError("all recovery writers must be frozen")
    if len(key) != 32:
        raise RecoveryError("recovery key must contain 32 bytes")
    _generation(generation)
    _hash(m0_sha256)
    if set(image_digests) != {"api", "agent", "openvpn", "web"}:
        raise RecoveryError("invalid recovery image inventory")
    for digest in image_digests.values():
        if not isinstance(digest, str):
            raise RecoveryError("invalid recovery image digest")
        _hash(digest)
    root = pathlib.Path(os.path.abspath(root))
    if root.is_symlink() or not root.is_dir():
        raise RecoveryError("private recovery source root required")
    try:
        with filesystem.directory(root) as descriptor:
            info = os.fstat(descriptor)
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise RecoveryError("private recovery source root required")
    except OSError, ValueError:
        raise RecoveryError("private recovery source root required") from None
    before = _fingerprint(root)
    files, metadata = _capture_files(root)
    if _fingerprint(root) != before:
        raise RecoveryError("recovery source changed during frozen capture")
    manifest: dict[str, object] = {
        "schema": 1,
        "generation": generation,
        "captured_at": datetime.datetime.now(datetime.UTC).isoformat(),
        "m0_sha256": m0_sha256,
        "image_digests": image_digests,
        **metadata,
    }
    stream = io.BytesIO()
    payload = {"manifest.json": json.dumps(manifest, sort_keys=True).encode()}
    payload.update({f"files/{name}": data for name, data in files.items()})
    try:
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for name, data in sorted(payload.items()):
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                entry.mode = 0o600
                tar.addfile(entry, io.BytesIO(data))
    except OSError, ValueError, tarfile.TarError:
        raise RecoveryError("recovery archive cannot be encoded") from None
    plain = stream.getvalue()
    if len(plain) > MAX_TOTAL_BYTES + 4 * 1024 * 1024:
        raise RecoveryError("recovery archive size limit exceeded")
    nonce = os.urandom(12)
    return MAGIC + nonce + AESGCM(key).encrypt(nonce, plain, MAGIC)


def _pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for name, item in items:
        if name in value:
            raise RecoveryError("duplicate recovery manifest field")
        value[name] = item
    return value


def _validate_snapshot(
    snapshot: RecoverySnapshot,
    m0_sha256: str,
    expected_images: dict[str, str],
) -> None:
    manifest = snapshot.manifest
    if (
        set(manifest)
        != {
            "schema",
            "generation",
            "captured_at",
            "m0_sha256",
            "image_digests",
            "files",
            "directories",
        }
        or manifest["schema"] != 1
        or manifest["m0_sha256"] != m0_sha256
        or not isinstance(manifest["generation"], str)
        or not isinstance(manifest["files"], dict)
        or not isinstance(manifest["directories"], dict)
        or set(manifest["files"]) != set(snapshot.files)
    ):
        raise RecoveryError("coordinated recovery manifest mismatch")
    _generation(manifest["generation"])
    _hash(m0_sha256)
    if not isinstance(manifest["captured_at"], str):
        raise RecoveryError("invalid recovery capture timestamp")
    try:
        captured = datetime.datetime.fromisoformat(manifest["captured_at"])
    except ValueError:
        raise RecoveryError("invalid recovery capture timestamp") from None
    if captured.utcoffset() != datetime.timedelta(0):
        raise RecoveryError("recovery capture timestamp must be UTC")
    images = manifest["image_digests"]
    if (
        not isinstance(images, dict)
        or set(images) != {"api", "agent", "openvpn", "web"}
        or images != expected_images
    ):
        raise RecoveryError("invalid recovery image inventory")
    for digest in images.values():
        if not isinstance(digest, str):
            raise RecoveryError("invalid recovery image digest")
        _hash(digest)
    if len(snapshot.files) > MAX_FILES:
        raise RecoveryError("recovery file count limit exceeded")
    if sum(len(data) for data in snapshot.files.values()) > MAX_TOTAL_BYTES:
        raise RecoveryError("recovery total size limit exceeded")
    for name, data in snapshot.files.items():
        path = pathlib.PurePosixPath(name)
        if (
            path.is_absolute()
            or ".." in path.parts
            or len(path.parts) < 2
            or path.parts[0] not in ROLES
            or name != path.as_posix()
            or "\\" in name
        ):
            raise RecoveryError("unsafe recovery member path")
        detail = manifest["files"][name]
        role = path.parts[0]
        if (
            role == "vpn-config"
            and name.removeprefix("vpn-config/") not in CONFIG_INTENT
        ):
            raise RecoveryError("unreviewed agent configuration artifact")
        if path.name in SQLITE_SIDEFILES.get(role, ()):
            raise RecoveryError("ephemeral SQLite artifact in recovery set")
        if (
            not isinstance(detail, dict)
            or detail
            != {
                "uid": ROLE_IDENTITIES[role][0],
                "gid": ROLE_IDENTITIES[role][1],
                "mode": detail.get("mode"),
                "size": len(data),
                "sha256": _digest(data),
            }
            or detail["mode"] not in {0o400, 0o600}
        ):
            raise RecoveryError("recovery member metadata mismatch")
    for name, detail in manifest["directories"].items():
        path = pathlib.PurePosixPath(name)
        if (
            path.is_absolute()
            or ".." in path.parts
            or not path.parts
            or path.parts[0] not in ROLES
            or name != path.as_posix()
            or "\\" in name
            or (path.parts[0] == "vpn-config" and len(path.parts) != 1)
            or name in snapshot.files
            or detail
            != {
                "uid": ROLE_IDENTITIES[path.parts[0]][0],
                "gid": ROLE_IDENTITIES[path.parts[0]][1],
                "mode": 0o700,
            }
        ):
            raise RecoveryError("recovery directory metadata mismatch")
    for name in snapshot.files:
        if str(pathlib.PurePosixPath(name).parent) not in manifest["directories"]:
            raise RecoveryError("recovery file parent directory missing")
    for name in manifest["directories"]:
        parent = pathlib.PurePosixPath(name).parent
        if str(parent) != "." and str(parent) not in manifest["directories"]:
            raise RecoveryError("recovery parent directory missing")
    for role in ROLES:
        if role not in manifest["directories"]:
            raise RecoveryError("recovery role missing")
    for required in (
        "api-data/ovpncp.db",
        "vpn-config/ownership.json",
        "vpn-config/.ovpncp-journal-identity",
        "vpn-journal/operations.sqlite3",
    ):
        if required not in snapshot.files:
            raise RecoveryError("required coordinated recovery state missing")


def open_set(
    data: bytes,
    key: bytes,
    *,
    m0_sha256: str,
    expected_images: dict[str, str],
) -> RecoverySnapshot:
    """Authenticate all bytes and the linked M0 digest before parsing members."""
    if (
        len(key) != 32
        or len(data) > MAX_TOTAL_BYTES + 4 * 1024 * 1024 + 64
        or not data.startswith(MAGIC)
    ):
        raise RecoveryError("invalid encrypted recovery artifact")
    try:
        offset = len(MAGIC)
        plain = AESGCM(key).decrypt(
            data[offset : offset + 12], data[offset + 12 :], MAGIC
        )
    except InvalidTag, ValueError:
        raise RecoveryError("recovery authentication failed") from None
    files: dict[str, bytes] = {}
    manifest: dict[str, Any] | None = None
    try:
        with tarfile.open(fileobj=io.BytesIO(plain), mode="r:") as tar:
            for member in tar:
                if (
                    not member.isfile()
                    or member.mode != 0o600
                    or member.uid != 0
                    or member.gid != 0
                    or member.name == ""
                    or member.size > MAX_FILE_BYTES
                    or len(files) > MAX_FILES
                ):
                    raise RecoveryError("unsafe recovery archive member")
                stream = tar.extractfile(member)
                if stream is None:
                    raise RecoveryError("missing recovery archive member")
                content = stream.read(MAX_FILE_BYTES + 1)
                if len(content) != member.size:
                    raise RecoveryError("truncated recovery archive member")
                if member.name == "manifest.json":
                    if manifest is not None:
                        raise RecoveryError("duplicate recovery manifest")
                    manifest = json.loads(content, object_pairs_hook=_pairs)
                elif member.name.startswith("files/"):
                    name = member.name[6:]
                    if name in files:
                        raise RecoveryError("duplicate recovery member")
                    files[name] = content
                else:
                    raise RecoveryError("unexpected recovery archive member")
    except OSError, UnicodeError, json.JSONDecodeError, tarfile.TarError:
        raise RecoveryError("invalid recovery archive") from None
    if not isinstance(manifest, dict):
        raise RecoveryError("missing recovery manifest")
    result = RecoverySnapshot(manifest, files)
    _validate_snapshot(result, m0_sha256, expected_images)
    return result


def restore(
    snapshot: RecoverySnapshot,
    destination: pathlib.Path,
    *,
    expected_images: dict[str, str],
) -> None:
    """Write authenticated roles only into a new stopped private generation."""
    _validate_snapshot(snapshot, snapshot.manifest["m0_sha256"], expected_images)
    destination = pathlib.Path(os.path.abspath(destination))
    if destination.exists() or destination.is_symlink():
        raise RecoveryError("recovery destination must be a new private generation")
    try:
        with filesystem.directory(destination.parent) as descriptor:
            parent = os.fstat(descriptor)
            if parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
                raise RecoveryError("private recovery destination parent required")
    except OSError, ValueError:
        raise RecoveryError("private recovery destination parent required") from None
    destination.mkdir(mode=0o700)
    try:
        directories = snapshot.manifest["directories"]
        for name in sorted(directories, key=lambda value: (value.count("/"), value)):
            path = destination / name
            path.mkdir(mode=0o700)
            role = pathlib.PurePosixPath(name).parts[0]
            os.chown(path, *ROLE_IDENTITIES[role], follow_symlinks=False)
            path.chmod(0o700)
        for name, data in sorted(snapshot.files.items()):
            path = destination / name
            filesystem.write_private(path, data)
            role = pathlib.PurePosixPath(name).parts[0]
            os.chown(path, *ROLE_IDENTITIES[role], follow_symlinks=False)
            path.chmod(snapshot.manifest["files"][name]["mode"])
    except OSError, ValueError:
        raise RecoveryError("recovery staging failed; inspect private target") from None
