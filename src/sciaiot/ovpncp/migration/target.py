"""Offline migration-owned staging, activation, verification, and rollback."""

import contextlib
import fcntl
import grp
import json
import os
import pathlib
import pwd
import re
import shutil
import stat
import uuid
from collections.abc import Iterator

from sciaiot.ovpncp.migration import filesystem, validation
from sciaiot.ovpncp.migration.models import (
    MAX_FILES,
    MigrationError,
    Snapshot,
    TargetSpec,
    validate_versions,
)

MARKER = ".ovpncp-migration.json"
JOURNAL = ".rollback.json"


def _sync(path: pathlib.Path) -> None:
    with filesystem.directory(path) as fd:
        os.fsync(fd)


def _json(path: pathlib.Path) -> dict[str, object]:
    try:
        value = json.loads(filesystem.read_file(path))
        if not isinstance(value, dict):
            raise TypeError
        return value
    except ValueError, TypeError, UnicodeError:
        raise MigrationError("invalid target migration metadata") from None


def _replace_json(path: pathlib.Path, value: dict[str, object]) -> None:
    temporary = path.with_name(f".metadata-{uuid.uuid4().hex}")
    filesystem.write_private(temporary, json.dumps(value, sort_keys=True).encode())
    os.replace(temporary, path)
    _sync(path.parent)


def _owned(
    destination: pathlib.Path,
    *,
    create: bool = False,
    profile: str = "offline",
) -> None:
    expected = {"schema": 1, "destination": str(destination)}
    if profile == "container":
        expected["profile"] = "container"
    elif profile != "offline":
        raise MigrationError("unsupported migration target profile")
    if not destination.exists():
        if not create:
            return
        with filesystem.directory(destination.parent):
            destination.mkdir(mode=0o700)
    with filesystem.directory(destination) as fd:
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise MigrationError("target must be privately owned by migration operator")
        children = set(os.listdir(fd))
    if not children and create:
        filesystem.write_private(
            destination / MARKER,
            json.dumps(expected).encode(),
        )
        return
    if not children:
        return
    if MARKER not in children or _json(destination / MARKER) != expected:
        raise MigrationError("non-empty target is not migration-owned")
    allowed = {MARKER, JOURNAL, "active", "rollback", ".lock"}
    if JOURNAL in children:
        stage = _json(destination / JOURNAL).get("stage")
        if isinstance(stage, str) and re.fullmatch(r"\.stage-[0-9a-f]{32}", stage):
            allowed.add(stage)
    if children - allowed:
        raise MigrationError(
            "unexpected migration-owned target contents; recover privately"
        )


@contextlib.contextmanager
def _lock(destination: pathlib.Path) -> Iterator[None]:
    with filesystem.directory(destination) as parent:
        fd = os.open(
            ".lock",
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
            dir_fd=parent,
        )
        try:
            if os.fstat(fd).st_nlink != 1 or not stat.S_ISREG(os.fstat(fd).st_mode):
                raise MigrationError("unsafe migration lock")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise MigrationError("conflicting migration operation") from None
            yield
        finally:
            os.close(fd)


def _identity(policy: TargetSpec) -> tuple[int, int]:
    try:
        owner = policy.owner or pwd.getpwuid(os.geteuid()).pw_name
        group = policy.group or grp.getgrgid(os.getegid()).gr_name
        if any(
            re.fullmatch(r"[a-z_][a-z0-9_-]*[$]?", name) is None
            for name in (owner, group)
        ):
            raise KeyError
        owner_id = pwd.getpwnam(owner).pw_uid
        if owner_id != os.geteuid():
            raise MigrationError(
                "offline target owner must be the migration operator; separate runtime ownership needs a reviewed mount adapter"
            )
        return owner_id, grp.getgrnam(group).gr_gid
    except KeyError:
        raise MigrationError(
            "target ownership requires existing reviewed user/group names"
        ) from None


def _render(
    state: Snapshot, active: pathlib.Path, policy: TargetSpec
) -> dict[str, bytes]:
    files = dict(state.files)
    for name, items in state.manifest.configurations.items():
        lines = []
        for item in items:
            args = list(item.args)
            for index, reference in item.references.items():
                if reference.startswith("hook/"):
                    replacement = policy.replacements.get(reference[5:])
                    if replacement is None:
                        raise MigrationError(
                            "compatibility requires reviewed hook replacement"
                        )
                    path = pathlib.Path(replacement.path)
                    if (
                        not path.is_absolute()
                        or filesystem.digest(filesystem.read_file(path))
                        != replacement.sha256
                    ):
                        raise MigrationError("reviewed hook replacement hash mismatch")
                    args[int(index)] = str(path)
                else:
                    args[int(index)] = str(active / reference)
            lines.append(" ".join(_quote(value) for value in [item.name, *args]))
        files[name] = ("\n".join(lines) + "\n").encode()
    return files


def _hash_tree(path: pathlib.Path) -> dict[str, object]:
    if not path.exists():
        return {"exists": False}
    files, directories = filesystem.tree(path, MAX_FILES * 2)
    entries: dict[str, object] = {}
    for name in ["", *directories, *files]:
        item = path / name
        info = item.stat(follow_symlinks=False)
        record: dict[str, object] = {
            "mode": info.st_mode & 0o7777,
            "uid": info.st_uid,
            "gid": info.st_gid,
        }
        if name in files:
            record["sha256"] = filesystem.digest(filesystem.read_file(item))
        entries[name] = record
    return {"exists": True, "entries": entries}


def _check_files(
    path: pathlib.Path, expected: dict[str, bytes], owner: int, group: int
) -> None:
    names, directories = filesystem.tree(path, MAX_FILES * 2)
    for name in ["", *directories, *names]:
        info = (path / name).stat(follow_symlinks=False)
        mode = 0o600 if name in names else 0o700
        if (
            info.st_mode & 0o7777 != mode
            or info.st_uid != owner
            or info.st_gid != group
        ):
            raise MigrationError("staged or active ownership/mode mismatch")
    if set(names) != set(expected) or any(
        filesystem.read_file(path / name) != data for name, data in expected.items()
    ):
        raise MigrationError("staged or active tree hash mismatch")


def install(
    state: Snapshot,
    destination: pathlib.Path,
    policy: TargetSpec,
    *,
    apply: bool = False,
    target_stopped: bool = False,
) -> dict[str, object]:
    """Validate by default; explicitly activate only an offline owned target.

    The prior active tree is the mandatory same-filesystem rollback snapshot.
    A durable journal precedes both atomic renames and permits crash recovery.
    """
    destination = pathlib.Path(os.path.abspath(destination))
    validate_policy(state, policy)
    owner, group = _identity(policy)
    expected = _render(state, destination / "active", policy)
    _owned(destination)
    if not apply:
        return {"dry_run": True, "compatible": True, "file_count": len(expected)}
    if not target_stopped:
        raise MigrationError("target must be stopped with all writers frozen")
    _owned(destination, create=True)
    with _lock(destination):
        if (destination / JOURNAL).exists():
            raise MigrationError(
                "rollback snapshot retained; roll back before another import"
            )
        active, backup = destination / "active", destination / "rollback"
        if backup.exists():
            raise MigrationError("unrecorded rollback snapshot; recover before import")
        stage = destination / f".stage-{uuid.uuid4().hex}"
        stage.mkdir(mode=0o700)
        journal_written = False
        try:
            folders = set(state.manifest.directories)
            for name in expected:
                folders.update(
                    parent.as_posix()
                    for parent in pathlib.PurePosixPath(name).parents
                    if parent.as_posix() != "."
                )
            for name in sorted(folders, key=lambda value: (value.count("/"), value)):
                (stage / name).mkdir(mode=0o700, exist_ok=True)
            for name, data in expected.items():
                filesystem.write_private(stage / name, data)
                os.chown(stage / name, owner, group, follow_symlinks=False)
            for name in sorted(folders, key=lambda value: -value.count("/")):
                os.chown(stage / name, owner, group, follow_symlinks=False)
                _sync(stage / name)
            os.chown(stage, owner, group, follow_symlinks=False)
            _check_files(stage, expected, owner, group)
            validation.validate(state)
            _sync(stage)
            previous = _hash_tree(active)
            _replace_json(
                destination / JOURNAL,
                {
                    "schema": 1,
                    "service_state": "stopped",
                    "previous": previous,
                    "stage": stage.name,
                },
            )
            journal_written = True
            if active.exists():
                os.replace(active, backup)
                _sync(destination)
            os.replace(stage, active)
            _sync(destination)
            _check_files(active, expected, owner, group)
        except BaseException:
            if journal_written:
                _restore(destination)
            raise
        finally:
            if stage.exists():
                shutil.rmtree(stage)
        return {
            "dry_run": False,
            "activated": True,
            "rollback_retained": True,
            "service_state": "stopped",
        }


def verify(
    state: Snapshot, destination: pathlib.Path, policy: TargetSpec | None = None
) -> dict[str, object]:
    """Compare exact rendered state and validated protected semantic identity."""
    destination = pathlib.Path(os.path.abspath(destination))
    validation.validate(state)
    _owned(destination)
    if policy is None:
        policy = TargetSpec(
            versions=state.manifest.versions, serial_policy=state.manifest.serial_policy
        )
    else:
        validate_policy(state, policy)
    owner, group = _identity(policy)
    _check_files(
        destination / "active",
        _render(state, destination / "active", policy),
        owner,
        group,
    )
    return {
        "matches": True,
        "ca_identity": True,
        "server_identity": True,
        "client_serial_status": True,
        "ccd": True,
        "server_options": True,
    }


def _restore(destination: pathlib.Path) -> None:
    journal = _json(destination / JOURNAL)
    if journal.get("schema") != 1 or journal.get("service_state") != "stopped":
        raise MigrationError("unsupported rollback journal")
    previous = journal.get("previous")
    if not isinstance(previous, dict):
        raise MigrationError("invalid rollback snapshot metadata")
    active, backup = destination / "active", destination / "rollback"
    stage_name = journal.get("stage")
    if (
        not isinstance(stage_name, str)
        or re.fullmatch(r"\.stage-[0-9a-f]{32}", stage_name) is None
    ):
        raise MigrationError("invalid rollback stage metadata")
    stage = destination / stage_name
    if previous.get("exists"):
        if backup.exists():
            if _hash_tree(backup) != previous:
                raise MigrationError("rollback snapshot hash mismatch; retain evidence")
            if active.exists():
                filesystem.tree(active, MAX_FILES * 2)
                shutil.rmtree(active)
            os.replace(backup, active)
        elif _hash_tree(active) != previous:
            raise MigrationError("rollback snapshot unavailable; retain evidence")
    elif active.exists():
        filesystem.tree(active, MAX_FILES * 2)
        shutil.rmtree(active)
    if _hash_tree(active) != previous:
        raise MigrationError("restored target hashes differ from snapshot")
    if stage.exists():
        filesystem.tree(stage, MAX_FILES * 2)
        shutil.rmtree(stage)
    (destination / JOURNAL).unlink()
    _sync(destination)


def rollback(
    destination: pathlib.Path,
    *,
    apply: bool = False,
    target_stopped: bool = False,
    profile: str = "offline",
) -> dict[str, object]:
    """Restore exact prior file hashes/modes/owners and stopped service state."""
    destination = pathlib.Path(os.path.abspath(destination))
    _owned(destination, profile=profile)
    if not (destination / JOURNAL).exists():
        raise MigrationError("mandatory rollback snapshot is unavailable")
    if not apply:
        return {"dry_run": True, "rollback_available": True}
    if not target_stopped:
        raise MigrationError("target must be stopped before rollback")
    with _lock(destination):
        _restore(destination)
    return {"dry_run": False, "restored": True, "service_state": "stopped"}


def validate_policy(state: Snapshot, policy: TargetSpec) -> dict[str, object]:
    """Check exact versions and independently observed target capabilities."""
    validation.validate(state)
    validate_versions(policy.versions)
    if (
        policy.versions != state.manifest.versions
        or policy.serial_policy != state.manifest.serial_policy
    ):
        raise MigrationError("compatibility mismatch; reviewed transformation required")
    directives = [
        item for items in state.manifest.configurations.values() for item in items
    ]
    if {item.name for item in directives} - set(policy.supported_options):
        raise MigrationError("compatibility requires observed supported target options")
    for item in directives:
        if item.name in {
            "cipher",
            "data-ciphers",
            "data-ciphers-fallback",
            "tls-cipher",
            "tls-ciphersuites",
        } and (
            len(item.args) != 1
            or any(
                cipher.removeprefix("?") not in policy.supported_ciphers
                for cipher in item.args[0].split(":")
            )
        ):
            raise MigrationError(
                "compatibility requires observed supported target ciphers"
            )
    _identity(policy)
    _render(state, pathlib.Path("/logical-target/active"), policy)
    return {"valid": True, "compatible": True, "capabilities_verified": True}


def _quote(value: str) -> str:
    # OpenVPN supports backslash escapes inside double quotes, not shell
    # concatenation emitted by shlex.join for embedded apostrophes.
    if any(ord(char) < 32 for char in value):
        raise MigrationError("unsafe rendered configuration argument")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
