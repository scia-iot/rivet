"""AES-256-GCM protected, bounded, versioned logical migration bundles."""

import io
import json
import os
import tarfile

import pydantic
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sciaiot.rivet.migration import validation
from sciaiot.rivet.migration.models import (
    MAX_BUNDLE_BYTES,
    MAX_FILE_BYTES,
    MAX_FILES,
    Manifest,
    MigrationError,
    Snapshot,
    logical_path,
    parse_model,
)

MAGIC = b"OVPNCP-MIGRATION\x00\x01AES256GCM\x00"


def _key(key: bytes) -> None:
    if len(key) != 32:
        raise MigrationError("encryption key must contain exactly 32 random bytes")


def seal(state: Snapshot, key: bytes) -> bytes:
    """Validate and encrypt a bounded uncompressed USTAR logical archive."""
    _key(key)
    validation.validate(state)
    stream = io.BytesIO()
    payload = {
        "manifest.json": state.manifest.model_dump_json().encode(),
        **{f"files/{name}": data for name, data in state.files.items()},
    }
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in sorted(payload.items()):
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            entry.mode = 0o600
            entry.uname = entry.gname = "vpn-state"
            archive.addfile(entry, io.BytesIO(data))
    plain = stream.getvalue()
    if len(plain) > MAX_BUNDLE_BYTES - len(MAGIC) - 28:
        raise MigrationError("bundle size limit exceeded")
    nonce = os.urandom(12)
    return MAGIC + nonce + AESGCM(key).encrypt(nonce, plain, MAGIC)


def open_bundle(
    data: bytes, key: bytes, *, key_passwords: dict[str, bytes] | None = None
) -> Snapshot:
    """Authenticate before archive parsing; never extract untrusted entries."""
    _key(key)
    if len(data) > MAX_BUNDLE_BYTES or not data.startswith(MAGIC):
        raise MigrationError("invalid bundle format or size")
    try:
        offset = len(MAGIC)
        plain = AESGCM(key).decrypt(
            data[offset : offset + 12], data[offset + 12 :], MAGIC
        )
    except InvalidTag, ValueError:
        raise MigrationError(
            "bundle authentication failed; check key and artifact"
        ) from None
    return decode_archive(plain, key_passwords=key_passwords)


def decode_archive(
    plain: bytes, *, key_passwords: dict[str, bytes] | None = None
) -> Snapshot:
    """Parse authenticated USTAR with explicit bounds and strict entry types."""
    if len(plain) > MAX_BUNDLE_BYTES:
        raise MigrationError("archive size limit exceeded")
    files: dict[str, bytes] = {}
    manifest_data = None
    seen: set[str] = set()
    try:
        offset = 0
        ended = False
        while offset + 512 <= len(plain):
            header = plain[offset : offset + 512]
            offset += 512
            if header == bytes(512):
                if len(plain) - offset < 512 or any(plain[offset:]):
                    raise MigrationError("invalid archive terminator or trailing data")
                ended = True
                break
            entry = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
            if (
                entry.name in seen
                or len(seen) >= MAX_FILES + 1
                or entry.type != tarfile.REGTYPE
                or entry.pax_headers
                or entry.size < 0
                or entry.size > MAX_FILE_BYTES
                or entry.mode != 0o600
                or entry.uid != 0
                or entry.gid != 0
                or entry.linkname
                or header[257:263] != b"ustar\x00"
            ):
                raise MigrationError("unsafe or excessive archive entry")
            seen.add(entry.name)
            if entry.name != "manifest.json":
                if not entry.name.startswith("files/"):
                    raise MigrationError("unexpected archive artifact")
                logical_path(entry.name[6:])
            content = plain[offset : offset + entry.size]
            if len(content) != entry.size:
                raise MigrationError("truncated archive entry")
            padded = ((entry.size + 511) // 512) * 512
            if any(plain[offset + entry.size : offset + padded]):
                raise MigrationError("nonzero archive padding")
            offset += padded
            if entry.name == "manifest.json":
                manifest_data = content
            else:
                files[entry.name[6:]] = content
        if not ended:
            raise MigrationError("archive terminator missing")
        if manifest_data is None:
            raise MigrationError("bundle manifest missing")
        manifest = parse_model(Manifest, manifest_data)
        state = Snapshot(manifest, files, key_passwords or {})
        validation.validate(state)
        return state
    except (
        tarfile.TarError,
        pydantic.ValidationError,
        json.JSONDecodeError,
        UnicodeError,
    ):
        raise MigrationError("invalid archive or unsupported manifest schema") from None
