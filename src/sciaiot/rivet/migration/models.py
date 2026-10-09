"""Versioned migration schema and deliberately redacted errors."""

import dataclasses
import pathlib
import re
from typing import Literal

import pydantic

MAX_FILES = 10000
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_BUNDLE_BYTES = MAX_TOTAL_BYTES + 16 * 1024 * 1024
SCHEMA = 1


class MigrationError(ValueError):
    """Expose only stable, non-sensitive migration failure descriptions."""


class StrictModel(pydantic.BaseModel):
    """Reject unknown fields rather than silently weakening policy."""

    model_config = pydantic.ConfigDict(extra="forbid", strict=True)


class SourceSpec(StrictModel):
    """Operator-approved roots and independently observed version metadata."""

    openvpn_root: str
    easyrsa_root: str
    server_config: str
    pki_subdirectory: str = ""
    easyrsa_config: dict[str, str] = pydantic.Field(default_factory=dict)
    external_files: dict[str, Literal["pool", "hook"]] = pydantic.Field(
        default_factory=dict
    )
    container_runtime_hooks: bool = False
    versions: dict[str, str]
    serial_policy: Literal["sequential", "random"]


class Replacement(StrictModel):
    """Reviewed target code replacing a source executable dependency."""

    path: str
    sha256: str


class TargetSpec(StrictModel):
    """Exact-version policy and reviewed target identity/code mapping."""

    versions: dict[str, str]
    serial_policy: Literal["sequential", "random"]
    supported_options: list[str] = pydantic.Field(default_factory=list)
    supported_ciphers: list[str] = pydantic.Field(default_factory=list)
    owner: str = ""
    group: str = ""
    replacements: dict[str, Replacement] = pydantic.Field(default_factory=dict)


class ContainerTargetSpec(TargetSpec):
    """Reviewed immutable image and one explicit OpenSSL transition policy."""

    image_digest: str
    openssl_transition: Literal["3.0.13-to-3.5.7"] | None = None
    target_device: str

    @pydantic.field_validator("image_digest")
    @classmethod
    def validate_image_digest(cls, value: str) -> str:
        """Require an exact lowercase SHA-256 digest selected by the operator."""
        if re.fullmatch(r"sha256:[a-f0-9]{64}", value) is None:
            raise ValueError("reviewed immutable image digest required")
        return value


class Entry(StrictModel):
    """A bounded regular file with a logical owner and protected checksum."""

    sha256: str
    size: int
    mode: Literal[384] = 0o600
    owner: Literal["vpn-state"] = "vpn-state"


class Directive(StrictModel):
    """An OpenVPN option with logical references replacing source paths."""

    name: str
    args: list[str]
    references: dict[str, str] = pydantic.Field(default_factory=dict)


class Manifest(StrictModel):
    """Authenticated schema-one logical bundle metadata."""

    schema_version: Literal[1] = 1
    versions: dict[str, str]
    serial_policy: Literal["sequential", "random"]
    main_config: str
    files: dict[str, Entry]
    directories: list[str]
    configurations: dict[str, list[Directive]]
    hooks: dict[str, str]
    excluded_runtime: list[str] = pydantic.Field(default_factory=list)
    semantics: dict[str, object]


@dataclasses.dataclass(frozen=True)
class Snapshot:
    """Sensitive in-memory state; callers must never log its representation."""

    manifest: Manifest = dataclasses.field(repr=False)
    files: dict[str, bytes] = dataclasses.field(repr=False)
    key_passwords: dict[str, bytes] = dataclasses.field(
        default_factory=dict, repr=False, compare=False
    )


def logical_path(value: str) -> str:
    """Validate a portable POSIX relative path without normalization."""
    path = pathlib.PurePosixPath(value)
    if (
        not value
        or len(value) > 512
        or "\\" in value
        or any(ord(char) < 32 for char in value)
        or path.is_absolute()
        or any(part in ("", ".", "..") for part in value.split("/"))
        or path.parts[0] not in ("pki", "config", "assets", "ccd", "pool")
    ):
        raise MigrationError("unsafe logical path; review bundle inputs")
    return value


def validate_versions(versions: dict[str, str]) -> None:
    """Require exact observed OpenVPN, Easy-RSA, and OpenSSL versions."""
    if set(versions) != {"openvpn", "easyrsa", "openssl"} or any(
        re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+[a-z0-9.+_-]*", value) is None
        for value in versions.values()
    ):
        raise MigrationError("invalid version metadata; record exact versions")


def parse_model[T: pydantic.BaseModel](model: type[T], data: bytes) -> T:
    """Decode strict bounded JSON, rejecting duplicate keys before validation."""
    import json

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in items:
            if key in value:
                raise MigrationError("duplicate JSON object key")
            value[key] = item
        return value

    try:
        value = json.loads(data, object_pairs_hook=pairs)
        pending = [(value, 0)]
        while pending:
            item, depth = pending.pop()
            if depth > 64:
                raise MigrationError("JSON nesting limit exceeded")
            if isinstance(item, dict):
                pending.extend((child, depth + 1) for child in item.values())
            elif isinstance(item, list):
                pending.extend((child, depth + 1) for child in item)
        return model.model_validate(value)
    except RecursionError, UnicodeError, json.JSONDecodeError:
        raise MigrationError("invalid JSON document") from None
