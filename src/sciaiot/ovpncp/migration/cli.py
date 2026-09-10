"""Non-interactive migration CLI with redacted machine-readable output."""

import argparse
import json
import pathlib
import stat
import sys
from typing import Never

import pydantic

from sciaiot.ovpncp.migration import bundle, filesystem, source, target
from sciaiot.ovpncp.migration.models import (
    MAX_BUNDLE_BYTES,
    MigrationError,
    SourceSpec,
    TargetSpec,
    parse_model,
)


class _Passphrases(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="forbid", strict=True)
    keys: dict[str, str]


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        raise MigrationError("invalid command arguments; consult --help")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(description="Offline, authenticated OpenVPN migration")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("inventory", "export", "validate", "import", "verify", "rollback"):
        command = commands.add_parser(name)
        if name in ("inventory", "export"):
            command.add_argument("--source", type=pathlib.Path, required=True)
        if name == "export":
            command.add_argument("--writers-frozen", action="store_true")
        if name in ("export", "validate", "import", "verify"):
            command.add_argument("--bundle", type=pathlib.Path, required=True)
            command.add_argument("--key-file", type=pathlib.Path, required=True)
            command.add_argument("--pki-passphrases-file", type=pathlib.Path)
        if name in ("validate", "import", "verify"):
            command.add_argument("--policy", type=pathlib.Path, required=True)
        if name in ("import", "verify", "rollback"):
            command.add_argument("--target", type=pathlib.Path, required=True)
        if name in ("import", "rollback"):
            command.add_argument("--apply", action="store_true")
            command.add_argument("--target-stopped", action="store_true")
    return parser


def _read_key(path: pathlib.Path) -> bytes:
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise MigrationError("key file must be a private mode-0600 regular file")
    key = filesystem.read_file(path, 32)
    if len(key) != 32:
        raise MigrationError("key file must contain exactly 32 random bytes")
    return key


def main(argv: list[str] | None = None) -> int:
    """Run one explicit subcommand and emit redacted JSON with exit 0 or 2."""
    try:
        args = _parser().parse_args(argv)
        result: dict[str, object]
        passwords: dict[str, bytes] = {}
        secret_file = getattr(args, "pki_passphrases_file", None)
        if secret_file is not None:
            if secret_file.stat(follow_symlinks=False).st_mode & 0o077:
                raise MigrationError("PKI passphrase file must be private")
            values = parse_model(_Passphrases, filesystem.read_file(secret_file, 16384))
            passwords = {
                name: password.encode() for name, password in values.keys.items()
            }
        if args.command in ("inventory", "export"):
            spec = parse_model(SourceSpec, filesystem.read_file(args.source))
            if args.command == "inventory":
                result = source.inventory(spec)
            else:
                key = _read_key(args.key_file)
                state = source.capture(
                    spec, writers_frozen=args.writers_frozen, key_passwords=passwords
                )
                filesystem.write_private(args.bundle, bundle.seal(state, key))
                result = {
                    "exported": True,
                    "encrypted": True,
                    "file_count": len(state.files),
                }
        elif args.command == "rollback":
            result = target.rollback(
                args.target, apply=args.apply, target_stopped=args.target_stopped
            )
        else:
            state = bundle.open_bundle(
                filesystem.read_file(args.bundle, MAX_BUNDLE_BYTES),
                _read_key(args.key_file),
                key_passwords=passwords,
            )
            policy = parse_model(TargetSpec, filesystem.read_file(args.policy))
            if args.command == "validate":
                # Compatibility rendering uses no target writes or services.
                result = target.validate_policy(state, policy)
            elif args.command == "verify":
                result = target.verify(state, args.target, policy)
            else:
                result = target.install(
                    state,
                    args.target,
                    policy,
                    apply=args.apply,
                    target_stopped=args.target_stopped,
                )
        print(json.dumps(result, sort_keys=True))
        return 0
    except MigrationError as exc:
        print(
            json.dumps({"error": "migration_failed", "detail": str(exc)}),
            file=sys.stderr,
        )
        return 2
    except OSError, pydantic.ValidationError, ValueError, TypeError:
        # Never echo exception arguments: they can contain paths or secrets.
        print(
            json.dumps(
                {
                    "error": "migration_failed",
                    "detail": "Input, compatibility, consistency, or target validation failed; review private inputs and documented prerequisites.",
                }
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
