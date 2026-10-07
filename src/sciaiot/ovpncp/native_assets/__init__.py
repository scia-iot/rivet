"""Export reviewed native deployment templates from the installed wheel."""

import argparse
import importlib.resources
import os
import stat
from pathlib import Path

ASSETS = (
    "ovpncp.service",
    "ovpncp-vpn-agent.service",
    "ovpncp-openvpn.service",
    "ovpncp-forward-policy.service",
    "ovpncp.conf",
    "api.env.example",
    "agent.env.example",
    "server.conf.example",
    "nginx.conf.template",
    "web-config.sh",
)


def export(destination: Path) -> None:
    """Write all native templates to an empty operator-owned directory.

    Args:
        destination: Existing or new directory for reviewable templates.

    Raises:
        FileExistsError: Any template already exists.
        ValueError: The destination is a symbolic link or is not a directory.
    """
    if not destination.is_absolute() or ".." in destination.parts:
        raise ValueError("Export destination must be a canonical absolute path.")
    for ancestor in (destination.parent, *destination.parent.parents):
        metadata = ancestor.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("Export path must contain only real directories.")
    if not destination.exists():
        destination.mkdir(mode=0o700)
    metadata = destination.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o022
    ):
        raise ValueError("Export destination must be privately owned.")
    for name in ASSETS:
        if (destination / name).exists() or (destination / name).is_symlink():
            raise FileExistsError(f"Refusing to replace {name}.")
    resources = importlib.resources.files(__package__)
    for name in ASSETS:
        target = destination / name
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(resources.joinpath(name).read_bytes())
            os.fchmod(output.fileno(), 0o755 if name.endswith(".sh") else 0o644)


def main() -> None:
    """Export native templates for review before privileged installation."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    try:
        export(args.destination)
    except (FileExistsError, OSError, ValueError) as exc:
        parser.exit(1, f"Native template export failed: {exc}\n")


if __name__ == "__main__":
    main()
