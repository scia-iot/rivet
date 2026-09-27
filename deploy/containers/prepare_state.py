"""Prepare an empty deployment tree; never adopt or rewrite migration state."""

import argparse
import os
from pathlib import Path

# Numeric identities match the four first-party images and Compose manifest.
DIRECTORIES = (
    ("api-data", 65531, 65531, 0o700),
    ("api-data/certs", 65531, 65531, 0o700),
    ("api-profile", 65531, 65531, 0o700),
    ("api-archives", 65531, 65531, 0o700),
    ("vpn-config", 65532, 65532, 0o700),
    ("vpn-pki", 65532, 65532, 0o700),
    ("vpn-ccd", 65532, 65532, 0o700),
    ("vpn-journal", 65532, 65532, 0o700),
    ("vpn-projection", 65532, 65532, 0o750),
    ("vpn-projection/ccd", 65532, 65532, 0o750),
    ("vpn-pool", 65530, 65532, 0o2770),
    ("agent-socket", 65532, 65531, 0o2750),
    ("management-socket", 65530, 65532, 0o2770),
    ("event-socket", 65532, 65532, 0o2770),
)


def prepare(root: Path) -> None:
    """Create a new private tree with the reviewed owners and permissions.

    Args:
        root: New absolute path under an existing operator-controlled parent.

    Raises:
        ValueError: If the path is relative, noncanonical or traverses symlinks.
        FileExistsError: If any destination already exists; it is preserved.
        OSError: If directory creation or ownership assignment fails.
    """
    if not root.is_absolute() or root.resolve() != root:
        raise ValueError("Use an absolute path without symlinks or '..'.")
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    for name, uid, gid, mode in DIRECTORIES:
        path = root / name
        path.mkdir(mode=0o700)
        os.chown(path, uid, gid, follow_symlinks=False)
        os.chmod(path, mode)
    for name in ("vpn-pool/ipp.txt", "management-socket/status.log"):
        path = root / name
        with path.open("xb"):
            pass
        os.chown(path, 65530, 65532, follow_symlinks=False)
        os.chmod(path, 0o660)


def main() -> None:
    """Initialize deployment permissions only when explicitly run as root."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Run as the deployment administrator with root privileges.")
    try:
        prepare(args.root)
    except (OSError, ValueError):
        parser.exit(
            1,
            "State preparation failed. Use a new absolute destination under "
            "an existing trusted parent; inspect partial state before retrying.\n",
        )


if __name__ == "__main__":
    main()
