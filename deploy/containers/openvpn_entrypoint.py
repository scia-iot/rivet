"""Validate operator-prepared runtime grants before starting OpenVPN."""

import os
import stat
from pathlib import Path


def validate(path: Path, *, directory: bool, mode: int) -> None:
    """Require the declared daemon identity and exact runtime permissions."""
    metadata = path.lstat()
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected_type(metadata.st_mode)
        or metadata.st_uid != 65530
        or metadata.st_gid != 65532
        or stat.S_IMODE(metadata.st_mode) != mode
        or (not directory and metadata.st_nlink != 1)
    ):
        raise ValueError("Invalid OpenVPN runtime grants.")


def main() -> None:
    """Start in the foreground; configuration owns the daemon privilege drop."""
    try:
        for directory in ("/run/openvpn", "/var/lib/openvpn"):
            validate(Path(directory), directory=True, mode=0o2770)
        for filename in (
            "/run/openvpn/status.log",
            "/var/lib/openvpn/ipp.txt",
        ):
            validate(Path(filename), directory=False, mode=0o660)
        os.umask(0o007)
        os.execv(
            "/usr/local/sbin/openvpn",
            [
                "openvpn",
                "--config",
                "/var/lib/ovpn-agent/projection/server.conf",
            ],
        )
    except (OSError, ValueError):
        raise SystemExit("OpenVPN startup failed; check runtime grants.") from None


if __name__ == "__main__":
    main()
