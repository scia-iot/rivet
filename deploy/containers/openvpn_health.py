"""Check local daemon liveness; agent readiness and canaries prove VPN health."""

import stat
from pathlib import Path


def main() -> None:
    """Require PID 1 to be OpenVPN and its protected management socket to exist."""
    try:
        if Path("/proc/1/comm").read_text().strip() != "openvpn":
            raise ValueError
        metadata = Path("/run/openvpn/management.sock").lstat()
        if not stat.S_ISSOCK(metadata.st_mode):
            raise ValueError
    except (OSError, ValueError):
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
