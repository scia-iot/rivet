"""Standalone entry point for the private read-only agent."""

import signal

from .server import UnixAgentServer
from .settings import Settings


def main() -> None:
    """Load explicit deployment configuration and serve until termination."""
    try:
        settings = Settings.from_environment()
        with UnixAgentServer(settings) as server:
            signal.signal(signal.SIGTERM, lambda *_: server.shutdown())
            signal.signal(signal.SIGINT, lambda *_: server.shutdown())
            server.serve_forever()
    except (OSError, ValueError):
        raise SystemExit(
            "Private VPN agent unavailable; check deployment configuration."
        ) from None


if __name__ == "__main__":
    main()
