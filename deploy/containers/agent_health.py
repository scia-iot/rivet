"""Observe VPN readiness locally without impersonating the API socket peer."""

import uuid

from sciaiot.ovpncp.application.vpn_control import schemas
from sciaiot.ovpncp.application.vpn_control.errors import ControlError
from sciaiot.ovpncp.vpn_agent.control import ReadOnlyVpnControl
from sciaiot.ovpncp.vpn_agent.settings import Settings


def main() -> None:
    """Run the same bounded readiness checks used by the agent protocol."""
    try:
        response = ReadOnlyVpnControl(Settings.from_environment()).execute(
            schemas.Request(
                request_id=str(uuid.uuid4()),
                deadline_ms=10000,
                command=schemas.Health(),
            )
        )
        if (
            not isinstance(response.result, schemas.HealthResult)
            or not response.result.ready
        ):
            raise SystemExit(1)
    except ControlError, OSError, ValueError:
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
