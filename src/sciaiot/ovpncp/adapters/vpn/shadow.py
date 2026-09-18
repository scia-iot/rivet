"""Legacy-authoritative shadow reads with fixed, metadata-free comparisons."""

import ipaddress
import logging
import threading
import time
import uuid
from typing import Any

from sciaiot.ovpncp.application.vpn_control import schemas as s
from sciaiot.ovpncp.application.vpn_control.port import VpnControl

from .host import HostVpnControl

logger = logging.getLogger(__name__)
READ_KINDS = frozenset(
    {
        "health",
        "server_config",
        "get_client",
        "list_clients",
        "list_routes",
        "list_access",
        "list_sessions",
    }
)


def projection(value: Any) -> Any:
    """Remove observation revisions before comparing semantic read results."""
    if isinstance(value, s.Model):
        return projection(value.model_dump(mode="json"))
    if isinstance(value, dict):
        return {
            key: projection(item)
            for key, item in value.items()
            if key not in {"generation", "next_cursor"}
        }
    if isinstance(value, (list, tuple)):
        return [projection(item) for item in value]
    return value


class ShadowHostVpnControl(HostVpnControl):
    """Preserve all host behavior, dispatching only observations to the agent."""

    def __init__(self, agent: VpnControl, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.agent = agent
        self.local = threading.local()
        self.retry_after = 0.0

    def _compare(
        self, command: s.Command, expected: Any, transform: Any = projection
    ) -> None:
        if getattr(self.local, "suppress", False):
            return
        if time.monotonic() < self.retry_after:
            logger.info("VPN shadow %s unavailable", command.kind)
            return
        try:
            request = s.Request(
                request_id=str(uuid.uuid4()), command=command, deadline_ms=500
            )
            result = self.agent.execute(request).result
            outcome = "match" if transform(result) == expected else "mismatch"
        except Exception:  # noqa: BLE001 - shadow never alters legacy behavior
            self.retry_after = time.monotonic() + 5
            outcome = "unavailable"
        logger.info("VPN shadow %s %s", command.kind, outcome)

    def execute(self, request: s.Request) -> s.Response:
        """Return the original host result; mutations never reach the agent."""
        self.local.suppress = True
        try:
            response = super().execute(request)
        finally:
            self.local.suppress = False
        if request.command.kind in READ_KINDS and not isinstance(
            response.result, s.Failure
        ):
            self._compare(request.command, projection(response.result))
        return response

    def configuration(self) -> dict[str, Any]:
        """Return exact legacy fields while comparing the sanitized projection."""
        result = super().configuration()
        if not getattr(self.local, "suppress", False):
            # Project this exact observation through the existing host parser.
            temporary = HostVpnControl()
            temporary.configuration = lambda: result  # type: ignore[method-assign]
            try:
                expected = temporary._read(s.ServerConfig())
                self._compare(s.ServerConfig(), projection(expected))
            except Exception:  # noqa: BLE001 - observation cannot change a host read
                logger.info("VPN shadow server_config unavailable")
        return result

    def health(self) -> dict[str, Any]:
        """Compare readiness only, preserving legacy service timestamps."""
        result = super().health()
        self._compare(
            s.Health(),
            result.get("status") == "active (running)",
            lambda item: isinstance(item, s.HealthResult) and item.ready,
        )
        return result

    def discovered_names(self) -> list[str]:
        """Compare bounded client names without exporting invalid candidates."""
        result = super().discovered_names()
        if len(result) <= s.MAX_PAGE:
            self._compare(
                s.ListClients(),
                sorted(result),
                lambda item: sorted(entry.client for entry in item.items),
            )
        return result

    def read_certificate(self, client: str) -> dict[str, Any]:
        """Compare public certificate metadata and retain the missing sentinel."""
        result = super().read_certificate(client)
        if result:
            try:
                expected = (
                    result["issued_by"],
                    result["issued_to"],
                    int(result["issued_on"].timestamp() * 1_000_000),
                    int(result["expires_on"].timestamp() * 1_000_000),
                )
                self._compare(
                    s.GetClient(client=client),
                    expected,
                    lambda value: (
                        value.item.issuer,
                        value.item.subject,
                        value.item.not_before,
                        value.item.not_after,
                    ),
                )
            except Exception:  # noqa: BLE001 - preserve legacy metadata
                logger.info("VPN shadow get_client unavailable")
        return result

    def client_revoked(self, client: str) -> bool:
        """Compare only certificate state against an independent agent read."""
        result = super().client_revoked(client)
        self._compare(
            s.GetClient(client=client),
            result,
            lambda item: item.item.state == "revoked",
        )
        return result

    def client_address(self, client: str) -> str | None:
        """Compare the optional assigned IPv4 address without logging it."""
        result = super().client_address(client)
        self._compare(
            s.GetClient(client=client),
            result,
            lambda item: (
                item.item.assignment.address
                if item.item.assignment is not None
                else None
            ),
        )
        return result

    def route_lines(self, device: str) -> list[str]:
        """Check owned routes against legacy observations, retaining foreign rows."""
        result = super().route_lines(device)
        actual = set()
        try:
            for line in result:
                fields = line.split()
                if "via" in fields:
                    actual.add(
                        (
                            str(ipaddress.IPv4Network(fields[0])),
                            fields[fields.index("via") + 1],
                        )
                    )
            self._compare(
                s.ListRoutes(),
                True,
                lambda item: all(
                    (route.network, route.gateway) in actual for route in item.items
                ),
            )
        except Exception:  # noqa: BLE001 - retain legacy route text on malformed observations
            logger.info("VPN shadow list_routes unavailable")
        return result
