"""Exact owned route realization, without replacing administrator routes."""

import ipaddress
import json

from sciaiot.rivet.application.vpn_control import schemas as s
from sciaiot.rivet.application.vpn_control.errors import ControlError, ErrorCode

from . import bounded, files, network
from .journal import Journal
from .mutations import atomic_write, read_optional
from .settings import Settings


class RouteMutations:
    """Bind owned inventory transitions to the durable accepted operation."""

    def __init__(self, settings: Settings, journal: Journal) -> None:
        self.settings = settings
        self.journal = journal

    def apply(self, request: s.Request, deadline: float) -> None:
        """Add/remove an exact dedicated-protocol route and retain foreign state."""
        command = request.command
        assert isinstance(command, s.SetRoute)
        assert request.operation_id is not None
        if self.settings.ownership_path is None or self.settings.route_protocol is None:
            raise ControlError(ErrorCode.UNAVAILABLE)
        config = files.configuration(self.settings, deadline)
        route = command.route
        pool = ipaddress.IPv4Network(config.network)
        gateway = ipaddress.IPv4Address(route.gateway)
        if (
            gateway not in pool
            # Server routes use the local TUN address as their next hop;
            # OpenVPN selects the destination client using its CCD iroute.
            or gateway in {pool.network_address, pool.broadcast_address}
            or ipaddress.IPv4Network(route.network).overlaps(pool)
        ):
            raise ControlError(ErrorCode.INVALID_INPUT)
        raw = self.journal.evidence(request.operation_id, "routes")
        if raw is None:
            inventory_bytes = read_optional(self.settings.ownership_path, deadline)
            inventory = (
                network.Ownership.model_validate_json(inventory_bytes)
                if inventory_bytes
                else network.Ownership()
            )
            owned = next(
                (item for item in inventory.routes if item.route_id == route.route_id),
                None,
            )
            if owned is not None and owned != route:
                raise ControlError(ErrorCode.CONFLICT)
            observed = self._observe(config.device, deadline)
            candidates = [item for item in observed if item.get("dst") == route.network]
            if candidates and (
                owned is None or not self._exact(candidates, route, config.device)
            ):
                raise ControlError(ErrorCode.CONFLICT)
            if any(
                item.route_id != route.route_id and item.network == route.network
                for item in inventory.routes
            ):
                raise ControlError(ErrorCode.CONFLICT)
            desired = tuple(
                item for item in inventory.routes if item.route_id != route.route_id
            )
            if command.present:
                desired += (route,)
            target = network.Ownership.model_validate(
                inventory.model_copy(update={"routes": desired})
            )
            raw = json.dumps(
                {"before": inventory_bytes.decode(), "after": target.model_dump_json()}
            ).encode()
            self.journal.stage(request.operation_id, "routes", raw)
        evidence = json.loads(raw)
        current = read_optional(self.settings.ownership_path, deadline)
        if current.decode() not in {evidence["before"], evidence["after"]}:
            raise ControlError(ErrorCode.CONFLICT)
        observed = self._observe(config.device, deadline)
        candidates = [item for item in observed if item.get("dst") == route.network]
        if candidates and not self._exact(candidates, route, config.device):
            raise ControlError(ErrorCode.CONFLICT)
        if bool(candidates) != command.present:
            bounded.command(
                [
                    "/usr/sbin/ip",
                    "-4",
                    "route",
                    "add" if command.present else "del",
                    route.network,
                    "via",
                    route.gateway,
                    "dev",
                    config.device,
                    "proto",
                    str(self.settings.route_protocol),
                ],
                deadline,
            )
        observed = self._observe(config.device, deadline)
        candidates = [item for item in observed if item.get("dst") == route.network]
        if (command.present and not self._exact(candidates, route, config.device)) or (
            not command.present and candidates
        ):
            raise ControlError(ErrorCode.CONFLICT)
        atomic_write(self.settings.ownership_path, evidence["after"].encode(), deadline)
        self.journal.checkpoint(request.operation_id, "routes")

    def _observe(self, device: str, deadline: float) -> list[dict[str, object]]:
        observed = json.loads(bounded.observe("routes", device, deadline))
        if not isinstance(observed, list) or len(observed) > bounded.MAX_RECORDS:
            raise ControlError(ErrorCode.EXHAUSTED)
        if not all(isinstance(item, dict) for item in observed):
            raise ControlError(ErrorCode.INTEGRITY)
        return observed

    def _exact(
        self, candidates: list[dict[str, object]], route: s.ManagedRoute, device: str
    ) -> bool:
        if len(candidates) != 1:
            return False
        item = candidates[0]
        return (
            item.get("dst") == route.network
            and item.get("gateway") == route.gateway
            and item.get("dev") == device
            and str(item.get("protocol")) == str(self.settings.route_protocol)
            and item.get("type", "unicast") == "unicast"
            and "multipath" not in item
        )
