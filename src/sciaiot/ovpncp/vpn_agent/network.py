"""Inspect explicit read-only ownership declarations against actual state."""

import ipaddress
import json
import shlex
from typing import Annotated, Literal

import pydantic

from sciaiot.ovpncp.application.vpn_control import schemas as s
from sciaiot.ovpncp.application.vpn_control import wire
from sciaiot.ovpncp.application.vpn_control.errors import ControlError, ErrorCode

from . import bounded, files
from .settings import Settings


class Ownership(s.Model):
    """Operator-provided inspection inventory, never created by this agent."""

    version: Literal["1.0"] = "1.0"
    routes: Annotated[tuple[s.ManagedRoute, ...], pydantic.Field(max_length=10000)] = ()
    access: Annotated[tuple[s.AccessIntent, ...], pydantic.Field(max_length=10000)] = ()
    pushes: Annotated[tuple[s.OwnedPushes, ...], pydantic.Field(max_length=10000)] = ()


def ownership(settings: Settings, deadline: float) -> Ownership:
    """Absence means no owned records; existing legacy rules are not adopted."""
    if settings.ownership_path is None:
        return Ownership()
    raw = bounded.read_file(settings.ownership_path, deadline)
    wire._bounded_json(raw)
    result = Ownership.model_validate_json(raw)
    for identifiers in (
        [item.route_id for item in result.routes],
        [item.access_id for item in result.access],
        [(item.intent_id, item.client) for item in result.pushes],
    ):
        if len(identifiers) != len(set(identifiers)):
            raise ControlError(ErrorCode.INTEGRITY)
    return result


def routes(
    settings: Settings, config: s.ConfigResult, deadline: float
) -> tuple[s.ManagedRoute, ...]:
    """Require exact network, gateway, device and numeric owned protocol."""
    inventory = ownership(settings, deadline)
    declared = inventory.routes
    if not declared:
        return ()
    observed = json.loads(bounded.observe("routes", config.device, deadline))
    if not isinstance(observed, list) or len(observed) > bounded.MAX_RECORDS:
        raise ControlError(ErrorCode.EXHAUSTED)
    for route in declared:
        matches = [
            item
            for item in observed
            if (
                item.get("dst") == route.network
                and item.get("gateway") == route.gateway
                and item.get("dev") == config.device
                and str(item.get("protocol")) == str(settings.route_protocol or 200)
                and item.get("type", "unicast") == "unicast"
                and "multipath" not in item
            )
        ]
        if len(matches) != 1:
            raise ControlError(ErrorCode.CONFLICT)
    if ownership(settings, deadline) != inventory:
        raise ControlError(ErrorCode.CONFLICT)
    return tuple(sorted(declared, key=lambda item: item.route_id))


def _rule(source: str, destination: str, marker: str, device: str) -> tuple[str, ...]:
    """Limit an owned access grant to peer traffic on one TUN device."""
    return (
        "-A",
        "OVPNCP_FORWARD",
        "-s",
        source,
        "-d",
        destination,
        "-i",
        device,
        "-o",
        device,
        "-m",
        "comment",
        "--comment",
        marker,
        "-j",
        "ACCEPT",
    )


def access(
    settings: Settings, config: s.ConfigResult, deadline: float
) -> tuple[tuple[s.AccessIntent, ...], tuple[s.OwnedPushes, ...]]:
    """Report only fully realized paired rules and declared CCD pushes."""
    declared = ownership(settings, deadline)
    if (
        not declared.access
        and not declared.pushes
        and "access" not in settings.mutation_families
    ):
        return (), ()
    version = bounded.observe("backend", config.device, deadline)
    if b"(nf_tables)" not in version:
        raise ControlError(ErrorCode.UNAVAILABLE)
    raw = bounded.observe("rules", config.device, deadline)
    observed = [
        tuple(shlex.split(line))
        for line in raw.decode().splitlines()
        if line.startswith("-A ")
    ]
    if len(observed) > bounded.MAX_RECORDS:
        raise ControlError(ErrorCode.EXHAUSTED)
    required: list[tuple[str, ...]] = []
    if declared.access or "access" in settings.mutation_families:
        for direction, flag in (("ingress", "-i"), ("egress", "-o")):
            required.append(
                (
                    "-A",
                    "FORWARD",
                    flag,
                    config.device,
                    "-m",
                    "comment",
                    "--comment",
                    f"ovpncp:anchor:{direction}",
                    "-j",
                    "OVPNCP_FORWARD",
                )
            )
    for item in declared.access:
        pairs = [
            (
                f"{item.source_address}/32",
                f"{item.destination_address}/32",
                f"ovpncp:{item.access_id}",
            )
        ]
        pairs.extend(
            (
                f"{item.source_address}/32",
                network,
                f"ovpncp:{item.access_id}:private:{index}",
            )
            for index, network in enumerate(item.private_networks)
        )
        for source, destination, prefix in pairs:
            required.append(
                _rule(source, destination, f"{prefix}:forward", config.device)
            )
            required.append(
                _rule(destination, source, f"{prefix}:reverse", config.device)
            )
    if "access" in settings.mutation_families:
        required.append(
            (
                "-A",
                "OVPNCP_FORWARD",
                "-m",
                "comment",
                "--comment",
                "ovpncp:terminal-deny",
                "-j",
                "DROP",
            )
        )
        forward = [rule for rule in observed if rule[1] == "FORWARD"]
        if forward[:2] != required[:2]:
            raise ControlError(ErrorCode.CONFLICT)
    for rule in observed:
        if (
            (len(rule) > 1 and rule[1] == "OVPNCP_FORWARD")
            or any(
                rule[index : index + 2] == ("-j", "OVPNCP_FORWARD")
                for index in range(2, len(rule) - 1)
            )
        ) and rule not in required:
            raise ControlError(ErrorCode.CONFLICT)
    for rule in required:
        if observed.count(rule) != 1:
            raise ControlError(ErrorCode.CONFLICT)
    by_id = {item.access_id: item for item in declared.access}
    for push in declared.pushes:
        intent = by_id.get(push.intent_id)
        if intent is None or push.client not in {
            intent.source_client,
            intent.destination_client,
        }:
            raise ControlError(ErrorCode.INTEGRITY)
        options = files.ccd(settings, push.client, deadline)
        actual = []
        for entry in options.get("push", []):
            if len(entry) != 1:
                raise ControlError(ErrorCode.INTEGRITY)
            tokens = shlex.split(entry[0])
            if tokens and tokens[0] == "route":
                if len(tokens) != 4:
                    raise ControlError(ErrorCode.CONFLICT)
                actual.append(
                    s.PushRoute(
                        network=str(ipaddress.IPv4Network(f"{tokens[1]}/{tokens[2]}")),
                        gateway=tokens[3],
                    )
                )
        if any(actual.count(route) != 1 for route in push.routes):
            raise ControlError(ErrorCode.CONFLICT)
    if ownership(settings, deadline) != declared:
        raise ControlError(ErrorCode.CONFLICT)
    return (
        tuple(sorted(declared.access, key=lambda item: item.access_id)),
        tuple(sorted(declared.pushes, key=lambda item: (item.intent_id, item.client))),
    )
