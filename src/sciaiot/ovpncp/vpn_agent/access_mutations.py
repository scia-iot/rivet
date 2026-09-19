"""Atomic owned firewall realization with first-position TUN anchors."""

import json
import shlex

from sciaiot.ovpncp.application.vpn_control import schemas as s
from sciaiot.ovpncp.application.vpn_control.errors import ControlError, ErrorCode

from . import bounded, files, network
from .journal import Journal
from .mutations import atomic_write, read_optional
from .settings import Settings

CHAIN = "OVPNCP_FORWARD"


def rules(inventory: network.Ownership, device: str) -> tuple[tuple[str, ...], ...]:
    """Render complete paired access and a terminal owned deny rule."""
    result: list[tuple[str, ...]] = []
    for direction, flag in (("ingress", "-i"), ("egress", "-o")):
        result.append(
            (
                "-A",
                "FORWARD",
                flag,
                device,
                "-m",
                "comment",
                "--comment",
                f"ovpncp:anchor:{direction}",
                "-j",
                CHAIN,
            )
        )
    for intent in inventory.access:
        pairs = [
            (
                f"{intent.source_address}/32",
                f"{intent.destination_address}/32",
                f"ovpncp:{intent.access_id}",
            )
        ]
        pairs.extend(
            (
                f"{intent.source_address}/32",
                block,
                f"ovpncp:{intent.access_id}:private:{index}",
            )
            for index, block in enumerate(intent.private_networks)
        )
        for source, destination, marker in pairs:
            result.append(network._rule(source, destination, f"{marker}:forward"))
            result.append(network._rule(destination, source, f"{marker}:reverse"))
    result.append(
        (
            "-A",
            CHAIN,
            "-m",
            "comment",
            "--comment",
            "ovpncp:terminal-deny",
            "-j",
            "DROP",
        )
    )
    return tuple(result)


class AccessMutations:
    """Never flush a foreign chain or alter foreign FORWARD rules."""

    def __init__(self, settings: Settings, journal: Journal) -> None:
        self.settings = settings
        self.journal = journal

    def apply(self, request: s.Request, deadline: float) -> None:
        """Stage exact ownership, atomically install rules, verify then publish."""
        command = request.command
        assert isinstance(command, s.SetAccess)
        assert request.operation_id is not None
        if self.settings.ownership_path is None:
            raise ControlError(ErrorCode.UNAVAILABLE)
        config = files.configuration(self.settings, deadline)
        if b"(nf_tables)" not in bounded.observe("backend", config.device, deadline):
            raise ControlError(ErrorCode.UNAVAILABLE)
        raw = self.journal.evidence(request.operation_id, "access")
        if raw is None:
            if command.present:
                clients = {
                    item.client: item for item in files.clients(self.settings, deadline)
                }
                for name, address in (
                    (command.intent.source_client, command.intent.source_address),
                    (
                        command.intent.destination_client,
                        command.intent.destination_address,
                    ),
                ):
                    client = clients.get(name)
                    if (
                        client is None
                        or client.state != "active"
                        or client.assignment is None
                        or client.assignment.address != address
                    ):
                        raise ControlError(ErrorCode.CONFLICT)
            before = read_optional(self.settings.ownership_path, deadline)
            inventory = (
                network.Ownership.model_validate_json(before)
                if before
                else network.Ownership()
            )
            existing = next(
                (
                    item
                    for item in inventory.access
                    if item.access_id == command.intent.access_id
                ),
                None,
            )
            if existing is not None and existing != command.intent:
                raise ControlError(ErrorCode.CONFLICT)
            desired = tuple(
                item
                for item in inventory.access
                if item.access_id != command.intent.access_id
            )
            if command.present:
                desired += (command.intent,)
            elif any(
                item.intent_id == command.intent.access_id for item in inventory.pushes
            ):
                raise ControlError(ErrorCode.CONFLICT)
            target = network.Ownership.model_validate(
                inventory.model_copy(update={"access": desired})
            )
            initial_state = self._observe(config.device, deadline)
            expected = rules(inventory, config.device)
            if initial_state[0] and initial_state[1] != expected:
                raise ControlError(ErrorCode.CONFLICT)
            if not initial_state[0] and (inventory.access or initial_state[1]):
                raise ControlError(ErrorCode.CONFLICT)
            raw = json.dumps(
                {
                    "before": before.decode(),
                    "after": target.model_dump_json(),
                    "initial": initial_state[0],
                }
            ).encode()
            self.journal.stage(request.operation_id, "access", raw)
        evidence = json.loads(raw)
        current = read_optional(self.settings.ownership_path, deadline).decode()
        if current not in {evidence["before"], evidence["after"]}:
            raise ControlError(ErrorCode.CONFLICT)
        old = (
            network.Ownership.model_validate_json(evidence["before"])
            if evidence["before"]
            else network.Ownership()
        )
        desired_inventory = network.Ownership.model_validate_json(evidence["after"])
        old_rules = rules(old, config.device) if evidence["initial"] else ()
        desired_rules = rules(desired_inventory, config.device)
        exists, actual, forward = self._observe(config.device, deadline)
        if actual not in {old_rules, desired_rules}:
            raise ControlError(ErrorCode.CONFLICT)
        anchors = desired_rules[:2]
        if actual != desired_rules or tuple(forward[:2]) != anchors:
            lines = ["*filter"]
            lines.append(f"-F {CHAIN}" if exists else f":{CHAIN} - [0:0]")
            for anchor in actual[:2]:
                lines.append(shlex.join(("-D", *anchor[1:])))
            for anchor in reversed(anchors):
                lines.append(shlex.join(("-I", "FORWARD", "1", *anchor[2:])))
            lines.extend(shlex.join(rule) for rule in desired_rules[2:])
            lines.extend(("COMMIT", ""))
            bounded.command(
                ["/usr/sbin/iptables-nft-restore", "--noflush", "--wait", "5"],
                deadline,
                "\n".join(lines).encode(),
            )
        exists, actual, forward = self._observe(config.device, deadline)
        if not exists or actual != desired_rules or tuple(forward[:2]) != anchors:
            raise ControlError(ErrorCode.CONFLICT)
        atomic_write(self.settings.ownership_path, evidence["after"].encode(), deadline)
        self.journal.checkpoint(request.operation_id, "access")

    def _observe(
        self, device: str, deadline: float
    ) -> tuple[bool, tuple[tuple[str, ...], ...], list[tuple[str, ...]]]:
        raw = bounded.observe("rules", device, deadline).decode()
        parsed = [
            tuple(shlex.split(line))
            for line in raw.splitlines()
            if line.startswith("-A ")
        ]
        owned = tuple(
            item
            for item in parsed
            if item[1] == CHAIN
            or ("-j" in item and item[item.index("-j") + 1] == CHAIN)
        )
        # Return anchors first regardless of save's chain output order.
        owned = tuple(item for item in owned if item[1] == "FORWARD") + tuple(
            item for item in owned if item[1] != "FORWARD"
        )
        forward = [item for item in parsed if item[1] == "FORWARD"]
        for rule in forward:
            if rule in owned:
                continue
            target_flag = next(
                (flag for flag in ("-j", "--jump", "-g", "--goto") if flag in rule),
                None,
            )
            target = (
                rule[rule.index(target_flag) + 1] if target_flag is not None else None
            )
            if target not in {"ACCEPT", "LOG", "NFLOG", None}:
                interfaces = [
                    rule[rule.index(flag) + 1] for flag in ("-i", "-o") if flag in rule
                ]
                if (
                    len(interfaces) < 2
                    or device in interfaces
                    or "+" in "".join(interfaces)
                    or "!" in rule
                ):
                    raise ControlError(ErrorCode.CONFLICT)

        exists = any(line.startswith(f":{CHAIN} ") for line in raw.splitlines())
        return exists, owned, forward
