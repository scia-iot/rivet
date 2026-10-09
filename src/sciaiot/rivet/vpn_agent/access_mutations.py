"""Atomic owned firewall realization with first-position TUN anchors."""

import json
import re
import shlex
from collections import defaultdict
from dataclasses import dataclass

from sciaiot.rivet.application.vpn_control import schemas as s
from sciaiot.rivet.application.vpn_control.errors import ControlError, ErrorCode

from . import bounded, files, network
from .journal import Journal
from .mutations import atomic_write, read_optional
from .settings import Settings

CHAIN = "OVPNCP_FORWARD"
MAX_CHAIN_DEPTH = 16
MAX_REACHABLE_CHAINS = 64
_MATCH_OPTIONS = {
    "-s": 1,
    "--source": 1,
    "-d": 1,
    "--destination": 1,
    "-p": 1,
    "--protocol": 1,
    "-m": 1,
    "--match": 1,
    "--comment": 1,
    "--ctstate": 1,
    "--dport": 1,
    "--sport": 1,
    "--dports": 1,
    "--sports": 1,
    "--dst-type": 1,
    "--src-type": 1,
    "--tcp-flags": 2,
}
_MATCH_MODULES = {"addrtype", "comment", "conntrack", "icmp", "multiport", "tcp", "udp"}
_INTERFACES = {
    "-i": "ingress",
    "--in-interface": "ingress",
    "-o": "egress",
    "--out-interface": "egress",
}
_JUMPS = {"-j", "--jump", "-g", "--goto"}


@dataclass(frozen=True)
class _FilterRule:
    """A strict, side-effect-free parse of one iptables-save rule."""

    words: tuple[str, ...]
    chain: str
    target: str
    ingress: tuple[str, bool] | None
    egress: tuple[str, bool] | None

    def disjoint_from_peer_traffic(self, device: str) -> bool:
        """Prove one positive exact interface excludes TUN-to-TUN packets."""
        for selector in (self.ingress, self.egress):
            if selector is not None and not selector[1] and selector[0] != device:
                return True
        return False


def _filter_rule(words: tuple[str, ...]) -> _FilterRule:
    """Parse only known match syntax, never treating a value as an option."""
    if len(words) < 4 or words[0] != "-A":
        raise ControlError(ErrorCode.CONFLICT)
    selectors: dict[str, tuple[str, bool]] = {}
    target: str | None = None
    negated = False
    index = 2
    while index < len(words):
        option = words[index]
        if option == "!":
            if negated:
                raise ControlError(ErrorCode.CONFLICT)
            negated = True
            index += 1
            continue
        if option in _JUMPS:
            if negated or target is not None or index + 1 >= len(words):
                raise ControlError(ErrorCode.CONFLICT)
            if option in {"-g", "--goto"}:
                raise ControlError(ErrorCode.CONFLICT)
            target = words[index + 1]
            index += 2
            continue
        if option in _INTERFACES:
            kind = _INTERFACES[option]
            if kind in selectors or index + 1 >= len(words):
                raise ControlError(ErrorCode.CONFLICT)
            value = words[index + 1]
            if re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", value) is None:
                raise ControlError(ErrorCode.CONFLICT)
            selectors[kind] = (value, negated)
            negated = False
            index += 2
            continue
        arity = _MATCH_OPTIONS.get(option)
        if arity is None or index + arity >= len(words):
            raise ControlError(ErrorCode.CONFLICT)
        if option in {"-m", "--match"} and words[index + 1] not in _MATCH_MODULES:
            raise ControlError(ErrorCode.CONFLICT)
        if negated and option in {"-m", "--match", "--comment"}:
            raise ControlError(ErrorCode.CONFLICT)
        negated = False
        index += arity + 1
    if negated or target is None or not target:
        raise ControlError(ErrorCode.CONFLICT)
    return _FilterRule(
        words, words[1], target, selectors.get("ingress"), selectors.get("egress")
    )


def prove_foreign_forward(
    raw: str, device: str, owned: tuple[tuple[str, ...], ...] = ()
) -> None:
    """Fail unless foreign policy cannot deny an owned TUN-to-TUN grant.

    A bridge-specific rule is harmless only when its positive exact interface
    selector cannot match either side of peer traffic. All other reachable
    verdicts and targets are checked recursively with fixed graph bounds.

    Args:
        raw: Complete iptables-nft-save filter-table output.
        device: Configured TUN device whose peer traffic may be granted.
        owned: Exact already-identified agent rules to exclude from proof.

    Raises:
        ControlError: The observation is incomplete, ambiguous, unsafe, or
            exceeds the fixed parse or graph bounds.
    """
    policies: dict[str, str] = {}
    by_chain: dict[str, list[tuple[str, ...]]] = defaultdict(list)
    count = 0
    if len(raw.encode()) > bounded.MAX_BYTES:
        raise ControlError(ErrorCode.EXHAUSTED)
    lines = [line for line in raw.splitlines() if line and not line.startswith("#")]
    if len(lines) < 3 or lines[0] != "*filter" or lines[-1] != "COMMIT":
        raise ControlError(ErrorCode.CONFLICT)
    try:
        for line in lines[1:-1]:
            if line.startswith(":"):
                declaration = line.split()
                if (
                    len(declaration) != 3
                    or declaration[0][1:] in policies
                    or re.fullmatch(r"\[\d+:\d+\]", declaration[2]) is None
                ):
                    raise ControlError(ErrorCode.CONFLICT)
                policies[declaration[0][1:]] = declaration[1]
            elif line.startswith("-A "):
                count += 1
                if count > bounded.MAX_RECORDS:
                    raise ControlError(ErrorCode.EXHAUSTED)
                words = tuple(shlex.split(line))
                if words in owned:
                    continue
                # Parse reachable chains below; unrelated chains may use
                # match extensions that this proof does not understand.
                if len(words) < 2:
                    raise ControlError(ErrorCode.CONFLICT)
                by_chain[words[1]].append(words)
            else:
                raise ControlError(ErrorCode.CONFLICT)
    except ValueError as error:
        raise ControlError(ErrorCode.CONFLICT) from error
    if policies.get("FORWARD") not in {"ACCEPT", "DROP"}:
        raise ControlError(ErrorCode.CONFLICT)

    checked: set[str] = set()
    active: set[str] = set()

    def walk(chain: str, depth: int) -> None:
        """Prove every reachable rule in a declared acyclic user chain."""
        if depth > MAX_CHAIN_DEPTH or chain in active:
            raise ControlError(ErrorCode.CONFLICT)
        if chain in checked:
            return
        if len(checked) + len(active) >= MAX_REACHABLE_CHAINS:
            raise ControlError(ErrorCode.CONFLICT)
        policy = policies.get(chain)
        if policy is None or (chain != "FORWARD" and policy != "-"):
            raise ControlError(ErrorCode.CONFLICT)
        active.add(chain)
        for words in by_chain.get(chain, ()):
            rule = _filter_rule(words)
            if rule.disjoint_from_peer_traffic(device):
                continue
            if rule.target in {"ACCEPT", "LOG", "NFLOG"}:
                continue
            if rule.target == "RETURN":
                if chain == "FORWARD" and policy != "ACCEPT":
                    raise ControlError(ErrorCode.CONFLICT)
                continue
            if rule.target not in policies or rule.target == CHAIN:
                raise ControlError(ErrorCode.CONFLICT)
            walk(rule.target, depth + 1)
        active.remove(chain)
        checked.add(chain)

    walk("FORWARD", 0)


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
            result.append(
                network._rule(source, destination, f"{marker}:forward", device)
            )
            result.append(
                network._rule(destination, source, f"{marker}:reverse", device)
            )
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
            or (
                _filter_rule(item).target == CHAIN
                if item[1] == "FORWARD"
                else any(
                    item[index : index + 2] == ("-j", CHAIN)
                    for index in range(2, len(item) - 1)
                )
            )
        )
        # Return anchors first regardless of save's chain output order.
        owned = tuple(item for item in owned if item[1] == "FORWARD") + tuple(
            item for item in owned if item[1] != "FORWARD"
        )
        forward = [item for item in parsed if item[1] == "FORWARD"]
        prove_foreign_forward(raw, device, owned)

        exists = any(line.startswith(f":{CHAIN} ") for line in raw.splitlines())
        return exists, owned, forward
