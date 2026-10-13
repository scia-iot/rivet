"""Bootstrap and verify the agent-owned native VPN firewall boundary."""

import os
import re
import shlex
import sys
import time
from pathlib import Path

from sciaiot.rivet.application.vpn_control.errors import ControlError
from sciaiot.rivet.vpn_agent import access_mutations, bounded, files, network
from sciaiot.rivet.vpn_agent.settings import Settings

DEVICE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}\Z")


def read_ipv4_sysctl(key: str) -> str:
    """Read one fixed IPv4 forwarding prerequisite from procfs."""
    return (Path("/proc/sys/net/ipv4") / key).read_text().strip()


def plan(snapshot: str, inventory: network.Ownership, device: str) -> str | None:
    """Return a no-flush bootstrap transaction or verify exact owned state.

    Args:
        snapshot: One complete iptables-nft-save filter table.
        inventory: Explicit agent ownership manifest.
        device: Reviewed numbered TUN interface.

    Returns:
        A restore transaction for absent empty state, or ``None`` when ready.

    Raises:
        ValueError: State is ambiguous, foreign-owned or unsafe to boot.
    """
    if DEVICE.fullmatch(device) is None or not device.startswith("tun"):
        raise ValueError("Invalid native VPN device.")
    lines = [
        line for line in snapshot.splitlines() if line and not line.startswith("#")
    ]
    if len(lines) < 3 or lines[0] != "*filter" or lines[-1] != "COMMIT":
        raise ValueError("Invalid firewall snapshot.")
    try:
        parsed = [
            tuple(shlex.split(line)) for line in lines[1:-1] if line.startswith("-A ")
        ]
    except ValueError:
        raise ValueError("Invalid firewall snapshot.") from None
    expected = access_mutations.rules(inventory, device)
    anchors = expected[:2]
    forward = tuple(rule for rule in parsed if rule[1] == "FORWARD")
    owned = tuple(
        rule
        for rule in parsed
        if rule[1] == access_mutations.CHAIN or access_mutations.CHAIN in rule[2:]
    )
    owned = tuple(rule for rule in owned if rule[1] == "FORWARD") + tuple(
        rule for rule in owned if rule[1] != "FORWARD"
    )
    exists = any(line.startswith(f":{access_mutations.CHAIN} ") for line in lines)
    if exists:
        if owned != expected or forward[:2] != anchors:
            raise ValueError("Unexpected owned firewall state.")
        try:
            access_mutations.prove_foreign_forward(snapshot, device, owned)
        except ControlError:
            raise ValueError("Unsafe foreign forwarding policy.") from None
        return None
    if owned or inventory.access or "ovpncp:" in snapshot:
        raise ValueError("Unexpected owned firewall state.")
    try:
        access_mutations.prove_foreign_forward(snapshot, device)
    except ControlError:
        raise ValueError("Unsafe foreign forwarding policy.") from None
    transaction = ["*filter", f":{access_mutations.CHAIN} - [0:0]"]
    for anchor in reversed(anchors):
        transaction.append(shlex.join(("-I", "FORWARD", "1", *anchor[2:])))
    transaction.append(shlex.join(expected[-1]))
    transaction.extend(("COMMIT", ""))
    return "\n".join(transaction)


def ensure() -> None:
    """Initialize only empty owned state, then verify the kernel snapshot.

    Raises:
        ValueError: The reviewed device, manifest or firewall is unsafe.
        ControlError: A bounded system operation fails.
    """
    settings = Settings.from_environment()
    device = os.environ.get("RIVET_FIREWALL_DEVICE", "")
    if settings.ownership_path is None or not settings.ownership_path.exists():
        raise ValueError("An explicit ownership manifest is required.")
    deadline = time.monotonic() + 10
    config = files.configuration(settings, deadline)
    if config.device != device or config.device_type != "tun":
        raise ValueError("Firewall device does not match OpenVPN configuration.")
    for key, expected in (
        ("ip_forward", "1"),
        ("conf/all/send_redirects", "0"),
        ("conf/default/send_redirects", "0"),
    ):
        value = read_ipv4_sysctl(key)
        if value != expected:
            raise ValueError("Native forwarding sysctls are not ready.")
    inventory = network.ownership(settings, deadline)
    snapshot = bounded.observe("rules", device, deadline).decode("ascii")
    transaction = plan(snapshot, inventory, device)
    if transaction is not None:
        bounded.command(
            ["/usr/sbin/iptables-nft-restore", "--noflush", "--wait", "5"],
            deadline,
            transaction.encode("ascii"),
        )
    current = bounded.observe("rules", device, deadline).decode("ascii")
    if plan(current, inventory, device) is not None:
        raise ValueError("Owned firewall bootstrap was not retained.")


def main() -> None:
    """Fail closed before an OpenVPN listener can accept tunnel traffic."""
    try:
        ensure()
    except ControlError, OSError, UnicodeError, ValueError:
        print(
            "Native VPN firewall is not ready; review owned state and policy.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
