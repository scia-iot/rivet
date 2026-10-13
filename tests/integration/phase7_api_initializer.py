"""Initialize a fresh API inventory from the already imported VPN agent.

Run this operator-only script in a stopped API container with its private data
and profile volumes mounted read-write and the agent socket mounted read-only.
No HTTP listener or authentication override is created by this script.
"""

import argparse
import asyncio
import json
import os
import stat
from collections.abc import Sequence
from pathlib import Path

from sqlmodel import Session, select

from sciaiot.rivet import dependencies
from sciaiot.rivet.data.server import Client, Server
from sciaiot.rivet.routes import client, server
from sciaiot.rivet.services.vpn import VpnService, is_valid_name


class BootstrapError(Exception):
    """A reviewed source baseline or fresh API precondition did not hold."""


def _address(row: Client) -> str | None:
    """Return a persisted assignment without a nullable relationship race."""
    assignment = row.virtual_address
    return assignment.ip if assignment is not None else None


def read_remote_host(path: Path) -> str:
    """Read one privately staged endpoint without following a symlink."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) not in {0o400, 0o600}
            or info.st_size > 255
        ):
            raise BootstrapError("invalid endpoint file")
        value = os.read(descriptor, 256).decode("ascii").rstrip("\n")
        if not value or "\n" in value or "\r" in value:
            raise BootstrapError("invalid endpoint file")
        return value
    finally:
        os.close(descriptor)


def initialize(
    session: Session,
    *,
    remote_host: str,
    expected_active: int,
    expected_assigned: int,
) -> dict[str, int]:
    """Create server and client rows only after exact inventory preflight.

    Args:
        session: Dedicated session for a fresh, stopped API database.
        remote_host: Reviewed public endpoint for new shared client profiles.
        expected_active: Count of indexed active client leaves in the M0 source.
        expected_assigned: Count of active clients with a reviewed CCD address.

    Returns:
        Redacted counts of active, assigned, and skipped source identities.

    Raises:
        BootstrapError: Fresh state or reviewed inventory checks fail.
    """
    if (
        expected_active < 0
        or expected_assigned < 0
        or expected_assigned > expected_active
        or session.exec(select(Server)).first() is not None
        or session.exec(select(Client)).first() is not None
    ):
        raise BootstrapError("fresh API state is required")

    discovered = VpnService(session).discoveries()
    active = [item for item in discovered if item is not None]
    names = [item[0] for item in active]
    assigned = [item[2] for item in active if item[2] is not None]
    if (
        len(active) != expected_active
        or len(assigned) != expected_assigned
        or len(names) != len(set(names))
        or len(assigned) != len(set(assigned))
        or any(not is_valid_name(name) for name in names)
    ):
        raise BootstrapError("VPN inventory differs from reviewed baseline")

    request = server.ServerInitializationRequest(remote_host=remote_host)
    # Calling the same route business workflow in a private operator process
    # does not expose an unauthenticated HTTP endpoint.
    asyncio.run(server.init_server(request, session, None))  # type: ignore[arg-type]
    summary = client._import_clients(session)
    session.expire_all()
    rows = session.exec(select(Client)).all()
    by_name = {row.name: row for row in rows}
    if (
        summary.added != expected_active
        or summary.updated != 0
        or summary.devices_created != 0
        or set(by_name) != set(names)
        or any(_address(by_name[name]) != address for name, _, address in active)
    ):
        raise BootstrapError("persisted API inventory differs from VPN source")
    return {
        "active": len(active),
        "assigned": len(assigned),
        "skipped": len(discovered) - len(active),
    }


def main(argv: Sequence[str] | None = None) -> int:
    """Run one bounded initialization under an explicit operator boundary."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remote-host-file", type=Path, required=True)
    parser.add_argument("--expected-active", type=int, required=True)
    parser.add_argument("--expected-assigned", type=int, required=True)
    args = parser.parse_args(argv)
    if (
        os.geteuid() != 65531
        or os.environ.get("RIVET_VPN_BACKEND") != "agent"
        or os.environ.get("RIVET_VPN_EVENTS", "0") != "0"
        or os.environ.get("RIVET_VPN_RECONCILE", "0") != "0"
    ):
        parser.exit(2, "operator environment is not isolated\n")
    try:
        dependencies.create_tables()
        with Session(dependencies.engine) as session:
            result = initialize(
                session,
                remote_host=read_remote_host(args.remote_host_file),
                expected_active=args.expected_active,
                expected_assigned=args.expected_assigned,
            )
    except Exception:  # noqa: BLE001 - do not reveal endpoint or credentials
        parser.exit(1, "API inventory initialization failed; inspect private state\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
