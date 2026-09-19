"""Durable owned CCD edits with exact preimage crash reconciliation."""

import base64
import ipaddress
import json
import os
import shlex
import stat
import uuid
from pathlib import Path

from sciaiot.ovpncp.application.vpn_control import schemas as s
from sciaiot.ovpncp.application.vpn_control.errors import ControlError, ErrorCode

from . import bounded, files
from .journal import Journal
from .settings import Settings


def replace_block(content: bytes, owner: str, replacement: bytes) -> bytes:
    """Replace one exact marked block and preserve all operator-owned bytes."""
    begin = f"# ovpncp:begin:{owner}\n".encode()
    end = f"# ovpncp:end:{owner}\n".encode()
    if content.count(begin) != content.count(end) or content.count(begin) > 1:
        raise ControlError(ErrorCode.CONFLICT)
    if begin in content:
        start = content.index(begin)
        finish = content.index(end) + len(end)
        if (
            finish <= start
            or b"# ovpncp:" in content[start + len(begin) : finish - len(end)]
        ):
            raise ControlError(ErrorCode.CONFLICT)
        foreign = content[:start] + content[finish:]
    else:
        if owner.encode() in content and b"# ovpncp:" in content:
            raise ControlError(ErrorCode.CONFLICT)
        start = len(content)
        finish = start
        foreign = content
    if owner == "assignment":
        options = files.directives(foreign)
        if "ifconfig-push" in options or "iroute" in options:
            raise ControlError(ErrorCode.CONFLICT)
    block = begin + replacement + end if replacement else b""
    if block and start and content[start - 1 : start] != b"\n":
        raise ControlError(ErrorCode.CONFLICT)
    return content[:start] + block + content[finish:]


def atomic_write(
    path: Path,
    data: bytes,
    deadline: float,
    *,
    mode: int = 0o600,
    gid: int | None = None,
) -> None:
    """Fsync staged bytes and atomically replace within a verified directory."""
    if len(data) > bounded.MAX_BYTES:
        raise ControlError(ErrorCode.EXHAUSTED)
    for ancestor in (path.parent, *path.parent.parents):
        if not stat.S_ISDIR(ancestor.lstat().st_mode):
            raise ControlError(ErrorCode.UNAUTHORIZED)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = f".ovpncp-{uuid.uuid4().hex}"
    fd = -1
    try:
        try:
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ControlError(ErrorCode.INTEGRITY)
        except FileNotFoundError:
            pass
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        view = memoryview(data)
        while view:
            bounded.remaining(deadline)
            view = view[os.write(fd, view) :]
        os.fchmod(fd, mode)
        if gid is not None:
            os.fchown(fd, -1, gid)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)


def read_optional(path: Path, deadline: float) -> bytes:
    """Read a bounded existing regular file or the empty absent preimage."""
    try:
        return bounded.read_file(path, deadline)
    except FileNotFoundError:
        return b""


class CcdMutations:
    """Apply marked CCD state only after storing exact before/after bytes."""

    def __init__(self, settings: Settings, journal: Journal) -> None:
        self.settings = settings
        self.journal = journal

    def assignment(self, request: s.Request, deadline: float) -> None:
        """Ensure a valid subnet assignment without adopting foreign directives."""
        command = request.command
        assert isinstance(command, s.SetAssignment)
        assert request.operation_id is not None
        config = files.configuration(self.settings, deadline)
        if config.topology != "subnet":
            raise ControlError(ErrorCode.UNAVAILABLE)
        clients = files.clients(self.settings, deadline)
        client = next((item for item in clients if item.client == command.client), None)
        if client is None or client.state != "active":
            raise ControlError(ErrorCode.NOT_FOUND)
        replacement = b""
        if command.assignment is not None:
            assignment = command.assignment
            pool = ipaddress.IPv4Network(config.network)
            address = ipaddress.IPv4Address(assignment.address)
            if (
                address not in pool
                or address
                in {
                    pool.network_address,
                    pool.broadcast_address,
                    ipaddress.IPv4Address(config.server_address),
                }
                or any(
                    item.client != command.client
                    and item.assignment is not None
                    and item.assignment.address == assignment.address
                    for item in clients
                )
            ):
                raise ControlError(ErrorCode.CONFLICT)
            replacement = f"ifconfig-push {address} {pool.netmask}\n".encode()
            if assignment.network is not None:
                network = ipaddress.IPv4Network(assignment.network)
                if network.overlaps(pool):
                    raise ControlError(ErrorCode.CONFLICT)
                replacement += (
                    f"iroute {network.network_address} {network.netmask}\n".encode()
                )
        self._edit(
            request.operation_id, command.client, "assignment", replacement, deadline
        )

    def clear_assignment(self, operation_id: str, client: str, deadline: float) -> None:
        """Remove only owned assignment state during a revoked leaf deletion."""
        s.GetClient(client=client)
        self._edit(operation_id, client, "assignment", b"", deadline)

    def _edit(
        self,
        operation_id: str,
        client: str,
        owner: str,
        replacement: bytes,
        deadline: float,
    ) -> None:
        path = self.settings.ccd_path / client
        raw = self.journal.evidence(operation_id, "ccd")
        projection = (
            self.settings.projection_path / "ccd" / client
            if self.settings.projection_path is not None
            else None
        )
        if raw is None:
            before = read_optional(path, deadline)
            after = replace_block(before, owner, replacement)
            raw = json.dumps(
                {
                    "before": base64.b64encode(before).decode(),
                    "after": base64.b64encode(after).decode(),
                }
            ).encode()
            if projection is not None:
                projected_before = read_optional(projection, deadline)
                if projected_before and projected_before != before:
                    raise ControlError(ErrorCode.CONFLICT)
                self.journal.stage(operation_id, "ccd_projection", projected_before)
            self.journal.stage(operation_id, "ccd", raw)
        evidence = json.loads(raw)
        before = base64.b64decode(evidence["before"], validate=True)
        after = base64.b64decode(evidence["after"], validate=True)
        actual = read_optional(path, deadline)
        if actual not in {before, after}:
            raise ControlError(ErrorCode.CONFLICT)
        if actual != after:
            atomic_write(path, after, deadline)
        if read_optional(path, deadline) != after:
            raise ControlError(ErrorCode.CONFLICT)
        if projection is not None:
            retained_projection = self.journal.evidence(operation_id, "ccd_projection")
            if retained_projection is None:
                raise ControlError(ErrorCode.INTEGRITY)
            projected_actual = read_optional(projection, deadline)
            if projected_actual not in {retained_projection, after}:
                raise ControlError(ErrorCode.CONFLICT)
            if projected_actual != after:
                atomic_write(
                    projection,
                    after,
                    deadline,
                    mode=0o640,
                    gid=self.settings.management_gid,
                )
            if read_optional(projection, deadline) != after:
                raise ControlError(ErrorCode.CONFLICT)
        self.journal.checkpoint(operation_id, "ccd")

    def pushes(self, request: s.Request, deadline: float) -> None:
        """Replace pushes only for their exact existing access ownership key."""
        from . import network

        command = request.command
        assert isinstance(command, s.SetPushRoutes)
        assert request.operation_id is not None
        if self.settings.ownership_path is None:
            raise ControlError(ErrorCode.UNAVAILABLE)
        raw = self.journal.evidence(request.operation_id, "pushes")
        if raw is None:
            before = bounded.read_file(self.settings.ownership_path, deadline)
            inventory = network.Ownership.model_validate_json(before)
            intent = next(
                (
                    item
                    for item in inventory.access
                    if item.access_id == command.intent_id
                ),
                None,
            )
            if intent is None or command.client != intent.source_client:
                raise ControlError(ErrorCode.CONFLICT)
            if any(
                route.network not in intent.private_networks
                or route.gateway != intent.destination_address
                for route in command.routes
            ):
                raise ControlError(ErrorCode.CONFLICT)
            pushes = tuple(
                item
                for item in inventory.pushes
                if (item.intent_id, item.client) != (command.intent_id, command.client)
            )
            if command.routes:
                pushes += (
                    s.OwnedPushes(
                        intent_id=command.intent_id,
                        client=command.client,
                        routes=command.routes,
                    ),
                )
            target = network.Ownership.model_validate(
                inventory.model_copy(update={"pushes": pushes})
            )
            raw = json.dumps(
                {"before": before.decode(), "after": target.model_dump_json()}
            ).encode()
            self.journal.stage(request.operation_id, "pushes", raw)
        evidence = json.loads(raw)
        if bounded.read_file(self.settings.ownership_path, deadline).decode() not in {
            evidence["before"],
            evidence["after"],
        }:
            raise ControlError(ErrorCode.CONFLICT)
        content = b""
        for route in command.routes:
            subnet = ipaddress.IPv4Network(route.network)
            content += f'push "route {subnet.network_address} {subnet.netmask} {route.gateway}"\n'.encode()
        owner = f"push:{command.intent_id}"
        if self.journal.evidence(request.operation_id, "ccd") is None:
            original = read_optional(self.settings.ccd_path / command.client, deadline)
            foreign = replace_block(original, owner, b"")
            existing = files.directives(foreign).get("push", [])
            proposed = files.directives(content).get("push", [])
            if any(
                shlex.split(item[0]) == shlex.split(candidate[0])
                for item in existing
                if len(item) == 1
                for candidate in proposed
            ):
                raise ControlError(ErrorCode.CONFLICT)
        self._edit(request.operation_id, command.client, owner, content, deadline)
        atomic_write(self.settings.ownership_path, evidence["after"].encode(), deadline)
