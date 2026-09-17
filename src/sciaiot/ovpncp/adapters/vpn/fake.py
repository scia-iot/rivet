"""Deterministic, isolated implementation for application workflow tests.

State is explicitly injectable so simulated restart retains operation fences.
This adapter never accesses a host, a socket, PKI, or application database.
"""

import dataclasses
import hashlib
import threading
import time
from collections.abc import Callable
from typing import Any

from sciaiot.ovpncp.application.vpn_control import archive, wire
from sciaiot.ovpncp.application.vpn_control import schemas as s
from sciaiot.ovpncp.application.vpn_control.errors import ControlError, ErrorCode


def default_config() -> s.ConfigResult:
    """Return a finite synthetic IPv4 configuration."""
    return s.ConfigResult(
        generation=0,
        device="tun0",
        network="10.8.0.0/24",
        server_address="10.8.0.1",
        device_type="tun",
        ccd_exclusive=True,
        keepalive=(10, 120),
        port=1194,
        protocol="udp",
        topology="subnet",
        persist_key=True,
        persist_tun=True,
    )


@dataclasses.dataclass
class FakeState:
    """Explicit test-owned state retained across fake process restarts."""

    max_operations: int = 10_000
    generation: int = 0
    config: s.ConfigResult = dataclasses.field(default_factory=default_config)
    clients: dict[str, s.ClientMetadata] = dataclasses.field(default_factory=dict)
    routes: dict[str, s.ManagedRoute] = dataclasses.field(default_factory=dict)
    access: dict[str, s.AccessIntent] = dataclasses.field(default_factory=dict)
    pushes: dict[tuple[str, str], s.OwnedPushes] = dataclasses.field(
        default_factory=dict
    )
    sessions: dict[str, s.Session] = dataclasses.field(default_factory=dict)
    events: list[s.Event] = dataclasses.field(default_factory=list)
    journal: dict[str, s.MutationResult] = dataclasses.field(default_factory=dict)
    expired: set[str] = dataclasses.field(default_factory=set)
    lock: Any = dataclasses.field(default_factory=threading.RLock)
    streams: int = 0


class MemorySource:
    """Owned finite source with immediate quota release on cancellation."""

    def __init__(
        self,
        data: bytes,
        release: Callable[[], None],
        validate: Callable[[], None] = lambda: None,
    ) -> None:
        self.validate = validate
        self.data = data
        self.offset = 0
        self.release = release
        self.closed = False

    def __next__(self) -> bytes:
        self.validate()
        if self.closed or self.offset == len(self.data):
            raise StopIteration
        chunk = self.data[self.offset : self.offset + s.MAX_CHUNK_BYTES]
        self.offset += len(chunk)
        return chunk

    def close(self) -> None:
        """Release the source and its quota exactly once."""
        if not self.closed:
            self.closed = True
            self.data = b""
            self.release()


class FakeVpnControl:
    """Execute the complete typed vocabulary against deterministic state."""

    def __init__(self, state: FakeState | None = None) -> None:
        self.state = state if state is not None else FakeState()
        self.fault: str | None = None

    def _validate(self, request: s.Request) -> s.Request:
        checked = wire.decode_request(wire.encode(request))
        if self.fault == "unauthorized":
            raise ControlError(ErrorCode.UNAUTHORIZED)
        if self.fault == "timeout":
            raise ControlError(ErrorCode.TIMEOUT)
        return checked

    def execute(self, request: s.Request) -> s.Response:
        """Validate and serialize operations, preserving immutable replay IDs."""
        request = self._validate(request)
        with self.state.lock:
            if isinstance(request.command, s.Archive):
                raise ControlError(ErrorCode.INVALID_INPUT)
            result: s.Result
            if request.operation_id is not None:
                result = self._mutate(request)
            else:
                result = self._read(request.command)
            response = s.Response(request_id=request.request_id, result=result)
            return wire.decode_response(wire.encode(response), request)

    def _read(self, command: s.Command) -> s.Result:
        state = self.state
        if isinstance(command, s.Health):
            return s.HealthResult(ready=True, generation=state.generation)
        if isinstance(command, s.ServerConfig):
            return state.config.model_copy(update={"generation": state.generation})
        if isinstance(command, s.LookupOperation):
            if command.operation_id in state.expired:
                raise ControlError(ErrorCode.EXPIRED_OPERATION)
            if command.operation_id not in state.journal:
                raise ControlError(ErrorCode.NOT_FOUND)
            return state.journal[command.operation_id]
        if isinstance(command, s.GetClient):
            if command.client not in state.clients:
                raise ControlError(ErrorCode.NOT_FOUND)
            return s.ClientResult(item=state.clients[command.client])
        if isinstance(command, s.ListClients):
            items, cursor = self._page(command, list(state.clients.values()))
            return s.ClientsResult(
                items=items, next_cursor=cursor, generation=state.generation
            )
        if isinstance(command, s.ListRoutes):
            items, cursor = self._page(command, list(state.routes.values()))
            return s.RoutesResult(
                items=items, next_cursor=cursor, generation=state.generation
            )
        if isinstance(command, s.ListAccess):
            items, cursor = self._page(command, list(state.access.values()))
            pushes, push_cursor = self._page(command, list(state.pushes.values()))
            return s.AccessResult(
                items=items,
                pushes=pushes,
                next_cursor=cursor or push_cursor,
                generation=state.generation,
            )
        if isinstance(command, s.ListSessions):
            items, cursor = self._page(command, list(state.sessions.values()))
            return s.SessionsResult(
                items=items, next_cursor=cursor, generation=state.generation
            )
        if isinstance(command, s.PollEvents):
            items, cursor = self._page(
                command,
                [event for event in state.events if event.sequence > command.after],
            )
            return s.EventsResult(items=items, next_cursor=cursor)
        raise ControlError(ErrorCode.INVALID_INPUT)

    def _page(
        self, command: s.Page, items: list[Any]
    ) -> tuple[tuple[Any, ...], str | None]:
        offset = 0
        if command.cursor is not None:
            parts = command.cursor.split("_", 2)
            if (
                len(parts) != 3
                or parts[0] != str(self.state.generation)
                or not parts[1].isdigit()
                or parts[2] != getattr(command, "kind", "")
            ):
                raise ControlError(ErrorCode.CONFLICT)
            offset = int(parts[1])
        page = tuple(items[offset : offset + command.limit])
        cursor = None
        if offset + command.limit < len(items):
            cursor = f"{self.state.generation}_{offset + command.limit}_{getattr(command, 'kind', '')}"
        return page, cursor

    def _mutate(self, request: s.Request) -> s.MutationResult:
        state = self.state
        operation_id = request.operation_id
        assert operation_id is not None
        if operation_id in state.expired:
            raise ControlError(ErrorCode.EXPIRED_OPERATION)
        digest = wire.intent_digest(request)
        previous = state.journal.get(operation_id)
        if previous is not None:
            if previous.intent_sha256 != digest:
                raise ControlError(ErrorCode.CONFLICT)
            return previous
        if len(state.journal) + len(state.expired) >= state.max_operations:
            raise ControlError(ErrorCode.EXHAUSTED)
        if request.expected_generation != state.generation:
            raise ControlError(ErrorCode.CONFLICT)
        try:
            if self.fault == "failed":
                raise ControlError(ErrorCode.NOT_FOUND)
            self._apply(request.command)
        except ControlError as error:
            result = s.MutationResult(
                operation_id=operation_id,
                generation=state.generation,
                intent_sha256=digest,
                state="failed",
                failure=error.code,
                client=getattr(request.command, "client", None),
            )
        else:
            state.generation += 1
            result = s.MutationResult(
                operation_id=operation_id,
                generation=state.generation,
                intent_sha256=digest,
                state="partial" if self.fault == "partial" else "succeeded",
                completed=("pki",) if self.fault == "partial" else (),
                client=getattr(request.command, "client", None),
            )
        state.journal[operation_id] = result
        if self.fault == "lost_reply":
            raise ControlError(ErrorCode.UNKNOWN_OUTCOME)
        return result

    def _apply(self, command: s.Command) -> None:
        state = self.state
        if isinstance(command, s.ChangeClient):
            previous = state.clients.get(command.client)
            if command.action == "issue":
                if previous is not None:
                    raise ControlError(ErrorCode.CONFLICT)
                state.clients[command.client] = s.ClientMetadata(
                    client=command.client,
                    generation=0,
                    state="active",
                    issuer="Synthetic CA",
                    subject=command.client,
                    certificate_sha256=hashlib.sha256(
                        command.client.encode()
                    ).hexdigest(),
                    not_before=1_700_000_000_000_000,
                    not_after=1_900_000_000_000_000,
                )
            else:
                if previous is None:
                    raise ControlError(ErrorCode.NOT_FOUND)
                if command.action == "delete" and previous.state != "revoked":
                    raise ControlError(ErrorCode.CONFLICT)
                if command.action == "renew" and previous.state != "active":
                    raise ControlError(ErrorCode.CONFLICT)
                new_state = {
                    "renew": "active",
                    "revoke": "revoked",
                    "delete": "deleted",
                }[command.action]
                state.clients[command.client] = previous.model_copy(
                    update={"state": new_state, "generation": previous.generation + 1}
                )
        elif isinstance(command, s.SetAssignment):
            previous = state.clients.get(command.client)
            if previous is None:
                raise ControlError(ErrorCode.NOT_FOUND)
            if command.assignment is not None and previous.state != "active":
                raise ControlError(ErrorCode.CONFLICT)
            if command.assignment is not None and any(
                item.client != command.client
                and item.assignment is not None
                and item.assignment.address == command.assignment.address
                for item in state.clients.values()
            ):
                raise ControlError(ErrorCode.CONFLICT)
            state.clients[command.client] = previous.model_copy(
                update={"assignment": command.assignment}
            )
        elif isinstance(command, s.SetRoute):
            if command.present:
                if any(
                    item.route_id != command.route.route_id
                    and item.network == command.route.network
                    for item in state.routes.values()
                ):
                    raise ControlError(ErrorCode.CONFLICT)
                state.routes[command.route.route_id] = command.route
            else:
                state.routes.pop(command.route.route_id, None)
        elif isinstance(command, s.SetAccess):
            if command.present:
                for name, address in (
                    (command.intent.source_client, command.intent.source_address),
                    (
                        command.intent.destination_client,
                        command.intent.destination_address,
                    ),
                ):
                    item = state.clients.get(name)
                    if (
                        item is None
                        or item.state != "active"
                        or item.assignment is None
                        or item.assignment.address != address
                    ):
                        raise ControlError(ErrorCode.CONFLICT)
                previous_intent = state.access.get(command.intent.access_id)
                if previous_intent is not None and previous_intent != command.intent:
                    raise ControlError(ErrorCode.CONFLICT)
                state.access[command.intent.access_id] = command.intent
            else:
                state.access.pop(command.intent.access_id, None)
        elif isinstance(command, s.SetPushRoutes):
            if command.routes:
                client = state.clients.get(command.client)
                intent = state.access.get(command.intent_id)
                if (
                    client is None
                    or client.state != "active"
                    or intent is None
                    or intent.source_client != command.client
                ):
                    raise ControlError(ErrorCode.CONFLICT)
                state.pushes[(command.intent_id, command.client)] = s.OwnedPushes(
                    intent_id=command.intent_id,
                    client=command.client,
                    routes=command.routes,
                )
            else:
                state.pushes.pop((command.intent_id, command.client), None)
        elif isinstance(command, s.Disconnect):
            session = state.sessions.get(command.session_id)
            if session is not None and session.client != command.client:
                raise ControlError(ErrorCode.CONFLICT)
            state.sessions.pop(command.session_id, None)
        elif isinstance(command, s.AckEvents):
            state.events[:] = [
                event for event in state.events if event.sequence > command.through
            ]
        elif not isinstance(command, s.Reload):
            raise ControlError(ErrorCode.INVALID_INPUT)

    def open_archive(self, request: s.Request) -> archive.ArchiveStream:
        """Pin active credential identity and enforce four owned streams."""
        request = self._validate(request)
        command = request.command
        if not isinstance(command, s.Archive):
            raise ControlError(ErrorCode.INVALID_INPUT)
        with self.state.lock:
            item = self.state.clients.get(command.client)
            if item is None:
                raise ControlError(ErrorCode.NOT_FOUND)
            if item.state != "active" or item.generation != command.generation:
                raise ControlError(ErrorCode.CONFLICT)
            if self.state.streams >= s.MAX_STREAMS:
                raise ControlError(ErrorCode.EXHAUSTED)
            self.state.streams += 1

        def release() -> None:
            with self.state.lock:
                self.state.streams -= 1

        data = b"synthetic credential archive"

        def validate() -> None:
            current = self.state.clients.get(command.client)
            if (
                current is None
                or current.state != "active"
                or current.generation != command.generation
            ):
                raise ControlError(ErrorCode.CONFLICT)

        source = MemorySource(data, release, validate)
        manifest = s.ArchiveManifest(
            request_id=request.request_id,
            client=command.client,
            generation=command.generation,
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
        )
        return archive.ArchiveStream(source, manifest, request, time.monotonic)
