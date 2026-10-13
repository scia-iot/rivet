"""Reusable adapter assertions plus an IO-free, tests-only reference model.

Future adapter fixtures implement Harness against disposable mocked state.
This reference is a protocol oracle, not the Phase 2 application fake.
"""

import hashlib
from typing import Literal, Protocol

import pytest

from sciaiot.rivet.application.vpn_control import archive, port, wire
from sciaiot.rivet.application.vpn_control import schemas as s
from sciaiot.rivet.application.vpn_control.errors import ControlError, ErrorCode

RID = "00000000-0000-4000-8000-000000000001"
OID = "00000000-0000-4000-8000-000000000002"
OTHER = "00000000-0000-4000-8000-000000000003"


def request(command: s.Command, *, generation: int = 0) -> s.Request:
    """Create an isolated reference request with stable identities."""
    mutation = command.kind in s.MUTATION_KINDS
    return s.Request(
        request_id=RID,
        command=command,
        operation_id=OID if mutation else None,
        expected_generation=generation if mutation else None,
    )


class Harness(Protocol):
    """Fixture contract; controls are test facilities, never wire commands."""

    @property
    def control(self) -> port.VpnControl:
        """Return the adapter under test."""
        ...

    def set_fault(self, fault: str | None) -> None:
        """Configure trusted-peer denial, timeout, partial or lost reply."""
        ...

    def restart(self) -> None:
        """Recreate the adapter while retaining its committed test journal."""
        ...

    def expire(self, operation_id: str) -> None:
        """Advance retention while preserving anti-replay tombstones."""
        ...


class BytesSource:
    """Bounded synthetic source with observable close/cancel ownership."""

    def __init__(self, chunks: tuple[bytes, ...]) -> None:
        self.chunks = iter(chunks)
        self.closes = 0

    def __next__(self) -> bytes:
        return next(self.chunks)

    def close(self) -> None:
        """Record exact resource release count."""
        self.closes += 1


class ReferenceControl:
    """Minimal state machine for contract assertions, with no files or IO."""

    def __init__(self) -> None:
        self.generation = 0
        self.journal: dict[str, s.MutationResult] = {}
        self.expired: set[str] = set()
        self.fault: str | None = None
        self.sources: list[BytesSource] = []

    def _validate(self, incoming: s.Request) -> s.Request:
        if self.fault == "unauthorized":
            raise ControlError(ErrorCode.UNAUTHORIZED)
        checked = wire.decode_request(wire.encode(incoming))
        if self.fault == "timeout":
            raise ControlError(ErrorCode.TIMEOUT)
        return checked

    def execute(self, incoming: s.Request) -> s.Response:
        """Apply finite reference effects and correlate every return value."""
        checked = self._validate(incoming)
        command = checked.command
        result: s.Result
        if isinstance(command, s.Archive):
            raise ControlError(ErrorCode.INVALID_INPUT)
        if isinstance(command, s.LookupOperation):
            if command.operation_id in self.expired:
                raise ControlError(ErrorCode.EXPIRED_OPERATION)
            if command.operation_id not in self.journal:
                raise ControlError(ErrorCode.NOT_FOUND)
            result = self.journal[command.operation_id]
        elif checked.operation_id is not None:
            result = self._mutate(checked)
        elif isinstance(command, s.Health):
            result = s.HealthResult(ready=True, generation=self.generation)
        elif isinstance(command, s.ServerConfig):
            result = s.ConfigResult(
                generation=self.generation,
                device="tun-server",
                network="10.8.0.0/24",
                server_address="10.8.0.1",
                device_type="tun",
                ccd_exclusive=True,
                keepalive=(10, 120),
                port=1194,
                protocol="udp4",
                topology="subnet",
                persist_key=True,
                persist_tun=True,
                data_ciphers=("AES-256-GCM",),
                verbosity=3,
                explicit_exit_notify=1,
            )
        elif isinstance(command, s.GetClient):
            result = s.ClientResult(item=client(command.client))
        elif isinstance(command, s.ListClients):
            result = s.ClientsResult(items=(client(),), generation=0)
        elif isinstance(command, s.ListRoutes):
            result = s.RoutesResult(items=(), generation=self.generation)
        elif isinstance(command, s.ListAccess):
            result = s.AccessResult(items=(), pushes=(), generation=0)
        elif isinstance(command, s.ListSessions):
            result = s.SessionsResult(items=(), generation=self.generation)
        elif isinstance(command, s.PollEvents):
            result = s.EventsResult(items=())
        else:
            raise AssertionError("unhandled reference command")
        response = s.Response(request_id=checked.request_id, result=result)
        return wire.decode_response(wire.encode(response), checked)

    def _mutate(self, checked: s.Request) -> s.MutationResult:
        operation_id = checked.operation_id
        assert operation_id is not None
        if operation_id in self.expired:
            raise ControlError(ErrorCode.EXPIRED_OPERATION)
        fingerprint = wire.intent_digest(checked)
        previous = self.journal.get(operation_id)
        if previous is not None:
            if previous.intent_sha256 != fingerprint:
                raise ControlError(ErrorCode.CONFLICT)
            return previous
        if checked.expected_generation != self.generation:
            raise ControlError(ErrorCode.CONFLICT)
        if self.fault == "failed":
            result = s.MutationResult(
                operation_id=operation_id,
                generation=self.generation,
                intent_sha256=fingerprint,
                state="failed",
                failure=ErrorCode.NOT_FOUND,
                client=getattr(checked.command, "client", None),
            )
            self.journal[operation_id] = result
            return result
        self.generation += 1
        state: Literal["partial", "succeeded"] = (
            "partial" if self.fault == "partial" else "succeeded"
        )
        result = s.MutationResult(
            operation_id=operation_id,
            generation=self.generation,
            intent_sha256=fingerprint,
            state=state,
            completed=("pki",) if state == "partial" else (),
            client=getattr(checked.command, "client", None),
        )
        self.journal[operation_id] = result
        if self.fault == "lost_reply":
            raise ControlError(ErrorCode.UNKNOWN_OUTCOME)
        return result

    def open_archive(self, incoming: s.Request) -> archive.ArchiveStream:
        """Return an owned synthetic archive without accessing any PKI."""
        checked = self._validate(incoming)
        if not isinstance(checked.command, s.Archive):
            raise ControlError(ErrorCode.INVALID_INPUT)
        if checked.command.generation != 0:
            raise ControlError(ErrorCode.CONFLICT)
        if sum(source.closes == 0 for source in self.sources) >= s.MAX_STREAMS:
            raise ControlError(ErrorCode.EXHAUSTED)
        data = b"synthetic credential archive"
        source = BytesSource((data,))
        self.sources.append(source)
        manifest = s.ArchiveManifest(
            request_id=checked.request_id,
            client=checked.command.client,
            generation=0,
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
        )
        return archive.ArchiveStream(source, manifest, checked, lambda: 0.0)


class ReferenceHarness:
    """Supply out-of-band test controls over the reference state machine."""

    def __init__(self) -> None:
        self.control = ReferenceControl()

    def set_fault(self, fault: str | None) -> None:
        """Inject a reference failure without accepting caller-supplied claims."""
        self.control.fault = fault

    def restart(self) -> None:
        """Replace the service object while preserving journal and generation."""
        replacement = ReferenceControl()
        replacement.generation = self.control.generation
        replacement.journal = dict(self.control.journal)
        replacement.expired = set(self.control.expired)
        self.control = replacement

    def expire(self, operation_id: str) -> None:
        """Expire payload retention while permanently fencing the same ID."""
        self.control.expired.add(operation_id)
        self.control.journal.pop(operation_id, None)


def client(name: str = "edge_1") -> s.ClientMetadata:
    """Return safe public metadata for the synthetic fixture client."""
    return s.ClientMetadata(
        client=name,
        generation=0,
        state="active",
        issuer="fixture CA",
        subject=name,
        certificate_sha256="a" * 64,
        not_before=1,
        not_after=2,
    )


def assert_core_contract(harness: Harness) -> None:
    """Test success, durable duplicates, conflict and post-retention replay."""
    assert isinstance(harness.control, port.VpnControl)
    read = request(s.Health())
    assert isinstance(harness.control.execute(read).result, s.HealthResult)
    mutation = request(s.ChangeClient(client="edge_1", action="issue"))
    result = harness.control.execute(mutation).result
    assert isinstance(result, s.MutationResult)
    assert result.state == "succeeded"
    harness.restart()
    assert harness.control.execute(mutation).result == result
    changed = request(s.ChangeClient(client="edge_2", action="issue"))
    with pytest.raises(ControlError, match="conflict"):
        harness.control.execute(changed)
    stale = mutation.model_copy(update={"operation_id": OTHER})
    with pytest.raises(ControlError, match="conflict"):
        harness.control.execute(stale)
    lookup = request(s.LookupOperation(operation_id=OID))
    assert harness.control.execute(lookup).result == result
    harness.expire(OID)
    for expired in (mutation, lookup):
        with pytest.raises(ControlError, match="expired_operation"):
            harness.control.execute(expired)


def assert_failure_contract(harness: Harness, fault: str) -> None:
    """Exercise stable denial/timeouts and durable uncertain/partial results."""
    mutation = request(s.ChangeClient(client="edge_1", action="renew"))
    harness.set_fault(fault)
    if fault == "partial":
        result = harness.control.execute(mutation).result
        assert isinstance(result, s.MutationResult)
        assert result.state == "partial" and result.completed
    else:
        code = "unknown_outcome" if fault == "lost_reply" else fault
        with pytest.raises(ControlError, match=code):
            harness.control.execute(mutation)
    harness.set_fault(None)
    lookup = request(s.LookupOperation(operation_id=OID))
    if fault in {"partial", "lost_reply"}:
        harness.restart()
        result = harness.control.execute(lookup).result
        assert isinstance(result, s.MutationResult)
        assert result.state == ("partial" if fault == "partial" else "succeeded")
    else:
        with pytest.raises(ControlError, match="not_found"):
            harness.control.execute(lookup)


def assert_archive_contract(harness: Harness) -> None:
    """Enforce four-slot quota and release on EOF and unread cancellation."""
    command = request(s.Archive(client="edge_1", generation=0))
    streams = [harness.control.open_archive(command) for _ in range(s.MAX_STREAMS)]
    try:
        with pytest.raises(ControlError, match="exhausted"):
            harness.control.open_archive(command)
        streams[0].close()
        with harness.control.open_archive(command) as replacement:
            assert b"".join(replacement)
            assert replacement.verified
    finally:
        for stream in streams:
            stream.close()


def assert_validation_contract(harness: Harness) -> None:
    """Each adapter revalidates typed input; constructors alone are not trust."""
    read = request(s.Health())
    for invalid in (
        read.model_copy(update={"deadline_ms": True}),
        read.model_copy(update={"command": {"kind": "shell", "argv": ["SECRET"]}}),
        read.model_copy(update={"operation_id": OID}),
    ):
        with pytest.raises(ControlError, match="invalid_input") as error:
            harness.control.execute(invalid)
        assert "SECRET" not in str(error.value) + repr(error.value)
    with pytest.raises(ControlError, match="version_mismatch"):
        harness.control.execute(read.model_copy(update={"version": "2.0"}))
    harness.set_fault("unauthorized")
    with pytest.raises(ControlError, match="unauthorized"):
        harness.control.execute(read)
    with pytest.raises(ControlError, match="unauthorized"):
        harness.control.open_archive(request(s.Archive(client="edge_1", generation=0)))
    harness.set_fault(None)
    assert isinstance(harness.control.execute(read).result, s.HealthResult)


def assert_known_failure_contract(harness: Harness) -> None:
    """Known pre-effect rejection is terminal, durable and never reexecuted."""
    mutation = request(s.ChangeClient(client="edge_1", action="renew"))
    harness.set_fault("failed")
    response = harness.control.execute(mutation)
    result = response.result
    assert isinstance(result, s.MutationResult)
    assert result.state == "failed" and result.failure == ErrorCode.NOT_FOUND
    assert result.generation == 0 and result.completed == ()
    with pytest.raises(ControlError, match="not_found"):
        wire.require_success(response)
    harness.set_fault(None)
    harness.restart()
    assert harness.control.execute(mutation).result == result
    lookup = request(s.LookupOperation(operation_id=OID))
    assert harness.control.execute(lookup).result == result
