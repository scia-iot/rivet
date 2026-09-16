"""Independent adversarial checks for the unused VPN control boundary."""

import hashlib
import json

import pytest

from sciaiot.ovpncp.application.vpn_control import archive, schemas, wire
from sciaiot.ovpncp.application.vpn_control.errors import ControlError

REQUEST_ID = "00000000-0000-4000-8000-000000000001"


def _health_wire() -> bytes:
    """Obtain a valid request through the public contract before corrupting it."""
    return wire.encode(schemas.Request(request_id=REQUEST_ID, command=schemas.Health()))


def test_duplicate_request_identity_is_rejected() -> None:
    """A parser must not silently choose either duplicated operation identity."""
    payload = _health_wire().rstrip()
    duplicate = payload[:-1] + b',"request_id":"00000000-0000-4000-8000-000000000002"}'
    with pytest.raises(ControlError):
        wire.decode_request(duplicate)


def test_nested_duplicate_command_field_is_rejected() -> None:
    """Duplicate rejection applies inside a valid allowlisted command too."""
    value = json.loads(_health_wire())
    command = value["command"]
    name, field = next(iter(command.items()))
    command_json = json.dumps(command)
    duplicate = (
        command_json[:-1] + "," + json.dumps(name) + ":" + json.dumps(field) + "}"
    )
    members = [
        json.dumps(key) + ":" + (duplicate if key == "command" else json.dumps(item))
        for key, item in value.items()
    ]
    with pytest.raises(ControlError):
        wire.decode_request(("{" + ",".join(members) + "}").encode())


def test_unknown_command_field_does_not_leak_input() -> None:
    """Strict rejection never echoes private paths or supplied secret values."""
    value = json.loads(_health_wire())
    sensitive = "PRIVATE_TEST_VALUE_/outside-approved-root/credential.key"
    value["command"]["executable"] = sensitive
    with pytest.raises(ControlError) as caught:
        wire.decode_request(json.dumps(value).encode())
    assert sensitive not in str(caught.value)
    assert sensitive not in repr(caught.value)


@pytest.mark.parametrize(
    "payload",
    [b"\xff", b'{"version":', b"[" * 2000 + b"0" + b"]" * 2000],
)
def test_malformed_wire_has_a_controlled_error(payload: bytes) -> None:
    """Encoding, JSON and recursion failures stay within the public error type."""
    with pytest.raises(ControlError):
        wire.decode_request(payload)


def test_whitespace_cannot_bypass_wire_size_limit() -> None:
    """The byte limit applies before parsing even when extra bytes are spaces."""
    with pytest.raises(ControlError):
        wire.decode_request(_health_wire() + b" " * (1024 * 1024))


@pytest.mark.parametrize(
    "result",
    [
        schemas.HealthResult(ready=True, generation=0),
        schemas.ArchiveManifest(
            request_id=REQUEST_ID,
            client="different_client",
            generation=7,
            size=1,
            sha256="0" * 64,
        ),
        schemas.ArchiveManifest(
            request_id=REQUEST_ID,
            client="edge_1",
            generation=8,
            size=1,
            sha256="0" * 64,
        ),
    ],
)
def test_archive_response_cannot_substitute_identity(
    result: schemas.HealthResult | schemas.ArchiveManifest,
) -> None:
    """Valid schemas still require the exact operation, client and generation."""
    request = schemas.Request(
        request_id=REQUEST_ID,
        command=schemas.Archive(client="edge_1", generation=7),
    )
    response = schemas.Response(request_id=REQUEST_ID, result=result)
    with pytest.raises(ControlError):
        wire.decode_response(wire.encode(response), request)


def test_failed_response_must_match_request_identity() -> None:
    """A fixed error cannot bypass correlation and fail another request."""
    from sciaiot.ovpncp.application.vpn_control.errors import ErrorCode

    request = schemas.Request(request_id=REQUEST_ID, command=schemas.Health())
    response = schemas.Response(
        request_id="00000000-0000-4000-8000-000000000002",
        result=schemas.Failure(code=ErrorCode.UNAVAILABLE),
    )
    with pytest.raises(ControlError):
        wire.decode_response(wire.encode(response), request)


class ReviewSource:
    """An independent observable source with no files or privileged IO."""

    def __init__(self, chunks: tuple[bytes, ...]) -> None:
        self.chunks = iter(chunks)
        self.closes = 0
        self.reads = 0

    def __next__(self) -> bytes:
        self.reads += 1
        return next(self.chunks)

    def close(self) -> None:
        """Record whether ownership releases exactly once."""
        self.closes += 1


def _review_stream(
    source: ReviewSource,
    content: bytes,
) -> archive.ArchiveStream:
    request = schemas.Request(
        request_id=REQUEST_ID,
        command=schemas.Archive(client="edge_1", generation=7),
    )
    manifest = schemas.ArchiveManifest(
        request_id=REQUEST_ID,
        client="edge_1",
        generation=7,
        size=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
    )
    return archive.ArchiveStream(source, manifest, request, lambda: 0.0)


def test_abandoning_unread_archive_releases_owned_source() -> None:
    """Context exit closes even if the consumer never advances the stream."""
    source = ReviewSource((b"content",))
    with _review_stream(source, b"content") as stream:
        assert not stream.verified
    stream.close()
    assert source.reads == 0
    assert source.closes == 1


def test_archive_requires_eof_before_becoming_verified() -> None:
    """Correct size and hash alone cannot hide an additional trailing chunk."""
    source = ReviewSource((b"content", b"extra"))
    with _review_stream(source, b"content") as stream:
        assert next(stream) == b"content"
        assert not stream.verified
        with pytest.raises(ControlError):
            next(stream)
        assert not stream.verified
    assert source.closes == 1


def test_consumer_exception_releases_partial_archive() -> None:
    """API/storage failure releases the stream's bounded slot immediately."""
    source = ReviewSource((b"first", b"last"))
    with (
        pytest.raises(RuntimeError, match="storage unavailable"),
        _review_stream(source, b"firstlast") as stream,
    ):
        assert next(stream) == b"first"
        raise RuntimeError("storage unavailable")
    assert not stream.verified
    assert source.closes == 1


def test_failed_mutation_cannot_advance_generation() -> None:
    """A known pre-effect failure must retain its admitted state revision."""
    from sciaiot.ovpncp.application.vpn_control.errors import ErrorCode

    operation_id = "00000000-0000-4000-8000-000000000002"
    request = schemas.Request(
        request_id=REQUEST_ID,
        operation_id=operation_id,
        expected_generation=7,
        command=schemas.ChangeClient(client="edge_1", action="issue"),
    )
    response = schemas.Response(
        request_id=REQUEST_ID,
        result=schemas.MutationResult(
            operation_id=operation_id,
            generation=8,
            state="failed",
            failure=ErrorCode.UNAVAILABLE,
            intent_sha256=wire.intent_digest(request),
            client="edge_1",
        ),
    )
    with pytest.raises(ControlError):
        wire.decode_response(wire.encode(response), request)


def test_corrupted_mutation_reply_requires_reconciliation() -> None:
    """An unusable reply cannot establish that the requested write had no effect."""
    from sciaiot.ovpncp.application.vpn_control.errors import (
        ErrorCode,
        RetryAction,
        retry_action,
    )

    assert retry_action(ErrorCode.INTEGRITY, mutation=True) == (RetryAction.RECONCILE)
