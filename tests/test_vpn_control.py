"""Pure application protocol validation and adapter conformance tests."""

import pytest

from sciaiot.ovpncp.application.vpn_control import schemas, wire
from sciaiot.ovpncp.application.vpn_control.errors import ControlError


def test_unknown_operation_has_redacted_error() -> None:
    with pytest.raises(ControlError, match="invalid_input"):
        wire.decode_request(b'{"version":"1.0","operation":"shell"}')


def test_health_request_round_trip() -> None:
    request = schemas.Request(
        request_id="00000000-0000-4000-8000-000000000001",
        command=schemas.Health(),
    )
    assert wire.decode_request(wire.encode(request)) == request


@pytest.mark.parametrize("value", [True, 0, 60_001, "10", 1.2])
def test_deadline_is_strict_and_bounded(value: object) -> None:
    import json

    payload = json.loads(
        wire.encode(
            schemas.Request(
                request_id=REQUEST_ID,
                command=schemas.Health(),
            )
        )
    )
    payload["deadline_ms"] = value
    with pytest.raises(ControlError):
        wire.decode_request(json.dumps(payload).encode())


REQUEST_ID = "00000000-0000-4000-8000-000000000001"
OPERATION_ID = "00000000-0000-4000-8000-000000000002"


def mutation() -> schemas.Request:
    """A canonical issuance intent used by multiple contract checks."""
    return schemas.Request(
        request_id=REQUEST_ID,
        operation_id=OPERATION_ID,
        expected_generation=0,
        command=schemas.ChangeClient(client="edge_1", action="issue"),
    )


def test_immutable_intent_and_canonical_digest() -> None:
    import pydantic

    request = mutation()
    with pytest.raises(pydantic.ValidationError):
        request.command.client = "different"  # type: ignore[union-attr]
    retried = request.model_copy(update={"request_id": OPERATION_ID})
    assert wire.intent_digest(request) == wire.intent_digest(retried)
    changed = request.model_copy(update={"expected_generation": 1})
    assert wire.intent_digest(request) != wire.intent_digest(changed)


@pytest.mark.parametrize("name", ["../key", "a;b", "a b", "a\n", "a" * 256])
def test_unsafe_client_names_rejected(name: str) -> None:
    import pydantic

    with pytest.raises(pydantic.ValidationError) as error:
        schemas.GetClient(client=name)
    assert name not in str(error.value)
    assert name not in repr(error.value)


def test_existing_long_names_preserved() -> None:
    assert schemas.GetClient(client="a" * 255).client == "a" * 255


def test_retry_matrix_and_stable_status() -> None:
    from sciaiot.ovpncp.application.vpn_control.errors import (
        ErrorCode,
        RetryAction,
        problem_status,
        retry_action,
    )

    for code in ErrorCode:
        assert 400 <= problem_status(code) <= 599
        assert code.value in repr(ControlError(code))
        assert retry_action(code, mutation=False) in RetryAction
        assert retry_action(code, mutation=True) in RetryAction
    assert retry_action(ErrorCode.TIMEOUT, mutation=True) == (
        RetryAction.QUERY_OPERATION
    )
    assert retry_action(ErrorCode.EXPIRED_OPERATION, mutation=True) == (
        RetryAction.RECONCILE
    )


def test_reference_contract_available() -> None:
    from tests.vpn_control_conformance import ReferenceHarness, assert_core_contract

    assert_core_contract(ReferenceHarness())


@pytest.mark.parametrize("fault", ["unauthorized", "timeout", "lost_reply", "partial"])
def test_reusable_failure_contract(fault: str) -> None:
    from tests.vpn_control_conformance import ReferenceHarness, assert_failure_contract

    assert_failure_contract(ReferenceHarness(), fault)


def test_reusable_archive_contract() -> None:
    from tests.vpn_control_conformance import ReferenceHarness, assert_archive_contract

    assert_archive_contract(ReferenceHarness())


@pytest.mark.parametrize(
    "command",
    [
        schemas.Health(),
        schemas.ServerConfig(),
        schemas.ListClients(),
        schemas.GetClient(client="edge_1"),
        schemas.ListRoutes(),
        schemas.ListSessions(),
        schemas.PollEvents(),
        schemas.SetAssignment(
            client="edge_1",
            assignment=schemas.Assignment(
                address="10.8.0.2",
                network="192.168.1.0/24",
            ),
        ),
        schemas.SetAssignment(client="edge_1", assignment=None),
        schemas.SetRoute(
            route=schemas.ManagedRoute(
                route_id=OPERATION_ID,
                network="192.168.1.0/24",
                gateway="10.8.0.2",
            ),
            present=True,
        ),
        schemas.SetAccess(
            intent=schemas.AccessIntent(
                access_id=OPERATION_ID,
                source_client="edge_1",
                destination_client="edge_2",
                source_address="10.8.0.2",
                destination_address="10.8.0.3",
                private_networks=("192.168.1.0/24", "10.0.0.0/8"),
            ),
            present=True,
        ),
        schemas.SetPushRoutes(
            client="edge_1",
            intent_id=OPERATION_ID,
            routes=(schemas.PushRoute(network="192.168.1.0/24", gateway="10.8.0.3"),),
        ),
        schemas.AckEvents(through=12),
        schemas.Disconnect(client="edge_1", session_id=OPERATION_ID),
        schemas.Reload(),
        *[
            schemas.ChangeClient(client="edge_1", action=action)
            for action in ("issue", "renew", "revoke", "delete")
        ],
    ],
)
def test_operation_families_round_trip(command: schemas.Command) -> None:
    from tests.vpn_control_conformance import ReferenceHarness, request

    incoming = request(command)
    assert wire.decode_request(wire.encode(incoming)) == incoming
    result = ReferenceHarness().control.execute(incoming)
    assert wire.decode_response(wire.encode(result), incoming) == result


@pytest.mark.parametrize(
    "payload",
    [
        b"null",
        b"[]",
        b'{"version":"1.0","number":NaN}',
        b'{"version":"1.0","number":Infinity}',
        b'{"version":"1.0","number":-Infinity}',
        b'{"version":"2.0"}',
        b'{"version":true}',
        b'{"version":"1.1"}',
    ],
)
def test_invalid_json_values(payload: bytes) -> None:
    with pytest.raises(ControlError):
        wire.decode_request(payload)


def test_response_error_round_trip_and_redaction() -> None:
    from sciaiot.ovpncp.application.vpn_control.errors import ErrorCode

    request = schemas.Request(request_id=REQUEST_ID, command=schemas.Health())
    response = schemas.Response(
        request_id=REQUEST_ID,
        result=schemas.Failure(
            code=ErrorCode.UNAUTHORIZED,
        ),
    )
    assert wire.decode_response(wire.encode(response), request) == response
    private = schemas.Session(
        session_id=REQUEST_ID,
        client="edge_1",
        address="10.8.0.2",
        remote_address="192.0.2.1",
        remote_port=1194,
        connected_at=1,
    )
    assert "192.0.2.1" not in str(private) + repr(private)


@pytest.mark.parametrize(
    "changes",
    [
        {"operation_id": REQUEST_ID},
        {"intent_sha256": "b" * 64},
        {"client": "another"},
        {"generation": 0},
        {"generation": 2},
    ],
)
def test_mutation_response_correlation(changes: dict[str, object]) -> None:
    from tests.vpn_control_conformance import ReferenceHarness

    request = mutation()
    response = ReferenceHarness().control.execute(request)
    changed = response.model_copy(
        update={
            "result": response.result.model_copy(update=changes),
        }
    )
    with pytest.raises(ControlError, match="integrity"):
        wire.decode_response(wire.encode(changed), request)


def test_response_kind_id_and_client_correlation() -> None:
    request = schemas.Request(request_id=REQUEST_ID, command=schemas.Health())
    wrong = schemas.Response(
        request_id=OPERATION_ID,
        result=schemas.HealthResult(
            ready=True,
            generation=0,
        ),
    )
    with pytest.raises(ControlError, match="integrity"):
        wire.decode_response(wire.encode(wrong), request)
    with pytest.raises(ControlError, match="integrity"):
        wire.decode_response(
            wire.encode(
                schemas.Response(
                    request_id=REQUEST_ID,
                    result=schemas.RoutesResult(items=(), generation=0),
                )
            ),
            request,
        )
    with pytest.raises(ControlError):
        wire.intent_digest(request)


@pytest.mark.parametrize(
    "field,value",
    [
        ("client", "wrong"),
        ("generation", 1),
        ("request_id", OPERATION_ID),
    ],
)
def test_archive_correlation_closes_unread_source(field: str, value: object) -> None:
    import hashlib

    from sciaiot.ovpncp.application.vpn_control import archive
    from tests.vpn_control_conformance import BytesSource, request

    incoming = request(schemas.Archive(client="edge_1", generation=0))
    manifest = schemas.ArchiveManifest(
        request_id=REQUEST_ID,
        client="edge_1",
        generation=0,
        size=1,
        sha256=hashlib.sha256(b"x").hexdigest(),
    ).model_copy(update={field: value})
    source = BytesSource((b"x",))
    with pytest.raises(ControlError, match="integrity"):
        archive.ArchiveStream(source, manifest, incoming, lambda: 0.0)
    assert source.closes == 1


@pytest.mark.parametrize(
    "fault",
    [
        "success",
        "short",
        "oversize",
        "chunk",
        "empty",
        "digest",
        "source",
        "deadline",
        "cancel",
        "cleanup",
        "clock",
    ],
)
def test_archive_stream_lifetime(fault: str) -> None:
    import hashlib

    from sciaiot.ovpncp.application.vpn_control import archive
    from tests.vpn_control_conformance import BytesSource, request

    class Source(BytesSource):
        def __next__(self) -> bytes:
            if fault == "source":
                raise OSError("SECRET")
            return super().__next__()

        def close(self) -> None:
            super().close()
            if fault == "cleanup":
                raise OSError("SECRET")

    chunks = {
        "short": (),
        "oversize": (b"xxx",),
        "chunk": (b"x" * (schemas.MAX_CHUNK_BYTES + 1),),
        "empty": (b"",),
        "digest": (b"y",),
    }.get(fault, (b"x",))
    source = Source(chunks)
    elapsed = 0.0

    def clock() -> float:
        if fault == "clock" and elapsed:
            raise OSError("SECRET")
        return elapsed

    incoming = request(schemas.Archive(client="edge_1", generation=0))
    manifest = schemas.ArchiveManifest(
        request_id=REQUEST_ID,
        client="edge_1",
        generation=0,
        size=1,
        sha256=hashlib.sha256(b"x").hexdigest(),
    )
    with archive.ArchiveStream(source, manifest, incoming, clock) as stream:
        if fault == "cancel":
            stream.close()
            assert list(stream) == []
        elif fault in {"success", "cleanup"}:
            assert b"".join(stream) == b"x"
            assert stream.verified == (fault == "success")
        else:
            if fault in {"deadline", "clock"}:
                elapsed = 60.0
            with pytest.raises(ControlError) as error:
                list(stream)
            assert "SECRET" not in str(error.value) + repr(error.value)
    assert source.closes == 1


def test_strict_nested_models_and_event_order() -> None:
    import pydantic

    from tests.vpn_control_conformance import client

    for value in ("8.8.8.0/24", "192.168.1.1/24", "127.0.0.0/8"):
        with pytest.raises(pydantic.ValidationError):
            schemas.AccessIntent(
                access_id=OPERATION_ID,
                source_client="a",
                destination_client="b",
                source_address="10.8.0.2",
                destination_address="10.8.0.3",
                private_networks=(value,),
            )
    with pytest.raises(pydantic.ValidationError):
        schemas.Assignment(address="not-an-ip")
    with pytest.raises(pydantic.ValidationError):
        schemas.AccessIntent(
            access_id=OPERATION_ID,
            source_client="a",
            destination_client="a",
            source_address="10.8.0.2",
            destination_address="10.8.0.3",
        )
    with pytest.raises(pydantic.ValidationError):
        schemas.ClientMetadata.model_validate(
            client().model_copy(
                update={
                    "not_after": 0,
                }
            )
        )
    with pytest.raises(pydantic.ValidationError):
        schemas.Event(sequence=1, event_id=REQUEST_ID, occurred_at=1, event="connect")
    event = schemas.Event(sequence=1, event_id=REQUEST_ID, occurred_at=1, event="gap")
    with pytest.raises(pydantic.ValidationError):
        schemas.EventsResult(items=(event, event))
    assert schemas.EventsResult(items=(event,)).items == (event,)


def test_model_construct_cannot_bypass_wire_validation() -> None:
    import pydantic

    bad = mutation().model_copy(update={"deadline_ms": True})
    with pytest.raises(ControlError):
        wire.encode(bad)
    with pytest.raises(pydantic.ValidationError):
        schemas.Request(
            request_id=REQUEST_ID, command=schemas.Health(), operation_id=OPERATION_ID
        )
    with pytest.raises(pydantic.ValidationError):
        schemas.Request(
            request_id=REQUEST_ID, command=schemas.Health(), expected_generation=0
        )


def test_reusable_validation_contract() -> None:
    from tests.vpn_control_conformance import (
        ReferenceHarness,
        assert_validation_contract,
    )

    assert_validation_contract(ReferenceHarness())


def test_reusable_known_failure_contract() -> None:
    from tests.vpn_control_conformance import (
        ReferenceHarness,
        assert_known_failure_contract,
    )

    assert_known_failure_contract(ReferenceHarness())


@pytest.mark.parametrize(
    "state,expected",
    [
        ("pending", "unknown_outcome"),
        ("unknown", "unknown_outcome"),
        ("partial", "partial_failure"),
        ("expired", "expired_operation"),
    ],
)
def test_nonterminal_results_cannot_be_public_success(
    state: str, expected: str
) -> None:
    from tests.vpn_control_conformance import ReferenceHarness

    response = ReferenceHarness().control.execute(mutation())
    wire.require_success(response)
    result = response.result.model_copy(
        update={
            "state": state,
            "completed": ("pki",) if state == "partial" else (),
        }
    )
    with pytest.raises(ControlError, match=expected):
        wire.require_success(response.model_copy(update={"result": result}))


def test_failure_result_is_not_success() -> None:
    from sciaiot.ovpncp.application.vpn_control.errors import ErrorCode

    response = schemas.Response(
        request_id=REQUEST_ID,
        result=schemas.Failure(
            code=ErrorCode.EXHAUSTED,
        ),
    )
    with pytest.raises(ControlError, match="exhausted"):
        wire.require_success(response)


def test_access_snapshot_and_event_metadata_round_trip() -> None:
    from tests.vpn_control_conformance import ReferenceHarness, request

    incoming = request(schemas.ListAccess())
    response = ReferenceHarness().control.execute(incoming)
    assert wire.decode_response(wire.encode(response), incoming) == response
    session = schemas.Session(
        session_id=REQUEST_ID,
        client="edge_1",
        address="10.8.0.2",
        remote_address="2001:db8::1",
        remote_port=443,
        connected_at=1778888888123456,
    )
    event = schemas.Event(
        sequence=1,
        event_id=OPERATION_ID,
        occurred_at=1778888889123456,
        event="disconnect",
        session=session,
    )
    incoming = request(schemas.PollEvents())
    response = schemas.Response(
        request_id=REQUEST_ID,
        result=schemas.EventsResult(
            items=(event,),
        ),
    )
    assert wire.decode_response(wire.encode(response), incoming) == response


def test_invalid_transport_address_and_partial_ledger() -> None:
    import pydantic

    from tests.vpn_control_conformance import ReferenceHarness

    for address in ("fe80::1%eth0", "invalid"):
        with pytest.raises(pydantic.ValidationError):
            schemas.Session(
                session_id=REQUEST_ID,
                client="edge_1",
                address="10.8.0.2",
                remote_address=address,
                remote_port=443,
                connected_at=1,
            )
    response = ReferenceHarness().control.execute(mutation())
    for changes in (
        {"state": "partial"},
        {"state": "failed"},
        {"state": "pending", "completed": ("pki",)},
        {"completed": ("pki", "pki")},
    ):
        invalid = response.model_copy(
            update={
                "result": response.result.model_copy(update=changes),
            }
        )
        with pytest.raises(ControlError):
            wire.encode(invalid)


def test_access_page_limit_covers_push_collection() -> None:
    from tests.vpn_control_conformance import request

    incoming = request(schemas.ListAccess(limit=1))
    push = schemas.OwnedPushes(intent_id=OPERATION_ID, client="edge_1", routes=())
    response = schemas.Response(
        request_id=REQUEST_ID,
        result=schemas.AccessResult(
            items=(),
            pushes=(push, push),
            generation=0,
        ),
    )
    with pytest.raises(ControlError, match="integrity"):
        wire.decode_response(wire.encode(response), incoming)


def test_decode_response_rejects_malformed_result_and_wrong_client() -> None:
    import json

    from tests.vpn_control_conformance import client, request

    incoming = request(schemas.GetClient(client="edge_1"))
    response = schemas.Response(
        request_id=REQUEST_ID, result=schemas.ClientResult(item=client("other"))
    )
    with pytest.raises(ControlError, match="integrity"):
        wire.decode_response(wire.encode(response), incoming)
    payload = json.loads(wire.encode(response))
    payload["result"]["executable"] = 'secret"\\path'
    with pytest.raises(ControlError, match="invalid_input"):
        wire.decode_response(json.dumps(payload).encode(), incoming)


def test_reply_page_and_event_cursor_are_correlated() -> None:
    from tests.vpn_control_conformance import client, request

    incoming = request(schemas.ListClients(limit=1))
    response = schemas.Response(
        request_id=REQUEST_ID,
        result=schemas.ClientsResult(
            items=(client(), client("other")),
            generation=0,
        ),
    )
    with pytest.raises(ControlError, match="integrity"):
        wire.decode_response(wire.encode(response), incoming)
    incoming = request(schemas.PollEvents(after=2))
    response = schemas.Response(
        request_id=REQUEST_ID,
        result=schemas.EventsResult(
            items=(
                schemas.Event(
                    sequence=2, event_id=OPERATION_ID, occurred_at=1, event="gap"
                ),
            ),
        ),
    )
    with pytest.raises(ControlError, match="integrity"):
        wire.decode_response(wire.encode(response), incoming)
