"""Durable privileged intent acceptance and immutable operation evidence."""

import uuid
from pathlib import Path

import pytest

from sciaiot.rivet.application.vpn_control import schemas as s
from sciaiot.rivet.application.vpn_control.errors import ControlError
from sciaiot.rivet.vpn_agent.journal import Journal


def request(generation: int = 0) -> s.Request:
    """Create an immutable reload intent."""
    return s.Request(
        request_id=str(uuid.uuid4()),
        operation_id=str(uuid.uuid4()),
        expected_generation=generation,
        command=s.Reload(),
    )


def test_acceptance_survives_restart_and_rejects_changed_id(tmp_path: Path) -> None:
    intent = request()
    with Journal(tmp_path) as journal:
        assert journal.accept(intent).state == "pending"
        with pytest.raises(ControlError):
            journal.accept(
                intent.model_copy(update={"command": s.AckEvents(through=1)})
            )
    with Journal(tmp_path) as journal:
        assert journal.lookup(str(intent.operation_id)).state == "pending"
        assert journal.pending() == (intent,)
        assert journal.accept(request()).state == "failed"


def test_checkpoint_and_success_are_durable(tmp_path: Path) -> None:
    intent = request()
    with Journal(tmp_path) as journal:
        journal.accept(intent)
        journal.checkpoint(str(intent.operation_id), "reload")
    with Journal(tmp_path) as journal:
        result = journal.lookup(str(intent.operation_id))
        assert result.state == "partial"
        assert result.completed == ("reload",)
        assert journal.finish(str(intent.operation_id)).state == "succeeded"
        assert journal.generation == 1
        assert journal.accept(intent).state == "succeeded"
        assert journal.pending() == ()


def test_expiry_keeps_id_tombstone(tmp_path: Path) -> None:
    intent = request()
    with Journal(tmp_path) as journal:
        journal.accept(intent)
        journal.finish(str(intent.operation_id))
        journal.expire(now=10**12)
        assert journal.lookup(str(intent.operation_id)).state == "expired"
        assert journal.accept(intent).state == "expired"


def test_single_writer_and_unknown_lookup(tmp_path: Path) -> None:
    with Journal(tmp_path) as journal:
        with pytest.raises(ControlError):
            Journal(tmp_path)
        with pytest.raises(ControlError):
            journal.lookup(str(uuid.uuid4()))


def test_generation_failure_and_immutable_evidence(tmp_path: Path) -> None:
    from sciaiot.rivet.application.vpn_control.errors import ErrorCode

    with Journal(tmp_path) as journal:
        assert journal.accept(request(5)).state == "failed"
        intent = request()
        journal.accept(intent)
        operation_id = str(intent.operation_id)
        journal.stage(operation_id, "before", b"fixed")
        assert journal.evidence(operation_id, "before") == b"fixed"
        with pytest.raises(ControlError):
            journal.stage(operation_id, "before", b"changed")
        result = journal.finish(operation_id, ErrorCode.CONFLICT)
        assert result.state == "failed"
        assert journal.generation == 0
