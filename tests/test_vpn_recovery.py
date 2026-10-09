"""Recovery refreshes exact persisted operations without a privileged API."""

import uuid

import pytest
from sqlmodel import Session, SQLModel, create_engine

from sciaiot.rivet.adapters.vpn.fake import FakeVpnControl
from sciaiot.rivet.application.vpn_control import schemas as s
from sciaiot.rivet.application.vpn_control import wire
from sciaiot.rivet.data.vpn import VpnStep, VpnWorkflow
from sciaiot.rivet.services.vpn_recovery import BackgroundSettings, OperationRecovery


@pytest.fixture
def recovery(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'recovery.db'}")
    SQLModel.metadata.create_all(engine)
    control = FakeVpnControl()
    request = s.Request(
        request_id=str(uuid.uuid4()),
        operation_id=str(uuid.uuid4()),
        expected_generation=0,
        command=s.ChangeClient(client="edge", action="issue"),
    )
    with Session(engine) as session:
        workflow = VpnWorkflow(
            id=str(uuid.uuid4()),
            resource="fixture",
            active_resource="fixture",
            desired_json='{"client":"edge"}',
        )
        session.add(workflow)
        session.add(
            VpnStep(
                id=request.operation_id,
                workflow_id=workflow.id,
                position=0,
                request_json=wire.encode(request).decode(),
            )
        )
        session.commit()
    yield OperationRecovery(engine, control), control, engine, request
    engine.dispose()


def test_restart_observes_same_id_without_repeating_effect(recovery):
    worker, control, engine, original = recovery
    actual = control.execute(original)
    worker.run_once()
    with Session(engine) as session:
        row = session.get(VpnStep, original.operation_id)
        assert (
            wire.decode_response(row.response_json.encode(), original).result
            == actual.result
        )
        assert not session.get(VpnWorkflow, row.workflow_id).completed
    assert control.state.generation == 1


def test_background_does_not_start_unsent_pki_with_short_deadline(recovery):
    worker, control, engine, original = recovery
    worker.run_once()
    with Session(engine) as session:
        row = session.get(VpnStep, original.operation_id)
        assert row.response_json is None
        assert wire.decode_request(row.request_json.encode()) == original
    worker.run_once()
    assert control.state.generation == 0


@pytest.mark.parametrize("name", ["RIVET_VPN_EVENTS", "RIVET_VPN_RECONCILE"])
def test_background_flags_are_explicit_and_fail_closed(monkeypatch, name):
    monkeypatch.setenv(name, "maybe")
    with pytest.raises(ValueError):
        BackgroundSettings.from_environment()


def test_background_worker_stops_and_redacts_unexpected_failures(recovery, caplog):
    import logging
    import time

    from sciaiot.rivet.services.vpn_recovery import BackgroundWorker

    _, control, engine, _ = recovery
    worker = BackgroundWorker(engine, control, BackgroundSettings(events=True))

    class Failing:
        def run_once(self):
            raise RuntimeError("private-address-and-token")

    worker.events = Failing()
    with caplog.at_level(logging.WARNING):
        worker.start()
        deadline = time.monotonic() + 2
        while not caplog.records and time.monotonic() < deadline:
            time.sleep(0.01)
        worker.close()
    assert not worker.thread.is_alive()
    assert "synchronization unavailable" in caplog.text
    assert "private-address-and-token" not in caplog.text


def test_read_only_api_lifespan_never_starts_agent_jobs(monkeypatch):
    import asyncio

    from sciaiot.rivet import main

    monkeypatch.setenv("RIVET_VPN_BACKEND", "host")
    monkeypatch.setenv("RIVET_VPN_EVENTS", "1")
    monkeypatch.setattr(main, "create_tables", lambda: None)
    monkeypatch.setattr(main, "create_app_directory", lambda: None)
    monkeypatch.setattr(main, "init_scripts", lambda: None)
    monkeypatch.setattr(main, "get_vpn_control", FakeVpnControl)

    def forbidden(*args):
        raise AssertionError("host must not start remote jobs")

    monkeypatch.setattr(main, "BackgroundWorker", forbidden)

    async def run():
        async with main.lifespan(main.app):
            pass

    asyncio.run(run())


def test_agent_lifespan_starts_and_closes_only_enabled_jobs(monkeypatch):
    import asyncio

    from sciaiot.rivet import main

    monkeypatch.setenv("RIVET_VPN_BACKEND", "agent")
    monkeypatch.setenv("RIVET_AGENT_UID", "1000")
    monkeypatch.setenv("RIVET_VPN_RECONCILE", "1")
    monkeypatch.setattr(main, "create_tables", lambda: None)
    monkeypatch.setattr(main, "create_app_directory", lambda: None)
    monkeypatch.setattr(main, "get_vpn_control", FakeVpnControl)
    calls = []

    class Worker:
        def __init__(self, engine, control, configured):
            assert configured.reconcile

        def start(self):
            calls.append("start")

        def close(self):
            calls.append("close")

    monkeypatch.setattr(main, "BackgroundWorker", Worker)

    async def run():
        async with main.lifespan(main.app):
            assert calls == ["start"]

    asyncio.run(run())
    assert calls == ["start", "close"]


def test_explicit_retry_can_replace_only_a_proven_pre_effect_failure(
    recovery, monkeypatch
):
    from sqlmodel import select

    from sciaiot.rivet import dependencies
    from sciaiot.rivet.application.vpn_control.errors import ControlError
    from sciaiot.rivet.data.vpn import VpnStepAttempt
    from sciaiot.rivet.services.vpn import VpnService

    _, control, engine, _ = recovery
    monkeypatch.setattr(dependencies, "vpn_control", control)
    control.fault = "failed"
    with Session(engine) as session, pytest.raises(ControlError):
        VpnService(session).change_client("retry-client", "issue")
    control.fault = None
    with Session(engine) as session:
        service = VpnService(session)
        service.change_client("retry-client", "issue")
        service.finish()
        session.commit()
        retired = session.exec(select(VpnStepAttempt)).one()
        previous = wire.decode_request(retired.request_json.encode())
        outcome = wire.decode_response(retired.response_json.encode(), previous).result
        assert outcome.state == "failed" and not outcome.completed
    assert control.state.generation == 1


def test_missing_operation_resubmit_must_match_original_request(recovery):
    from sciaiot.rivet.application.vpn_control.errors import ControlError
    from sciaiot.rivet.services.vpn_recovery import recover_response

    _, original_control, _, original = recovery

    class Mismatched(FakeVpnControl):
        def execute(self, request):
            response = original_control.execute(request)
            if request.operation_id is not None:
                return response.model_copy(update={"request_id": str(uuid.uuid4())})
            return response

    with pytest.raises(ControlError, match="integrity"):
        recover_response(Mismatched(), original)
