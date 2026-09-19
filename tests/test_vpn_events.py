"""Durable API event ingestion without privileged operations or live services."""

import uuid
from datetime import datetime, timezone

import pytest
from sqlmodel import Session, SQLModel, create_engine, select

from sciaiot.ovpncp.adapters.vpn.fake import FakeVpnControl
from sciaiot.ovpncp.application.vpn_control import schemas as s
from sciaiot.ovpncp.application.vpn_control.errors import ControlError, ErrorCode
from sciaiot.ovpncp.data.server import Client, Connection
from sciaiot.ovpncp.services.vpn_events import EventConsumer


def event(sequence=1, kind="connect", session=None):
    """Create validated event input with exact microsecond timestamps."""
    return s.Event(
        sequence=sequence,
        event_id=str(uuid.uuid4()),
        occurred_at=1_700_000_000_123456 + sequence,
        event=kind,
        session=session
        or s.Session(
            session_id=str(uuid.uuid4()),
            client="edge",
            address="10.8.0.10",
            remote_address="2001:db8::1",
            remote_port=1194,
            connected_at=1_700_000_000_123456,
        ),
    )


class Events(FakeVpnControl):
    """Use the existing real mutation contract with a controlled event stream."""

    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.events = []
        self.sessions = ()
        self.acks = []
        self.lose_reply = False
        self.fail_commit_check = False

    def execute(self, request):
        command = request.command
        if isinstance(command, s.PollEvents):
            return s.Response(
                request_id=request.request_id,
                result=s.EventsResult(
                    items=tuple(
                        item for item in self.events if item.sequence > command.after
                    )
                ),
            )
        if isinstance(command, s.ListSessions):
            return s.Response(
                request_id=request.request_id,
                result=s.SessionsResult(items=self.sessions, generation=1),
            )
        if isinstance(command, s.AckEvents):
            with Session(self.engine) as session:
                from sciaiot.ovpncp.data.vpn_events import EventCursor, EventReceipt

                assert session.get(EventCursor, 1).after >= command.through
                assert session.exec(select(EventReceipt)).first() is not None
            self.acks.append(request)
            self.state.events = list(self.events)
            result = super().execute(request)
            if self.lose_reply:
                self.lose_reply = False
                raise ControlError(ErrorCode.TIMEOUT)
            return result
        return super().execute(request)


@pytest.fixture
def consumer(tmp_path):
    """Create a file database so separate transactions observe real commits."""
    engine = create_engine(f"sqlite:///{tmp_path / 'events.db'}")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(Client(name="edge"))
        session.commit()
    control = Events(engine)
    yield EventConsumer(engine, control), control, engine
    engine.dispose()


def test_event_commit_precedes_ack_and_replay_is_deduplicated(consumer):
    worker, control, engine = consumer
    connected = event()
    control.events = [connected, event(2, "disconnect", connected.session)]
    worker.run_once()
    worker.run_once()
    with Session(engine) as session:
        rows = session.exec(select(Connection)).all()
        assert len(rows) == 1
        assert rows[0].remote_address == "[2001:db8::1]:1194"
        assert rows[0].connected_time == datetime.fromtimestamp(
            1_700_000_000, timezone.utc
        ).replace(microsecond=123456, tzinfo=None)
        assert rows[0].disconnected_time.microsecond == 123458
    assert len(control.acks) == 1


def test_lost_ack_reply_uses_original_id_after_restart(consumer):
    worker, control, engine = consumer
    control.events = [event()]
    control.lose_reply = True
    with pytest.raises(ControlError, match="timeout"):
        worker.run_once()
    EventConsumer(engine, control).run_once()
    assert len(control.acks) == 1
    with Session(engine) as session:
        from sciaiot.ovpncp.data.vpn_events import EventCursor

        assert session.get(EventCursor, 1).acknowledged == 1
        assert len(session.exec(select(Connection)).all()) == 1


def test_unknown_client_event_is_retained_until_import(consumer):
    worker, control, engine = consumer
    item = event().model_copy(
        update={"session": event().session.model_copy(update={"client": "later"})}
    )
    control.events = [item]
    worker.run_once()
    with Session(engine) as session:
        assert session.exec(select(Connection)).first() is None
        session.add(Client(name="later"))
        session.commit()
    worker.run_once()
    with Session(engine) as session:
        assert len(session.exec(select(Connection)).all()) == 1


def test_history_commit_failure_never_acknowledges(consumer, monkeypatch):
    worker, control, engine = consumer
    control.events = [event()]
    original = Session.commit

    def fail(session):
        if any(
            type(item).__name__ == "EventReceipt"
            for item in session.identity_map.values()
        ):
            from sqlalchemy.exc import OperationalError

            raise OperationalError("secret sql", {}, Exception("secret"))
        original(session)

    monkeypatch.setattr(Session, "commit", fail)
    with pytest.raises(ControlError, match="unavailable"):
        worker.run_once()
    assert not control.acks
    with Session(engine) as session:
        assert not session.exec(select(Connection)).all()


def test_gap_reconciles_active_snapshot_without_inventing_disconnect_time(consumer):
    worker, control, engine = consumer
    connected = event()
    control.events = [connected]
    worker.run_once()
    control.events.append(
        s.Event(
            sequence=4,
            event_id=str(uuid.uuid4()),
            event="gap",
            occurred_at=1_700_000_005_000000,
        )
    )
    control.sessions = ()
    worker.run_once()
    with Session(engine) as session:
        from sciaiot.ovpncp.data.vpn_events import EventReceipt, SessionBinding

        assert len(session.exec(select(EventReceipt)).all()) == 2
        assert session.exec(select(SessionBinding)).one().uncertain
        assert session.exec(select(Connection)).one().disconnected_time is None


def test_reused_database_connection_id_cannot_close_another_client(consumer):
    worker, control, engine = consumer
    connected = event()
    control.events = [connected]
    worker.run_once()
    with Session(engine) as session:
        original = session.exec(select(Connection)).one()
        identity = original.id
        session.delete(original)
        session.commit()
        other = Client(name="other")
        session.add(other)
        session.flush()
        session.add(
            Connection(
                id=identity,
                client_id=other.id,
                remote_address="192.0.2.2:1234",
                connected_time=datetime(2025, 1, 1, tzinfo=timezone.utc),
            )
        )
        session.commit()
    control.events.append(event(2, "disconnect", connected.session))
    with pytest.raises(ControlError, match="integrity"):
        worker.run_once()
    with Session(engine) as session:
        assert session.get(Connection, identity).disconnected_time is None


def test_sequence_loss_without_gap_is_not_acknowledged(consumer):
    worker, control, _ = consumer
    control.events = [event(3)]
    with pytest.raises(ControlError, match="integrity"):
        worker.run_once()
    assert not control.acks


def test_same_event_id_with_changed_content_is_rejected(consumer):
    worker, control, _ = consumer
    original = event()
    control.events = [original]
    worker.run_once()
    control.events.append(original.model_copy(update={"sequence": 2}))
    with pytest.raises(ControlError, match="integrity"):
        worker.run_once()
    assert len(control.acks) == 1


def test_session_identity_cannot_change_under_existing_id(consumer):
    worker, control, _ = consumer
    original = event()
    control.events = [original]
    worker.run_once()
    changed = original.session.model_copy(update={"remote_port": 443})
    control.events.append(event(2, "disconnect", changed))
    with pytest.raises(ControlError, match="integrity"):
        worker.run_once()


def test_gap_snapshot_creates_only_known_client_connections(consumer):
    worker, control, engine = consumer
    control.events = [
        s.Event(
            sequence=8,
            event_id=str(uuid.uuid4()),
            event="gap",
            occurred_at=1_700_000_009_000000,
        )
    ]
    known = event().session
    control.sessions = (
        known,
        known.model_copy(update={"session_id": str(uuid.uuid4()), "client": "unknown"}),
    )
    worker.run_once()
    with Session(engine) as session:
        assert len(session.exec(select(Connection)).all()) == 1
        assert len(session.exec(select(Client)).all()) == 1


def test_ack_known_pre_effect_failure_allows_new_fenced_ack(consumer):
    worker, control, _engine = consumer
    control.events = [event()]
    control.fault = "failed"
    with pytest.raises(ControlError):
        worker.run_once()
    control.fault = None
    worker.run_once()
    assert len(control.acks) == 2
    assert control.acks[0].operation_id != control.acks[1].operation_id


def test_unknown_clients_do_not_starve_later_imported_receipts(consumer):
    worker, _control, engine = consumer
    import hashlib

    from sciaiot.ovpncp.data.vpn_events import EventReceipt

    with Session(engine) as session:
        for index in range(101):
            name = f"missing_{index}"
            item = event(index + 1).model_copy(
                update={"session": event().session.model_copy(update={"client": name})}
            )
            raw = item.model_dump_json()
            session.add(
                EventReceipt(
                    id=item.event_id,
                    sequence=item.sequence,
                    digest=hashlib.sha256(raw.encode()).hexdigest(),
                    payload_json=raw,
                    client_name=name,
                )
            )
        session.add(Client(name="missing_100"))
        session.commit()
    worker.run_once()
    with Session(engine) as session:
        assert len(session.exec(select(Connection)).all()) == 1


def test_retention_removes_only_old_acknowledged_history(consumer):
    worker, control, engine = consumer
    from datetime import timedelta

    from sciaiot.ovpncp.data.vpn_events import EventReceipt

    connected = event()
    control.events = [connected, event(2, "disconnect", connected.session)]
    worker.run_once()
    now = datetime.now(timezone.utc)
    with Session(engine) as session:
        for row in session.exec(select(EventReceipt)).all():
            row.received_at = now - timedelta(days=91)
            session.add(row)
        session.commit()
    worker.purge(now)
    with Session(engine) as session:
        assert not session.exec(select(EventReceipt)).all()
        assert not session.exec(select(Connection)).all()


def test_distinct_sessions_in_same_second_keep_separate_history(consumer):
    worker, control, engine = consumer
    first = event()
    second_session = first.session.model_copy(update={"session_id": str(uuid.uuid4())})
    control.events = [
        first,
        event(2, "disconnect", first.session),
        event(3, "connect", second_session),
        event(4, "disconnect", second_session),
    ]
    worker.run_once()
    with Session(engine) as session:
        rows = session.exec(select(Connection).order_by(Connection.id)).all()
        assert len(rows) == 2
        assert rows[0].connected_time == rows[1].connected_time
        assert rows[0].disconnected_time != rows[1].disconnected_time


def test_retention_preserves_active_history_with_uncertain_alias(consumer):
    from sciaiot.ovpncp.data.vpn_events import SessionBinding

    worker, control, engine = consumer
    connected = event()
    control.events = [connected]
    worker.run_once()
    with Session(engine) as session:
        binding = session.exec(select(SessionBinding)).one()
        session.add(
            SessionBinding(
                id=str(uuid.uuid4()),
                identity=binding.identity,
                connection_id=binding.connection_id,
                uncertain=True,
            )
        )
        session.commit()
    worker.purge(datetime.now(timezone.utc))
    with Session(engine) as session:
        assert len(session.exec(select(Connection)).all()) == 1


@pytest.mark.parametrize("corruption", ["identity", "command", "through"])
def test_acknowledgement_invariants_checked_before_recovery(consumer, corruption):
    from sciaiot.ovpncp.application.vpn_control import wire
    from sciaiot.ovpncp.data.vpn_events import EventAcknowledgement

    worker, control, engine = consumer
    control.events = [event()]
    control.lose_reply = True
    with pytest.raises(ControlError):
        worker.run_once()
    with Session(engine) as session:
        pending = session.exec(select(EventAcknowledgement)).one()
        original = wire.decode_request(pending.request_json.encode())
        update = {
            "identity": {"operation_id": str(uuid.uuid4())},
            "command": {"command": s.ChangeClient(client="unexpected", action="issue")},
            "through": {"command": s.AckEvents(through=999)},
        }[corruption]
        pending.request_json = wire.encode(original.model_copy(update=update)).decode()
        session.add(pending)
        session.commit()
    calls = []
    execute = control.execute

    def observed(request):
        calls.append(request.command.kind)
        return execute(request)

    control.execute = observed
    with pytest.raises(ControlError, match="integrity"):
        worker.run_once()
    assert "lookup_operation" not in calls
    assert "ack_events" not in calls and "change_client" not in calls


def test_ack_retention_keeps_pending_but_prunes_old_completed(consumer):
    from datetime import timedelta

    from sciaiot.ovpncp.data.vpn_events import EventAcknowledgement, EventCursor

    worker, control, engine = consumer
    control.events = [event()]
    worker.run_once()
    with Session(engine) as session:
        completed = session.exec(select(EventAcknowledgement)).one()
        completed.created_at = datetime.now(timezone.utc) - timedelta(days=91)
        session.add(completed)
        pending = EventAcknowledgement(
            id=str(uuid.uuid4()),
            request_json=completed.request_json,
            created_at=completed.created_at,
        )
        session.add(pending)
        cursor = session.get(EventCursor, 1)
        cursor.pending_id = pending.id
        session.add(cursor)
        session.commit()
        pending_id = pending.id
    worker.purge()
    with Session(engine) as session:
        assert [row.id for row in session.exec(select(EventAcknowledgement)).all()] == [
            pending_id
        ]
