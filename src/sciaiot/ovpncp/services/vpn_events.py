"""Bounded at-least-once API ingestion; acknowledge only committed observations."""

import hashlib
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Engine, and_, delete, or_, update
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import Session, col, select

from sciaiot.ovpncp.application.vpn_control import schemas as s
from sciaiot.ovpncp.application.vpn_control import wire
from sciaiot.ovpncp.application.vpn_control.errors import ControlError, ErrorCode
from sciaiot.ovpncp.application.vpn_control.port import VpnControl
from sciaiot.ovpncp.data.server import Client, Connection
from sciaiot.ovpncp.data.vpn_events import (
    EventAcknowledgement,
    EventCursor,
    EventReceipt,
    SessionBinding,
)

EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def timestamp(value: int) -> datetime:
    """Preserve protocol microseconds without floating-point timestamp rounding."""
    return EPOCH + timedelta(microseconds=value)


class EventConsumer:
    """Commit deduplicated history before persisting/sending an exact ack intent.

    Unknown clients remain durable receipts until authorized API import creates
    their business records. Gaps reconcile active observations and mark absent
    bindings uncertain; missing transitions never invent disconnect times.
    """

    def __init__(self, engine: Engine, control: VpnControl) -> None:
        self.engine = engine
        self.control = control
        self.deadline = 0.0

    def _request(self, command: s.Command, **fields: Any) -> s.Request:
        remaining = min(2000, int((self.deadline - time.monotonic()) * 1000))
        if remaining <= 0:
            raise ControlError(ErrorCode.TIMEOUT)
        return s.Request(
            request_id=str(uuid.uuid4()),
            command=command,
            deadline_ms=remaining,
            **fields,
        )

    def _exchange(self, original: s.Request) -> s.Response:
        remaining = int((self.deadline - time.monotonic()) * 1000)
        if remaining <= 0:
            raise ControlError(ErrorCode.TIMEOUT)
        delivery = original.model_copy(
            update={"deadline_ms": min(remaining, original.deadline_ms)}
        )
        response = self.control.execute(delivery)
        return wire.decode_response(wire.encode(response), original)

    def _read(self, command: s.Command) -> s.Result:
        response = self._exchange(self._request(command))
        wire.require_success(response)
        return response.result

    def _cursor(self, session: Session) -> EventCursor:
        row = session.get(EventCursor, 1)
        if row is None:
            row = EventCursor()
            session.add(row)
            session.commit()
            session.refresh(row)
        return row

    def _binding(self, session: Session, item: s.Session) -> SessionBinding | None:
        identity = hashlib.sha256(
            item.model_dump_json(exclude={"session_id"}).encode()
        ).hexdigest()
        binding = session.get(SessionBinding, item.session_id)
        if binding is not None:
            if binding.identity != identity:
                raise ControlError(ErrorCode.INTEGRITY)
            previous = session.get(Connection, binding.connection_id)
            if previous is not None:
                owner = session.get(Client, previous.client_id)
                remote = (
                    f"[{item.remote_address}]:{item.remote_port}"
                    if ":" in item.remote_address
                    else f"{item.remote_address}:{item.remote_port}"
                )
                if (
                    owner is None
                    or owner.name != item.client
                    or previous.remote_address != remote
                    or previous.connected_time.replace(tzinfo=UTC)
                    != timestamp(item.connected_at)
                ):
                    raise ControlError(ErrorCode.INTEGRITY)
            return binding
        client = session.exec(
            select(Client).where(Client.name == item.client)
        ).one_or_none()
        if client is None:
            return None
        remote = (
            f"[{item.remote_address}]:{item.remote_port}"
            if ":" in item.remote_address
            else f"{item.remote_address}:{item.remote_port}"
        )
        connection = session.exec(
            select(Connection).where(
                Connection.client_id == client.id,
                Connection.remote_address == remote,
                Connection.connected_time == timestamp(item.connected_at),
                col(Connection.disconnected_time) == None,
                ~select(SessionBinding.id)
                .where(col(SessionBinding.connection_id) == col(Connection.id))
                .exists(),
            )
        ).one_or_none()
        if connection is None:
            connection = Connection(
                client_id=client.id,
                remote_address=remote,
                connected_time=timestamp(item.connected_at),
            )
            session.add(connection)
            session.flush()
        binding = SessionBinding(
            id=item.session_id, identity=identity, connection_id=connection.id
        )
        session.add(binding)
        return binding

    def _apply(self, session: Session, event: s.Event) -> bool:
        if event.session is None:
            return True
        binding = self._binding(session, event.session)
        if binding is None:
            return False
        connection = session.get(Connection, binding.connection_id)
        if connection is None:
            # Deleted business clients must never be recreated by telemetry.
            return True
        if event.event == "disconnect":
            if event.occurred_at < event.session.connected_at:
                raise ControlError(ErrorCode.INTEGRITY)
            disconnected = timestamp(event.occurred_at)
            if connection.disconnected_time is None:
                connection.disconnected_time = disconnected
                session.add(connection)
            elif connection.disconnected_time.replace(tzinfo=UTC) != disconnected:
                raise ControlError(ErrorCode.INTEGRITY)
        binding.uncertain = False
        session.add(binding)
        return True

    def _snapshot(self) -> tuple[s.Session, ...]:
        result: list[s.Session] = []
        cursor = None
        revision = None
        seen = set()
        while True:
            page = self._read(s.ListSessions(cursor=cursor))
            if not isinstance(page, s.SessionsResult):
                raise ControlError(ErrorCode.INTEGRITY)
            if revision is not None and revision != page.generation:
                raise ControlError(ErrorCode.CONFLICT)
            revision = page.generation
            result.extend(page.items)
            if len(result) > 10_000 or len({item.session_id for item in result}) != len(
                result
            ):
                raise ControlError(ErrorCode.EXHAUSTED)
            cursor = page.next_cursor
            if cursor is None:
                return tuple(result)
            if cursor in seen or not page.items:
                raise ControlError(ErrorCode.INTEGRITY)
            seen.add(cursor)

    def _ingest(self) -> None:
        with Session(self.engine) as session:
            cursor = self._cursor(session)
            after, revision = cursor.after, cursor.revision
        page = self._read(s.PollEvents(after=after))
        if not isinstance(page, s.EventsResult):
            raise ControlError(ErrorCode.INTEGRITY)
        snapshot = (
            self._snapshot()
            if any(item.event == "gap" for item in page.items)
            else None
        )
        with Session(self.engine) as session:
            current = session.get(EventCursor, 1)
            assert current is not None
            if (current.after, current.revision) != (after, revision):
                raise ControlError(ErrorCode.CONFLICT)
            for item in page.items:
                if item.sequence != after + 1 and item.event != "gap":
                    raise ControlError(ErrorCode.INTEGRITY)
                payload = item.model_dump_json()
                digest = hashlib.sha256(payload.encode()).hexdigest()
                receipt = session.get(EventReceipt, item.event_id)
                if receipt is None:
                    receipt = EventReceipt(
                        id=item.event_id,
                        sequence=item.sequence,
                        digest=digest,
                        payload_json=payload,
                        client_name=item.session.client
                        if item.session is not None
                        else None,
                    )
                    receipt.applied = self._apply(session, item)
                    session.add(receipt)
                elif receipt.digest != digest:
                    raise ControlError(ErrorCode.INTEGRITY)
                after = item.sequence
            if snapshot is not None:
                # Mark open bindings in the database without loading lifetime
                # history. The bounded current snapshot then clears uncertainty.
                session.flush()
                session.connection().execute(
                    update(SessionBinding)
                    .where(
                        col(SessionBinding.connection_id).in_(
                            select(Connection.id).where(
                                col(Connection.disconnected_time) == None
                            )
                        )
                    )
                    .values(uncertain=True)
                )
                session.expire_all()
                for observed_session in snapshot:
                    binding = self._binding(session, observed_session)
                    if binding is not None:
                        binding.uncertain = False
                        session.add(binding)
            # Deferred unknown-client events replay in sequence after API import.
            for receipt in session.exec(
                select(EventReceipt)
                .join(Client, col(EventReceipt.client_name) == col(Client.name))
                .where(EventReceipt.applied == False)
                .order_by(col(EventReceipt.sequence))
                .limit(100)
            ).all():
                receipt.applied = self._apply(
                    session, s.Event.model_validate_json(receipt.payload_json)
                )
                session.add(receipt)
            changed = session.connection().execute(
                update(EventCursor)
                .where(col(EventCursor.id) == 1, col(EventCursor.revision) == revision)
                .values(after=after, revision=revision + 1)
            )
            if changed.rowcount != 1:
                raise ControlError(ErrorCode.CONFLICT)
            session.commit()

    def _acknowledge(self) -> None:
        with Session(self.engine) as session:
            cursor = self._cursor(session)
            existing = cursor.pending_id is not None
            if not existing:
                if cursor.after <= cursor.acknowledged:
                    return
                health = self._read(s.Health())
                if not isinstance(health, s.HealthResult) or not health.ready:
                    raise ControlError(ErrorCode.UNAVAILABLE)
                original = self._request(
                    s.AckEvents(through=cursor.after),
                    operation_id=str(uuid.uuid4()),
                    expected_generation=health.generation,
                )
                pending: EventAcknowledgement | None = EventAcknowledgement(
                    id=original.operation_id,
                    request_json=wire.encode(original).decode(),
                )
                assert pending is not None
                session.add(pending)
                update_result = session.connection().execute(
                    update(EventCursor)
                    .where(
                        col(EventCursor.id) == 1, col(EventCursor.pending_id) == None
                    )
                    .values(pending_id=pending.id)
                )
                if update_result.rowcount != 1:
                    raise ControlError(ErrorCode.CONFLICT)
                session.commit()
            else:
                pending = session.get(EventAcknowledgement, cursor.pending_id)
                if pending is None:
                    raise ControlError(ErrorCode.INTEGRITY)
                original = wire.decode_request(pending.request_json.encode())
                if (
                    original.operation_id != pending.id
                    or not isinstance(original.command, s.AckEvents)
                    or original.command.through > cursor.after
                    or original.command.through <= cursor.acknowledged
                ):
                    raise ControlError(ErrorCode.INTEGRITY)
            assert pending is not None
            pending_id = pending.id
        if existing:
            from sciaiot.ovpncp.services.vpn_recovery import recover_response

            remaining = min(2000, int((self.deadline - time.monotonic()) * 1000))
            if remaining <= 0:
                raise ControlError(ErrorCode.TIMEOUT)
            response = recover_response(self.control, original, deadline_ms=remaining)
        else:
            response = self._exchange(original)
        with Session(self.engine) as session:
            pending = session.get(EventAcknowledgement, pending_id)
            refreshed = session.get(EventCursor, 1)
            if (
                pending is None
                or refreshed is None
                or refreshed.pending_id != pending_id
            ):
                raise ControlError(ErrorCode.CONFLICT)
            pending.response_json = wire.encode(response).decode()
            session.add(pending)
            if isinstance(response.result, s.MutationResult):
                if response.result.state == "succeeded":
                    assert isinstance(original.command, s.AckEvents)
                    refreshed.acknowledged = original.command.through
                    refreshed.pending_id = None
                elif response.result.state == "failed":
                    # A proven pre-effect rejection may be replaced, never an
                    # unknown outcome or missing admission/recovery evidence.
                    refreshed.pending_id = None
            session.add(refreshed)
            session.commit()
        wire.require_success(response)

    def run_once(self) -> None:
        """Consume one bounded page and persist exact ack intent after DB commit."""
        self.deadline = time.monotonic() + 5
        try:
            self._ingest()
            self._acknowledge()
        except SQLAlchemyError:
            raise ControlError(ErrorCode.UNAVAILABLE) from None

    def purge(self, now: datetime | None = None) -> None:
        """Bound acknowledged history retention without removing pending evidence."""
        cutoff = (now or datetime.now(UTC)) - timedelta(days=90)
        try:
            with Session(self.engine) as session:
                cursor = self._cursor(session)
                receipt_ids = session.exec(
                    select(EventReceipt.id)
                    .where(
                        col(EventReceipt.received_at) < cutoff,
                        col(EventReceipt.sequence) <= cursor.acknowledged,
                    )
                    .order_by(col(EventReceipt.sequence))
                    .limit(1000)
                ).all()
                old_ids = session.exec(
                    select(Connection.id)
                    .where(
                        or_(
                            col(Connection.disconnected_time) < cutoff,
                            and_(
                                col(Connection.connected_time) < cutoff,
                                select(SessionBinding.id)
                                .where(
                                    col(SessionBinding.connection_id)
                                    == col(Connection.id),
                                    col(SessionBinding.uncertain) == True,
                                )
                                .exists(),
                                ~select(SessionBinding.id)
                                .where(
                                    col(SessionBinding.connection_id)
                                    == col(Connection.id),
                                    col(SessionBinding.uncertain) == False,
                                )
                                .exists(),
                            ),
                        )
                    )
                    .order_by(col(Connection.id))
                    .limit(1000)
                ).all()
                old_acks = session.exec(
                    select(EventAcknowledgement)
                    .where(
                        col(EventAcknowledgement.created_at) < cutoff,
                        col(EventAcknowledgement.id) != cursor.pending_id,
                        col(EventAcknowledgement.response_json) != None,
                    )
                    .order_by(col(EventAcknowledgement.created_at))
                    .limit(1000)
                ).all()
                for acknowledgement in old_acks:
                    original = wire.decode_request(
                        acknowledgement.request_json.encode()
                    )
                    assert acknowledgement.response_json is not None
                    result = wire.decode_response(
                        acknowledgement.response_json.encode(), original
                    ).result
                    if isinstance(result, s.MutationResult) and result.state in {
                        "succeeded",
                        "failed",
                    }:
                        session.delete(acknowledgement)
                if receipt_ids:
                    session.connection().execute(
                        delete(EventReceipt).where(
                            col(EventReceipt.id).in_(receipt_ids)
                        )
                    )
                if old_ids:
                    session.connection().execute(
                        delete(SessionBinding).where(
                            col(SessionBinding.connection_id).in_(old_ids)
                        )
                    )
                    session.connection().execute(
                        delete(Connection).where(col(Connection.id).in_(old_ids))
                    )
                session.commit()
        except SQLAlchemyError:
            raise ControlError(ErrorCode.UNAVAILABLE) from None
