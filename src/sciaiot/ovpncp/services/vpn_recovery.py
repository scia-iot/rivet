"""Optional bounded API workers for committed event delivery and workflow recovery."""

import dataclasses
import logging
import os
import threading
import time
import uuid

from sqlalchemy import Engine, update
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import Session, col, select

from sciaiot.ovpncp.application.vpn_control import schemas as s
from sciaiot.ovpncp.application.vpn_control import wire
from sciaiot.ovpncp.application.vpn_control.errors import ControlError, ErrorCode
from sciaiot.ovpncp.application.vpn_control.port import VpnControl
from sciaiot.ovpncp.data.vpn import VpnStep, VpnWorkflow
from sciaiot.ovpncp.services.vpn_events import EventConsumer

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class BackgroundSettings:
    """Require explicit opt-in; host/shadow mode never starts agent workers."""

    events: bool = False
    reconcile: bool = False

    @classmethod
    def from_environment(cls) -> BackgroundSettings:
        """Accept only 0/1 values so a typo cannot silently change behavior."""
        values = []
        for name in ("OVPNCP_VPN_EVENTS", "OVPNCP_VPN_RECONCILE"):
            value = os.environ.get(name, "0")
            if value not in {"0", "1"}:
                raise ValueError("VPN background flags must be 0 or 1.")
            values.append(value == "1")
        return cls(events=values[0], reconcile=values[1])


def recover_response(
    control: VpnControl,
    original: s.Request,
    *,
    deadline_ms: int = 2000,
    resubmit_missing: bool = True,
) -> s.Response:
    """Query the same durable ID; resubmit only the identical fenced intent.

    Missing lookup evidence never creates a replacement operation. Reusing the
    original ID and generation lets the agent's durable admission/reconciliation
    reject stale or restored state and prevents duplicate effects.
    """
    deadline = time.monotonic() + deadline_ms / 1000
    assert original.operation_id is not None
    lookup = s.Request(
        request_id=str(uuid.uuid4()),
        command=s.LookupOperation(operation_id=original.operation_id),
        deadline_ms=deadline_ms,
    )
    try:
        response = control.execute(lookup)
        response = wire.decode_response(wire.encode(response), lookup)
        if isinstance(response.result, s.Failure):
            raise ControlError(response.result.code)
    except ControlError as error:
        if error.code != ErrorCode.NOT_FOUND or not resubmit_missing:
            raise
        remaining = int((deadline - time.monotonic()) * 1000)
        if remaining <= 0:
            raise ControlError(ErrorCode.TIMEOUT) from None
        delivery = original.model_copy(update={"deadline_ms": remaining})
        response = control.execute(delivery)
        response = wire.decode_response(wire.encode(response), delivery)
    return wire.decode_response(
        wire.encode(s.Response(request_id=original.request_id, result=response.result)),
        original,
    )


class OperationRecovery:
    """Refresh bounded pending steps; business completion stays transactional.

    Agent effects may be irreversible. A result refresh never undoes them or
    invents business ownership. The original API workflow can finish its business
    transaction from the cached proven result after a database failure. Missing
    operations await an explicit API retry with the original execution budget;
    this short background cycle never starts a new privileged effect.
    """

    def __init__(self, engine: Engine, control: VpnControl) -> None:
        self.engine = engine
        self.control = control
        self.after = ""

    def run_once(self) -> None:
        """Fairly inspect at most 100 retained steps within a five-second budget."""
        deadline = time.monotonic() + 5
        try:
            with Session(self.engine) as session:
                steps = session.exec(
                    select(VpnStep)
                    .join(VpnWorkflow, col(VpnStep.workflow_id) == col(VpnWorkflow.id))
                    .where(VpnWorkflow.completed == False, VpnStep.id > self.after)
                    .order_by(col(VpnStep.id))
                    .limit(100)
                ).all()
                observed = [
                    (step.id, step.request_json, step.response_json) for step in steps
                ]
            for identity, raw, previous in observed:
                remaining = min(1000, int((deadline - time.monotonic()) * 1000))
                if remaining <= 0:
                    return
                self.after = identity
                original = wire.decode_request(raw.encode())
                if original.operation_id != identity:
                    raise ControlError(ErrorCode.INTEGRITY)
                if previous is not None:
                    known = wire.decode_response(previous.encode(), original).result
                    if isinstance(known, s.MutationResult) and known.state in {
                        "succeeded",
                        "failed",
                        "expired",
                    }:
                        continue
                try:
                    response = recover_response(
                        self.control,
                        original,
                        deadline_ms=remaining,
                        resubmit_missing=False,
                    )
                except ControlError:
                    # One unavailable operation must not starve independent rows.
                    continue
                with Session(self.engine) as session:
                    session.connection().execute(
                        update(VpnStep)
                        .where(
                            col(VpnStep.id) == identity,
                            col(VpnStep.request_json) == raw,
                            col(VpnStep.response_json) == previous,
                        )
                        .values(response_json=wire.encode(response).decode())
                    )
                    session.commit()
            if len(observed) < 100:
                self.after = ""
        except SQLAlchemyError:
            raise ControlError(ErrorCode.UNAVAILABLE) from None


class BackgroundWorker:
    """One bounded daemon worker; API shutdown signals it without VPN effects."""

    def __init__(
        self, engine: Engine, control: VpnControl, settings: BackgroundSettings
    ) -> None:
        self.events = EventConsumer(engine, control) if settings.events else None
        self.recovery = (
            OperationRecovery(engine, control) if settings.reconcile else None
        )
        self.stopped = threading.Event()
        self.thread = threading.Thread(
            target=self._run, name="vpn-recovery", daemon=True
        )
        self.next_warning = 0.0
        self.next_purge = 0.0

    def start(self) -> None:
        """Begin optional API-owned background work after table creation."""
        self.thread.start()

    def close(self) -> None:
        """Stop between bounded cycles, without restarting or signaling OpenVPN."""
        self.stopped.set()
        self.thread.join(timeout=6)

    def _run(self) -> None:
        while not self.stopped.is_set():
            for action in (self.events, self.recovery):
                if action is None or self.stopped.is_set():
                    continue
                try:
                    action.run_once()
                    if action is self.events and time.monotonic() >= self.next_purge:
                        action.purge()
                        self.next_purge = time.monotonic() + 60
                except Exception:  # noqa: BLE001 - no SQL or privileged payload in logs
                    if time.monotonic() >= self.next_warning:
                        logger.warning(
                            "VPN background synchronization unavailable; recovery will retry."
                        )
                        self.next_warning = time.monotonic() + 60
            self.stopped.wait(1)
