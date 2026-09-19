"""Persistent bounded event spool, acknowledgement and overflow evidence."""

from pathlib import Path

import pytest

from sciaiot.ovpncp.application.vpn_control import schemas as s
from sciaiot.ovpncp.application.vpn_control.errors import ControlError
from sciaiot.ovpncp.vpn_agent.events import EventSpool
from sciaiot.ovpncp.vpn_agent.journal import Journal


def test_events_survive_restart_and_ack_is_bounded(tmp_path: Path) -> None:
    with Journal(tmp_path) as journal:
        spool = EventSpool(journal, maximum=3)
        event = spool.gap()
        assert spool.poll(s.PollEvents()).items == (event,)
        with pytest.raises(ControlError):
            spool.acknowledge(event.sequence + 1)
    with Journal(tmp_path) as journal:
        spool = EventSpool(journal, maximum=3)
        assert spool.poll(s.PollEvents()).items == (event,)
        spool.acknowledge(event.sequence)
        spool.acknowledge(event.sequence)
        assert spool.poll(s.PollEvents(after=event.sequence)).items == ()


def test_overflow_records_gap_and_sequences_never_reset(tmp_path: Path) -> None:
    with Journal(tmp_path) as journal:
        spool = EventSpool(journal, maximum=3)
        for _ in range(8):
            spool.gap()
        events = spool.poll(s.PollEvents()).items
        assert 1 <= len(events) <= 3
        assert events[0].event == "gap"
        assert events[-1].sequence >= 8
        spool.acknowledge(events[-1].sequence)
        assert spool.gap().sequence > events[-1].sequence


def test_same_second_reconnect_gets_new_identity_and_cid_never_aliases(
    tmp_path: Path,
) -> None:
    import uuid

    with Journal(tmp_path) as journal:
        spool = EventSpool(journal)
        base = s.Session(
            session_id=str(uuid.uuid4()),
            client="device",
            address="10.8.0.2",
            remote_address="192.0.2.1",
            remote_port=1234,
            connected_at=100_000_000,
        )
        for kind in ("connect", "disconnect", "connect"):
            spool.produce(
                s.Event(
                    sequence=0,
                    event_id=str(uuid.uuid4()),
                    occurred_at=101_000_000,
                    event=kind,
                    session=base,
                )
            )
        events = spool.poll(s.PollEvents()).items
        assert events[0].session is not None
        assert events[1].session is not None
        assert events[2].session is not None
        assert events[0].session.session_id == events[1].session.session_id
        assert events[0].session.session_id != events[2].session.session_id
        current = spool.normalize(base, 4)
        assert current.session_id == events[2].session.session_id
        replacement = spool.normalize(base, 5)
        assert replacement.session_id != current.session_id
        assert spool.poll(s.PollEvents()).items[-1].event == "gap"
        assert spool.normalize(base, 5).session_id == replacement.session_id
