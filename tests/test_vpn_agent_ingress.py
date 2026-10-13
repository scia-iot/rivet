"""Real private UDS daemon events preserve short-lived sessions and loss evidence."""

import dataclasses
import os
import socket
import sys
import time
import uuid
from pathlib import Path

import pytest

from sciaiot.rivet.application.vpn_control import schemas as s
from sciaiot.rivet.application.vpn_control.errors import ControlError
from sciaiot.rivet.vpn_agent import event_hook
from sciaiot.rivet.vpn_agent.events import EventSpool
from sciaiot.rivet.vpn_agent.ingress import Ingress, session_identity
from sciaiot.rivet.vpn_agent.journal import Journal
from tests.support.agent import settings


@pytest.fixture
def producer(tmp_path: Path):
    """Run the local-only producer with current test UID/GID and private paths."""
    directory = tmp_path / "events"
    directory.mkdir(mode=0o2770)
    directory.chmod(0o2770)
    configured = dataclasses.replace(
        settings(tmp_path), event_socket=str(directory / "events.sock")
    )
    management = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    management.bind(configured.management_socket)
    with Journal(tmp_path) as journal:
        spool = EventSpool(journal)
        ingress = Ingress(configured, spool)
        yield configured, spool, ingress
        ingress.close()
    management.close()


def test_fast_connect_disconnect_hooks_need_no_api(
    producer, monkeypatch: pytest.MonkeyPatch
) -> None:
    configured, spool, _ = producer
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "rivet-vpn-event",
            "--socket",
            configured.event_socket,
            "--management-socket",
            configured.management_socket,
            "--agent-uid",
            str(os.getuid()),
        ],
    )
    for name, value in {
        "common_name": "device",
        "ifconfig_pool_remote_ip": "10.8.0.2",
        "trusted_ip": "192.0.2.10",
        "trusted_port": "12345",
        "time_unix": "100",
    }.items():
        monkeypatch.setenv(name, value)
    for kind in ("client-connect", "client-disconnect"):
        monkeypatch.setenv("script_type", kind)
        event_hook.main()
    events = spool.poll(s.PollEvents()).items
    assert [item.event for item in events] == ["gap", "connect", "disconnect"]
    assert events[1].session == events[2].session
    assert events[1].session.connected_at == 100_000_000


def test_producer_timestamp_retained_and_invalid_peer_refused(producer) -> None:
    configured, spool, ingress = producer
    session = s.Session(
        session_id=str(uuid.uuid4()),
        client="device",
        address="10.8.0.2",
        remote_address="192.0.2.10",
        remote_port=12345,
        connected_at=100_000_000,
    )
    session = session.model_copy(
        update={
            "session_id": session_identity(session, Path(configured.management_socket))
        }
    )
    event = s.Event(
        sequence=0,
        event_id=str(uuid.uuid4()),
        occurred_at=101_123_456,
        event="disconnect",
        session=session,
    )
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(1)
        connection.connect(configured.event_socket)
        connection.sendall(event.model_dump_json().encode() + b"\n")
        assert connection.recv(3) == b"ok\n"
    assert spool.poll(s.PollEvents()).items[-1].occurred_at == 101_123_456
    ingress.settings = dataclasses.replace(configured, management_uid=os.getuid() + 1)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(1)
        connection.connect(configured.event_socket)
        assert connection.recv(1) == b""


def test_missing_agent_hook_returns_success_and_marks_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "missing.sock"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "rivet-vpn-event",
            "--socket",
            str(path),
            "--management-socket",
            str(tmp_path / "management.sock"),
            "--agent-uid",
            str(os.getuid()),
        ],
    )
    monkeypatch.setenv("script_type", "client-connect")
    monkeypatch.setenv("common_name", "../../unsafe")
    event_hook.main()
    assert len((tmp_path / "producer-gap").read_bytes()) == 32


def test_live_ingress_socket_never_replaced(producer) -> None:
    configured, spool, _ = producer
    before = Path(configured.event_socket).stat().st_ino
    with pytest.raises(ControlError):
        Ingress(configured, spool)
    assert Path(configured.event_socket).stat().st_ino == before


def test_trickle_is_bounded_by_total_deadline(producer) -> None:
    configured, _, _ = producer
    started = time.monotonic()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(1)
        connection.connect(configured.event_socket)
        connection.sendall(b"{")
        assert connection.recv(1) == b""
    assert time.monotonic() - started < 0.8
