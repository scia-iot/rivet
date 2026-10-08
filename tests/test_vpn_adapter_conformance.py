"""Shared port assertions on fake, mocked host and real synthetic UDS IO.

The test server is deliberately not a production agent implementation.
Restarts retain explicit fixture state; they do not prove OS crash recovery.
"""

import contextlib
import os
import socket
import struct
import tempfile
import threading
from pathlib import Path

import pytest

from sciaiot.ovpncp.adapters.vpn.agent import AgentVpnControl
from sciaiot.ovpncp.adapters.vpn.fake import FakeState, FakeVpnControl
from sciaiot.ovpncp.adapters.vpn.host import HostVpnControl
from sciaiot.ovpncp.application.vpn_control import port, wire
from sciaiot.ovpncp.application.vpn_control import schemas as s
from sciaiot.ovpncp.application.vpn_control.errors import ControlError, problem_status
from sciaiot.ovpncp.utils import openvpn
from tests import vpn_control_conformance as contract


class SyntheticServer:
    """Serve only disposable protocol fixtures over a local test socket."""

    def __init__(self, path: str, control: FakeVpnControl) -> None:
        self.control = control
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(path)
        self.listener.listen()
        self.listener.settimeout(0.1)
        self.stopping = threading.Event()
        self.errors: list[Exception] = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while not self.stopping.is_set():
            try:
                connection, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                with connection:
                    self._reply(connection)
            except BrokenPipeError, ConnectionResetError:
                pass
            except Exception as error:  # noqa: BLE001 - report fixture failure
                self.errors.append(error)

    def _reply(self, connection: socket.socket) -> None:
        connection.settimeout(2)
        data = b""
        while b"\r\n\r\n" not in data:
            data += connection.recv(4096)
        headers, payload = data.split(b"\r\n\r\n", 1)
        fields = dict(line.split(b": ", 1) for line in headers.split(b"\r\n")[1:])
        size = int(fields[b"Content-Length"])
        while len(payload) < size:
            payload += connection.recv(size - len(payload))
        request = wire.decode_request(payload)
        status = 200
        media_type = "application/json"
        try:
            if isinstance(request.command, s.Archive):
                with self.control.open_archive(request) as stream:
                    manifest = wire.encode(
                        s.Response(
                            request_id=request.request_id, result=stream.manifest
                        )
                    )
                    payload = (
                        struct.pack("!I", len(manifest)) + manifest + b"".join(stream)
                    )
                media_type = "application/octet-stream"
            else:
                payload = wire.encode(self.control.execute(request))
        except ControlError as error:
            status = problem_status(error.code)
            payload = wire.encode(
                s.Response(
                    request_id=request.request_id, result=s.Failure(code=error.code)
                )
            )
        connection.sendall(
            f"HTTP/1.1 {status} Result\r\nContent-Type: {media_type}\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode()
            + payload
        )

    def close(self) -> None:
        """Stop the listener and verify no fixture handler failed silently."""
        self.stopping.set()
        self.listener.close()
        self.thread.join(timeout=2)
        assert not self.thread.is_alive()
        assert not self.errors


class AdapterHarness:
    """Apply the same assertions to each actual production adapter class."""

    def __init__(self, kind: str, path: str, *, seeded: bool) -> None:
        self.kind = kind
        self.path = path
        self.state = FakeState()
        if seeded:
            self.state.clients["edge_1"] = contract.client()
        self.backend = FakeVpnControl(self.state)
        self.server = SyntheticServer(path, self.backend) if kind == "agent" else None
        self.control: port.VpnControl
        self.restart()

    def restart(self) -> None:
        """Recreate an adapter while retaining the explicit test-owned ledger."""
        if self.kind == "agent":
            self.control = AgentVpnControl(self.path, peer_uid=os.getuid())
        elif self.kind == "host":
            self.control = HostVpnControl(self.state)
        else:
            self.control = FakeVpnControl(self.state)

    def set_fault(self, fault: str | None) -> None:
        """Configure test faults without adding fields to wire requests."""
        if self.kind == "agent":
            self.backend.fault = fault
        else:
            assert isinstance(self.control, FakeVpnControl)
            self.control.fault = fault

    def expire(self, operation_id: str) -> None:
        """Retain the immutable replay fence after discarding full results."""
        self.state.expired.add(operation_id)
        self.state.journal.pop(operation_id, None)


@pytest.fixture(params=["fake", "host", "agent"])
def harness_factory(request, monkeypatch):
    """Isolate all privileged host operations and every socket resource."""
    monkeypatch.setattr(openvpn, "get_status", lambda: {"status": "active (running)"})
    monkeypatch.setattr(openvpn, "build_client", lambda name: True)
    monkeypatch.setattr(openvpn, "renew_client_cert", lambda name: {"synthetic": True})
    monkeypatch.setattr(openvpn, "client_is_revoked", lambda name: False)

    def package(name, directory):
        Path(directory, f"{name}.zip").write_bytes(b"synthetic credential archive")

    monkeypatch.setattr(openvpn, "package_client_cert", package)
    with contextlib.ExitStack() as stack:

        def create(*, seeded=False):
            directory = stack.enter_context(
                tempfile.TemporaryDirectory(prefix="ovpn-contract-")
            )
            harness = AdapterHarness(
                request.param, f"{directory}/agent.sock", seeded=seeded
            )
            if harness.server is not None:
                stack.callback(harness.server.close)
            return harness

        yield create


def test_shared_core_contract(harness_factory):
    contract.assert_core_contract(harness_factory())


def test_shared_archive_contract(harness_factory):
    contract.assert_archive_contract(harness_factory(seeded=True))


def test_shared_validation_contract(harness_factory):
    contract.assert_validation_contract(harness_factory())


def test_shared_known_failure_contract(harness_factory):
    contract.assert_known_failure_contract(harness_factory())


@pytest.mark.parametrize("fault", ["unauthorized", "timeout", "partial", "lost_reply"])
def test_shared_failure_contract(harness_factory, fault):
    contract.assert_failure_contract(harness_factory(seeded=True), fault)


def test_agent_unavailable_socket_redacts_its_path(tmp_path):
    """Connection diagnostics cannot expose configured runtime paths."""
    from sciaiot.ovpncp.application.vpn_control.errors import ControlError

    control = AgentVpnControl(str(tmp_path / "missing.sock"), peer_uid=os.getuid())
    with pytest.raises(ControlError, match="unavailable") as error:
        control.execute(contract.request(s.Health()))
    assert str(tmp_path) not in str(error.value)


@pytest.mark.parametrize("failure", ["deadline", "truncated", "trailing"])
def test_socket_body_rejects_deadline_and_framing_failures(failure):
    """Reads enforce elapsed deadlines and exact byte framing without PKI."""
    import time

    from sciaiot.ovpncp.adapters.vpn.agent import SocketBody

    receiving, sending = socket.socketpair()
    released = []
    body = SocketBody(
        receiving,
        b"",
        1,
        time.monotonic() + (-1 if failure == "deadline" else 1),
        lambda: released.append(True),
    )
    with sending:
        if failure == "trailing":
            sending.sendall(b"ab")
        sending.shutdown(socket.SHUT_WR)
        try:
            with pytest.raises(ControlError):
                if failure == "trailing":
                    assert body.read(1) == b"a"
                    next(body)
                else:
                    body.read(1)
        finally:
            body.close()
            body.close()
    assert released == [True]


def test_agent_archive_error_releases_the_stream_slot():
    """A correlated server refusal never leaks one of the four stream slots."""
    with tempfile.TemporaryDirectory(prefix="ovpn-error-") as directory:
        control = FakeVpnControl()
        server = SyntheticServer(f"{directory}/agent.sock", control)
        try:
            agent = AgentVpnControl(f"{directory}/agent.sock", peer_uid=os.getuid())
            for _ in range(s.MAX_STREAMS + 1):
                with pytest.raises(ControlError, match="not_found"):
                    agent.open_archive(
                        contract.request(s.Archive(client="missing", generation=0))
                    )
        finally:
            server.close()
