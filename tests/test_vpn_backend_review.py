"""Independent security and compatibility review of the backend transition."""

import asyncio
from pathlib import Path
from unittest import mock

import pytest
from fastapi import HTTPException, Request, Response

from sciaiot.ovpncp.middlewares import azure_security


@pytest.mark.parametrize("method", ["POST", "PUT"])
@pytest.mark.parametrize("address", ["127.0.0.1", "::1"])
def test_agent_backend_authenticates_loopback_connection_requests(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    address: str,
) -> None:
    """An API behind a local proxy cannot grant the host-hook exception."""
    monkeypatch.setenv("OVPNCP_VPN_BACKEND", "agent")
    request = Request(
        {
            "type": "http",
            "method": method,
            "path": "/clients/edge_1/connections",
            "root_path": "",
            "scheme": "http",
            "server": ("localhost", 8000),
            "client": (address, 43210),
            "headers": [],
            "query_string": b"",
        }
    )
    downstream = mock.AsyncMock(return_value=Response(status_code=204))
    with mock.patch.object(
        azure_security,
        "validate_token",
        side_effect=HTTPException(401, "Authentication required."),
    ) as authenticate:
        response = asyncio.run(
            azure_security.azure_security_middleware(request, downstream)
        )
    assert response.status_code == 401
    authenticate.assert_called_once_with(request)
    downstream.assert_not_called()
    assert getattr(request.state, "local_connection_hook", False) is False


@pytest.mark.parametrize(
    "path",
    [
        "relative.sock",
        "/run/ovpn-agent/../private.sock",
        "http://localhost/agent.sock",
        "/run/ovpn-agent/secret\x00.sock",
        "/run/ovpn-agent/" + "x" * 108,
    ],
)
def test_agent_socket_setting_rejects_unsafe_paths(
    monkeypatch: pytest.MonkeyPatch,
    path: str,
) -> None:
    """Configuration cannot select an ambiguous or non-Unix destination."""
    from sciaiot.ovpncp.adapters.vpn.settings import BackendSettings
    from sciaiot.ovpncp.application.vpn_control.errors import ControlError

    monkeypatch.setenv("OVPNCP_VPN_BACKEND", "agent")
    monkeypatch.setenv("OVPNCP_AGENT_UID", "12345")
    if "\x00" in path:
        # OS environment cannot contain NUL; exercise the same constructor.
        from sciaiot.ovpncp.adapters.vpn.agent import AgentVpnControl

        with pytest.raises((ControlError, ValueError)):
            AgentVpnControl(path, peer_uid=12345)
        return
    monkeypatch.setenv("OVPNCP_AGENT_SOCKET", path)
    with pytest.raises((ControlError, ValueError)) as caught:
        BackendSettings.from_environment()
    assert path not in str(caught.value)


@pytest.mark.parametrize("backend", ["", "Agent", "typo", "host ", "agent,host"])
def test_unknown_backend_cannot_fall_back_to_host(
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
) -> None:
    """A misspelled agent selection never silently enables local privileges."""
    from sciaiot.ovpncp.adapters.vpn.settings import BackendSettings
    from sciaiot.ovpncp.application.vpn_control.errors import ControlError

    monkeypatch.setenv("OVPNCP_VPN_BACKEND", backend)
    with pytest.raises((ControlError, ValueError)):
        BackendSettings.from_environment()


def test_fake_pagination_can_follow_its_own_cursor() -> None:
    """A deterministic fake must exercise more than the first discovery page."""
    from sciaiot.ovpncp.adapters.vpn.fake import FakeVpnControl
    from sciaiot.ovpncp.application.vpn_control import schemas as s

    control = FakeVpnControl()
    for index, name in enumerate(("edge_1", "edge_2")):
        control.execute(
            s.Request(
                request_id=f"00000000-0000-4000-8000-{index + 1:012d}",
                operation_id=f"00000000-0000-4000-8000-{index + 10:012d}",
                expected_generation=index,
                command=s.ChangeClient(client=name, action="issue"),
            )
        )
    request_id = "00000000-0000-4000-8000-000000000003"
    first = control.execute(
        s.Request(request_id=request_id, command=s.ListClients(limit=1))
    ).result
    assert isinstance(first, s.ClientsResult)
    assert first.next_cursor is not None
    second = control.execute(
        s.Request(
            request_id=request_id,
            command=s.ListClients(limit=1, cursor=first.next_cursor),
        )
    ).result
    assert isinstance(second, s.ClientsResult)
    assert {first.items[0].client, second.items[0].client} == {"edge_1", "edge_2"}
    assert second.next_cursor is None


def test_fake_revocation_invalidates_an_unread_archive_handle() -> None:
    """A previously authorized stream cannot deliver a revoked credential."""
    from sciaiot.ovpncp.adapters.vpn.fake import FakeVpnControl
    from sciaiot.ovpncp.application.vpn_control import schemas as s
    from sciaiot.ovpncp.application.vpn_control.errors import ControlError

    control = FakeVpnControl()
    request_id = "00000000-0000-4000-8000-000000000001"
    control.execute(
        s.Request(
            request_id=request_id,
            operation_id="00000000-0000-4000-8000-000000000002",
            expected_generation=0,
            command=s.ChangeClient(client="edge_1", action="issue"),
        )
    )
    with control.open_archive(
        s.Request(
            request_id=request_id,
            command=s.Archive(client="edge_1", generation=0),
        )
    ) as stream:
        control.execute(
            s.Request(
                request_id=request_id,
                operation_id="00000000-0000-4000-8000-000000000003",
                expected_generation=1,
                command=s.ChangeClient(client="edge_1", action="revoke"),
            )
        )
        with pytest.raises(ControlError):
            next(stream)
        assert not stream.verified


@pytest.mark.parametrize("failure", ["identity", "redirect", "oversized", "peer"])
def test_real_unix_transport_rejects_untrusted_responses(
    tmp_path: Path,
    failure: str,
) -> None:
    """Exercise real peer credentials and hostile HTTP over an isolated socket."""
    import os
    import socket
    import threading

    from sciaiot.ovpncp.adapters.vpn.agent import AgentVpnControl
    from sciaiot.ovpncp.application.vpn_control import schemas as s
    from sciaiot.ovpncp.application.vpn_control import wire
    from sciaiot.ovpncp.application.vpn_control.errors import ControlError

    socket_path = str(tmp_path / "agent.sock")
    observed: list[bytes] = []
    server_errors: list[BaseException] = []
    request_id = "00000000-0000-4000-8000-000000000001"
    response = wire.encode(
        s.Response(
            request_id=(
                "00000000-0000-4000-8000-000000000002"
                if failure == "identity"
                else request_id
            ),
            result=s.HealthResult(ready=True, generation=0),
        )
    )
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(socket_path)
        listener.listen(1)
        listener.settimeout(2.0)

        def serve() -> None:
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(2.0)
                    received = connection.recv(4096)
                    observed.append(received)
                    if failure == "peer":
                        return
                    if failure == "oversized":
                        message = (
                            b"HTTP/1.1 200 OK\r\n"
                            b"Content-Type: application/json\r\n"
                            b"Content-Length: 999999999\r\n\r\n"
                        )
                    else:
                        status = b"302 Found" if failure == "redirect" else b"200 OK"
                        message = (
                            b"HTTP/1.1 " + status + b"\r\n"
                            b"Content-Type: application/json\r\n"
                            b"Location: http://127.0.0.1:9/forbidden\r\n"
                            b"Content-Length: "
                            + str(len(response)).encode()
                            + b"\r\n\r\n"
                            + response
                        )
                    connection.sendall(message)
            except (OSError, ValueError) as error:
                server_errors.append(error)

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            peer_uid = os.getuid() + 1 if failure == "peer" else os.getuid()
            control = AgentVpnControl(socket_path, peer_uid=peer_uid)
            with pytest.raises(ControlError):
                control.execute(
                    s.Request(
                        request_id=request_id,
                        command=s.Health(),
                        deadline_ms=1000,
                    )
                )
        finally:
            worker.join(timeout=3.0)
        assert not worker.is_alive()
    assert not server_errors
    assert len(observed) == 1
    if failure == "peer":
        assert observed == [b""]


def test_pending_operation_is_looked_up_on_retry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Persisted pending evidence cannot permanently mask later completion."""
    from sqlmodel import Session, SQLModel, create_engine

    from sciaiot.ovpncp import dependencies
    from sciaiot.ovpncp.adapters.vpn.fake import FakeVpnControl
    from sciaiot.ovpncp.application.vpn_control import schemas as s
    from sciaiot.ovpncp.application.vpn_control.errors import ControlError
    from sciaiot.ovpncp.data import identity  # noqa: F401 -- register ORM models
    from sciaiot.ovpncp.services.vpn import VpnService

    class PendingReply(FakeVpnControl):
        """Report admission before the caller observes a committed result."""

        def execute(self, request: s.Request) -> s.Response:
            """Store real completion but return one nonterminal observation."""
            response = super().execute(request)
            if request.operation_id is not None:
                assert isinstance(response.result, s.MutationResult)
                pending = response.result.model_copy(
                    update={
                        "state": "pending",
                        "generation": request.expected_generation,
                        "completed": (),
                    }
                )
                return s.Response(request_id=request.request_id, result=pending)
            return response

    control = PendingReply()
    monkeypatch.setattr(dependencies, "vpn_control", control)
    engine = create_engine(f"sqlite:///{tmp_path / 'workflow.db'}")
    SQLModel.metadata.create_all(engine)
    try:
        with (
            Session(engine) as session,
            pytest.raises(ControlError, match="unknown_outcome"),
        ):
            VpnService(session).change_client("edge_1", "issue")
        with Session(engine) as session:
            service = VpnService(session)
            service.change_client("edge_1", "issue")
            service.finish()
            session.commit()
        assert control.state.generation == 1
        assert len(control.state.journal) == 1
    finally:
        engine.dispose()


def test_agent_address_pool_excludes_the_observed_server_address() -> None:
    """The agent's explicit server IP must never become assignable to a client."""
    from sciaiot.ovpncp.adapters.vpn.fake import default_config
    from sciaiot.ovpncp.routes.server import load_from_config
    from sciaiot.ovpncp.services.vpn import config_projection

    config = default_config().model_copy(update={"server_address": "10.8.0.5"})
    server = load_from_config(config_projection(config))
    addresses = {item.ip for item in server.virtual_addresses}
    assert server.ip == "10.8.0.5"
    assert server.ip not in addresses
    assert "10.8.0.1" in addresses


def test_agent_can_lookup_durable_operations_while_not_ready(monkeypatch):
    """Recovery must remain reachable when unresolved effects gate new work."""
    import uuid

    from sciaiot.ovpncp.adapters.vpn.agent import AgentVpnControl
    from sciaiot.ovpncp.application.vpn_control import schemas as s
    from sciaiot.ovpncp.application.vpn_control.errors import ControlError, ErrorCode

    control = AgentVpnControl("/run/ovpn-agent/agent.sock", peer_uid=0)
    observed = []

    def exchange(request, deadline):
        observed.append(request.command)
        result = (
            s.HealthResult(ready=False, generation=1)
            if isinstance(request.command, s.Health)
            else s.Failure(code=ErrorCode.NOT_FOUND)
        )
        return s.Response(request_id=request.request_id, result=result)

    monkeypatch.setattr(control, "_json", exchange)
    with pytest.raises(ControlError) as caught:
        control.execute(
            s.Request(
                request_id=str(uuid.uuid4()),
                command=s.LookupOperation(operation_id=str(uuid.uuid4())),
            )
        )
    assert caught.value.code == ErrorCode.NOT_FOUND
    assert isinstance(observed[-1], s.LookupOperation)
    with pytest.raises(ControlError) as caught:
        control.execute(
            s.Request(request_id=str(uuid.uuid4()), command=s.ListClients())
        )
    assert caught.value.code == ErrorCode.UNAVAILABLE
    assert isinstance(observed[-1], s.Health)
