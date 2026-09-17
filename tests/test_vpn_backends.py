"""Application adapters and durable workflow regression tests."""

import pytest

from sciaiot.ovpncp.adapters.vpn.fake import FakeVpnControl
from sciaiot.ovpncp.adapters.vpn.settings import BackendSettings
from sciaiot.ovpncp.application.vpn_control import schemas as s
from tests.vpn_control_conformance import request


def test_default_backend_and_invalid_settings(monkeypatch):
    monkeypatch.delenv("OVPNCP_VPN_BACKEND", raising=False)
    assert BackendSettings.from_environment().backend == "host"
    monkeypatch.setenv("OVPNCP_VPN_BACKEND", "invalid")
    with pytest.raises(ValueError):
        BackendSettings.from_environment()


def test_fake_client_lifecycle_and_replay():
    control = FakeVpnControl()
    creation = request(s.ChangeClient(client="edge_1", action="issue"))
    result = control.execute(creation).result
    assert isinstance(result, s.MutationResult)
    assert result.state == "succeeded"
    assert control.execute(creation).result == result
    item = control.execute(request(s.GetClient(client="edge_1"))).result
    assert isinstance(item, s.ClientResult)
    assert item.item.state == "active"


@pytest.fixture
def fake_api(tmp_path, monkeypatch):
    """Serve the real API with isolated SQL state and no privileged adapter."""
    from unittest.mock import patch

    from fastapi.testclient import TestClient
    from sqlmodel import Session, SQLModel, create_engine

    from sciaiot.ovpncp import dependencies
    from sciaiot.ovpncp.main import app

    engine = create_engine(
        f"sqlite:///{tmp_path / 'api.db'}", connect_args={"check_same_thread": False}
    )
    SQLModel.metadata.create_all(engine)
    control = FakeVpnControl()
    monkeypatch.setattr(dependencies, "vpn_control", control)
    monkeypatch.setattr(
        dependencies, "client_config_path", str(tmp_path / "client.ovpn")
    )
    monkeypatch.setattr(dependencies, "certs_directory", str(tmp_path / "archives"))

    def session_override():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[dependencies.get_session] = session_override
    from sciaiot.ovpncp.middlewares import azure_security

    monkeypatch.setattr(azure_security, "USER_ROLE", "user")
    monkeypatch.setattr(azure_security, "ADMIN_ROLE", "admin")
    monkeypatch.setattr(azure_security, "TENANT_ID", "fixture-tenant")
    monkeypatch.setattr(azure_security, "APP_CLIENT_ID", "fixture-client")
    with (
        patch(
            "sciaiot.ovpncp.middlewares.azure_security.validate_token",
            return_value={
                "iss": "https://login.example/tenant/v2.0",
                "sub": "service-id",
                "oid": "service-id",
                "roles": ["ServiceAdmin"],
            },
        ),
        patch(
            "sciaiot.ovpncp.middlewares.azure_security.SERVICE_ADMIN_ROLE",
            "ServiceAdmin",
        ),
        patch(
            "subprocess.run",
            side_effect=AssertionError("privileged operation forbidden"),
        ),
    ):
        client = TestClient(app, headers={"Authorization": "Bearer fixture"})
        yield client, control, engine
    app.dependency_overrides.clear()
    engine.dispose()


def test_fake_api_lifecycle_network_routes_and_archives(fake_api):
    """Exercise every privileged public workflow through an in-process port."""
    from sqlmodel import Session, select

    from sciaiot.ovpncp.data.vpn import VpnWorkflow

    client, control, engine = fake_api
    response = client.post("/server", json={"remote_host": "vpn.example.test"})
    assert response.status_code == 200, response.text
    assert response.json()["dev"] == "tun0"
    assert response.json()["ca"] == "agent-managed"
    assert (
        client.put(
            "/server/client-config", json={"remote_host": "vpn2.example.test"}
        ).status_code
        == 204
    )
    assert client.get("/server/health").json()["status"] == "active (running)"
    for index, name in enumerate(("edge_1", "edge_2"), 2):
        assert client.post("/clients", json={"name": name}).status_code == 200
        assert (
            client.put(
                f"/clients/{name}/assign-ip", json={"ip": f"10.8.0.{index}"}
            ).status_code
            == 200
        )
    response = client.post(
        "/networks",
        json={
            "source_name": "edge_1",
            "destination_name": "edge_2",
            "private_network_addresses": "192.168.10.0/24,192.168.20.5",
        },
    )
    assert response.status_code == 200, response.text
    network_id = response.json()["id"]
    assert len(control.state.access) == 1 and len(control.state.pushes) == 1
    assert client.delete(f"/networks/{network_id}").status_code == 204
    assert client.delete(f"/networks/{network_id}").status_code == 204
    assert not control.state.access and not control.state.pushes
    assert (
        client.post("/server/routes", json={"network": "192.168.30.0/24"}).status_code
        == 204
    )
    assert client.get("/server/routes").json() == ["192.168.30.0/24 via 10.8.0.1"]
    assert (
        client.delete(
            "/server/routes", params={"network": "192.168.30.0/24"}
        ).status_code
        == 204
    )
    assert (
        client.delete(
            "/server/routes", params={"network": "192.168.30.0/24"}
        ).status_code
        == 404
    )
    assert client.put("/clients/edge_1/package-cert").status_code == 204
    download = client.get("/clients/edge_1/download-cert")
    assert download.status_code == 200
    assert download.content == b"synthetic credential archive"
    assert download.headers["cache-control"] == "no-store"
    assert client.put("/clients/edge_1/renew-cert").status_code == 200
    assert (
        client.post("/clients/import", json={"create_devices": True}).json()["updated"]
        == 2
    )
    assert client.delete("/clients/edge_1/unassign-ip").status_code == 204
    assert client.put("/clients/edge_1/revoke").status_code == 200
    assert client.get("/clients/edge_1/download-cert").status_code == 500
    assert client.delete("/clients/edge_1").status_code == 204
    with Session(engine) as session:
        assert all(item.completed for item in session.exec(select(VpnWorkflow)).all())


def test_lost_reply_retries_original_operation_after_database_restart(fake_api):
    """A lost write reply cannot issue a second certificate on HTTP retry."""
    from sqlmodel import Session, select

    from sciaiot.ovpncp.data.vpn import VpnStep, VpnWorkflow

    client, control, engine = fake_api
    control.fault = "lost_reply"
    assert client.post("/clients", json={"name": "edge_1"}).status_code == 500
    assert control.state.generation == 1
    with Session(engine) as session:
        original = session.exec(select(VpnStep)).one().id
        assert not session.exec(select(VpnWorkflow)).one().completed
    control.fault = None
    assert client.post("/clients", json={"name": "edge_1"}).status_code == 200
    assert control.state.generation == 1
    with Session(engine) as session:
        assert session.exec(select(VpnStep)).one().id == original
        assert session.exec(select(VpnWorkflow)).one().completed


def test_conflicting_retry_is_fenced(fake_api):
    """Changed desired business metadata cannot repurpose unresolved issuance."""
    client, control, _ = fake_api
    control.fault = "lost_reply"
    assert (
        client.post(
            "/clients", json={"name": "edge_1", "cidr": "192.168.1.0/24"}
        ).status_code
        == 500
    )
    control.fault = None
    assert (
        client.post(
            "/clients", json={"name": "edge_1", "cidr": "192.168.2.0/24"}
        ).status_code
        == 500
    )
    assert control.state.generation == 1


def test_privileged_imports_are_confined_to_approved_boundaries():
    """Fail CI if business code regains direct privileged dependencies."""
    import ast
    from pathlib import Path

    root = Path(__file__).parents[1] / "src/sciaiot/ovpncp"
    privileged = {"openvpn", "iproute", "iptables", "subprocess"}
    for path in root.rglob("*.py"):
        relative = path.relative_to(root)
        if (
            relative.parts[0] in {"utils", "migration"}
            or relative.as_posix() == "adapters/vpn/host.py"
        ):
            continue
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(
                    alias.name.split(".")[-1] not in privileged for alias in node.names
                ), str(relative)
            if isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[-1] not in privileged, str(
                    relative
                )
                if (node.module or "").endswith("utils"):
                    assert all(alias.name not in privileged for alias in node.names), (
                        str(relative)
                    )
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert not (
                    isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "os"
                    and node.func.attr
                    in {"system", "popen", "execv", "execve", "spawnv", "spawnve"}
                ), str(relative)


def test_same_pending_network_has_one_business_completion(fake_api):
    """Two callers joining one intent cannot commit two network rows."""
    from datetime import datetime, timezone

    from sqlmodel import Session, select

    from sciaiot.ovpncp.application.vpn_control.errors import ControlError
    from sciaiot.ovpncp.data.network import RestrictedNetwork
    from sciaiot.ovpncp.services.vpn import VpnService

    _, control, engine = fake_api
    from tests.vpn_control_conformance import client as metadata

    control.state.clients = {
        "edge_1": metadata("edge_1").model_copy(
            update={"assignment": s.Assignment(address="10.8.0.2")}
        ),
        "edge_2": metadata("edge_2").model_copy(
            update={"assignment": s.Assignment(address="10.8.0.3")}
        ),
    }
    values = {
        "source_name": "edge_1",
        "destination_name": "edge_2",
        "source_virtual_address": "10.8.0.2",
        "destination_virtual_address": "10.8.0.3",
        "private_network_addresses": "",
        "start_time": datetime.now(timezone.utc),
    }
    with Session(engine) as first_session, Session(engine) as second_session:
        first, second = RestrictedNetwork(**values), RestrictedNetwork(**values)
        first_service, second_service = (
            VpnService(first_session),
            VpnService(second_session),
        )
        first_service.network(first, True)
        second_service.network(second, True)
        first_session.add(first)
        first_session.flush()
        first_service.finish(resource_id=str(first.id))
        first_session.commit()
        second_session.add(second)
        second_session.flush()
        with pytest.raises(ControlError, match="conflict"):
            second_service.finish(resource_id=str(second.id))
        second_session.rollback()
    with Session(engine) as session:
        assert len(session.exec(select(RestrictedNetwork)).all()) == 1


def test_blocked_vpn_read_does_not_block_the_event_loop(monkeypatch):
    """Health transport waits occupy a worker while the API loop progresses."""
    import asyncio
    import threading

    from sciaiot.ovpncp import dependencies
    from sciaiot.ovpncp.routes.server import get_service_health

    started, release = threading.Event(), threading.Event()

    class SlowControl(FakeVpnControl):
        def execute(self, incoming):
            started.set()
            assert release.wait(timeout=2)
            return super().execute(incoming)

    monkeypatch.setattr(dependencies, "vpn_control", SlowControl())

    async def exercise():
        task = asyncio.create_task(get_service_health(None))
        try:
            for _ in range(100):
                if started.is_set():
                    break
                await asyncio.sleep(0.005)
            assert started.is_set()
            assert not task.done()
        finally:
            release.set()
        assert (await task)["status"] == "active (running)"

    asyncio.run(exercise())


def test_fake_access_rejects_unobserved_client_assignment():
    """The fake cannot hide invalid ownership/address assumptions in workflows."""
    from sciaiot.ovpncp.application.vpn_control import wire
    from sciaiot.ovpncp.application.vpn_control.errors import ControlError
    from tests.vpn_control_conformance import OID

    control = FakeVpnControl()
    operation = request(
        s.SetAccess(
            intent=s.AccessIntent(
                access_id=OID,
                source_client="source",
                destination_client="destination",
                source_address="10.8.0.2",
                destination_address="10.8.0.3",
            ),
            present=True,
        )
    )
    with pytest.raises(ControlError, match="conflict"):
        wire.require_success(control.execute(operation))
    assert not control.state.access


def test_operation_capacity_refuses_before_effects():
    """Finite retained replay evidence is never silently evicted."""
    from sciaiot.ovpncp.adapters.vpn.fake import FakeState
    from sciaiot.ovpncp.application.vpn_control.errors import ControlError

    control = FakeVpnControl(FakeState(max_operations=0))
    with pytest.raises(ControlError, match="exhausted"):
        control.execute(request(s.ChangeClient(client="edge_1", action="issue")))
    assert not control.state.clients


def test_agent_snapshots_reject_repeated_cursors_before_import(fake_api):
    """A protocol-valid but looping peer cannot retain an API worker forever."""
    from sqlmodel import Session

    from sciaiot.ovpncp.application.vpn_control.errors import ControlError
    from sciaiot.ovpncp.services.vpn import VpnService
    from tests.vpn_control_conformance import client as metadata

    _, control, engine = fake_api
    original = control.execute

    def repeated(incoming):
        if isinstance(incoming.command, s.ListClients):
            return s.Response(
                request_id=incoming.request_id,
                result=s.ClientsResult(
                    items=(metadata(),), generation=0, next_cursor="repeated"
                ),
            )
        return original(incoming)

    control.execute = repeated
    with Session(engine) as session, pytest.raises(ControlError, match="integrity"):
        VpnService(session).discoveries()


def test_oversized_agent_pool_fails_before_enumeration():
    """A valid huge IPv4 network cannot allocate unbounded API memory."""
    from sciaiot.ovpncp.adapters.vpn.fake import default_config
    from sciaiot.ovpncp.routes.server import load_from_config
    from sciaiot.ovpncp.services.vpn import config_projection

    config = default_config().model_copy(update={"network": "0.0.0.0/0"})
    with pytest.raises(ValueError, match="capacity"):
        load_from_config(config_projection(config))


def test_journal_database_errors_are_redacted(fake_api, monkeypatch):
    """SQL statement parameters never escape a failed workflow admission."""
    from sqlalchemy.exc import OperationalError
    from sqlmodel import Session

    from sciaiot.ovpncp.application.vpn_control.errors import ControlError
    from sciaiot.ovpncp.services.vpn import VpnService

    _, _, engine = fake_api
    with Session(engine) as session:
        service = VpnService(session)
        monkeypatch.setattr(
            Session,
            "exec",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                OperationalError(
                    "SECRET SQL", {"private": "192.168.1.2"}, Exception("SECRET")
                )
            ),
        )
        with pytest.raises(ControlError, match="unavailable") as error:
            service.change_client("edge_1", "issue")
        assert "SECRET" not in str(error.value)
        assert error.value.__suppress_context__
