"""Scoped restricted-network API tests through a nonprivileged VPN port."""

from unittest.mock import patch

import pytest
from sqlmodel import Session, select

from sciaiot.rivet.application.vpn_control.errors import ControlError, ErrorCode
from sciaiot.rivet.data.identity import AccessGrant, Device, UserClient
from sciaiot.rivet.data.network import RestrictedNetwork
from sciaiot.rivet.data.server import Client
from sciaiot.rivet.data.vpn import VpnWorkflow
from tests import test_vpn_backends
from tests.support.authentication import authenticated_claims

fake_api = test_vpn_backends.fake_api

USER_CLAIMS = {
    "iss": "https://login.example/tenant/v2.0",
    "sub": "network-user",
    "oid": "network-user-object-id",
    "roles": ["user"],
    "scp": "access_as_user",
}
BODY = {"source_name": "laptop", "destination_device_id": 1}


@pytest.fixture
def network_api(fake_api):
    """Provision real application resources, then act as an ordinary user."""
    api, control, engine = fake_api
    assert (
        api.post("/server", json={"remote_host": "vpn.example.test"}).status_code == 200
    )
    ids = {}
    for index, name in enumerate(("laptop", "other-laptop", "edge", "replacement"), 2):
        response = api.post("/clients", json={"name": name})
        assert response.status_code == 200, response.text
        ids[name] = response.json()["id"]
        assert (
            api.put(
                f"/clients/{name}/assign-ip", json={"ip": f"10.8.0.{index}"}
            ).status_code
            == 200
        )
    user = api.post(
        "/users",
        json={
            "display_name": "Network user",
            "issuer": USER_CLAIMS["iss"],
            "subject": USER_CLAIMS["sub"],
        },
    ).json()
    ids["user"] = user["id"]
    assert api.put(f"/users/{user['id']}/clients/{ids['laptop']}").status_code == 201
    device = api.post(
        "/devices", json={"name": "Sensor", "client_id": ids["edge"]}
    ).json()
    assert device["id"] == BODY["destination_device_id"]
    assert api.put(f"/users/{user['id']}/devices/{device['id']}").status_code == 201
    api.post("/devices", json={"name": "Private sensor"})
    with authenticated_claims(return_value=USER_CLAIMS):
        yield api, control, engine, ids


def test_create_repeat_list_detail_close(network_api):
    """A device grant permits direct access and repeat requests reuse its row."""
    api, control, engine, _ = network_api
    response = api.post("/me/networks", json=BODY)
    assert response.status_code == 200, response.text
    record = response.json()
    assert record["destination_name"] == "edge"
    assert record["private_network_addresses"] == ""
    assert len(control.state.access) == 1
    assert len(control.state.pushes) == 0
    assert api.post("/me/networks", json=BODY).json()["id"] == record["id"]
    assert len(control.state.access) == 1
    assert api.get("/me/networks").json() == [record]
    assert api.get("/me/networks?source_name=laptop").json() == [record]
    assert api.get(f"/me/networks/{record['id']}").json() == record
    assert api.delete(f"/me/networks/{record['id']}").status_code == 204
    assert api.delete(f"/me/networks/{record['id']}").status_code == 204
    assert api.get(f"/me/networks/{record['id']}").json()["end_time"] is not None
    assert not control.state.access
    with Session(engine) as session:
        assert len(session.exec(select(RestrictedNetwork)).all()) == 1
        workflows = session.exec(
            select(VpnWorkflow).where(VpnWorkflow.resource_id == str(record["id"]))
        ).all()
        assert len(workflows) == 2
        assert all(workflow.completed for workflow in workflows)
    # A closed record never prevents opening a fresh access window.
    assert api.post("/me/networks", json=BODY).json()["id"] != record["id"]


@pytest.mark.parametrize(
    "body,status",
    [
        ({**BODY, "source_name": "other-laptop"}, 403),
        ({**BODY, "source_name": "missing"}, 403),
        ({**BODY, "destination_device_id": 2}, 403),
        ({**BODY, "destination_device_id": 999}, 403),
        ({**BODY, "destination_name": "other-laptop"}, 422),
        ({**BODY, "destination_virtual_address": "10.8.0.3"}, 422),
        ({**BODY, "private_network_addresses": "192.168.1.0/24"}, 422),
        ({**BODY, "source_name": "laptop;bad"}, 422),
        ({**BODY, "destination_device_id": 0}, 422),
    ],
)
def test_creation_denied_before_any_effect(network_api, body, status):
    """Forged targets and invalid requests cannot reach VPN mutation or SQL writes."""
    api, control, engine, _ = network_api
    with patch.object(control, "execute", wraps=control.execute) as execute:
        response = api.post("/me/networks", json=body)
        assert response.status_code == status, response.text
        assert response.headers["content-type"] == "application/problem+json"
        execute.assert_not_called()
    with Session(engine) as session:
        assert not session.exec(select(RestrictedNetwork)).all()
        assert not session.exec(
            select(VpnWorkflow).where(VpnWorkflow.active_resource != None)
        ).all()


@pytest.mark.parametrize(
    "case,status",
    [
        ("source-revoked", 409),
        ("destination-revoked", 409),
        ("source-unassigned", 412),
        ("destination-unassigned", 412),
        ("unlinked", 412),
        ("same-client", 400),
        ("invalid-destination-name", 409),
    ],
)
def test_provisioning_preconditions_precede_effects(network_api, case, status):
    """The server resolves and validates both endpoints before VPN mutation."""
    api, control, engine, ids = network_api
    with Session(engine) as session:
        source = session.get(Client, ids["laptop"])
        destination = session.get(Client, ids["edge"])
        device = session.get(Device, 1)
        assert source is not None and destination is not None and device is not None
        if case == "source-revoked":
            source.revoked = True
        elif case == "destination-revoked":
            destination.revoked = True
        elif case == "source-unassigned":
            source.virtual_address_id = None
        elif case == "destination-unassigned":
            destination.virtual_address_id = None
        elif case == "unlinked":
            device.client_id = None
        elif case == "same-client":
            device.client_id = source.id
        else:
            destination.name = "unsafe/name"
        session.add_all([source, destination, device])
        session.commit()
    with patch.object(control, "execute", wraps=control.execute) as execute:
        response = api.post("/me/networks", json=BODY)
        assert response.status_code == status, response.text
        execute.assert_not_called()
    with Session(engine) as session:
        assert not session.exec(select(RestrictedNetwork)).all()


@pytest.mark.parametrize(
    "method,path",
    [
        ("post", "/me/networks"),
        ("get", "/me/networks"),
        ("get", "/me/networks/1"),
        ("delete", "/me/networks/1"),
    ],
)
def test_missing_local_user_is_denied(network_api, method, path):
    """A valid token alone cannot operate on scoped networks."""
    api, control, _, _ = network_api
    with (
        authenticated_claims(return_value={**USER_CLAIMS, "sub": "unregistered"}),
        patch.object(control, "execute", wraps=control.execute) as execute,
    ):
        kwargs = {"json": BODY} if method == "post" else {}
        assert getattr(api, method)(path, **kwargs).status_code == 403
        execute.assert_not_called()


def test_scope_is_checked_before_detail_close_and_query(network_api):
    """Numeric guessing and source filters cannot expose another owner's rows."""
    api, control, engine, ids = network_api
    record = api.post("/me/networks", json=BODY).json()
    with Session(engine) as session:
        assignment = session.exec(select(UserClient)).one()
        assignment.client_id = ids["other-laptop"]
        session.add(assignment)
        session.commit()
    assert api.get("/me/networks").json() == []
    with patch.object(control, "execute", wraps=control.execute) as execute:
        for path in (f"/me/networks/{record['id']}", "/me/networks/999"):
            assert api.get(path).status_code == 403
            assert api.delete(path).status_code == 403
        assert api.get("/me/networks?source_name=laptop").status_code == 403
        assert api.get("/me/networks?source_name=bad%3Bname").status_code == 422
        assert api.post("/me/networks", json=BODY).status_code == 403
        execute.assert_not_called()
    assert len(control.state.access) == 1


@pytest.mark.parametrize("change", ["revoke-grant", "relink-device"])
def test_cleanup_remains_available_after_destination_changes(network_api, change):
    """Existing access can be closed by its source owner after grant changes."""
    api, control, engine, ids = network_api
    record = api.post("/me/networks", json=BODY).json()
    with Session(engine) as session:
        if change == "revoke-grant":
            session.delete(session.exec(select(AccessGrant)).one())
        else:
            device = session.get(Device, 1)
            assert device is not None
            device.client_id = ids["replacement"]
            session.add(device)
        session.commit()
    assert api.get("/me/networks").json() == [record]
    assert api.get(f"/me/networks/{record['id']}").status_code == 200
    if change == "revoke-grant":
        assert api.post("/me/networks", json=BODY).status_code == 403
    assert len(control.state.access) == 1
    assert api.delete(f"/me/networks/{record['id']}").status_code == 204
    assert not control.state.access
    if change == "relink-device":
        assert (
            api.post("/me/networks", json=BODY).json()["destination_name"]
            == "replacement"
        )


@pytest.mark.parametrize("action", ["create", "close"])
def test_control_failure_rolls_back_and_returns_problem(network_api, action):
    """Expected backend conflicts preserve business state and use RFC 7807."""
    api, control, engine, _ = network_api
    record = api.post("/me/networks", json=BODY).json() if action == "close" else None
    with patch(
        "sciaiot.rivet.services.vpn.VpnService.network",
        side_effect=ControlError(ErrorCode.CONFLICT),
    ):
        response = (
            api.post("/me/networks", json=BODY)
            if record is None
            else api.delete(f"/me/networks/{record['id']}")
        )
    assert response.status_code == 409, response.text
    assert response.headers["content-type"] == "application/problem+json"
    with Session(engine) as session:
        rows = session.exec(select(RestrictedNetwork)).all()
        assert len(rows) == (1 if record is not None else 0)
        assert all(row.end_time is None for row in rows)
    assert len(control.state.access) == (1 if record is not None else 0)


def test_commit_failure_retains_workflow_and_retry_completes_once(network_api):
    """An applied effect survives SQL rollback and is reused by the next request."""
    api, control, engine, _ = network_api
    # Fail the business flush after the separate durable journal has committed.
    original_flush = Session.flush

    def fail_business_flush(session, *args, **kwargs):
        if any(isinstance(item, RestrictedNetwork) for item in session.new):
            raise RuntimeError("private database diagnostic")
        return original_flush(session, *args, **kwargs)

    with patch.object(Session, "flush", fail_business_flush):
        response = api.post("/me/networks", json=BODY)
    assert response.status_code == 500, response.text
    assert "private database diagnostic" not in response.text
    assert len(control.state.access) == 1
    with Session(engine) as session:
        assert not session.exec(select(RestrictedNetwork)).all()
        pending = session.exec(
            select(VpnWorkflow).where(VpnWorkflow.completed == False)
        ).all()
        assert len(pending) == 1
    response = api.post("/me/networks", json=BODY)
    assert response.status_code == 200, response.text
    assert len(control.state.access) == 1
    assert api.delete(f"/me/networks/{response.json()['id']}").status_code == 204


def test_close_database_failure_retains_removal_for_retry(network_api):
    """An applied removal remains recoverable if its business flush fails."""
    api, control, engine, _ = network_api
    record = api.post("/me/networks", json=BODY).json()
    original_flush = Session.flush

    def fail_network_flush(session, *args, **kwargs):
        if any(isinstance(item, RestrictedNetwork) for item in session.dirty):
            raise RuntimeError("private database diagnostic")
        return original_flush(session, *args, **kwargs)

    with patch.object(Session, "flush", fail_network_flush):
        response = api.delete(f"/me/networks/{record['id']}")
    assert response.status_code == 500, response.text
    assert "private database diagnostic" not in response.text
    assert not control.state.access
    with Session(engine) as session:
        row = session.get(RestrictedNetwork, record["id"])
        assert row is not None and row.end_time is None
        pending = session.exec(
            select(VpnWorkflow).where(VpnWorkflow.completed == False)
        ).all()
        assert len(pending) == 1
    assert api.delete(f"/me/networks/{record['id']}").status_code == 204
    assert api.get(f"/me/networks/{record['id']}").json()["end_time"] is not None
