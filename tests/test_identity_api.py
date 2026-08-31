from collections.abc import Generator
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from sciaiot.ovpncp.dependencies import get_session
from sciaiot.ovpncp.main import app


@pytest.fixture(name="identity_client")
def identity_client_fixture() -> Generator[TestClient]:
    """Create an isolated API client for identity-domain tests."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    with Session(engine) as session:

        def get_session_override() -> Generator[Session]:
            yield session

        app.dependency_overrides[get_session] = get_session_override
        with (
            patch("sciaiot.ovpncp.main.create_app_directory"),
            patch("sciaiot.ovpncp.main.create_tables"),
            patch("sciaiot.ovpncp.main.init_scripts"),
            patch("sciaiot.ovpncp.utils.openvpn.build_client"),
            patch(
                "sciaiot.ovpncp.middlewares.azure_security.validate_token",
                return_value={
                    "iss": "https://login.example/tenant/v2.0",
                    "sub": "test-subject",
                    "oid": "test-object-id",
                    "roles": ["admin"],
                    "scp": "access_as_user",
                },
            ),
            patch("sciaiot.ovpncp.middlewares.azure_security.USER_ROLE", "user"),
            patch("sciaiot.ovpncp.middlewares.azure_security.ADMIN_ROLE", "admin"),
            patch(
                "sciaiot.ovpncp.middlewares.azure_security.SERVICE_ADMIN_ROLE",
                "ServiceAdmin",
            ),
            patch(
                "sciaiot.ovpncp.utils.openvpn.read_client_cert",
                return_value={
                    "issued_by": "test-ca",
                    "issued_to": "test-client",
                    "issued_on": datetime(2026, 1, 1, tzinfo=timezone.utc),
                    "expires_on": datetime(2027, 1, 1, tzinfo=timezone.utc),
                },
            ),
            TestClient(app) as test_client,
        ):
            yield test_client

    app.dependency_overrides.clear()
    SQLModel.metadata.drop_all(engine)
    engine.dispose()


def test_current_principal_is_resolved_from_validated_token(
    identity_client: TestClient,
) -> None:
    """The current principal maps only the validated issuer and subject."""
    user = identity_client.post(
        "/users",
        json={
            "display_name": "Current Operator",
            "issuer": "https://login.example/tenant/v2.0",
            "subject": "test-subject",
        },
    )
    assert user.status_code == 201

    response = identity_client.get("/me?user_id=999")

    assert response.status_code == 200
    assert response.json() == {
        "id": user.json()["id"],
        "display_name": "Current Operator",
        "issuer": "https://login.example/tenant/v2.0",
        "subject": "test-subject",
        "roles": ["sysadmin"],
        "permissions": [
            "devices:read",
            "devices:write",
            "users:read",
            "users:write",
            "clients:read",
            "clients:write",
            "access:read",
            "access:grant",
            "server:read",
            "server:write",
        ],
    }


def test_current_principal_requires_a_registered_local_user(
    identity_client: TestClient,
) -> None:
    """An authenticated external identity has no implicit local access."""
    response = identity_client.get("/me")

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "The signed-in identity is not registered for this application."
    )


def test_current_principal_rejects_partial_validated_identity(
    identity_client: TestClient,
) -> None:
    """Missing stable token claims fail closed instead of selecting a user."""
    with patch(
        "sciaiot.ovpncp.middlewares.azure_security.validate_token",
        return_value={
            "iss": "https://login.example/tenant/v2.0",
            "roles": ["admin"],
        },
    ):
        response = identity_client.get("/me")

    assert response.status_code == 401
    assert response.json()["detail"] == "The validated token identity is incomplete."


def test_device_lifecycle(identity_client: TestClient) -> None:
    """A device can be registered independently and linked to a VPN client."""
    client_response = identity_client.post(
        "/clients",
        json={"name": "edge-client"},
    )
    assert client_response.status_code == 200

    response = identity_client.post(
        "/devices",
        json={"name": "edge-device", "client_id": client_response.json()["id"]},
    )
    assert response.status_code == 201
    assert response.json()["name"] == "edge-device"
    assert response.json()["client_id"] == client_response.json()["id"]

    response = identity_client.get("/devices")
    assert response.status_code == 200
    assert len(response.json()) == 1

    response = identity_client.get(f"/devices/{response.json()[0]['id']}")
    assert response.status_code == 200
    assert response.json()["name"] == "edge-device"

    response = identity_client.patch(
        f"/devices/{response.json()['id']}",
        json={"name": "renamed-device", "client_id": None},
    )
    assert response.status_code == 200
    assert response.json()["name"] == "renamed-device"
    assert response.json()["client_id"] is None

    response = identity_client.delete(f"/devices/{response.json()['id']}")
    assert response.status_code == 204


def test_device_rejects_unknown_or_reused_client(
    identity_client: TestClient,
) -> None:
    """A VPN client cannot be missing or assigned to multiple devices."""
    response = identity_client.post(
        "/devices",
        json={"name": "unknown-client-device", "client_id": 999},
    )
    assert response.status_code == 404

    client_response = identity_client.post(
        "/clients",
        json={"name": "single-client"},
    )
    client_id = client_response.json()["id"]
    first_response = identity_client.post(
        "/devices",
        json={"name": "first-device", "client_id": client_id},
    )
    assert first_response.status_code == 201

    response = identity_client.post(
        "/devices",
        json={"name": "second-device", "client_id": client_id},
    )
    assert response.status_code == 409


def test_user_and_access_grant_lifecycle(identity_client: TestClient) -> None:
    """A user can receive and lose individual access to a device."""
    user_response = identity_client.post(
        "/users",
        json={
            "display_name": "Edge Operator",
            "issuer": "https://login.example/tenant/v2.0",
            "subject": "external-user-id",
        },
    )
    assert user_response.status_code == 201

    device_response = identity_client.post(
        "/devices",
        json={"name": "unprovisioned-device"},
    )
    assert device_response.status_code == 201

    user_id = user_response.json()["id"]
    device_id = device_response.json()["id"]
    response = identity_client.put(f"/users/{user_id}/devices/{device_id}")
    assert response.status_code == 201
    assert response.json()["user_id"] == user_id
    assert response.json()["device_id"] == device_id

    response = identity_client.get(f"/users/{user_id}/devices")
    assert response.status_code == 200
    assert response.json() == [device_response.json()]

    response = identity_client.put(f"/users/{user_id}/devices/{device_id}")
    assert response.status_code == 200
    assert response.json()["id"] is not None

    response = identity_client.delete(f"/users/{user_id}/devices/{device_id}")
    assert response.status_code == 204

    response = identity_client.get(f"/users/{user_id}/devices")
    assert response.status_code == 200
    assert response.json() == []

    response = identity_client.patch(
        f"/users/{user_id}", json={"display_name": "Renamed Operator"}
    )
    assert response.status_code == 200
    assert response.json()["display_name"] == "Renamed Operator"

    response = identity_client.delete(f"/users/{user_id}")
    assert response.status_code == 204


def test_access_grant_missing_entities(identity_client: TestClient) -> None:
    """Missing users, devices, and grants return safe not-found responses."""
    user_response = identity_client.post(
        "/users",
        json={
            "display_name": "Access User",
            "issuer": "https://login.example/tenant/v2.0",
            "subject": "access-user",
        },
    )
    device_response = identity_client.post(
        "/devices",
        json={"name": "access-device"},
    )
    user_id = user_response.json()["id"]
    device_id = device_response.json()["id"]

    response = identity_client.delete(f"/users/{user_id}/devices/{device_id}")
    assert response.status_code == 404
    assert response.json()["detail"] == "Access grant not found."

    response = identity_client.put(f"/users/999/devices/{device_id}")
    assert response.status_code == 404
    assert response.json()["detail"] == "User with ID 999 not found."

    response = identity_client.put(f"/users/{user_id}/devices/999")
    assert response.status_code == 404
    assert response.json()["detail"] == "Device with ID 999 not found."

    response = identity_client.get("/users/999/devices")
    assert response.status_code == 404
    assert response.json()["detail"] == "User with ID 999 not found."


def test_user_identity_must_be_unique(identity_client: TestClient) -> None:
    """The same external OAuth identity cannot create multiple users."""
    request = {
        "display_name": "Operator",
        "issuer": "https://login.example/tenant/v2.0",
        "subject": "stable-subject",
    }
    assert identity_client.post("/users", json=request).status_code == 201
    assert identity_client.post("/users", json=request).status_code == 409


def test_user_client_lifecycle(identity_client: TestClient) -> None:
    """An administrator can assign multiple VPN clients to one user."""
    user_response = identity_client.post(
        "/users",
        json={
            "display_name": "Laptop User",
            "issuer": "https://login.example/tenant/v2.0",
            "subject": "laptop-user",
        },
    )
    first_client = identity_client.post(
        "/clients",
        json={"name": "laptop-one"},
    )
    second_client = identity_client.post(
        "/clients",
        json={"name": "laptop-two"},
    )
    user_id = user_response.json()["id"]
    first_client_id = first_client.json()["id"]
    second_client_id = second_client.json()["id"]

    response = identity_client.put(
        f"/users/{user_id}/clients/{first_client_id}",
    )
    assert response.status_code == 201
    assert response.json()["user_id"] == user_id
    assert response.json()["client_id"] == first_client_id

    response = identity_client.put(
        f"/users/{user_id}/clients/{first_client_id}",
    )
    assert response.status_code == 200

    response = identity_client.put(
        f"/users/{user_id}/clients/{second_client_id}",
    )
    assert response.status_code == 201

    response = identity_client.get(f"/users/{user_id}/clients")
    assert response.status_code == 200
    assert {item["name"] for item in response.json()} == {
        "laptop-one",
        "laptop-two",
    }

    response = identity_client.delete(
        f"/users/{user_id}/clients/{first_client_id}",
    )
    assert response.status_code == 204

    response = identity_client.get(f"/users/{user_id}/clients")
    assert response.status_code == 200
    assert [item["name"] for item in response.json()] == ["laptop-two"]


def test_vpn_client_cannot_belong_to_multiple_users(
    identity_client: TestClient,
) -> None:
    """A VPN client has at most one owning user."""
    first_user = identity_client.post(
        "/users",
        json={
            "display_name": "First User",
            "issuer": "https://login.example/tenant/v2.0",
            "subject": "first-user",
        },
    )
    second_user = identity_client.post(
        "/users",
        json={
            "display_name": "Second User",
            "issuer": "https://login.example/tenant/v2.0",
            "subject": "second-user",
        },
    )
    vpn_client = identity_client.post(
        "/clients",
        json={"name": "owned-laptop"},
    )
    client_id = vpn_client.json()["id"]

    response = identity_client.put(
        f"/users/{first_user.json()['id']}/clients/{client_id}",
    )
    assert response.status_code == 201

    response = identity_client.put(
        f"/users/{second_user.json()['id']}/clients/{client_id}",
    )
    assert response.status_code == 409


def test_user_client_requires_existing_entities(
    identity_client: TestClient,
) -> None:
    """A user-client association requires both records to exist."""
    response = identity_client.put("/users/999/clients/999")
    assert response.status_code == 404
