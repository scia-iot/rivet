import os
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from threading import Barrier
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from sciaiot.ovpncp.data.identity import User, UserBase
from sciaiot.ovpncp.dependencies import get_session
from sciaiot.ovpncp.main import app
from sciaiot.ovpncp.services.identity import UserService


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


def test_current_principal_auto_registers_a_missing_local_user(
    identity_client: TestClient,
) -> None:
    """The first delegated `/me` request creates its local identity."""
    with patch(
        "sciaiot.ovpncp.middlewares.azure_security.validate_token",
        return_value={
            "iss": "https://login.example/tenant/v2.0",
            "sub": "new-subject",
            "oid": "new-object-id",
            "name": "New Operator",
            "roles": ["admin"],
            "scp": "access_as_user",
        },
    ):
        response = identity_client.get(
            "/me?display_name=Browser+Supplied&subject=browser-subject"
        )

    assert response.status_code == 200
    assert response.json()["display_name"] == "New Operator"
    assert response.json()["subject"] == "new-subject"
    assert response.json()["roles"] == ["sysadmin"]
    users = identity_client.get("/users")
    assert users.status_code == 200
    assert len(users.json()) == 1


def test_current_principal_preserves_an_existing_renamed_user(
    identity_client: TestClient,
) -> None:
    """Validated claims never overwrite the local administrator-owned name."""
    created = identity_client.post(
        "/users",
        json={
            "display_name": "Locally Renamed",
            "issuer": "https://login.example/tenant/v2.0",
            "subject": "test-subject",
        },
    )
    assert created.status_code == 201

    with patch(
        "sciaiot.ovpncp.middlewares.azure_security.validate_token",
        return_value={
            "iss": "https://login.example/tenant/v2.0",
            "sub": "test-subject",
            "oid": "test-object-id",
            "name": "Token Name",
            "roles": ["admin"],
            "scp": "access_as_user",
        },
    ):
        response = identity_client.get("/me")

    assert response.status_code == 200
    assert response.json()["display_name"] == "Locally Renamed"


@pytest.mark.parametrize(
    ("value", "expected_status"),
    [
        (None, 200),
        ("true", 200),
        ("TRUE", 200),
        ("false", 403),
        ("FALSE", 403),
        ("yes", 500),
        ("1", 500),
        (" true ", 500),
    ],
)
def test_auto_registration_setting_is_strict_and_defaults_enabled(
    identity_client: TestClient,
    value: str | None,
    expected_status: int,
) -> None:
    """Only explicit booleans configure automatic local registration."""
    environment = os.environ.copy()
    if value is None:
        environment.pop("AZURE_ENTRAID_AUTO_REGISTER_USERS", None)
    else:
        environment["AZURE_ENTRAID_AUTO_REGISTER_USERS"] = value

    with patch.dict(os.environ, environment, clear=True):
        response = identity_client.get("/me")

    assert response.status_code == expected_status
    if expected_status == 403:
        assert response.json()["detail"] == (
            "The signed-in identity is not registered for this application."
        )
    if expected_status == 500:
        assert response.json()["detail"] == (
            "Automatic user registration is misconfigured."
        )


def test_invalid_auto_registration_setting_fails_closed_for_existing_user(
    identity_client: TestClient,
) -> None:
    """An invalid registration flag is never ignored for known identities."""
    created = identity_client.post(
        "/users",
        json={
            "display_name": "Existing User",
            "issuer": "https://login.example/tenant/v2.0",
            "subject": "test-subject",
        },
    )
    assert created.status_code == 201

    with patch.dict(
        os.environ,
        {"AZURE_ENTRAID_AUTO_REGISTER_USERS": "invalid"},
    ):
        response = identity_client.get("/me")

    assert response.status_code == 500
    assert response.json()["detail"] == (
        "Automatic user registration is misconfigured."
    )


def test_auto_registration_errors_do_not_expose_validated_identity(
    identity_client: TestClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Registration failures keep tokens and stable claims out of diagnostics."""
    claims = {
        "iss": "https://login.example/private-issuer",
        "sub": "stable-private-subject",
        "oid": "private-object-id",
        "name": "Private Display Name",
        "roles": ["admin"],
        "scp": "access_as_user",
    }
    with (
        patch(
            "sciaiot.ovpncp.middlewares.azure_security.validate_token",
            return_value=claims,
        ),
        patch.dict(
            os.environ,
            {"AZURE_ENTRAID_AUTO_REGISTER_USERS": "invalid"},
        ),
    ):
        response = identity_client.get(
            "/me",
            headers={"Authorization": "Bearer private-token-value"},
        )

    diagnostics = caplog.text + response.text
    assert response.status_code == 500
    assert "private-token-value" not in diagnostics
    assert "private-issuer" not in diagnostics
    assert "stable-private-subject" not in diagnostics
    assert "private-object-id" not in diagnostics
    assert "Private Display Name" not in diagnostics


@pytest.mark.parametrize(
    ("name", "preferred_username", "expected"),
    [
        ("  Display Name  ", "ignored@example.com", "Display Name"),
        (42, "person@example.com", "person@example.com"),
        ("A" * 300, "ignored@example.com", "A" * 255),
        (None, "   ", "Microsoft Entra user"),
    ],
)
def test_auto_registration_uses_a_bounded_validated_claim_display_name(
    identity_client: TestClient,
    name: object,
    preferred_username: object,
    expected: str,
) -> None:
    """Display names use trusted claim precedence, bounds, and safe fallback."""
    claims: dict[str, object] = {
        "iss": "https://login.example/tenant/v2.0",
        "sub": f"display-name-{len(expected)}",
        "oid": f"object-id-{len(expected)}",
        "roles": ["user"],
        "scp": "access_as_user",
        "name": name,
        "preferred_username": preferred_username,
    }
    with patch(
        "sciaiot.ovpncp.middlewares.azure_security.validate_token",
        return_value=claims,
    ):
        response = identity_client.get("/me")

    assert response.status_code == 200
    assert response.json()["display_name"] == expected
    assert response.json()["roles"] == ["device_user"]


def test_service_admin_is_never_auto_registered(
    identity_client: TestClient,
) -> None:
    """App-only service administration never creates a local User."""
    with patch(
        "sciaiot.ovpncp.middlewares.azure_security.validate_token",
        return_value={
            "iss": "https://login.example/tenant/v2.0",
            "sub": "service-object-id",
            "oid": "service-object-id",
            "name": "Service application",
            "roles": ["ServiceAdmin"],
        },
    ):
        response = identity_client.get("/me")
        users = identity_client.get("/users")

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "The signed-in identity is not registered for this application."
    )
    assert users.status_code == 200
    assert users.json() == []


def test_racing_auto_registration_is_idempotent(tmp_path: Path) -> None:
    """Concurrent first-user creation resolves to one external identity."""
    engine = create_engine(
        f"sqlite:///{tmp_path / 'identity-race.db'}",
        connect_args={"check_same_thread": False},
    )
    SQLModel.metadata.create_all(engine)
    barrier = Barrier(4)

    def register() -> int:
        with Session(engine) as session:
            barrier.wait()
            user = UserService(session).get_or_create_external_identity(
                UserBase(
                    display_name="Race User",
                    issuer="https://login.example/tenant/v2.0",
                    subject="race-subject",
                )
            )
            assert user.id is not None
            return user.id

    with ThreadPoolExecutor(max_workers=4) as executor:
        user_ids = list(executor.map(lambda _: register(), range(4)))

    with Session(engine) as session:
        users = list(session.exec(select(User)).all())
    engine.dispose()

    assert len(set(user_ids)) == 1
    assert len(users) == 1


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
