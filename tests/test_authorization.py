"""Authorization policy tests for trusted principals and management routes."""

from collections.abc import Generator
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from sciaiot.ovpncp.authorization import (
    AuthenticatedPrincipal,
    Permission,
    authorize_granted_device,
    authorize_owned_client,
)
from sciaiot.ovpncp.data.identity import AccessGrant, Device, User, UserClient
from sciaiot.ovpncp.data.server import Client
from sciaiot.ovpncp.dependencies import get_session
from sciaiot.ovpncp.main import app
from sciaiot.ovpncp.middlewares.azure_security import validate_token


@pytest.fixture(name="authorization_context")
def authorization_context_fixture() -> Generator[
    tuple[TestClient, dict[str, object], Session]
]:
    """Create isolated principals and resources for policy tests."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    with Session(engine) as session:
        admin = User(
            display_name="Control plane administrator",
            issuer="https://login.example/tenant/v2.0",
            subject="admin-subject",
        )
        device_user = User(
            display_name="Device user",
            issuer="https://login.example/tenant/v2.0",
            subject="device-user-subject",
        )
        other_user = User(
            display_name="Other user",
            issuer="https://login.example/tenant/v2.0",
            subject="other-user-subject",
        )
        owned_client = Client(name="owned-laptop")
        granted_device = Device(name="granted-edge")
        ungranted_device = Device(name="other-edge")
        session.add_all(
            [
                admin,
                device_user,
                other_user,
                owned_client,
                granted_device,
                ungranted_device,
            ]
        )
        session.commit()
        for entity in (
            admin,
            device_user,
            other_user,
            owned_client,
            granted_device,
            ungranted_device,
        ):
            session.refresh(entity)

        assert device_user.id is not None
        assert owned_client.id is not None
        assert granted_device.id is not None
        session.add(UserClient(user_id=device_user.id, client_id=owned_client.id))
        session.add(AccessGrant(user_id=device_user.id, device_id=granted_device.id))
        session.commit()

        claims: dict[str, object] = {
            "iss": device_user.issuer,
            "sub": device_user.subject,
            "roles": ["Device.User"],
        }

        def get_session_override() -> Generator[Session]:
            yield session

        app.dependency_overrides[get_session] = get_session_override
        with (
            patch(
                "sciaiot.ovpncp.middlewares.azure_security.validate_token",
                side_effect=lambda request: dict(claims),
            ),
            patch("sciaiot.ovpncp.main.create_app_directory"),
            patch("sciaiot.ovpncp.main.create_tables"),
            patch("sciaiot.ovpncp.main.init_scripts"),
            patch(
                "sciaiot.ovpncp.middlewares.azure_security.APP_ROLE",
                "ControlPlane.Admin",
            ),
            TestClient(app) as test_client,
        ):
            yield test_client, claims, session

    app.dependency_overrides.clear()
    SQLModel.metadata.drop_all(engine)
    engine.dispose()


def test_registered_non_admin_resolves_device_user_principal(
    authorization_context: tuple[TestClient, dict[str, object], Session],
) -> None:
    """Authentication succeeds without granting management permissions."""
    test_client, _, _ = authorization_context

    response = test_client.get("/me")

    assert response.status_code == 200
    assert response.json()["roles"] == ["device_user"]
    assert response.json()["permissions"] == []


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("GET", "/devices", None),
        ("POST", "/devices", {"name": "blocked-device"}),
        ("GET", "/users", None),
        (
            "POST",
            "/users",
            {
                "display_name": "Blocked",
                "issuer": "https://login.example/tenant/v2.0",
                "subject": "blocked-subject",
            },
        ),
        ("GET", "/clients", None),
        ("POST", "/clients", {"name": "blocked-client"}),
        ("GET", "/server", None),
        ("POST", "/server", None),
        ("GET", "/server/routes", None),
        ("POST", "/server/routes", {"network": "10.42.0.0/24"}),
        ("GET", "/networks", None),
        (
            "POST",
            "/networks",
            {
                "source_name": "source",
                "destination_name": "destination",
            },
        ),
        (
            "POST",
            "/clients/owned-laptop/connections",
            {
                "remote_address": "10.0.0.8",
                "connected_time": "2026-08-25T10:00:00Z",
            },
        ),
    ],
)
def test_device_user_cannot_call_management_routes(
    authorization_context: tuple[TestClient, dict[str, object], Session],
    method: str,
    path: str,
    body: dict[str, object] | None,
) -> None:
    """Direct API calls remain forbidden when frontend controls are hidden."""
    test_client, _, _ = authorization_context

    response = test_client.request(method, path, json=body)

    assert response.status_code == 403
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["detail"] == (
        "The current principal lacks the required permission."
    )


def test_exact_loopback_connection_hook_remains_available(
    authorization_context: tuple[TestClient, dict[str, object], Session],
) -> None:
    """The OpenVPN script can call only the exact loopback hook."""
    with TestClient(
        app,
        client=("127.0.0.1", 50000),
    ) as local_client:
        response = local_client.post(
            "/clients/owned-laptop/connections",
            json={
                "remote_address": "10.0.0.9",
                "connected_time": "2026-08-25T10:00:00Z",
            },
        )

    assert response.status_code == 200
    assert response.json()["client_id"] is not None


def test_sysadmin_role_receives_authoritative_permissions(
    authorization_context: tuple[TestClient, dict[str, object], Session],
) -> None:
    """The configured Entra role maps to the canonical sysadmin policy."""
    test_client, claims, _ = authorization_context
    claims["sub"] = "admin-subject"
    claims["roles"] = ["ControlPlane.Admin"]

    principal_response = test_client.get("/me")
    devices_response = test_client.get("/devices")

    assert principal_response.status_code == 200
    assert principal_response.json()["roles"] == ["sysadmin"]
    assert principal_response.json()["permissions"] == [
        permission.value for permission in Permission
    ]
    assert devices_response.status_code == 200


def test_owned_client_and_granted_device_policies(
    authorization_context: tuple[TestClient, dict[str, object], Session],
) -> None:
    """Resource policies expose only explicit ownership and grants."""
    _, _, session = authorization_context
    principal = AuthenticatedPrincipal(
        issuer="https://login.example/tenant/v2.0",
        subject="device-user-subject",
        roles=("device_user",),
        permissions=frozenset(),
    )

    client = authorize_owned_client(principal, "owned-laptop", session)
    device = authorize_granted_device(principal, 1, session)

    assert client.name == "owned-laptop"
    assert device.name == "granted-edge"

    with pytest.raises(HTTPException) as client_error:
        authorize_owned_client(principal, "unowned-laptop", session)
    with pytest.raises(HTTPException) as device_error:
        authorize_granted_device(principal, 2, session)

    assert client_error.value.status_code == 403
    assert device_error.value.status_code == 403


def test_validate_token_does_not_require_admin_role() -> None:
    """Signature and identity validation are independent of authorization."""
    request = MagicMock()
    request.headers.get.return_value = "Bearer signed-token"
    keys = MagicMock()
    keys.read.return_value = (
        b'{"keys":[{"kid":"key-1","kty":"RSA","use":"sig","n":"n","e":"AQAB"}]}'
    )

    with (
        patch(
            "sciaiot.ovpncp.middlewares.azure_security.TENANT_ID",
            "tenant",
        ),
        patch(
            "sciaiot.ovpncp.middlewares.azure_security.APP_CLIENT_ID",
            "client",
        ),
        patch(
            "sciaiot.ovpncp.middlewares.azure_security.APP_ROLE",
            "ControlPlane.Admin",
        ),
        patch(
            "sciaiot.ovpncp.middlewares.azure_security.urlopen",
            return_value=keys,
        ),
        patch(
            ("sciaiot.ovpncp.middlewares.azure_security.jwt.get_unverified_header"),
            return_value={"kid": "key-1"},
        ),
        patch(
            "sciaiot.ovpncp.middlewares.azure_security.jwt.decode",
            return_value={
                "iss": "https://login.microsoftonline.com/tenant/v2.0",
                "sub": "device-user-subject",
                "roles": ["Device.User"],
            },
        ),
    ):
        claims = validate_token(request)

    assert claims["sub"] == "device-user-subject"
