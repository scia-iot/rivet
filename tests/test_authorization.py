"""Authorization policy tests for trusted principals and management routes."""

from collections.abc import Generator
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from sciaiot.ovpncp import dependencies
from sciaiot.ovpncp.authorization import (
    AuthenticatedPrincipal,
    Permission,
    authorize_granted_device,
    authorize_owned_client,
    get_authenticated_principal,
)
from sciaiot.ovpncp.data.identity import AccessGrant, Device, User, UserClient
from sciaiot.ovpncp.data.server import Client
from sciaiot.ovpncp.dependencies import get_session
from sciaiot.ovpncp.main import app
from sciaiot.ovpncp.middlewares.azure_security import validate_token
from sciaiot.ovpncp.services.client_config import (
    MAX_CLIENT_CONFIG_BYTES,
    ClientConfigReadError,
    client_config_response,
)


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
        other_client = Client(name="other-laptop")
        granted_device = Device(name="granted-edge")
        ungranted_device = Device(name="other-edge")
        session.add_all(
            [
                admin,
                device_user,
                other_user,
                owned_client,
                other_client,
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
            other_client,
            granted_device,
            ungranted_device,
        ):
            session.refresh(entity)

        assert device_user.id is not None
        assert owned_client.id is not None
        assert granted_device.id is not None
        assert other_user.id is not None
        assert other_client.id is not None
        session.add(UserClient(user_id=device_user.id, client_id=owned_client.id))
        session.add(UserClient(user_id=other_user.id, client_id=other_client.id))
        session.add(AccessGrant(user_id=device_user.id, device_id=granted_device.id))
        session.commit()

        claims: dict[str, object] = {
            "iss": device_user.issuer,
            "sub": device_user.subject,
            "oid": "device-user-object-id",
            "roles": ["user"],
            "scp": "access_as_user",
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
            patch("sciaiot.ovpncp.middlewares.azure_security.USER_ROLE", "user"),
            patch("sciaiot.ovpncp.middlewares.azure_security.ADMIN_ROLE", "admin"),
            patch(
                "sciaiot.ovpncp.middlewares.azure_security.SERVICE_ADMIN_ROLE",
                "ServiceAdmin",
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
        ("DELETE", "/clients/owned-laptop", None),
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
    """A delegated admin role maps to the canonical sysadmin policy."""
    test_client, claims, _ = authorization_context
    claims["sub"] = "admin-subject"
    claims["roles"] = ["admin"]

    principal_response = test_client.get("/me")
    devices_response = test_client.get("/devices")

    assert principal_response.status_code == 200
    assert principal_response.json()["roles"] == ["sysadmin"]
    assert principal_response.json()["permissions"] == [
        permission.value for permission in Permission
    ]
    assert devices_response.status_code == 200


def test_sysadmin_reaches_revoked_only_client_delete_policy(
    authorization_context: tuple[TestClient, dict[str, object], Session],
) -> None:
    """A sysadmin is authorized and reaches the active-client conflict."""
    test_client, claims, _ = authorization_context
    claims["sub"] = "admin-subject"
    claims["roles"] = ["admin"]

    response = test_client.delete("/clients/other-laptop")

    assert response.status_code == 409
    assert response.json()["detail"] == (
        "Revoke the client certificate before deleting this VPN client."
    )


def test_service_admin_receives_authoritative_permissions(
    authorization_context: tuple[TestClient, dict[str, object], Session],
) -> None:
    """An app-only ServiceAdmin receives the full management policy."""
    test_client, claims, _ = authorization_context
    claims["sub"] = "business-platform-object-id"
    claims["oid"] = "business-platform-object-id"
    claims["roles"] = ["ServiceAdmin"]
    claims.pop("scp")

    devices_response = test_client.get("/devices")

    assert devices_response.status_code == 200
    principal = get_authenticated_principal(_principal_request(dict(claims)))

    assert principal.roles == ("service_admin",)
    assert principal.permissions == frozenset(Permission)


def _principal_request(claims: dict[str, object]) -> MagicMock:
    """Build a request carrying middleware-validated claims."""
    request = MagicMock()
    request.state.token_payload = claims
    return request


@pytest.mark.parametrize(
    "claims",
    [
        {
            "iss": "https://login.example/tenant/v2.0",
            "sub": "subject",
            "oid": "object-id",
            "roles": [],
            "scp": "access_as_user",
        },
        {
            "iss": "https://login.example/tenant/v2.0",
            "sub": "subject",
            "oid": "object-id",
            "roles": ["unknown"],
            "scp": "access_as_user",
        },
        {
            "iss": "https://login.example/tenant/v2.0",
            "sub": "subject",
            "oid": "object-id",
            "roles": ["user", "admin"],
            "scp": "access_as_user",
        },
        {
            "iss": "https://login.example/tenant/v2.0",
            "sub": "subject",
            "oid": "object-id",
            "roles": ["admin", "unknown"],
            "scp": "access_as_user",
        },
    ],
)
def test_missing_unknown_and_ambiguous_roles_fail_closed(
    claims: dict[str, object],
) -> None:
    """Only one explicitly configured app role can select a policy."""
    with (
        patch("sciaiot.ovpncp.middlewares.azure_security.USER_ROLE", "user"),
        patch("sciaiot.ovpncp.middlewares.azure_security.ADMIN_ROLE", "admin"),
        patch(
            "sciaiot.ovpncp.middlewares.azure_security.SERVICE_ADMIN_ROLE",
            "ServiceAdmin",
        ),
        pytest.raises(HTTPException) as error,
    ):
        get_authenticated_principal(_principal_request(claims))

    assert error.value.status_code == 403
    assert error.value.detail == "The token has no recognized application role."


@pytest.mark.parametrize(
    "claims",
    [
        {
            "iss": "https://login.example/tenant/v2.0",
            "sub": "subject",
            "oid": "object-id",
            "roles": ["user"],
        },
        {
            "iss": "https://login.example/tenant/v2.0",
            "sub": "subject",
            "oid": "object-id",
            "roles": ["admin"],
            "scp": "another_scope",
        },
        {
            "iss": "https://login.example/tenant/v2.0",
            "sub": "same-object-id",
            "oid": "same-object-id",
            "roles": ["user"],
            "scp": "access_as_user",
        },
        {
            "iss": "https://login.example/tenant/v2.0",
            "sub": "subject",
            "roles": ["user"],
            "scp": "access_as_user",
        },
        {
            "iss": "https://login.example/tenant/v2.0",
            "sub": "subject",
            "oid": 42,
            "roles": ["admin"],
            "scp": "access_as_user",
        },
    ],
)
def test_delegated_roles_require_user_token_and_access_scope(
    claims: dict[str, object],
) -> None:
    """Human roles cannot authorize app-only or unscoped tokens."""
    with (
        patch("sciaiot.ovpncp.middlewares.azure_security.USER_ROLE", "user"),
        patch("sciaiot.ovpncp.middlewares.azure_security.ADMIN_ROLE", "admin"),
        patch(
            "sciaiot.ovpncp.middlewares.azure_security.SERVICE_ADMIN_ROLE",
            "ServiceAdmin",
        ),
        pytest.raises(HTTPException) as error,
    ):
        get_authenticated_principal(_principal_request(claims))

    assert error.value.status_code == 403
    assert error.value.detail == "The token is not valid for delegated access."


@pytest.mark.parametrize(
    "claims",
    [
        {
            "iss": "https://login.example/tenant/v2.0",
            "sub": "service-subject",
            "oid": "different-object-id",
            "roles": ["ServiceAdmin"],
        },
        {
            "iss": "https://login.example/tenant/v2.0",
            "sub": "service-object-id",
            "oid": "service-object-id",
            "roles": ["ServiceAdmin"],
            "scp": "access_as_user",
        },
    ],
)
def test_service_admin_requires_unscoped_app_only_token(
    claims: dict[str, object],
) -> None:
    """ServiceAdmin cannot authorize delegated or ambiguously scoped tokens."""
    with (
        patch("sciaiot.ovpncp.middlewares.azure_security.USER_ROLE", "user"),
        patch("sciaiot.ovpncp.middlewares.azure_security.ADMIN_ROLE", "admin"),
        patch(
            "sciaiot.ovpncp.middlewares.azure_security.SERVICE_ADMIN_ROLE",
            "ServiceAdmin",
        ),
        pytest.raises(HTTPException) as error,
    ):
        get_authenticated_principal(_principal_request(claims))

    assert error.value.status_code == 403
    assert error.value.detail == "The token is not valid for app-only access."


@pytest.mark.parametrize(
    ("user_role", "admin_role", "service_role"),
    [
        (None, "admin", "ServiceAdmin"),
        ("   ", "admin", "ServiceAdmin"),
        ("user", " admin ", "ServiceAdmin"),
        ("user", "user", "ServiceAdmin"),
    ],
)
def test_missing_or_duplicate_role_configuration_fails_closed(
    user_role: str | None,
    admin_role: str,
    service_role: str,
) -> None:
    """Role mappings must be present and mutually distinct."""
    claims: dict[str, object] = {
        "iss": "https://login.example/tenant/v2.0",
        "sub": "subject",
        "oid": "object-id",
        "roles": ["user"],
        "scp": "access_as_user",
    }
    with (
        patch("sciaiot.ovpncp.middlewares.azure_security.USER_ROLE", user_role),
        patch("sciaiot.ovpncp.middlewares.azure_security.ADMIN_ROLE", admin_role),
        patch(
            "sciaiot.ovpncp.middlewares.azure_security.SERVICE_ADMIN_ROLE",
            service_role,
        ),
        pytest.raises(HTTPException) as error,
    ):
        get_authenticated_principal(_principal_request(claims))

    assert error.value.status_code == 500
    assert error.value.detail == "Authorization service is misconfigured."


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


def test_validate_token_accepts_complete_role_configuration() -> None:
    """Signature validation accepts explicit authorization configuration."""
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
        patch("sciaiot.ovpncp.middlewares.azure_security.USER_ROLE", "user"),
        patch("sciaiot.ovpncp.middlewares.azure_security.ADMIN_ROLE", "admin"),
        patch(
            "sciaiot.ovpncp.middlewares.azure_security.SERVICE_ADMIN_ROLE",
            "ServiceAdmin",
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
                "roles": ["user"],
            },
        ),
    ):
        claims = validate_token(request)

    assert claims["sub"] == "device-user-subject"


def test_current_user_portal_lists_only_owned_and_granted_resources(
    authorization_context: tuple[TestClient, dict[str, object], Session],
) -> None:
    """Portal collections derive identity and exclude other users data."""
    test_client, _, session = authorization_context
    owned_client = session.exec(
        select(Client).where(Client.name == "owned-laptop")
    ).one()

    clients_response = test_client.get("/me/clients?user_id=3")
    devices_response = test_client.get("/me/devices?user_id=3")

    assert clients_response.status_code == 200
    assert clients_response.json() == [
        {
            "id": owned_client.id,
            "name": "owned-laptop",
            "revoked": False,
        }
    ]
    assert devices_response.status_code == 200
    assert [item["name"] for item in devices_response.json()] == ["granted-edge"]


def test_current_user_device_detail_does_not_enumerate_resources(
    authorization_context: tuple[TestClient, dict[str, object], Session],
) -> None:
    """Existing and missing ungranted devices return the same denial."""
    test_client, _, session = authorization_context
    granted = session.exec(select(Device).where(Device.name == "granted-edge")).one()
    ungranted = session.exec(select(Device).where(Device.name == "other-edge")).one()
    assert granted.id is not None
    assert ungranted.id is not None

    allowed = test_client.get(f"/me/devices/{granted.id}")
    existing_denial = test_client.get(f"/me/devices/{ungranted.id}")
    missing_denial = test_client.get("/me/devices/99999")

    assert allowed.status_code == 200
    assert allowed.json()["name"] == "granted-edge"
    for denial in (existing_denial, missing_denial):
        assert denial.status_code == 403
        assert denial.json()["detail"] == (
            "The current principal is not authorized for this resource."
        )


def test_current_user_can_package_and_download_only_owned_credentials(
    authorization_context: tuple[TestClient, dict[str, object], Session],
) -> None:
    """Credential routes apply ownership before archive operations."""
    test_client, _, _ = authorization_context
    archive = b"owned certificate archive"

    with (
        patch("sciaiot.ovpncp.utils.openvpn.package_client_cert") as package,
        patch(
            "builtins.open",
            mock_open(read_data=archive),
            create=True,
        ),
    ):
        packaged = test_client.put("/me/clients/owned-laptop/package-cert?user_id=3")
        downloaded = test_client.get("/me/clients/owned-laptop/download-cert?user_id=3")
        package_denial = test_client.put("/me/clients/other-laptop/package-cert")
        existing_denial = test_client.get("/me/clients/other-laptop/download-cert")
        missing_denial = test_client.get("/me/clients/missing-laptop/download-cert")

    assert packaged.status_code == 204
    package.assert_called_once_with(
        "owned-laptop",
        dependencies.certs_directory,
    )
    assert downloaded.status_code == 200
    assert downloaded.content == archive
    assert downloaded.headers["cache-control"] == "no-store"
    assert downloaded.headers["content-disposition"] == (
        'attachment; filename="owned-laptop.zip"'
    )
    for denial in (package_denial, existing_denial, missing_denial):
        assert denial.status_code == 403
        assert denial.json()["detail"] == (
            "The current principal is not authorized for this resource."
        )


@pytest.mark.parametrize(
    ("role", "subject", "object_id", "scope"),
    [
        ("user", "device-user-subject", "device-user-object-id", "access_as_user"),
        ("admin", "admin-subject", "admin-object-id", "access_as_user"),
        (
            "ServiceAdmin",
            "service-principal-object-id",
            "service-principal-object-id",
            None,
        ),
    ],
)
def test_authenticated_roles_download_the_same_shared_client_config(
    authorization_context: tuple[TestClient, dict[str, object], Session],
    tmp_path: Path,
    role: str,
    subject: str,
    object_id: str,
    scope: str | None,
) -> None:
    """Every recognized role receives one deployment-managed profile."""
    test_client, claims, _ = authorization_context
    profile = b"client\nremote vpn.example.test 1194\n"
    profile_path = tmp_path / "shared.ovpn"
    profile_path.write_bytes(profile)
    claims.update({"roles": [role], "sub": subject, "oid": object_id})
    if scope is None:
        claims.pop("scp", None)
    else:
        claims["scp"] = scope

    with patch.object(dependencies, "client_config_path", str(profile_path)):
        response = test_client.get("/me/client-config")

    assert response.status_code == 200
    assert response.content == profile
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-disposition"] == (
        'attachment; filename="ovpncp-client.ovpn"'
    )


@pytest.mark.parametrize(
    ("target_kind", "expected_status", "expected_detail"),
    [
        (
            "missing",
            404,
            (
                "The shared OpenVPN client configuration is not available. "
                "Ask an administrator to configure it."
            ),
        ),
        (
            "unreadable",
            500,
            (
                "The shared OpenVPN client configuration could not be read. "
                "Check the deployment configuration and file permissions."
            ),
        ),
    ],
)
def test_shared_client_config_failures_are_fixed_and_path_safe(
    authorization_context: tuple[TestClient, dict[str, object], Session],
    tmp_path: Path,
    target_kind: str,
    expected_status: int,
    expected_detail: str,
) -> None:
    """Missing and unreadable profiles disclose no deployment paths."""
    test_client, _, _ = authorization_context
    target = tmp_path / "private-profile.ovpn"
    if target_kind == "unreadable":
        target.mkdir()

    with patch.object(dependencies, "client_config_path", str(target)):
        response = test_client.get("/me/client-config")

    assert response.status_code == expected_status
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["detail"] == expected_detail
    assert str(target) not in response.text


@pytest.mark.parametrize(
    "content",
    [b"", b"x" * (MAX_CLIENT_CONFIG_BYTES + 1)],
)
def test_shared_client_config_rejects_empty_and_oversized_files(
    tmp_path: Path,
    content: bytes,
) -> None:
    """Invalid deployment artifacts fail before building a response."""
    target = tmp_path / "invalid.ovpn"
    target.write_bytes(content)

    with pytest.raises(ClientConfigReadError):
        client_config_response(str(target))


def test_shared_client_config_rejects_relative_deployment_path() -> None:
    """The deployment path cannot depend on the service working directory."""
    with pytest.raises(ClientConfigReadError):
        client_config_response("relative/client.ovpn")


def test_shared_client_config_route_never_returns_private_key_content(
    authorization_context: tuple[TestClient, dict[str, object], Session],
    tmp_path: Path,
) -> None:
    """A mistaken credential path fails closed instead of leaking its bytes."""
    test_client, _, _ = authorization_context
    target = tmp_path / "server-private.key"
    private_content = (
        b"client\nremote vpn.example.test 1194\n"
        b"-----BEGIN PRIVATE KEY-----\nsecret-material\n"
    )
    target.write_bytes(private_content)

    with patch.object(dependencies, "client_config_path", str(target)):
        response = test_client.get("/me/client-config")

    assert response.status_code == 500
    assert response.json()["detail"] == (
        "The shared OpenVPN client configuration could not be read. "
        "Check the deployment configuration and file permissions."
    )
    assert b"secret-material" not in response.content
    assert str(target) not in response.text


def test_revoked_current_user_credentials_fail_before_archive_work(
    authorization_context: tuple[TestClient, dict[str, object], Session],
) -> None:
    """Revoked credentials cannot invoke package, file, or Blob operations."""
    test_client, _, session = authorization_context
    user = session.exec(select(User).where(User.subject == "device-user-subject")).one()
    revoked_client = Client(name="revoked-laptop", revoked=True)
    session.add(revoked_client)
    session.commit()
    session.refresh(revoked_client)
    assert user.id is not None
    assert revoked_client.id is not None
    session.add(UserClient(user_id=user.id, client_id=revoked_client.id))
    session.commit()

    container = MagicMock()
    sensitive = "/private/revoked.zip?sig=secret-token"
    with (
        patch(
            "sciaiot.ovpncp.middlewares.azure_storage.STORAGE_CONNECTION_STRING",
            "configured",
        ),
        patch(
            "sciaiot.ovpncp.middlewares.azure_storage.container_client",
            container,
            create=True,
        ),
        patch("sciaiot.ovpncp.utils.openvpn.package_client_cert") as package,
        patch("builtins.open", side_effect=AssertionError(sensitive)) as opened,
    ):
        package_response = test_client.put("/me/clients/revoked-laptop/package-cert")
        download_response = test_client.get("/me/clients/revoked-laptop/download-cert")

    for response in (package_response, download_response):
        assert response.status_code == 409
        assert response.json()["detail"] == (
            "Credentials are unavailable for this client."
        )
        assert sensitive not in response.text
    package.assert_not_called()
    opened.assert_not_called()
    container.get_blob_client.assert_not_called()
