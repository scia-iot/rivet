"""API routes for users, devices, and individual access grants."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlmodel import Session

from sciaiot.ovpncp import dependencies
from sciaiot.ovpncp.authorization import (
    Permission,
    PermissionRoute,
    PrincipalDependency,
    RequireAccessGrant,
    RequireAccessRead,
    RequireDevicesRead,
    RequireDevicesWrite,
    RequireUsersRead,
    RequireUsersWrite,
    authorize_granted_device,
    authorize_owned_client,
    list_granted_devices,
    list_owned_clients,
)
from sciaiot.ovpncp.data.identity import (
    AccessGrant,
    CurrentPrincipal,
    CurrentUserClient,
    Device,
    DeviceBase,
    DeviceUpdate,
    User,
    UserBase,
    UserClient,
    UserUpdate,
)
from sciaiot.ovpncp.data.server import Client
from sciaiot.ovpncp.dependencies import get_session
from sciaiot.ovpncp.middlewares import azure_security
from sciaiot.ovpncp.services.certificates import (
    CertificateArchiveError,
    CertificateArchiveService,
)
from sciaiot.ovpncp.services.client_config import (
    CLIENT_CONFIG_MEDIA_TYPE,
    ClientConfigNotFoundError,
    ClientConfigReadError,
    client_config_response,
)
from sciaiot.ovpncp.services.identity import (
    AccessService,
    DeviceService,
    EntityConflictError,
    EntityNotFoundError,
    IdentityRegistrationError,
    UserClientService,
    UserService,
)

DBSession = Annotated[Session, Depends(get_session)]
device_router = APIRouter(route_class=PermissionRoute)
user_router = APIRouter(route_class=PermissionRoute)
principal_router = APIRouter(route_class=PermissionRoute)


@principal_router.get("/me", response_model=CurrentPrincipal)
def retrieve_current_principal(
    principal: PrincipalDependency,
    session: DBSession,
) -> CurrentPrincipal:
    """Resolve the authenticated external identity to its local principal."""
    try:
        auto_register = azure_security.auto_register_users_enabled()
    except ValueError as configuration_error:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Automatic user registration is misconfigured.",
        ) from configuration_error

    user_service = UserService(session)
    try:
        user = user_service.get_by_external_identity(
            principal.issuer,
            principal.subject,
        )
    except EntityNotFoundError as error:
        if principal.roles == ("service_admin",) or not auto_register:
            raise HTTPException(status.HTTP_403_FORBIDDEN, str(error)) from error
        try:
            user = user_service.get_or_create_external_identity(
                UserBase(
                    display_name=principal.registration_display_name,
                    issuer=principal.issuer,
                    subject=principal.subject,
                )
            )
        except IdentityRegistrationError as registration_error:
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                "Automatic user registration failed.",
            ) from registration_error

    if user.id is None:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "The local identity record is invalid.",
        )
    return CurrentPrincipal(
        id=user.id,
        display_name=user.display_name,
        issuer=user.issuer,
        subject=user.subject,
        roles=list(principal.roles),
        permissions=[
            permission.value
            for permission in Permission
            if permission in principal.permissions
        ],
    )


def _portal_certificate_failure(error: Exception) -> HTTPException:
    """Return a fixed credential failure without exposing internals."""
    return HTTPException(
        status.HTTP_500_INTERNAL_SERVER_ERROR,
        "The certificate operation failed.",
    )


def _require_active_credentials(client: Client) -> None:
    """Reject revoked owned credentials before any archive operation."""
    if client.revoked:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Credentials are unavailable for this client.",
        )


@principal_router.get(
    "/me/client-config",
    response_class=Response,
    responses={
        200: {
            "content": {
                CLIENT_CONFIG_MEDIA_TYPE: {
                    "schema": {
                        "type": "string",
                        "format": "binary",
                    }
                }
            },
            "description": "Deployment-managed shared OpenVPN client profile.",
        }
    },
    openapi_extra={"x-authenticated-principal": True},
)
def download_shared_client_config(
    _principal: PrincipalDependency,
) -> Response:
    """Download the same deployment-managed profile for any valid principal.

    Returns:
        A no-store OpenVPN profile attachment.

    Raises:
        HTTPException: If the configured profile is missing or unreadable.
    """
    try:
        return client_config_response(dependencies.client_config_path)
    except ClientConfigNotFoundError as error:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "The shared OpenVPN client configuration is not available. "
            "Ask an administrator to configure it.",
        ) from error
    except ClientConfigReadError as error:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "The shared OpenVPN client configuration could not be read. "
            "Check the deployment configuration and file permissions.",
        ) from error


@principal_router.get(
    "/me/clients",
    response_model=list[CurrentUserClient],
    openapi_extra={"x-current-user-resource": "owned-client"},
)
def retrieve_current_clients(
    principal: PrincipalDependency,
    session: DBSession,
) -> list[CurrentUserClient]:
    """List minimal VPN client summaries owned by the principal."""
    return [
        CurrentUserClient(
            id=client.id,
            name=client.name,
            revoked=client.revoked,
        )
        for client in list_owned_clients(principal, session)
    ]


@principal_router.get(
    "/me/devices",
    response_model=list[Device],
    openapi_extra={"x-current-user-resource": "granted-device"},
)
def retrieve_current_devices(
    principal: PrincipalDependency,
    session: DBSession,
) -> list[Device]:
    """List devices explicitly granted to the authenticated principal."""
    return list_granted_devices(principal, session)


@principal_router.get(
    "/me/devices/{device_id}",
    response_model=Device,
    openapi_extra={"x-current-user-resource": "granted-device"},
)
def retrieve_current_device(
    device_id: int,
    principal: PrincipalDependency,
    session: DBSession,
) -> Device:
    """Retrieve one device explicitly granted to the principal."""
    return authorize_granted_device(principal, device_id, session)


@principal_router.put(
    "/me/clients/{client_name}/package-cert",
    status_code=status.HTTP_204_NO_CONTENT,
    openapi_extra={"x-current-user-resource": "owned-client"},
)
def package_current_client_certificate(
    client_name: str,
    principal: PrincipalDependency,
    session: DBSession,
) -> None:
    """Package credentials only for a client owned by the principal."""
    client = authorize_owned_client(principal, client_name, session)
    _require_active_credentials(client)
    try:
        CertificateArchiveService(dependencies.certs_directory).package(client)
    except CertificateArchiveError as error:
        raise _portal_certificate_failure(error) from error


@principal_router.get(
    "/me/clients/{client_name}/download-cert",
    response_class=Response,
    responses={
        200: {
            "content": {
                "application/zip": {
                    "schema": {
                        "type": "string",
                        "format": "binary",
                    }
                }
            },
            "description": "Owned client certificate archive.",
        }
    },
    openapi_extra={"x-current-user-resource": "owned-client"},
)
def download_current_client_certificate(
    client_name: str,
    request: Request,
    principal: PrincipalDependency,
    session: DBSession,
) -> Response:
    """Download credentials only for a client owned by the principal."""
    client = authorize_owned_client(principal, client_name, session)
    _require_active_credentials(client)
    try:
        return CertificateArchiveService(
            dependencies.certs_directory
        ).download_response(
            client,
            from_cloud_storage=getattr(
                request.state,
                "certificate_download_from_azure",
                False,
            ),
        )
    except CertificateArchiveError as error:
        raise _portal_certificate_failure(error) from error


def _handle_domain_error(error: Exception) -> HTTPException:
    """Translate a business error into the matching HTTP response."""
    if isinstance(error, EntityConflictError):
        return HTTPException(status.HTTP_409_CONFLICT, str(error))
    return HTTPException(status.HTTP_404_NOT_FOUND, str(error))


@device_router.post("", response_model=Device, status_code=status.HTTP_201_CREATED)
def create_device(
    request: DeviceBase,
    session: DBSession,
    _principal: RequireDevicesWrite,
) -> Device:
    """Register a stable device identity."""
    try:
        return DeviceService(session).create(request)
    except (EntityNotFoundError, EntityConflictError) as error:
        raise _handle_domain_error(error) from error


@device_router.get("", response_model=list[Device])
def retrieve_devices(
    session: DBSession,
    _principal: RequireDevicesRead,
) -> list[Device]:
    """List all registered devices."""
    return DeviceService(session).list()


@device_router.get("/{device_id}", response_model=Device)
def retrieve_device(
    device_id: int,
    session: DBSession,
    _principal: RequireDevicesRead,
) -> Device:
    """Retrieve one registered device."""
    try:
        return DeviceService(session).get(device_id)
    except EntityNotFoundError as error:
        raise _handle_domain_error(error) from error


@device_router.patch("/{device_id}", response_model=Device)
def update_device(
    device_id: int,
    request: DeviceUpdate,
    session: DBSession,
    _principal: RequireDevicesWrite,
) -> Device:
    """Update a device or replace its current VPN client link."""
    try:
        return DeviceService(session).update(device_id, request)
    except (EntityNotFoundError, EntityConflictError) as error:
        raise _handle_domain_error(error) from error


@device_router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_device(
    device_id: int,
    session: DBSession,
    _principal: RequireDevicesWrite,
) -> None:
    """Delete a device without deleting its VPN client."""
    try:
        DeviceService(session).delete(device_id)
    except EntityNotFoundError as error:
        raise _handle_domain_error(error) from error


@user_router.post("", response_model=User, status_code=status.HTTP_201_CREATED)
def create_user(
    request: UserBase,
    session: DBSession,
    _principal: RequireUsersWrite,
) -> User:
    """Create a user mapped to an external OAuth identity."""
    try:
        return UserService(session).create(request)
    except EntityConflictError as error:
        raise _handle_domain_error(error) from error


@user_router.get("", response_model=list[User])
def retrieve_users(
    session: DBSession,
    _principal: RequireUsersRead,
) -> list[User]:
    """List all local users."""
    return UserService(session).list()


@user_router.get("/{user_id}", response_model=User)
def retrieve_user(
    user_id: int,
    session: DBSession,
    _principal: RequireUsersRead,
) -> User:
    """Retrieve one local user."""
    try:
        return UserService(session).get(user_id)
    except EntityNotFoundError as error:
        raise _handle_domain_error(error) from error


@user_router.patch("/{user_id}", response_model=User)
def update_user(
    user_id: int,
    request: UserUpdate,
    session: DBSession,
    _principal: RequireUsersWrite,
) -> User:
    """Update a user's local display name."""
    try:
        return UserService(session).update(user_id, request)
    except EntityNotFoundError as error:
        raise _handle_domain_error(error) from error


@user_router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    session: DBSession,
    _principal: RequireUsersWrite,
) -> None:
    """Delete a user and their access grants."""
    try:
        UserService(session).delete(user_id)
    except EntityNotFoundError as error:
        raise _handle_domain_error(error) from error


@user_router.put(
    "/{user_id}/devices/{device_id}",
    response_model=AccessGrant,
)
def grant_device_access(
    user_id: int,
    device_id: int,
    session: DBSession,
    response: Response,
    _principal: RequireAccessGrant,
) -> AccessGrant:
    """Grant a user individual access to a device idempotently."""
    try:
        grant, created = AccessService(session).grant(user_id, device_id)
    except EntityNotFoundError as error:
        raise _handle_domain_error(error) from error
    if created:
        response.status_code = status.HTTP_201_CREATED
    return grant


@user_router.delete(
    "/{user_id}/devices/{device_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def revoke_device_access(
    user_id: int,
    device_id: int,
    session: DBSession,
    _principal: RequireAccessGrant,
) -> None:
    """Revoke a user's individual access to a device."""
    try:
        AccessService(session).revoke(user_id, device_id)
    except EntityNotFoundError as error:
        raise _handle_domain_error(error) from error


@user_router.get("/{user_id}/devices", response_model=list[Device])
def retrieve_user_devices(
    user_id: int,
    session: DBSession,
    _principal: RequireAccessRead,
) -> list[Device]:
    """List devices that a user may access."""
    try:
        return AccessService(session).list_devices(user_id)
    except EntityNotFoundError as error:
        raise _handle_domain_error(error) from error


@user_router.put(
    "/{user_id}/clients/{client_id}",
    response_model=UserClient,
)
def link_user_client(
    user_id: int,
    client_id: int,
    session: DBSession,
    response: Response,
    _principal: RequireUsersWrite,
) -> UserClient:
    """Assign a VPN client to a user as an administrative action."""
    try:
        assignment, created = UserClientService(session).link(user_id, client_id)
    except (EntityNotFoundError, EntityConflictError) as error:
        raise _handle_domain_error(error) from error
    if created:
        response.status_code = status.HTTP_201_CREATED
    return assignment


@user_router.delete(
    "/{user_id}/clients/{client_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def unlink_user_client(
    user_id: int,
    client_id: int,
    session: DBSession,
    _principal: RequireUsersWrite,
) -> None:
    """Remove a VPN client assignment as an administrative action."""
    try:
        UserClientService(session).unlink(user_id, client_id)
    except EntityNotFoundError as error:
        raise _handle_domain_error(error) from error


@user_router.get("/{user_id}/clients", response_model=list[Client])
def retrieve_user_clients(
    user_id: int,
    session: DBSession,
    _principal: RequireUsersRead,
) -> list[Client]:
    """List VPN clients administratively assigned to a user."""
    try:
        return UserClientService(session).list_clients(user_id)
    except EntityNotFoundError as error:
        raise _handle_domain_error(error) from error
