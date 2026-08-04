"""API routes for users, devices, and individual access grants."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlmodel import Session

from sciaiot.ovpncp.data.identity import (
    AccessGrant,
    CurrentPrincipal,
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
from sciaiot.ovpncp.services.identity import (
    AccessService,
    DeviceService,
    EntityConflictError,
    EntityNotFoundError,
    UserClientService,
    UserService,
)

DBSession = Annotated[Session, Depends(get_session)]
device_router = APIRouter()
user_router = APIRouter()
principal_router = APIRouter()

SYSADMIN_PERMISSIONS = (
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
)


def _validated_external_identity(request: Request) -> tuple[str, str]:
    """Read a stable identity only from middleware-validated token claims."""
    payload = getattr(request.state, "token_payload", None)
    if not isinstance(payload, dict):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "A validated authentication token is required.",
        )

    issuer = payload.get("iss")
    subject = payload.get("sub")
    if (
        not isinstance(issuer, str)
        or not issuer
        or not isinstance(subject, str)
        or not subject
    ):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "The validated token identity is incomplete.",
        )
    return issuer, subject


@principal_router.get("/me", response_model=CurrentPrincipal)
def retrieve_current_principal(
    request: Request, session: DBSession
) -> CurrentPrincipal:
    """Resolve the validated external identity to its local principal."""
    issuer, subject = _validated_external_identity(request)
    try:
        user = UserService(session).get_by_external_identity(issuer, subject)
    except EntityNotFoundError as error:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(error)) from error

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
        roles=["sysadmin"],
        permissions=list(SYSADMIN_PERMISSIONS),
    )


def _handle_domain_error(error: Exception) -> HTTPException:
    """Translate a business error into the matching HTTP response."""
    if isinstance(error, EntityConflictError):
        return HTTPException(status.HTTP_409_CONFLICT, str(error))
    return HTTPException(status.HTTP_404_NOT_FOUND, str(error))


@device_router.post("", response_model=Device, status_code=status.HTTP_201_CREATED)
def create_device(request: DeviceBase, session: DBSession) -> Device:
    """Register a stable device identity."""
    try:
        return DeviceService(session).create(request)
    except (EntityNotFoundError, EntityConflictError) as error:
        raise _handle_domain_error(error) from error


@device_router.get("", response_model=list[Device])
def retrieve_devices(session: DBSession) -> list[Device]:
    """List all registered devices."""
    return DeviceService(session).list()


@device_router.get("/{device_id}", response_model=Device)
def retrieve_device(device_id: int, session: DBSession) -> Device:
    """Retrieve one registered device."""
    try:
        return DeviceService(session).get(device_id)
    except EntityNotFoundError as error:
        raise _handle_domain_error(error) from error


@device_router.patch("/{device_id}", response_model=Device)
def update_device(device_id: int, request: DeviceUpdate, session: DBSession) -> Device:
    """Update a device or replace its current VPN client link."""
    try:
        return DeviceService(session).update(device_id, request)
    except (EntityNotFoundError, EntityConflictError) as error:
        raise _handle_domain_error(error) from error


@device_router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_device(device_id: int, session: DBSession) -> None:
    """Delete a device without deleting its VPN client."""
    try:
        DeviceService(session).delete(device_id)
    except EntityNotFoundError as error:
        raise _handle_domain_error(error) from error


@user_router.post("", response_model=User, status_code=status.HTTP_201_CREATED)
def create_user(request: UserBase, session: DBSession) -> User:
    """Create a user mapped to an external OAuth identity."""
    try:
        return UserService(session).create(request)
    except EntityConflictError as error:
        raise _handle_domain_error(error) from error


@user_router.get("", response_model=list[User])
def retrieve_users(session: DBSession) -> list[User]:
    """List all local users."""
    return UserService(session).list()


@user_router.get("/{user_id}", response_model=User)
def retrieve_user(user_id: int, session: DBSession) -> User:
    """Retrieve one local user."""
    try:
        return UserService(session).get(user_id)
    except EntityNotFoundError as error:
        raise _handle_domain_error(error) from error


@user_router.patch("/{user_id}", response_model=User)
def update_user(user_id: int, request: UserUpdate, session: DBSession) -> User:
    """Update a user's local display name."""
    try:
        return UserService(session).update(user_id, request)
    except EntityNotFoundError as error:
        raise _handle_domain_error(error) from error


@user_router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int, session: DBSession) -> None:
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
def revoke_device_access(user_id: int, device_id: int, session: DBSession) -> None:
    """Revoke a user's individual access to a device."""
    try:
        AccessService(session).revoke(user_id, device_id)
    except EntityNotFoundError as error:
        raise _handle_domain_error(error) from error


@user_router.get("/{user_id}/devices", response_model=list[Device])
def retrieve_user_devices(user_id: int, session: DBSession) -> list[Device]:
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
def unlink_user_client(user_id: int, client_id: int, session: DBSession) -> None:
    """Remove a VPN client assignment as an administrative action."""
    try:
        UserClientService(session).unlink(user_id, client_id)
    except EntityNotFoundError as error:
        raise _handle_domain_error(error) from error


@user_router.get("/{user_id}/clients", response_model=list[Client])
def retrieve_user_clients(user_id: int, session: DBSession) -> list[Client]:
    """List VPN clients administratively assigned to a user."""
    try:
        return UserClientService(session).list_clients(user_id)
    except EntityNotFoundError as error:
        raise _handle_domain_error(error) from error
