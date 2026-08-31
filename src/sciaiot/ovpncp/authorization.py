"""Authentication principal normalization and authorization policies."""

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Any, cast

from fastapi import Depends, HTTPException, Request, status
from fastapi.routing import APIRoute
from sqlmodel import Session, col, select

from sciaiot.ovpncp.data.identity import AccessGrant, Device, User, UserClient
from sciaiot.ovpncp.data.server import Client
from sciaiot.ovpncp.middlewares import azure_security


class Permission(StrEnum):
    """Authoritative permissions enforced by FastAPI management routes."""

    DEVICES_READ = "devices:read"
    DEVICES_WRITE = "devices:write"
    USERS_READ = "users:read"
    USERS_WRITE = "users:write"
    CLIENTS_READ = "clients:read"
    CLIENTS_WRITE = "clients:write"
    ACCESS_READ = "access:read"
    ACCESS_GRANT = "access:grant"
    SERVER_READ = "server:read"
    SERVER_WRITE = "server:write"


SYSADMIN_PERMISSIONS = tuple(Permission)


class PermissionRoute(APIRoute):
    """Document required permissions from the enforcing dependency."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize a route and publish its enforced policy in OpenAPI."""
        super().__init__(*args, **kwargs)
        for dependency in self.dependant.dependencies:
            permission = getattr(
                dependency.call,
                "required_permission",
                None,
            )
            if not isinstance(permission, str):
                continue
            extra = dict(self.openapi_extra or {})
            if getattr(dependency.call, "allows_local_hook", False):
                extra["x-local-hook-or-permission"] = permission
            else:
                extra["x-required-permission"] = permission
            self.openapi_extra = extra
            break


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    """Canonical application principal derived only from verified claims."""

    issuer: str
    subject: str
    roles: tuple[str, ...]
    permissions: frozenset[Permission]


def get_authenticated_principal(request: Request) -> AuthenticatedPrincipal:
    """Normalize middleware-validated claims into an application principal.

    Args:
        request: Current FastAPI request containing verified token claims.

    Returns:
        A canonical principal with application roles and permissions.

    Raises:
        HTTPException: If authentication state or authorization configuration
            is missing or invalid.
    """
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

    role_config = {
        "device_user": azure_security.USER_ROLE,
        "sysadmin": azure_security.ADMIN_ROLE,
        "service_admin": azure_security.SERVICE_ADMIN_ROLE,
    }
    configured_roles = tuple(role_config.values())
    if not all(
        isinstance(role, str) and bool(role) and role == role.strip()
        for role in configured_roles
    ) or len(set(configured_roles)) != len(configured_roles):
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Authorization service is misconfigured.",
        )

    token_roles = payload.get("roles")
    if (
        not isinstance(token_roles, list)
        or len(token_roles) != 1
        or not isinstance(token_roles[0], str)
        or token_roles[0] not in configured_roles
    ):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "The token has no recognized application role.",
        )

    token_role = token_roles[0]
    canonical_role = next(
        name for name, configured in role_config.items() if configured == token_role
    )
    object_id = payload.get("oid")
    is_app_only = (
        isinstance(object_id, str) and bool(object_id) and object_id == subject
    )
    has_human_object_id = (
        isinstance(object_id, str) and bool(object_id) and object_id != subject
    )
    if canonical_role == "service_admin":
        if not is_app_only or payload.get("scp") is not None:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "The token is not valid for app-only access.",
            )
        roles = (canonical_role,)
        permissions = frozenset(SYSADMIN_PERMISSIONS)
    else:
        token_scope = payload.get("scp")
        scopes = token_scope.split() if isinstance(token_scope, str) else []
        if not has_human_object_id or azure_security.DELEGATED_SCOPE not in scopes:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "The token is not valid for delegated access.",
            )
        roles = (canonical_role,)
        permissions = (
            frozenset(SYSADMIN_PERMISSIONS)
            if canonical_role == "sysadmin"
            else frozenset()
        )

    return AuthenticatedPrincipal(
        issuer=issuer,
        subject=subject,
        roles=roles,
        permissions=permissions,
    )


PrincipalDependency = Annotated[
    AuthenticatedPrincipal,
    Depends(get_authenticated_principal),
]


def require_permission(
    permission: Permission,
) -> Callable[[PrincipalDependency], AuthenticatedPrincipal]:
    """Create a dependency that enforces one explicit application permission.

    Args:
        permission: Permission required by the management operation.

    Returns:
        A FastAPI dependency returning the authorized principal.

    Raises:
        HTTPException: The returned dependency raises 403 when permission is
            absent.
    """

    def authorize(
        principal: PrincipalDependency,
    ) -> AuthenticatedPrincipal:
        if permission not in principal.permissions:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "The current principal lacks the required permission.",
            )
        return principal

    authorize.__name__ = f"require_{permission.value.replace(':', '_')}"
    metadata_target = cast(Any, authorize)
    metadata_target.required_permission = permission.value
    return authorize


RequireDevicesRead = Annotated[
    AuthenticatedPrincipal,
    Depends(require_permission(Permission.DEVICES_READ)),
]
RequireDevicesWrite = Annotated[
    AuthenticatedPrincipal,
    Depends(require_permission(Permission.DEVICES_WRITE)),
]
RequireUsersRead = Annotated[
    AuthenticatedPrincipal,
    Depends(require_permission(Permission.USERS_READ)),
]
RequireUsersWrite = Annotated[
    AuthenticatedPrincipal,
    Depends(require_permission(Permission.USERS_WRITE)),
]
RequireClientsRead = Annotated[
    AuthenticatedPrincipal,
    Depends(require_permission(Permission.CLIENTS_READ)),
]
RequireClientsWrite = Annotated[
    AuthenticatedPrincipal,
    Depends(require_permission(Permission.CLIENTS_WRITE)),
]
RequireAccessRead = Annotated[
    AuthenticatedPrincipal,
    Depends(require_permission(Permission.ACCESS_READ)),
]
RequireAccessGrant = Annotated[
    AuthenticatedPrincipal,
    Depends(require_permission(Permission.ACCESS_GRANT)),
]
RequireServerRead = Annotated[
    AuthenticatedPrincipal,
    Depends(require_permission(Permission.SERVER_READ)),
]
RequireServerWrite = Annotated[
    AuthenticatedPrincipal,
    Depends(require_permission(Permission.SERVER_WRITE)),
]


def require_connection_hook_access(
    request: Request,
) -> AuthenticatedPrincipal | None:
    """Allow an exact local hook request or require client-write permission.

    Args:
        request: Current request with middleware authentication state.

    Returns:
        None for an authenticated local OpenVPN hook, otherwise the authorized
        administrative principal.

    Raises:
        HTTPException: If a remote caller lacks client-write permission.
    """
    if getattr(request.state, "local_connection_hook", False) is True:
        return None

    principal = get_authenticated_principal(request)
    if Permission.CLIENTS_WRITE not in principal.permissions:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "The current principal lacks the required permission.",
        )
    return principal


connection_metadata = cast(Any, require_connection_hook_access)
connection_metadata.required_permission = Permission.CLIENTS_WRITE.value
connection_metadata.allows_local_hook = True

RequireConnectionHookAccess = Annotated[
    AuthenticatedPrincipal | None,
    Depends(require_connection_hook_access),
]


def _local_user(
    principal: AuthenticatedPrincipal,
    session: Session,
) -> User:
    """Resolve a principal to a local user without exposing identity values."""
    statement = select(User).where(
        User.issuer == principal.issuer,
        User.subject == principal.subject,
    )
    user = session.exec(statement).one_or_none()
    if user is None or user.id is None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "The current principal is not authorized for this resource.",
        )
    return user


def list_owned_clients(
    principal: AuthenticatedPrincipal,
    session: Session,
) -> list[Client]:
    """Return only VPN clients assigned to the current principal.

    Args:
        principal: Canonical authenticated application principal.
        session: Active persistence session.

    Returns:
        The principal-owned VPN clients in stable identifier order.
    """
    user = _local_user(principal, session)
    statement = (
        select(Client)
        .join(UserClient)
        .where(UserClient.user_id == user.id)
        .order_by(col(Client.id))
    )
    return list(session.exec(statement).all())


def list_granted_devices(
    principal: AuthenticatedPrincipal,
    session: Session,
) -> list[Device]:
    """Return only devices explicitly granted to the current principal.

    Args:
        principal: Canonical authenticated application principal.
        session: Active persistence session.

    Returns:
        The granted devices in stable identifier order.
    """
    user = _local_user(principal, session)
    statement = (
        select(Device)
        .join(AccessGrant)
        .where(AccessGrant.user_id == user.id)
        .order_by(col(Device.id))
    )
    return list(session.exec(statement).all())


def authorize_owned_client(
    principal: AuthenticatedPrincipal,
    client_name: str,
    session: Session,
) -> Client:
    """Return a VPN client only when it is owned by the principal.

    Args:
        principal: Canonical authenticated application principal.
        client_name: Stable OpenVPN client name requested by the caller.
        session: Active persistence session.

    Returns:
        The client assigned to the principal.

    Raises:
        HTTPException: If the local identity does not own the client.
    """
    user = _local_user(principal, session)
    client = session.exec(
        select(Client).where(Client.name == client_name)
    ).one_or_none()
    if client is None or client.id is None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "The current principal is not authorized for this resource.",
        )

    assignment = session.exec(
        select(UserClient).where(
            UserClient.user_id == user.id,
            UserClient.client_id == client.id,
        )
    ).one_or_none()
    if assignment is None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "The current principal is not authorized for this resource.",
        )
    return client


def authorize_granted_device(
    principal: AuthenticatedPrincipal,
    device_id: int,
    session: Session,
) -> Device:
    """Return a device only when the principal has an explicit access grant.

    Args:
        principal: Canonical authenticated application principal.
        device_id: Stable device identifier requested by the caller.
        session: Active persistence session.

    Returns:
        The explicitly granted device.

    Raises:
        HTTPException: If the local identity lacks the device grant.
    """
    user = _local_user(principal, session)
    grant = session.exec(
        select(AccessGrant).where(
            AccessGrant.user_id == user.id,
            AccessGrant.device_id == device_id,
        )
    ).one_or_none()
    if grant is None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "The current principal is not authorized for this resource.",
        )

    device = session.get(Device, device_id)
    if device is None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "The current principal is not authorized for this resource.",
        )
    return device
