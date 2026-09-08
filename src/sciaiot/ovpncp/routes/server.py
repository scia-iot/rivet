import ipaddress
import logging
from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlmodel import Session, select

from sciaiot.ovpncp import dependencies
from sciaiot.ovpncp.authorization import (
    PermissionRoute,
    RequireServerRead,
    RequireServerWrite,
)
from sciaiot.ovpncp.data.server import (
    Server,
    ServerWithVirtualAddresses,
    VirtualAddress,
)
from sciaiot.ovpncp.dependencies import get_session
from sciaiot.ovpncp.services.client_config import (
    ClientConfigGenerationError,
    normalize_remote_host,
    render_client_config,
    replace_client_config,
)
from sciaiot.ovpncp.utils import iproute, openvpn
from sciaiot.ovpncp.utils.network import is_rfc1918_ipv4_network

logger = logging.getLogger(__name__)
DBSession = Annotated[Session, Depends(get_session)]
router = APIRouter(route_class=PermissionRoute)


class RouteRequest(BaseModel):
    network: str


class ServerInitializationRequest(BaseModel):
    """Explicit reachable endpoint required for client profile generation."""

    remote_host: str

    @field_validator("remote_host")
    @classmethod
    def validate_remote_host(cls, value: str) -> str:
        """Reject values that cannot be emitted as one OpenVPN argument."""
        return normalize_remote_host(value)


class ServiceHealth(BaseModel):
    """Current state reported by the OpenVPN service manager."""

    status: str
    time: str | None = None
    period: str | None = None


@router.post("", response_model=ServerWithVirtualAddresses)
async def init_server(
    request: ServerInitializationRequest,
    session: DBSession,
    _principal: RequireServerWrite,
):
    """Initialize server records and the downloadable shared profile."""
    logger.info("Initializing the server and shared client profile...")
    if session.exec(select(Server)).first() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "The server is already initialized. Regenerate the shared "
                "client configuration instead."
            ),
        )

    replacement = None
    try:
        server_config = openvpn.get_server_config()
        content = render_client_config(server_config, request.remote_host)
        server = load_from_config(server_config.copy())
        replacement = replace_client_config(
            dependencies.client_config_path,
            content,
        )
        session.add(server)
        session.flush()
        session.refresh(server)
        session.commit()
    except Exception as error:
        session.rollback()
        if replacement is not None:
            try:
                replacement.rollback()
            except ClientConfigGenerationError:
                logger.error("Shared client profile rollback failed.")
        logger.error("Server and shared client profile initialization failed.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "The server and shared client configuration could not be "
                "initialized. Check the host OpenVPN configuration and "
                "profile path, then retry."
            ),
        ) from error

    try:
        replacement.commit()
    except OSError:
        logger.warning("A previous shared client profile backup remains.")
    logger.info("Server and shared client profile initialized successfully!")
    return server


@router.put("/client-config", status_code=status.HTTP_204_NO_CONTENT)
async def regenerate_client_config(
    request: ServerInitializationRequest,
    session: DBSession,
    _principal: RequireServerWrite,
) -> None:
    """Regenerate the shared profile for an initialized deployment."""
    get_server_record(session)
    try:
        server_config = openvpn.get_server_config()
        content = render_client_config(server_config, request.remote_host)
        replacement = replace_client_config(
            dependencies.client_config_path,
            content,
        )
    except Exception as error:
        logger.error("Shared client profile regeneration failed.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "The shared OpenVPN client configuration could not be "
                "generated. Check the host OpenVPN configuration and "
                "profile path, then retry."
            ),
        ) from error

    try:
        replacement.commit()
    except OSError:
        logger.warning("A previous shared client profile backup remains.")


def get_server_record(session: Session) -> Server:
    """Load the initialized server for authorized route operations."""
    logger.info("Getting the server...")
    server = session.exec(select(Server)).one_or_none()

    if not server:
        logger.error("Server not initialized yet!")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Server not found!",
        )

    logger.info("Server retrieved successfully!")
    return server


@router.get("", response_model=ServerWithVirtualAddresses)
async def get_server(
    session: DBSession,
    _principal: RequireServerRead,
):
    """Retrieve the initialized OpenVPN server configuration."""
    return get_server_record(session)


@router.get("/health", response_model=ServiceHealth)
async def get_service_health(_principal: RequireServerRead):
    logger.info("Checking the service health...")
    try:
        service_health = openvpn.get_status()
    except Exception as error:
        logger.error("OpenVPN service health check failed.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "OpenVPN health could not be loaded. Check the host service and retry."
            ),
        ) from error
    logger.info("Service health checked successfully!")
    return service_health


@router.get("/assignable-virtual-addresses", response_model=list[VirtualAddress])
async def get_assignable_virtual_addresses(
    session: DBSession,
    _principal: RequireServerRead,
):
    logger.info("Getting the assignable virtual addresses...")
    statement = select(VirtualAddress).where(VirtualAddress.client == None)
    addresses = session.exec(statement).all()
    logger.info(f"Found {len(addresses)} assignable virtual addresses.")
    return addresses


@router.get("/routes", response_model=list[str])
async def get_routes(
    session: DBSession,
    _principal: RequireServerRead,
):
    logger.info("Getting the routes...")
    server = get_server_record(session)
    try:
        routes = iproute.list(server.dev)
    except Exception as error:
        logger.error("Server routes could not be loaded.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "Server routes could not be loaded. Check the host route "
                "service and retry."
            ),
        ) from error
    logger.info(f"Found {len(routes)} routes.")
    return routes


@router.post("/routes", status_code=status.HTTP_204_NO_CONTENT)
async def add_route(
    request: RouteRequest,
    session: DBSession,
    _principal: RequireServerWrite,
):
    logger.info("Adding a route...")
    if not is_rfc1918_ipv4_network(request.network, require_cidr=True):
        logger.error("Invalid network address used for a server route.")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only internal network address is allowed!",
        )

    server = get_server_record(session)
    try:
        iproute.add(request.network, server.ip, server.dev)
    except Exception as error:
        logger.error("Server route addition failed.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "The server route could not be added. Check the host route "
                "service and retry."
            ),
        ) from error
    logger.info("Route added successfully!")


@router.delete("/routes", status_code=status.HTTP_204_NO_CONTENT)
async def delete_route(
    network: str,
    session: DBSession,
    _principal: RequireServerWrite,
):
    logger.info("Deleting a route...")
    if not is_rfc1918_ipv4_network(network, require_cidr=True):
        logger.error("Invalid network address used for route deletion.")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only internal network address is allowed!",
        )

    server = get_server_record(session)
    try:
        routes = iproute.list(server.dev)
    except Exception as error:
        logger.error("Server routes could not be loaded for deletion.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "The server route could not be removed. Check the host route "
                "service and retry."
            ),
        ) from error

    target = next(
        (route for route in routes if route.split(maxsplit=1)[0] == network),
        None,
    )
    if target is None:
        logger.error("Requested server route was not found.")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="The requested server route was not found.",
        )

    try:
        iproute.delete(target, server.dev)
    except Exception as error:
        logger.error("Server route removal failed.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "The server route could not be removed. Check the host route "
                "service and retry."
            ),
        ) from error
    logger.info("Route deleted successfully!")


def load_from_config(
    config: dict[str, object] | None = None,
) -> Server:
    """Build a persisted server model from parsed OpenVPN options."""
    if config is None:
        config = openvpn.get_server_config()

    server_network = config.get("server")
    device = config.get("dev")
    if not isinstance(server_network, str) or not isinstance(device, str):
        raise TypeError("OpenVPN server network or device is invalid.")

    network_address, subnet_mask = server_network.split()
    network = ipaddress.ip_network(f"{network_address}/{subnet_mask}", strict=False)
    hosts = list(network.hosts())

    config["network_address"] = network_address
    config["subnet_mask"] = subnet_mask
    config["ip"] = hosts.pop(0).compressed
    config["dev"] = f"{device}0"

    server = Server(**cast(dict[str, Any], config))
    server.virtual_addresses = [
        VirtualAddress(ip=h.compressed, server=server) for h in hosts
    ]

    return server
