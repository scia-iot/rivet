import ipaddress
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlmodel import Session, select

from sciaiot.ovpncp.data.server import (
    Server,
    ServerWithVirtualAddresses,
    VirtualAddress,
)
from sciaiot.ovpncp.dependencies import get_session
from sciaiot.ovpncp.utils import iproute, openvpn
from sciaiot.ovpncp.utils.network import is_rfc1918_ipv4_network

logger = logging.getLogger(__name__)
DBSession = Annotated[Session, Depends(get_session)]
router = APIRouter()


class RouteRequest(BaseModel):
    network: str


class ServiceHealth(BaseModel):
    """Current state reported by the OpenVPN service manager."""

    status: str
    time: str | None = None
    period: str | None = None


@router.post("", response_model=ServerWithVirtualAddresses)
async def init_server(session: DBSession):
    logger.info("Initializing the server...")
    server = load_from_config()

    session.add(server)
    session.commit()
    session.refresh(server)

    logger.info("Server initialized successfully!")
    return server


@router.get("", response_model=ServerWithVirtualAddresses)
async def get_server(session: DBSession):
    logger.info("Getting the server...")
    server = session.exec(select(Server)).one_or_none()

    if not server:
        logger.error("Server not initialized yet!")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Server not found!"
        )

    logger.info("Server retrieved successfully!")
    return server


@router.get("/health", response_model=ServiceHealth)
async def get_service_health():
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
async def get_assignable_virtual_addresses(session: DBSession):
    logger.info("Getting the assignable virtual addresses...")
    statement = select(VirtualAddress).where(VirtualAddress.client == None)
    addresses = session.exec(statement).all()
    logger.info(f"Found {len(addresses)} assignable virtual addresses.")
    return addresses


@router.get("/routes", response_model=list[str])
async def get_routes(session: DBSession):
    logger.info("Getting the routes...")
    server = await get_server(session)
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
async def add_route(request: RouteRequest, session: DBSession):
    logger.info("Adding a route...")
    if not is_rfc1918_ipv4_network(request.network, require_cidr=True):
        logger.error("Invalid network address used for a server route.")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only internal network address is allowed!",
        )

    server = await get_server(session)
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
async def delete_route(network: str, session: DBSession):
    logger.info("Deleting a route...")
    if not is_rfc1918_ipv4_network(network, require_cidr=True):
        logger.error("Invalid network address used for route deletion.")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only internal network address is allowed!",
        )

    server = await get_server(session)
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


def load_from_config():
    config = openvpn.get_server_config()

    network_address, subnet_mask = config["server"].split()
    network = ipaddress.ip_network(f"{network_address}/{subnet_mask}", strict=False)
    hosts = list(network.hosts())

    config["network_address"] = network_address
    config["subnet_mask"] = subnet_mask
    config["ip"] = hosts.pop(0).compressed
    config["dev"] = f"{config['dev']}0"

    server = Server(**config)
    server.virtual_addresses = [
        VirtualAddress(ip=h.compressed, server=server) for h in hosts
    ]

    return server
