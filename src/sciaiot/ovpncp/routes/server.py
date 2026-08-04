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
    service_health = openvpn.get_status()
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
    routes = iproute.list(server.dev)
    logger.info(f"Found {len(routes)} routes.")
    return routes


@router.post("/routes", status_code=status.HTTP_204_NO_CONTENT)
async def add_route(request: RouteRequest, session: DBSession):
    logger.info("Adding a route...")
    if not is_valid_address(request.network):
        logger.error(f"Invalid network address {request.network} used!")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only internal network address is allowed!",
        )

    server = await get_server(session)
    iproute.add(request.network, server.ip, server.dev)
    logger.info("Route added successfully!")


@router.delete("/routes", status_code=status.HTTP_204_NO_CONTENT)
async def delete_route(network: str, session: DBSession):
    logger.info("Deleting a route...")
    server = await get_server(session)
    routes = iproute.list(server.dev)

    target = None
    for route in routes:
        if route.startswith(network):
            target = route
            break

    if target:
        iproute.delete(target, server.dev)
        logger.info("Route deleted successfully!")
    else:
        logger.error(f'Network "{network}" not found in routes!')
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f'Network "{network}" not found in routes!',
        )


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


def is_valid_address(network):
    try:
        net = ipaddress.ip_network(network)
        return net.is_private
    except ValueError:
        return False
