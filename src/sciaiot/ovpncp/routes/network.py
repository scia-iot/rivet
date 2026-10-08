import logging
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlmodel import Session, select

from sciaiot.ovpncp.application.validation import is_rfc1918_ipv4_network
from sciaiot.ovpncp.authorization import (
    PermissionRoute,
    RequireServerRead,
    RequireServerWrite,
)
from sciaiot.ovpncp.data.network import RestrictedNetwork
from sciaiot.ovpncp.dependencies import get_session
from sciaiot.ovpncp.routes.client import get_client_by_name
from sciaiot.ovpncp.services.dispatch import threaded
from sciaiot.ovpncp.services.vpn import VpnService

logger = logging.getLogger(__name__)
DBSession = Annotated[Session, Depends(get_session)]
router = APIRouter(route_class=PermissionRoute)


class RestrictedNetworkRequest(BaseModel):
    source_name: str
    destination_name: str
    private_network_addresses: str | None = None

    @field_validator("private_network_addresses")
    @classmethod
    def validate_private_network_addresses(cls, value: str | None) -> str | None:
        """Validate optional private destinations before firewall use."""
        if value is None or not value.strip():
            return value

        addresses = []
        for raw_address in value.split(","):
            address = raw_address.strip()
            if not is_rfc1918_ipv4_network(address):
                raise ValueError(
                    "Only canonical RFC 1918 IPv4 destinations are allowed."
                )
            addresses.append(address)
        return ",".join(addresses)


def _network_operation_failure(action: str) -> HTTPException:
    """Build a fixed privileged-operation failure without sensitive details."""
    logger.error(f"Restricted network {action} failed.")
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=(
            f"The restricted network could not be {action}. "
            "Check the host firewall and retry."
        ),
    )


@router.post("", response_model=RestrictedNetwork)
@threaded
def create_restricted_network(
    request: RestrictedNetworkRequest,
    session: DBSession,
    _principal: RequireServerWrite,
):
    logger.info("Creating restricted network...")
    if request.source_name == request.destination_name:
        logger.error("Restricted network clients must be different.")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Source and destination VPN clients must be different.",
        )

    source = get_client_by_name(request.source_name, session)
    destination = get_client_by_name(request.destination_name, session)

    if not source.virtual_address or not destination.virtual_address:
        logger.error("Virtual address must assigned to both clients!")
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail="Virtual address must be assigned to both source and destination client!",
        )

    network = RestrictedNetwork(
        source_name=source.name,
        source_virtual_address=source.virtual_address.ip,
        destination_name=destination.name,
        destination_virtual_address=destination.virtual_address.ip,
        private_network_addresses=request.private_network_addresses or "",
        start_time=datetime.now(UTC),
    )

    try:
        control = VpnService(session)
        control.network(network, True)
        session.add(network)
        session.flush()
        control.finish(resource_id=str(network.id))
        session.commit()
        session.refresh(network)
    except Exception as error:
        session.rollback()
        raise _network_operation_failure("created") from error

    logger.info("Restricted network created successfully.")
    return network


@router.get("", response_model=list[RestrictedNetwork])
@threaded
def retrieve_restricted_networks(
    session: DBSession,
    _principal: RequireServerRead,
    source_name: str | None = None,
):
    logger.info("Retrieving restricted networks...")
    statement = select(RestrictedNetwork)
    if source_name is not None:
        statement = statement.where(RestrictedNetwork.source_name == source_name)
    networks = session.exec(statement).all()
    logger.info(f"Retrieved {len(networks)} restricted networks.")
    return networks


def get_restricted_network_record(
    network_id: int,
    session: Session,
) -> RestrictedNetwork:
    """Load one restricted network for an authorized route operation."""
    logger.info(f"Retrieving restricted network with ID {network_id}...")
    statement = select(RestrictedNetwork).where(RestrictedNetwork.id == network_id)
    network = session.exec(statement).one_or_none()

    if not network:
        logger.error(f"Network with ID {network_id} not found!")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Network with ID {network_id} not found!",
        )

    logger.info(f"Retrieved restricted network with ID {network_id}.")
    return network


@router.get("/{network_id}", response_model=RestrictedNetwork)
@threaded
def retrieve_restricted_network(
    network_id: int,
    session: DBSession,
    _principal: RequireServerRead,
):
    """Retrieve one restricted network."""
    return get_restricted_network_record(network_id, session)


@router.delete("/{network_id}", status_code=status.HTTP_204_NO_CONTENT)
@threaded
def drop_restricted_network(
    network_id: int,
    session: DBSession,
    _principal: RequireServerWrite,
):
    logger.info(f"Dropping restricted network with ID {network_id}...")
    network = get_restricted_network_record(network_id, session)
    if network.end_time is not None:
        logger.info("Restricted network was already closed.")
        return

    try:
        control = VpnService(session)
        control.network(network, False)

        network.end_time = datetime.now(UTC)
        session.add(network)
        session.flush()
        control.finish(resource_id=str(network.id))
        session.commit()
        session.refresh(network)
    except Exception as error:
        session.rollback()
        raise _network_operation_failure("closed") from error

    logger.info(f"Dropped restricted network with ID {network_id}.")
