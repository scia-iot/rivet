import logging
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlmodel import Session, select

from sciaiot.ovpncp.data.network import RestrictedNetwork
from sciaiot.ovpncp.dependencies import get_session
from sciaiot.ovpncp.routes.client import get_client_by_name
from sciaiot.ovpncp.utils import iptables, openvpn
from sciaiot.ovpncp.utils.network import is_rfc1918_ipv4_network

logger = logging.getLogger(__name__)
DBSession = Annotated[Session, Depends(get_session)]
router = APIRouter()


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
async def create_restricted_network(
    request: RestrictedNetworkRequest, session: DBSession
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
        start_time=datetime.now(timezone.utc),
    )

    # Add these rules before the final FORWARD-chain rule.
    chain = "FORWARD"
    try:
        size = len(iptables.list_rules(chain))
        if network.private_network_addresses:
            rules = network.iptable_rules() + network.private_iptable_rules()
            iptables.apply_rules(chain, size, rules)
            openvpn.push_client_routes(
                source.name,
                network.push_routes(destination.virtual_address.ip),
            )
        else:
            iptables.apply_rules(chain, size, network.iptable_rules())

        session.add(network)
        session.commit()
        session.refresh(network)
    except Exception as error:
        session.rollback()
        raise _network_operation_failure("created") from error

    logger.info("Restricted network created successfully.")
    return network


@router.get("", response_model=list[RestrictedNetwork])
async def retrieve_restricted_networks(
    session: DBSession,
    source_name: str | None = None,
):
    logger.info("Retrieving restricted networks...")
    statement = select(RestrictedNetwork)
    if source_name is not None:
        statement = statement.where(RestrictedNetwork.source_name == source_name)
    networks = session.exec(statement).all()
    logger.info(f"Retrieved {len(networks)} restricted networks.")
    return networks


@router.get("/{network_id}", response_model=RestrictedNetwork)
async def retrieve_restricted_network(network_id: int, session: DBSession):
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


@router.delete("/{network_id}", status_code=status.HTTP_204_NO_CONTENT)
async def drop_restricted_network(network_id: int, session: DBSession):
    logger.info(f"Dropping restricted network with ID {network_id}...")
    network = await retrieve_restricted_network(network_id, session)
    if network.end_time is not None:
        logger.info("Restricted network was already closed.")
        return

    chain = "FORWARD"
    try:
        if network.private_network_addresses:
            source = get_client_by_name(network.source_name, session)
            openvpn.pull_client_routes(source.name)
            rules = network.iptable_rules() + network.private_iptable_rules()
            iptables.drop_rules(chain, rules)
        else:
            iptables.drop_rules(chain, network.iptable_rules())

        network.end_time = datetime.now(timezone.utc)
        session.add(network)
        session.commit()
        session.refresh(network)
    except Exception as error:
        session.rollback()
        raise _network_operation_failure("closed") from error

    logger.info(f"Dropped restricted network with ID {network_id}.")
