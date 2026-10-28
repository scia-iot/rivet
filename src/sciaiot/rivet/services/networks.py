"""Shared restricted-network lifecycle over the durable VPN workflow."""

import logging
from datetime import UTC, datetime

from fastapi import HTTPException, status
from sqlmodel import Session, select

from sciaiot.rivet.application import client_name
from sciaiot.rivet.application.vpn_control.errors import ControlError
from sciaiot.rivet.data.network import RestrictedNetwork
from sciaiot.rivet.data.server import Client
from sciaiot.rivet.services.vpn import VpnService

logger = logging.getLogger(__name__)


def _operation_failure(action: str) -> HTTPException:
    """Build an actionable failure without privileged backend diagnostics."""
    logger.error("Restricted network %s failed.", action)
    return HTTPException(
        status.HTTP_500_INTERNAL_SERVER_ERROR,
        f"The restricted network could not be {action}. "
        "Check the host firewall and retry.",
    )


def create_network(
    session: Session,
    source: Client,
    destination: Client,
    private_network_addresses: str = "",
) -> RestrictedNetwork:
    """Validate resolved endpoints and persist access through VpnService.

    Args:
        session: Authorized caller's persistence session.
        source: Source client already authorized by the API.
        destination: Destination client already authorized by the API.
        private_network_addresses: Validated administrator-only LAN scope.

    Returns:
        The matching active record or a newly committed network.

    Raises:
        HTTPException: Invalid endpoint provisioning or persistence failure.
        ControlError: Expected VPN failure, after rolling back business state.
    """
    if source.virtual_address is None or destination.virtual_address is None:
        raise HTTPException(
            status.HTTP_412_PRECONDITION_FAILED,
            "Virtual address must be assigned to both source and destination client!",
        )
    if source.name == destination.name:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Source and destination VPN clients must be different.",
        )
    if source.revoked or destination.revoked:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Both VPN clients must have active credentials. "
            "Ask an administrator to provision active clients.",
        )
    if not all(
        client_name.is_valid_name(name) for name in (source.name, destination.name)
    ):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "A VPN client identity is invalid. Ask an administrator to repair it.",
        )
    existing = session.exec(
        select(RestrictedNetwork).where(
            RestrictedNetwork.source_name == source.name,
            RestrictedNetwork.destination_name == destination.name,
            RestrictedNetwork.source_virtual_address == source.virtual_address.ip,
            RestrictedNetwork.destination_virtual_address
            == destination.virtual_address.ip,
            RestrictedNetwork.private_network_addresses == private_network_addresses,
            RestrictedNetwork.end_time == None,
        )
    ).first()
    if existing is not None:
        return existing
    network = RestrictedNetwork(
        source_name=source.name,
        source_virtual_address=source.virtual_address.ip,
        destination_name=destination.name,
        destination_virtual_address=destination.virtual_address.ip,
        private_network_addresses=private_network_addresses,
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
    except ControlError:
        session.rollback()
        raise
    except Exception as error:
        session.rollback()
        raise _operation_failure("created") from error
    return network


def close_network(session: Session, network: RestrictedNetwork) -> None:
    """Close an authorized record, retaining durable retry and audit history.

    Args:
        session: Authorized caller's persistence session.
        network: A record scoped to the caller before invoking this workflow.

    Raises:
        HTTPException: A persistence or unexpected backend failure occurred.
        ControlError: Expected VPN failure, after rolling back business state.
    """
    if network.end_time is not None:
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
    except ControlError:
        session.rollback()
        raise
    except Exception as error:
        session.rollback()
        raise _operation_failure("closed") from error
