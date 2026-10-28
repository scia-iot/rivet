"""Restricted networks scoped to owned sources and explicitly granted devices."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlmodel import Session, col, select

from sciaiot.rivet.application.vpn_control.schemas import Name
from sciaiot.rivet.authorization import (
    PermissionRoute,
    PrincipalDependency,
    authorize_granted_device,
    authorize_owned_client,
    list_owned_clients,
)
from sciaiot.rivet.data.network import RestrictedNetwork
from sciaiot.rivet.data.server import Client
from sciaiot.rivet.dependencies import get_session
from sciaiot.rivet.services.dispatch import threaded
from sciaiot.rivet.services.networks import close_network, create_network

DBSession = Annotated[Session, Depends(get_session)]
router = APIRouter(
    route_class=PermissionRoute,
)
OWNED_NETWORK = {"x-current-user-resource": "source-owned-network"}


class CurrentUserNetworkRequest(BaseModel):
    """Direct VPN access from an owned client to one granted device."""

    model_config = ConfigDict(extra="forbid")

    source_name: Name
    destination_device_id: int = Field(gt=0, strict=True)


@router.post("", response_model=RestrictedNetwork, openapi_extra=OWNED_NETWORK)
@threaded
def create_current_network(
    request: CurrentUserNetworkRequest,
    principal: PrincipalDependency,
    session: DBSession,
) -> RestrictedNetwork:
    """Create direct device access after ownership and grant authorization."""
    source = authorize_owned_client(principal, request.source_name, session)
    device = authorize_granted_device(principal, request.destination_device_id, session)
    destination = (
        session.get(Client, device.client_id) if device.client_id is not None else None
    )
    if destination is None:
        raise HTTPException(
            status.HTTP_412_PRECONDITION_FAILED,
            "The device has no VPN client assigned. "
            "Ask an administrator to provision the device.",
        )
    return create_network(session, source, destination)


@router.get("", response_model=list[RestrictedNetwork], openapi_extra=OWNED_NETWORK)
@threaded
def list_current_networks(
    principal: PrincipalDependency,
    session: DBSession,
    source_name: Name | None = None,
) -> list[RestrictedNetwork]:
    """List history for currently owned sources, independent of device grants."""
    names = [client.name for client in list_owned_clients(principal, session)]
    if source_name is not None:
        authorize_owned_client(principal, source_name, session)
        names = [source_name]
    statement = (
        select(RestrictedNetwork)
        .where(col(RestrictedNetwork.source_name).in_(names))
        .order_by(col(RestrictedNetwork.id))
    )
    return list(session.exec(statement).all())


def _owned_network(
    network_id: int,
    principal: PrincipalDependency,
    session: Session,
) -> RestrictedNetwork:
    """Filter by current ownership before loading a guessed record ID."""
    names = [client.name for client in list_owned_clients(principal, session)]
    network = session.exec(
        select(RestrictedNetwork).where(
            RestrictedNetwork.id == network_id,
            col(RestrictedNetwork.source_name).in_(names),
        )
    ).one_or_none()
    if network is None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "The current principal is not authorized for this resource.",
        )
    return network


@router.get(
    "/{network_id}",
    response_model=RestrictedNetwork,
    openapi_extra=OWNED_NETWORK,
)
@threaded
def retrieve_current_network(
    network_id: int,
    principal: PrincipalDependency,
    session: DBSession,
) -> RestrictedNetwork:
    """Retrieve a record only while its source belongs to the caller."""
    return _owned_network(network_id, principal, session)


@router.delete(
    "/{network_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    openapi_extra=OWNED_NETWORK,
)
@threaded
def close_current_network(
    network_id: int,
    principal: PrincipalDependency,
    session: DBSession,
) -> None:
    """Remove owned access even after a destination grant or link changes."""
    close_network(session, _owned_network(network_id, principal, session))
