import ipaddress
import logging
import os
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlmodel import Session, select

from sciaiot.ovpncp import dependencies
from sciaiot.ovpncp.data.server import (
    Cert,
    CertBase,
    Client,
    ClientBase,
    ClientDetails,
    ClientWithVirtualAddress,
    Connection,
    VirtualAddress,
    VirtualAddressBase,
)
from sciaiot.ovpncp.dependencies import get_session
from sciaiot.ovpncp.routes.server import get_server
from sciaiot.ovpncp.utils import openvpn
from sciaiot.ovpncp.utils.logging import mask_sensitive

logger = logging.getLogger(__name__)
DBSession = Annotated[Session, Depends(get_session)]
router = APIRouter()


class ClientNetworkRequest(BaseModel):
    ip: str
    route_rules: list[str]


class StartConnectionRequest(BaseModel):
    remote_address: str
    connected_time: datetime


class CloseConnectionRequest(BaseModel):
    remote_address: str
    disconnected_time: datetime


class CertificatePackage(BaseModel):
    """Filesystem location of a packaged client certificate archive."""

    file_path: str


class ClientImportSummary(BaseModel):
    """Counts of client records changed during certificate import."""

    added: int
    updated: int


@router.post("", response_model=Client)
async def create_client(request: ClientBase, session: DBSession):
    logger.info(f"Creating client {request.name}...")
    client = Client.model_validate(request)
    openvpn.build_client(client.name)

    cert_details = openvpn.read_client_cert(client.name)
    cert = Cert(**cert_details)
    cert.client = client
    logger.info("Loaded client certificate details.")

    session.add(client)
    session.add(cert)
    session.commit()
    session.refresh(client)

    logger.info("Client created successfully!")
    return client


@router.get("", response_model=list[Client])
async def retrieve_clients(session: DBSession):
    logger.info("Retrieving all clients...")
    clients = session.exec(select(Client)).all()
    logger.info(f"Found {len(clients)} clients.")
    return clients


@router.get("/{client_name}", response_model=ClientDetails)
async def retrieve_client(client_name: str, session: DBSession):
    logger.info(f"Retrieving client {client_name}...")
    client = get_client_by_name(client_name, session)
    logger.info("Found client.")
    return client


@router.put("/{client_name}/package-cert", response_model=CertificatePackage)
async def package_client_cert(client_name: str, session: DBSession):
    logger.info(f"Packaging client certificate for {client_name}...")
    client = get_client_by_name(client_name, session)
    archive = openvpn.package_client_cert(client.name, dependencies.certs_directory)
    logger.info("Client certificate packaged successfully!")
    return {"file_path": archive}


@router.get(
    "/{client_name}/download-cert",
    response_class=FileResponse,
)
async def download_client_cert(client_name: str, session: DBSession):
    logger.info(f"Downloading client certificate for {client_name}...")
    client = get_client_by_name(client_name, session)
    file_name = f"{client.name}.zip"
    file_path = os.path.join(dependencies.certs_directory, file_name)
    logger.info("Client certificate ready to be downloaded.")
    return FileResponse(
        file_path, media_type="application/octet-stream", filename=file_name
    )


@router.put("/{client_name}/renew-cert", response_model=CertBase)
async def renew_client_cert(client_name: str, session: DBSession):
    logger.info(f"Renewing client certificate for {client_name}...")
    client = get_client_by_name(client_name, session)
    cert = client.cert

    if cert is not None:
        cert_details = openvpn.renew_client_cert(client.name)
        for key, value in cert_details.items():
            setattr(cert, key, value)

        session.add(cert)
        session.commit()
        session.refresh(cert)

        logger.info("Client certificate renewed successfully!")
        return cert


@router.put("/{client_name}/revoke", response_model=ClientBase)
async def revoke_client(client_name: str, session: DBSession):
    logger.info(f"Revoking client certificate for {client_name}...")
    client = get_client_by_name(client_name, session)
    client.revoked = True

    openvpn.revoke_client(client.name)
    openvpn.generate_crl()

    session.add(client)
    session.commit()
    session.refresh(client)

    logger.info("Client certificate revoked successfully!")
    return client


@router.put("/{client_name}/assign-ip", response_model=ClientWithVirtualAddress)
async def assign_virtual_address(
    client_name: str, address: VirtualAddressBase, session: DBSession
):
    logger.info(f"Assigning virtual address {address.ip} to client {client_name}...")
    statement = select(VirtualAddress).where(VirtualAddress.ip == address.ip)
    virtual_address = session.exec(statement).one_or_none()

    if not virtual_address:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f'Virtual address with IP "{address.ip}" not found!',
        )

    server = await get_server(session)
    client = get_client_by_name(client_name, session)
    client.virtual_address = virtual_address
    openvpn.assign_client_ip(client.name, virtual_address.ip, server.subnet_mask)

    if client.cidr:
        network = ipaddress.ip_network(client.cidr, strict=False)
        openvpn.add_iroute(client.name, f"{network.network_address} {network.netmask}")
        logger.info(f"Added iroute on {network.network_address} {network.netmask}.")

    session.add(client)
    session.commit()
    session.refresh(client)

    logger.info("Virtual address assigned successfully!")
    return client


@router.delete("/{client_name}/unassign-ip", status_code=status.HTTP_204_NO_CONTENT)
async def unassign_virtual_address(client_name: str, session: DBSession):
    logger.info(f"Unassigning virtual address from client {client_name}...")
    client = get_client_by_name(client_name, session)

    if not client.virtual_address:
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail=f'Client "{client_name}" has no virtual address assigned!',
        )

    openvpn.unassign_client_ip(client.name)
    client.virtual_address = None

    session.add(client)
    session.commit()
    session.refresh(client)

    logger.info("Virtual address unassigned successfully!")


@router.post("/{client_name}/connections", response_model=Connection)
async def start_connection(
    client_name: str, request: StartConnectionRequest, session: DBSession
):
    logger.info(f"Starting connection for client {client_name}...")
    client = get_client_by_name(client_name, session)
    connection = Connection(
        client=client,
        remote_address=request.remote_address,
        connected_time=request.connected_time,
    )

    session.add(connection)
    session.commit()
    session.refresh(connection)

    logger.info("Connection started successfully!")
    return connection


@router.put("/{client_name}/connections", response_model=Connection)
async def close_connection(
    client_name: str, request: CloseConnectionRequest, session: DBSession
):
    logger.info(f"Closing connection for client {client_name}...")
    client = get_client_by_name(client_name, session)
    statement = (
        select(Connection)
        .where(
            Connection.remote_address == request.remote_address,
            Connection.client_id == client.id,
            Connection.disconnected_time == None,
        )
        .order_by(Connection.connected_time.desc())  # type: ignore
    )
    connection = session.exec(statement).first()

    if not connection:
        logger.error("No active connection found for the given remote address!")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f'Connection with client "{client_name}" from "{mask_sensitive(request.remote_address)}" not found!',
        )

    connection.disconnected_time = request.disconnected_time
    session.add(connection)
    session.commit()
    session.refresh(connection)

    logger.info("Connection closed successfully!")
    return connection


@router.post("/import", response_model=ClientImportSummary)
async def import_clients(session: DBSession):
    """Import existing clients from Easy-RSA certificate directory."""
    logger.info("Importing existing clients from Easy-RSA...")
    discovered_names = openvpn.list_client_certs()

    added_count = 0
    updated_count = 0

    for name in discovered_names:
        cert_details = openvpn.read_client_cert(name)
        if not cert_details:
            continue

        assigned_ip = openvpn.read_client_ip(name)
        virtual_address = None
        if assigned_ip:
            virtual_address = session.exec(
                select(VirtualAddress).where(VirtualAddress.ip == assigned_ip)
            ).one_or_none()

        client = session.exec(select(Client).where(Client.name == name)).one_or_none()

        if client:
            # Update existing client's certificate
            if client.cert:
                for key, value in cert_details.items():
                    setattr(client.cert, key, value)
                session.add(client.cert)
            else:
                cert = Cert(**cert_details, client=client)
                session.add(cert)

            if virtual_address:
                client.virtual_address = virtual_address
                session.add(client)

            updated_count += 1
        else:
            # Create new client and certificate
            client = Client(name=name)
            cert = Cert(**cert_details, client=client)
            if virtual_address:
                client.virtual_address = virtual_address
            session.add(client)
            session.add(cert)
            added_count += 1

    session.commit()
    logger.info(f"Import complete: {added_count} added, {updated_count} updated.")
    return {"added": added_count, "updated": updated_count}


def get_client_by_name(client_name: str, session: Session) -> Client:
    statement = select(Client).where(Client.name == client_name)
    client = session.exec(statement).one_or_none()

    if not client:
        logger.error(f'Client "{client_name}" not found!')
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f'Client "{client_name}" not found!',
        )

    return client
