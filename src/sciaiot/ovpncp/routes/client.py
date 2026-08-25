import ipaddress
import logging
import os
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlmodel import Session, select

from sciaiot.ovpncp import dependencies
from sciaiot.ovpncp.authorization import (
    PermissionRoute,
    RequireClientsRead,
    RequireClientsWrite,
    RequireConnectionHookAccess,
)
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
from sciaiot.ovpncp.routes.server import get_server_record
from sciaiot.ovpncp.utils import openvpn
from sciaiot.ovpncp.utils.logging import mask_sensitive

logger = logging.getLogger(__name__)
DBSession = Annotated[Session, Depends(get_session)]
router = APIRouter(route_class=PermissionRoute)


class ClientNetworkRequest(BaseModel):
    ip: str
    route_rules: list[str]


class StartConnectionRequest(BaseModel):
    remote_address: str
    connected_time: datetime


class CloseConnectionRequest(BaseModel):
    remote_address: str
    disconnected_time: datetime


class ClientImportSummary(BaseModel):
    """Counts of client records changed during certificate import."""

    added: int
    updated: int


def _certificate_failure(operation: str) -> HTTPException:
    """Create a fixed failure response without logging exception details."""
    logger.error(f"Client certificate {operation} failed.")
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="The certificate operation failed.",
    )


@router.post("", response_model=Client)
async def create_client(
    request: ClientBase,
    session: DBSession,
    _principal: RequireClientsWrite,
):
    logger.info(f"Creating client {request.name}...")
    try:
        client = Client.model_validate(request)
        if not openvpn.build_client(client.name):
            raise RuntimeError("Client certificate creation failed.")

        cert_details = openvpn.read_client_cert(client.name)
        cert = Cert(**cert_details)
        cert.client = client
        logger.info("Loaded client certificate details.")

        session.add(client)
        session.add(cert)
        session.commit()
        session.refresh(client)
    except Exception as error:
        session.rollback()
        raise _certificate_failure("creation") from error

    logger.info("Client created successfully!")
    return client


@router.get("", response_model=list[Client])
async def retrieve_clients(
    session: DBSession,
    _principal: RequireClientsRead,
):
    logger.info("Retrieving all clients...")
    clients = session.exec(select(Client)).all()
    logger.info(f"Found {len(clients)} clients.")
    return clients


@router.get("/{client_name}", response_model=ClientDetails)
async def retrieve_client(
    client_name: str,
    session: DBSession,
    _principal: RequireClientsRead,
):
    logger.info(f"Retrieving client {client_name}...")
    client = get_client_by_name(client_name, session)
    logger.info("Found client.")
    return client


@router.put(
    "/{client_name}/package-cert",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def package_client_cert(
    client_name: str,
    session: DBSession,
    _principal: RequireClientsWrite,
):
    logger.info(f"Packaging client certificate for {client_name}...")
    client = get_client_by_name(client_name, session)
    try:
        openvpn.package_client_cert(client.name, dependencies.certs_directory)
    except Exception as error:
        raise _certificate_failure("packaging") from error
    logger.info("Client certificate packaged successfully!")


@router.get(
    "/{client_name}/download-cert",
    response_class=Response,
    responses={
        200: {
            "content": {
                "application/zip": {"schema": {"type": "string", "format": "binary"}}
            },
            "description": "Packaged client certificate archive.",
        }
    },
)
def download_client_cert(
    client_name: str,
    request: Request,
    session: DBSession,
    _principal: RequireClientsWrite,
):
    logger.info(f"Downloading client certificate for {client_name}...")
    client = get_client_by_name(client_name, session)
    try:
        openvpn.validate_name(client.name)
        file_name = f"{client.name}.zip"
        if getattr(request.state, "certificate_download_from_azure", False):
            return Response(
                headers={"Cache-Control": "no-store"},
                media_type="application/zip",
            )
        file_path = os.path.join(dependencies.certs_directory, file_name)
        with open(file_path, "rb") as archive:
            content = archive.read()
    # This is the safety boundary around filesystem and archive operations;
    # their implementation-specific errors must never reach the response.
    except Exception as error:
        raise _certificate_failure("download") from error
    logger.info("Client certificate ready to be downloaded.")
    return Response(
        content=content,
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": f'attachment; filename="{file_name}"',
        },
        media_type="application/zip",
    )


@router.put("/{client_name}/renew-cert", response_model=CertBase)
async def renew_client_cert(
    client_name: str,
    session: DBSession,
    _principal: RequireClientsWrite,
):
    logger.info(f"Renewing client certificate for {client_name}...")
    client = get_client_by_name(client_name, session)
    cert = client.cert

    if cert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="The client certificate record was not found.",
        )
    try:
        cert_details = openvpn.renew_client_cert(client.name)
        if not cert_details:
            raise RuntimeError("Renewed certificate details were unavailable.")
        for key, value in cert_details.items():
            setattr(cert, key, value)
        session.add(cert)
        session.commit()
        session.refresh(cert)
    except Exception as error:
        session.rollback()
        raise _certificate_failure("renewal") from error
    logger.info("Client certificate renewed successfully!")
    return cert


@router.put("/{client_name}/revoke", response_model=ClientBase)
async def revoke_client(
    client_name: str,
    session: DBSession,
    _principal: RequireClientsWrite,
):
    logger.info(f"Revoking client certificate for {client_name}...")
    client = get_client_by_name(client_name, session)
    try:
        if not openvpn.revoke_client(client.name):
            raise RuntimeError("Client certificate revocation failed.")
        if not openvpn.generate_crl():
            raise RuntimeError("Certificate revocation list generation failed.")
        client.revoked = True
        session.add(client)
        session.commit()
        session.refresh(client)
    except Exception as error:
        session.rollback()
        raise _certificate_failure("revocation") from error

    logger.info("Client certificate revoked successfully!")
    return client


@router.put("/{client_name}/assign-ip", response_model=ClientWithVirtualAddress)
async def assign_virtual_address(
    client_name: str,
    address: VirtualAddressBase,
    session: DBSession,
    _principal: RequireClientsWrite,
):
    logger.info(f"Assigning a virtual address to client {client_name}...")
    statement = select(VirtualAddress).where(VirtualAddress.ip == address.ip)
    virtual_address = session.exec(statement).one_or_none()

    if not virtual_address:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="The virtual address was not found.",
        )

    client = get_client_by_name(client_name, session)
    owner = session.exec(
        select(Client).where(
            Client.virtual_address_id == virtual_address.id,
        )
    ).first()
    if owner is not None and owner.id != client.id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The virtual address is assigned to another client.",
        )

    server = get_server_record(session)
    client.virtual_address = virtual_address
    openvpn.assign_client_ip(client.name, virtual_address.ip, server.subnet_mask)

    if client.cidr:
        network = ipaddress.ip_network(client.cidr, strict=False)
        openvpn.add_iroute(client.name, f"{network.network_address} {network.netmask}")
        logger.info("Added client iroute successfully.")

    session.add(client)
    session.commit()
    session.refresh(client)

    logger.info("Virtual address assigned successfully!")
    return client


@router.delete("/{client_name}/unassign-ip", status_code=status.HTTP_204_NO_CONTENT)
async def unassign_virtual_address(
    client_name: str,
    session: DBSession,
    _principal: RequireClientsWrite,
):
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
    client_name: str,
    request: StartConnectionRequest,
    session: DBSession,
    _principal: RequireConnectionHookAccess,
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
    client_name: str,
    request: CloseConnectionRequest,
    session: DBSession,
    _principal: RequireConnectionHookAccess,
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


def _import_clients(session: Session) -> dict[str, int]:
    """Import discovered Easy-RSA certificates in one transaction."""
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
    return {"added": added_count, "updated": updated_count}


@router.post("/import", response_model=ClientImportSummary)
async def import_clients(
    session: DBSession,
    _principal: RequireClientsWrite,
):
    """Import existing clients from Easy-RSA certificate directory."""
    logger.info("Importing existing clients from Easy-RSA...")
    try:
        result = _import_clients(session)
    except Exception as error:
        session.rollback()
        raise _certificate_failure("import") from error
    logger.info(
        f"Import complete: {result['added']} added, {result['updated']} updated."
    )
    return result


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
