"""Persisted server, address, client, certificate, and connection models."""

# SQLModel resolves these relationship names at mapper configuration time.
# ruff: noqa: UP037, UP045

from datetime import datetime
from typing import Optional

from sqlalchemy import Column, String
from sqlmodel import Field, Relationship, SQLModel


class ServerBase(SQLModel):
    port: str
    proto: str
    dev: str
    ca: str
    cert: str
    key: str
    dh: str
    data_ciphers_fallback: str
    topology: str
    network_address: str
    subnet_mask: str
    ip: str
    ifconfig_pool_persist: str
    client_config_dir: str
    ccd_exclusive: bool = False
    keepalive: str
    persist_key: bool = False
    persist_tun: bool = False
    status: str
    log: str
    verb: str
    explicit_exit_notify: str
    script_security: str | None = None
    client_connect: str | None = None
    client_disconnect: str | None = None


class Server(ServerBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    virtual_addresses: list["VirtualAddress"] = Relationship(back_populates="server")


class VirtualAddressBase(SQLModel):
    ip: str


class VirtualAddress(VirtualAddressBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    ip: str = Field(sa_column=Column("ip", String, unique=True))
    server_id: int = Field(default=None, foreign_key="server.id")
    server: Server = Relationship(back_populates="virtual_addresses")
    client: Optional["Client"] = Relationship(
        sa_relationship_kwargs={"uselist": False}, back_populates="virtual_address"
    )


class ServerWithVirtualAddresses(ServerBase):
    virtual_addresses: list[VirtualAddressBase] = []


class ClientBase(SQLModel):
    name: str
    cidr: str | None = None
    revoked: bool = False


class Client(ClientBase, table=True):
    id: int = Field(default=None, primary_key=True)
    name: str = Field(sa_column=Column("name", String, unique=True))
    virtual_address_id: int | None = Field(
        default=None, foreign_key="virtualaddress.id", unique=True
    )
    virtual_address: Optional["VirtualAddress"] = Relationship(back_populates="client")
    cert: Optional["Cert"] = Relationship(back_populates="client", cascade_delete=True)
    connections: list["Connection"] = Relationship(
        back_populates="client", cascade_delete=True
    )


class CertBase(SQLModel):
    issued_by: str
    issued_to: str
    issued_on: datetime
    expires_on: datetime


class Cert(CertBase, table=True):
    id: int = Field(default=None, primary_key=True)
    client_id: int = Field(default=None, foreign_key="client.id")
    client: Client = Relationship(
        sa_relationship_kwargs={"uselist": False}, back_populates="cert"
    )


class ConnectionBase(SQLModel):
    remote_address: str
    connected_time: datetime
    disconnected_time: datetime | None = None


class Connection(ConnectionBase, table=True):
    id: int = Field(default=None, primary_key=True)
    client_id: int = Field(default=None, foreign_key="client.id")
    client: Client = Relationship(back_populates="connections")


class ClientWithVirtualAddress(ClientBase):
    virtual_address: VirtualAddress | None


class ClientDetails(ClientBase):
    virtual_address: VirtualAddressBase | None
    cert: CertBase
    connections: list[ConnectionBase] = []
