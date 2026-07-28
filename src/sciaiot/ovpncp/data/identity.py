"""Persistence models for users, devices, and individual access."""

from sqlalchemy import Column, String, UniqueConstraint
from sqlmodel import Field, SQLModel


class DeviceBase(SQLModel):
    """Shared fields for an edge device."""

    name: str = Field(min_length=1, max_length=255)
    client_id: int | None = None


class DeviceUpdate(SQLModel):
    """Fields that can be changed on a device."""

    name: str | None = Field(default=None, min_length=1, max_length=255)
    client_id: int | None = None


class Device(DeviceBase, table=True):
    """Stable business identity for an edge device."""

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(sa_column=Column("name", String, unique=True))
    client_id: int | None = Field(
        default=None,
        foreign_key="client.id",
        unique=True,
    )


class UserBase(SQLModel):
    """Shared fields for a user backed by an external OAuth identity."""

    display_name: str = Field(min_length=1, max_length=255)
    issuer: str = Field(min_length=1, max_length=2048)
    subject: str = Field(min_length=1, max_length=255)


class UserUpdate(SQLModel):
    """Fields that can be changed on a local user."""

    display_name: str = Field(min_length=1, max_length=255)


class User(UserBase, table=True):
    """Local user mapped to a stable external issuer and subject."""

    __table_args__ = (
        UniqueConstraint("issuer", "subject", name="uq_user_external_identity"),
    )

    id: int | None = Field(default=None, primary_key=True)


class AccessGrant(SQLModel, table=True):
    """Permission for one user to access one device."""

    __table_args__ = (UniqueConstraint("user_id", "device_id", name="uq_access_grant"),)

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", ondelete="CASCADE")
    device_id: int = Field(foreign_key="device.id", ondelete="CASCADE")


class UserClient(SQLModel, table=True):
    """Administrative assignment of a VPN client to its owning user."""

    __table_args__ = (UniqueConstraint("client_id", name="uq_user_client_client"),)

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", ondelete="CASCADE")
    client_id: int = Field(foreign_key="client.id", ondelete="CASCADE")
