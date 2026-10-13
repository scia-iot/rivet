"""API-owned immutable VPN workflow intent and observed operation outcomes."""

from sqlalchemy import Column, Text, UniqueConstraint
from sqlalchemy.dialects.mysql import MEDIUMTEXT
from sqlmodel import Field, SQLModel


class VpnWorkflow(SQLModel, table=True):
    """Retain desired intent before dispatch and fence unresolved resources."""

    id: str = Field(primary_key=True)
    resource: str = Field(index=True)
    active_resource: str | None = Field(default=None, unique=True)
    resource_id: str | None = None
    desired_json: str = Field(
        sa_column=Column(Text().with_variant(MEDIUMTEXT(), "mysql"), nullable=False)
    )
    completed: bool = False


class VpnStep(SQLModel, table=True):
    """Persist the exact request and ID before any possible remote effect."""

    __table_args__ = (UniqueConstraint("workflow_id", "position"),)

    id: str = Field(primary_key=True)
    workflow_id: str = Field(index=True)
    position: int
    request_json: str = Field(
        sa_column=Column(Text().with_variant(MEDIUMTEXT(), "mysql"), nullable=False)
    )
    response_json: str | None = Field(
        default=None,
        sa_column=Column(Text().with_variant(MEDIUMTEXT(), "mysql"), nullable=True),
    )


class VpnArchiveCleanup(SQLModel, table=True):
    """Track invalidated archive cleanup independently of revoked business state."""

    client: str = Field(primary_key=True)
    pending: bool = True


class VpnStepAttempt(SQLModel, table=True):
    """Retain proven rejected attempts when an authorized retry creates a new ID."""

    id: str = Field(primary_key=True)
    workflow_id: str = Field(index=True)
    position: int
    request_json: str = Field(
        sa_column=Column(Text().with_variant(MEDIUMTEXT(), "mysql"), nullable=False)
    )
    response_json: str = Field(
        sa_column=Column(Text().with_variant(MEDIUMTEXT(), "mysql"), nullable=False)
    )
