"""Private API delivery receipts, session bindings and exact acknowledgement intent."""

from datetime import UTC, datetime

from sqlalchemy import BigInteger, Column, Text
from sqlalchemy.dialects.mysql import MEDIUMTEXT
from sqlmodel import Field, SQLModel


class EventCursor(SQLModel, table=True):
    """Advance only in the same transaction as durable event/history ingestion."""

    id: int = Field(default=1, primary_key=True)
    after: int = Field(default=0, sa_column=Column(BigInteger, nullable=False))
    acknowledged: int = Field(default=0, sa_column=Column(BigInteger, nullable=False))
    revision: int = 0
    pending_id: str | None = None


class EventReceipt(SQLModel, table=True):
    """Deduplicate immutable events and retain unknown-client history for import."""

    id: str = Field(primary_key=True)
    sequence: int = Field(sa_column=Column(BigInteger, unique=True, nullable=False))
    digest: str
    client_name: str | None = Field(default=None, index=True)
    payload_json: str = Field(
        sa_column=Column(Text().with_variant(MEDIUMTEXT(), "mysql"), nullable=False)
    )
    applied: bool = False
    received_at: datetime = Field(default_factory=lambda: datetime.now(UTC), index=True)


class SessionBinding(SQLModel, table=True):
    """Keep transport session IDs private and mark gaps without fabricated history."""

    id: str = Field(primary_key=True)
    identity: str = Field(index=True)
    connection_id: int = Field(index=True)
    uncertain: bool = False


class EventAcknowledgement(SQLModel, table=True):
    """Retain the original operation ID through lost replies and API restarts."""

    id: str = Field(primary_key=True)
    request_json: str = Field(sa_column=Column(Text, nullable=False))
    response_json: str | None = Field(
        default=None, sa_column=Column(Text, nullable=True)
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), index=True)
