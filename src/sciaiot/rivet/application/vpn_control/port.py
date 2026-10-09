"""Application-facing VPN operations, with no infrastructure dependency."""

from typing import Protocol, runtime_checkable

from . import archive, schemas


@runtime_checkable
class VpnControl(Protocol):
    """Shared synchronous contract for future fake, host and agent adapters.

    Adapters authenticate the configured kernel peer identity out of band,
    validate requests a second time, enforce deadlines and resource limits,
    and durably serialize mutations before effects. Business authorization,
    desired state, archive storage and HTTP responses remain API-owned.
    """

    def execute(self, request: schemas.Request) -> schemas.Response:
        """Return a correlated typed result or fixed ControlError.

        Archive commands use open_archive. Unknown mutation outcomes require
        lookup/reconciliation of the SAME operation ID, never blind replay.
        """
        ...

    def open_archive(self, request: schemas.Request) -> archive.ArchiveStream:
        """Transfer immediate source ownership to a bounded context manager.

        Only Archive requests are accepted. Active credentials, generation,
        stream quota and deadline are enforced before returning the stream.
        """
        ...
