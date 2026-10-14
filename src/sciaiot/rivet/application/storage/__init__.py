"""Provider-independent certificate archive storage contract."""

from typing import Protocol

from sciaiot.rivet.application.client_name import is_valid_name
from sciaiot.rivet.application.vpn_control.schemas import MAX_ARCHIVE_BYTES


class ArchiveStoreError(Exception):
    """Report an archive storage failure without provider details."""


class ArchiveNotFoundError(ArchiveStoreError):
    """Report that the requested packaged archive does not exist."""


class ArchiveStore(Protocol):
    """Store bounded client ZIP archives by validated client identity."""

    def put(self, client_name: str, content: bytes) -> None:
        """Replace one client's packaged archive."""
        ...

    def get(self, client_name: str) -> bytes:
        """Read one client's packaged archive."""
        ...

    def delete(self, client_name: str) -> None:
        """Delete one client's archive, succeeding when already absent."""
        ...

    def close(self) -> None:
        """Release resources owned by this store."""
        ...


def archive_name(client_name: str) -> str:
    """Derive one safe archive basename from a client identity."""
    if not is_valid_name(client_name):
        raise ValueError("Invalid VPN client name.")
    return f"{client_name}.zip"


def validate_content(content: bytes) -> bytes:
    """Reject empty, oversized, or non-byte archive content."""
    if not isinstance(content, bytes) or not 0 < len(content) <= MAX_ARCHIVE_BYTES:
        raise ArchiveStoreError("Invalid certificate archive content.")
    return content
