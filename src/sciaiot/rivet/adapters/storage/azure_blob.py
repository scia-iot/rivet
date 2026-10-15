"""Private Azure Blob adapter for bounded certificate archives."""

from collections.abc import Iterator
from typing import Any

from sciaiot.rivet.application.storage import (
    ArchiveNotFoundError,
    ArchiveStoreError,
    archive_name,
    validate_content,
)
from sciaiot.rivet.application.vpn_control.schemas import MAX_ARCHIVE_BYTES

CONTAINER_NAME = "ovpncp"


class AzureBlobArchiveStore:
    """Store archives in the existing private Azure Blob container."""

    def __init__(self, connection_string: str) -> None:
        """Create the selected Blob client without exposing its credentials."""
        if not connection_string.strip():
            raise ValueError("Azure Blob storage credentials are required.")
        try:
            from azure.core.exceptions import ResourceNotFoundError
            from azure.storage.blob import BlobServiceClient

            service = BlobServiceClient.from_connection_string(connection_string)
            try:
                container = service.get_container_client(CONTAINER_NAME)
            except Exception:
                service.close()
                raise
        except ImportError:
            raise ValueError("Azure Blob storage dependencies are missing.") from None
        except Exception:  # noqa: BLE001 - redact SDK configuration errors
            raise ValueError("Azure Blob storage configuration is invalid.") from None
        self._service = service
        self._container = container
        self._not_found = ResourceNotFoundError

    def _blob(self, client_name: str) -> Any:
        """Resolve only a validated client basename within the fixed container."""
        return self._container.get_blob_client(archive_name(client_name))

    def put(self, client_name: str, content: bytes) -> None:
        """Overwrite one bounded private Blob archive."""
        archive_name(client_name)
        data = validate_content(content)
        try:
            self._blob(client_name).upload_blob(data, overwrite=True)
        except Exception as error:
            raise ArchiveStoreError("Certificate archive upload failed.") from error

    def get(self, client_name: str) -> bytes:
        """Download at most one archive limit through private SDK chunks."""
        archive_name(client_name)
        try:
            downloader = self._blob(client_name).download_blob(
                length=MAX_ARCHIVE_BYTES + 1,
                max_concurrency=1,
            )
            chunks: Iterator[bytes] = iter(downloader.chunks())
            content = bytearray()
            for chunk in chunks:
                if not isinstance(chunk, bytes):
                    raise ArchiveStoreError("Invalid certificate archive.")
                if len(content) + len(chunk) > MAX_ARCHIVE_BYTES:
                    raise ArchiveStoreError("Certificate archive is too large.")
                content.extend(chunk)
            return validate_content(bytes(content))
        except self._not_found as error:
            raise ArchiveNotFoundError("Certificate archive unavailable.") from error
        except Exception as error:
            raise ArchiveStoreError("Certificate archive download failed.") from error

    def delete(self, client_name: str) -> None:
        """Remove a Blob archive, treating absence as success."""
        archive_name(client_name)
        try:
            self._blob(client_name).delete_blob()
        except self._not_found:
            pass
        except Exception as error:
            raise ArchiveStoreError("Certificate archive deletion failed.") from error

    def close(self) -> None:
        """Close SDK transport resources at application shutdown."""
        try:
            self._service.close()
        except Exception:  # noqa: BLE001 - redact SDK shutdown errors
            raise ArchiveStoreError("Archive storage shutdown failed.") from None
