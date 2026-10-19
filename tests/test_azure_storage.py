"""Tests for private, bounded Azure Blob archive operations."""

from unittest.mock import MagicMock, patch

import pytest
from azure.core.exceptions import ResourceNotFoundError

from sciaiot.rivet.adapters.storage.azure_blob import AzureBlobArchiveStore
from sciaiot.rivet.application.storage import (
    ArchiveNotFoundError,
    ArchiveStoreError,
)
from sciaiot.rivet.application.vpn_control.schemas import MAX_ARCHIVE_BYTES


@pytest.fixture
def blob_store() -> tuple[AzureBlobArchiveStore, MagicMock, MagicMock]:
    """Inject SDK mocks without creating an Azure transport."""
    service = MagicMock()
    container = service.get_container_client.return_value
    with patch(
        "azure.storage.blob.BlobServiceClient.from_connection_string",
        return_value=service,
    ) as create:
        store = AzureBlobArchiveStore("private-secret")
    create.assert_called_once_with("private-secret")
    service.get_container_client.assert_called_once_with("ovpncp")
    return store, service, container


def test_blob_put_get_delete_and_close(
    blob_store: tuple[AzureBlobArchiveStore, MagicMock, MagicMock],
) -> None:
    """The adapter uses fixed names and returns private bytes only."""
    store, service, container = blob_store
    blob = container.get_blob_client.return_value
    blob.download_blob.return_value.chunks.return_value = iter([b"archive"])

    store.put("safe-client", b"archive")
    assert store.get("safe-client") == b"archive"
    store.delete("safe-client")
    store.close()

    container.get_blob_client.assert_called_with("safe-client.zip")
    blob.upload_blob.assert_called_once_with(b"archive", overwrite=True)
    blob.download_blob.assert_called_once_with(
        length=MAX_ARCHIVE_BYTES + 1,
        max_concurrency=1,
    )
    blob.delete_blob.assert_called_once_with()
    service.close.assert_called_once_with()


def test_blob_limits_names_and_content(
    blob_store: tuple[AzureBlobArchiveStore, MagicMock, MagicMock],
) -> None:
    """Invalid inputs never reach the SDK and oversized downloads fail."""
    store, _service, container = blob_store
    with pytest.raises(ValueError):
        store.put("../outside", b"archive")
    with pytest.raises(ArchiveStoreError):
        store.put("safe", b"")
    container.get_blob_client.assert_not_called()
    blob = container.get_blob_client.return_value
    blob.download_blob.return_value.chunks.return_value = iter(
        [b"a" * MAX_ARCHIVE_BYTES, b"b"]
    )
    with pytest.raises(ArchiveStoreError):
        store.get("safe")


def test_blob_absence_is_only_idempotent_for_delete(
    blob_store: tuple[AzureBlobArchiveStore, MagicMock, MagicMock],
) -> None:
    """A missing read fails while a missing delete succeeds."""
    store, _service, container = blob_store
    blob = container.get_blob_client.return_value
    blob.download_blob.side_effect = ResourceNotFoundError("missing")
    with pytest.raises(ArchiveNotFoundError):
        store.get("safe")
    blob.delete_blob.side_effect = ResourceNotFoundError("missing")
    store.delete("safe")


def test_blob_failures_do_not_expose_sdk_details(
    blob_store: tuple[AzureBlobArchiveStore, MagicMock, MagicMock],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Public storage errors and logs contain no signed URL or credentials."""
    store, _service, container = blob_store
    secret = "https://private.example/archive?sig=secret"
    blob = container.get_blob_client.return_value
    blob.upload_blob.side_effect = RuntimeError(secret)
    with pytest.raises(ArchiveStoreError) as failure:
        store.put("safe", b"archive")
    assert secret not in str(failure.value)
    assert secret not in caplog.text
