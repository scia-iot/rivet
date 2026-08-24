"""Tests for secret-safe Azure certificate archive middleware."""

import asyncio
import json
import logging
from unittest.mock import MagicMock, mock_open, patch

from fastapi import Request, Response

from sciaiot.ovpncp.middlewares import azure_storage


def storage_request(method: str, path: str) -> Request:
    """Create a request with the route parameter middleware consumes."""
    return Request(
        {
            "type": "http",
            "method": method,
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": [],
            "scheme": "https",
            "server": ("example.test", 443),
            "client": ("127.0.0.1", 1234),
            "path_params": {"client_name": "safe-client"},
        }
    )


def returning_response(response: Response):
    """Create a route continuation that returns a fixed response."""

    async def call_next(_request: Request) -> Response:
        return response

    return call_next


def test_upload_uses_known_archive_and_returns_no_path(caplog) -> None:
    """A successful package upload preserves the route's empty 204 contract."""
    request = storage_request("PUT", "/clients/safe-client/package-cert")
    blob = MagicMock()
    blob.url = "https://storage.example/private/container/safe-client.zip"
    container = MagicMock()
    container.get_blob_client.return_value = blob

    async def call_next(_request: Request) -> Response:
        return Response(status_code=204)

    caplog.clear()
    with (
        patch.object(azure_storage, "container_client", container, create=True),
        patch.object(
            azure_storage.dependencies,
            "certs_directory",
            "/server/private/certs",
        ),
        patch("builtins.open", mock_open(read_data=b"archive")) as opened,
        caplog.at_level(logging.INFO),
    ):
        response = asyncio.run(azure_storage.handle_upload(request, call_next))

    assert response.status_code == 204
    assert response.body == b""
    opened.assert_called_once_with("/server/private/certs/safe-client.zip", "rb")
    blob.upload_blob.assert_called_once()
    assert "/server/private/certs" not in caplog.text
    assert blob.url not in caplog.text


def test_download_proxies_archive_without_sas_url(caplog) -> None:
    """Azure archives remain response bytes instead of sensitive URLs."""
    request = storage_request("GET", "/clients/safe-client/download-cert")
    downloader = MagicMock()
    downloader.readall.return_value = b"azure archive"
    blob = MagicMock()
    blob.download_blob.return_value = downloader
    container = MagicMock()
    container.get_blob_client.return_value = blob

    async def call_next(_request: Request) -> Response:
        return Response(content=b"local archive", media_type="application/zip")

    caplog.clear()
    with (
        patch.object(azure_storage, "container_client", container, create=True),
        caplog.at_level(logging.INFO),
    ):
        response = asyncio.run(azure_storage.handle_download(request, call_next))

    assert response.status_code == 200
    assert response.body == b"azure archive"
    assert response.media_type == "application/zip"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-disposition"] == (
        'attachment; filename="safe-client.zip"'
    )
    assert "https://" not in response.body.decode(errors="ignore")
    assert "SAS" not in caplog.text


def test_storage_failure_hides_sensitive_details(caplog) -> None:
    """Storage failures expose neither path nor token diagnostics."""
    request = storage_request("GET", "/clients/safe-client/download-cert")
    sensitive = "/private/archive.zip?sig=secret-token"
    blob = MagicMock()
    blob.download_blob.side_effect = RuntimeError(sensitive)
    container = MagicMock()
    container.get_blob_client.return_value = blob

    async def call_next(_request: Request) -> Response:
        return Response(content=b"local archive", media_type="application/zip")

    caplog.clear()
    with (
        patch.object(azure_storage, "container_client", container, create=True),
        caplog.at_level(logging.ERROR),
    ):
        response = asyncio.run(azure_storage.handle_download(request, call_next))

    assert response.status_code == 500
    assert response.headers["content-type"].startswith("application/problem+json")
    assert json.loads(response.body)["detail"] == ("The certificate operation failed.")
    assert sensitive.encode() not in response.body
    assert sensitive not in caplog.text


def test_storage_preserves_route_failures() -> None:
    """Blob operations never overwrite authentication or route failures."""
    cases = [
        (
            azure_storage.handle_upload,
            storage_request("PUT", "/clients/safe-client/package-cert"),
        ),
        (
            azure_storage.handle_download,
            storage_request("GET", "/clients/safe-client/download-cert"),
        ),
    ]

    for handler, request in cases:
        container = MagicMock()
        route_response = Response(
            content=b"route failure",
            media_type="application/problem+json",
            status_code=403,
        )

        call_next = returning_response(route_response)

        with patch.object(azure_storage, "container_client", container, create=True):
            response = asyncio.run(handler(request, call_next))

        assert response is route_response
        container.get_blob_client.assert_not_called()


def test_upload_failure_is_safe_problem(caplog) -> None:
    """Upload failures use fixed RFC 7807 responses and safe logs."""
    request = storage_request("PUT", "/clients/safe-client/package-cert")
    sensitive = "/private/archive.zip?sig=secret-token"
    blob = MagicMock()
    container = MagicMock()
    container.get_blob_client.return_value = blob

    async def call_next(_request: Request) -> Response:
        return Response(status_code=204)

    caplog.clear()
    with (
        patch.object(azure_storage, "container_client", container, create=True),
        patch.object(
            azure_storage.dependencies,
            "certs_directory",
            "/server/private/certs",
        ),
        patch("builtins.open", side_effect=RuntimeError(sensitive)),
        caplog.at_level(logging.ERROR),
    ):
        response = asyncio.run(azure_storage.handle_upload(request, call_next))

    assert response.status_code == 500
    assert response.headers["content-type"].startswith("application/problem+json")
    assert json.loads(response.body)["detail"] == ("The certificate operation failed.")
    assert sensitive.encode() not in response.body
    assert sensitive not in caplog.text
