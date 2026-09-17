import logging
import os
from typing import Any

from azure.storage.blob import BlobServiceClient
from fastapi import Request, Response, status
from fastapi.concurrency import run_in_threadpool

from sciaiot.ovpncp import dependencies
from sciaiot.ovpncp.adapters.vpn.host import HostVpnControl
from sciaiot.ovpncp.problems import problem_response
from sciaiot.ovpncp.services import vpn as openvpn

logger = logging.getLogger(__name__)

STORAGE_CONNECTION_STRING = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
CONTAINER_NAME = "ovpncp"

if STORAGE_CONNECTION_STRING:
    blob_service_client = BlobServiceClient.from_connection_string(
        STORAGE_CONNECTION_STRING
    )
    container_client = blob_service_client.get_container_client(CONTAINER_NAME)


async def azure_storage_middleware(request: Request, call_next):
    if STORAGE_CONNECTION_STRING:
        url_path = request.url.path
        if url_path.endswith("/package-cert"):
            response = await handle_upload(request, call_next)
            return response
        elif url_path.endswith("download-cert"):
            if not isinstance(dependencies.get_vpn_control(), HostVpnControl):
                return await call_next(request)
            request.state.certificate_download_from_azure = True
            response = await handle_download(request, call_next)
            return response
        elif (
            request.method == "DELETE"
            and url_path.rstrip("/").count("/") == 2
            and "/clients/" in url_path
        ):
            return await handle_archive_delete(request, call_next)

    response = await call_next(request)
    return response


def _upload_archive(blob_client: Any, file_path: str) -> None:
    """Upload one packaged archive without returning its location."""
    with open(file_path, "rb") as data:
        blob_client.upload_blob(data, overwrite=True)


def _download_archive(blob_client: Any) -> bytes:
    """Read one packaged archive from Blob Storage."""
    return blob_client.download_blob().readall()


def _delete_archive(blob_client: Any) -> None:
    """Delete one packaged archive from Blob Storage."""
    blob_client.delete_blob()


async def handle_archive_delete(request: Request, call_next):
    """Best-effort delete a blob after durable local client deletion."""
    response = await call_next(request)
    if response.status_code != status.HTTP_204_NO_CONTENT:
        return response

    client_name = request.path_params["client_name"]
    try:
        openvpn.validate_name(client_name)
        blob_client = container_client.get_blob_client(f"{client_name}.zip")
        await run_in_threadpool(_delete_archive, blob_client)
    except Exception:  # noqa: BLE001 -- third-party storage boundary
        logger.error(
            "Azure VPN client archive cleanup failed; remove the orphaned "
            "archive blob manually."
        )
    else:
        logger.info("Azure VPN client archive deleted successfully.")
    return response


async def handle_upload(request: Request, call_next):
    response = await call_next(request)
    if response.status_code != status.HTTP_204_NO_CONTENT:
        return response

    client_name = request.path_params["client_name"]
    try:
        openvpn.validate_name(client_name)
        file_path = os.path.join(dependencies.certs_directory, f"{client_name}.zip")
        blob_client = container_client.get_blob_client(f"{client_name}.zip")
        await run_in_threadpool(_upload_archive, blob_client, file_path)
    except Exception:  # noqa: BLE001 -- third-party storage boundary
        logger.error("Client certificate archive upload failed.")
        return problem_response(
            request,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "The certificate operation failed.",
        )

    logger.info("Client certificate archive uploaded to Azure Blob Storage.")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


async def handle_download(request: Request, call_next):
    response = await call_next(request)
    if response.status_code != status.HTTP_200_OK:
        return response

    client_name = request.path_params["client_name"]
    try:
        openvpn.validate_name(client_name)
        file_name = f"{client_name}.zip"
        blob_client = container_client.get_blob_client(file_name)
        content = await run_in_threadpool(_download_archive, blob_client)
    except Exception:  # noqa: BLE001 -- third-party storage boundary
        logger.error("Client certificate archive download failed.")
        return problem_response(
            request,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "The certificate operation failed.",
        )

    logger.info("Client certificate archive downloaded from Azure Blob Storage.")
    return Response(
        content=content,
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": f'attachment; filename="{file_name}"',
        },
        media_type="application/zip",
    )
