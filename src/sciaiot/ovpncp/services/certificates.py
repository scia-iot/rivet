"""Shared safe certificate archive operations."""

import os

from fastapi import Response

from sciaiot.ovpncp.data.server import Client
from sciaiot.ovpncp.utils import openvpn


class CertificateArchiveError(Exception):
    """Raised when a certificate archive operation fails safely."""


class CertificateArchiveService:
    """Package and load client archives behind one validated boundary."""

    def __init__(self, archive_directory: str) -> None:
        """Initialize archive operations.

        Args:
            archive_directory: Trusted directory containing packaged archives.
        """
        self.archive_directory = archive_directory

    def package(self, client: Client) -> None:
        """Package one authorized client's credential archive.

        Args:
            client: Client already authorized by the calling route.

        Raises:
            CertificateArchiveError: If validation or packaging fails.
        """
        try:
            openvpn.package_client_cert(client.name, self.archive_directory)
        except Exception as error:
            raise CertificateArchiveError from error

    def download_response(
        self,
        client: Client,
        *,
        from_cloud_storage: bool,
    ) -> Response:
        """Build a no-store response for an authorized client archive.

        Args:
            client: Client already authorized by the calling route.
            from_cloud_storage: Whether middleware will supply archive bytes.

        Returns:
            An empty cloud placeholder or local archive byte response.

        Raises:
            CertificateArchiveError: If validation or local reading fails.
        """
        try:
            openvpn.validate_name(client.name)
            file_name = f"{client.name}.zip"
            if from_cloud_storage:
                return Response(
                    headers={"Cache-Control": "no-store"},
                    media_type="application/zip",
                )
            file_path = os.path.join(self.archive_directory, file_name)
            with open(file_path, "rb") as archive:
                content = archive.read()
        except Exception as error:
            raise CertificateArchiveError from error

        return Response(
            content=content,
            headers={
                "Cache-Control": "no-store",
                "Content-Disposition": f'attachment; filename="{file_name}"',
            },
            media_type="application/zip",
        )
