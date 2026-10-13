"""Shared safe certificate archive operations."""

import os
import tempfile
from pathlib import Path

from fastapi import Response

from sciaiot.rivet import dependencies
from sciaiot.rivet.adapters.vpn.host import HostVpnControl
from sciaiot.rivet.application.vpn_control import schemas as s
from sciaiot.rivet.application.vpn_control import wire
from sciaiot.rivet.data.server import Client
from sciaiot.rivet.services import vpn


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
            control = dependencies.get_vpn_control()
            if isinstance(control, HostVpnControl):
                control.package_legacy(client.name, self.archive_directory)
            else:
                content, generation = self._verified_archive(client)
                target = Path(self.archive_directory, f"{client.name}.zip")
                target.parent.mkdir(parents=True, exist_ok=True)
                descriptor, name = tempfile.mkstemp(
                    dir=target.parent, prefix=".archive-"
                )
                try:
                    with os.fdopen(descriptor, "wb") as stream:
                        stream.write(content)
                        stream.flush()
                        os.fsync(stream.fileno())
                    self._check_generation(client, generation)
                    os.replace(name, target)
                finally:
                    Path(name).unlink(missing_ok=True)
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
            vpn.validate_name(client.name)
            if not isinstance(dependencies.get_vpn_control(), HostVpnControl):
                return Response(
                    content=self._verified_archive(client)[0],
                    headers={
                        "Cache-Control": "no-store",
                        "Content-Disposition": f'attachment; filename="{client.name}.zip"',
                    },
                    media_type="application/zip",
                )
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

    def _verified_archive(self, client: Client) -> tuple[bytes, int]:
        """Pin, bound and verify a fresh archive before any public publication."""
        vpn.validate_name(client.name)
        control = dependencies.get_vpn_control()
        observed = control.execute(vpn.request(s.GetClient(client=client.name)))
        wire.require_success(observed)
        if (
            not isinstance(observed.result, s.ClientResult)
            or observed.result.item.state != "active"
            or client.revoked
        ):
            raise CertificateArchiveError
        generation = observed.result.item.generation
        with control.open_archive(
            vpn.request(s.Archive(client=client.name, generation=generation))
        ) as stream:
            content = b"".join(stream)
            if not stream.verified:
                raise CertificateArchiveError
        self._check_generation(client, generation)
        return content, generation

    def _check_generation(self, client: Client, generation: int) -> None:
        """Recheck active generation immediately before cache or HTTP publication."""
        final = dependencies.get_vpn_control().execute(
            vpn.request(s.GetClient(client=client.name))
        )
        wire.require_success(final)
        if (
            not isinstance(final.result, s.ClientResult)
            or final.result.item.state != "active"
            or final.result.item.generation != generation
        ):
            raise CertificateArchiveError
