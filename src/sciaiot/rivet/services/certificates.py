"""Shared safe certificate archive operations."""

import logging
import tempfile

from fastapi import Response

from sciaiot.rivet import dependencies
from sciaiot.rivet.adapters.storage.local import LocalArchiveStore
from sciaiot.rivet.adapters.vpn.host import HostVpnControl
from sciaiot.rivet.adapters.vpn.shadow import ShadowHostVpnControl
from sciaiot.rivet.application.storage import (
    ArchiveStore,
    archive_name,
    validate_content,
)
from sciaiot.rivet.application.vpn_control import schemas as s
from sciaiot.rivet.application.vpn_control import wire
from sciaiot.rivet.data.server import Client
from sciaiot.rivet.services import vpn

logger = logging.getLogger(__name__)


class CertificateArchiveError(Exception):
    """Raised when a certificate archive operation fails safely."""


class CertificateArchiveService:
    """Package and load client archives behind one validated boundary."""

    def __init__(
        self, archive_directory: str, store: ArchiveStore | None = None
    ) -> None:
        """Initialize archive operations.

        Args:
            archive_directory: Trusted directory containing packaged archives.
        """
        self.archive_directory = archive_directory
        self.store = store if store is not None else dependencies.get_archive_store()

    def package(self, client: Client) -> None:
        """Package one authorized client's credential archive.

        Args:
            client: Client already authorized by the calling route.

        Raises:
            CertificateArchiveError: If validation or packaging fails.
        """
        try:
            vpn.validate_name(client.name)
            if client.revoked:
                raise CertificateArchiveError
            control = dependencies.get_vpn_control()
            staging = LocalArchiveStore(self.archive_directory)
            if isinstance(control, HostVpnControl) and not isinstance(
                control, ShadowHostVpnControl
            ):
                with tempfile.TemporaryDirectory(prefix="rivet-archive-") as work:
                    control.package_legacy(client.name, work)
                    content = LocalArchiveStore(work).get(client.name)
                staging.put(client.name, content)
            else:
                content, generation = self._verified_archive(client)
                staging.put(
                    client.name,
                    content,
                    before_publish=lambda: self._check_generation(client, generation),
                )
            if (
                not isinstance(self.store, LocalArchiveStore)
                or self.store.directory != staging.directory
            ):
                if not isinstance(control, HostVpnControl) or isinstance(
                    control, ShadowHostVpnControl
                ):
                    self._check_generation(client, generation)
                self.store.put(client.name, content)
        except Exception as error:
            raise CertificateArchiveError from error

    def download_response(
        self,
        client: Client,
    ) -> Response:
        """Build a no-store response for an authorized client archive.

        Args:
            client: Client already authorized by the calling route.
        Returns:
            A bounded ZIP attachment with no-store cache policy.

        Raises:
            CertificateArchiveError: If validation or local reading fails.
        """
        try:
            vpn.validate_name(client.name)
            if client.revoked:
                raise CertificateArchiveError
            control = dependencies.get_vpn_control()
            if not isinstance(control, HostVpnControl) or isinstance(
                control, ShadowHostVpnControl
            ):
                content = self._verified_archive(client)[0]
            else:
                content = self.store.get(client.name)
            validate_content(content)
            file_name = archive_name(client.name)
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

    def delete_after_commit(self, client_name: str) -> None:
        """Clean up an archive after durable deletion without changing 204."""
        try:
            vpn.validate_name(client_name)
            self.store.delete(client_name)
        except Exception:  # noqa: BLE001 - durable deletion cannot be rolled back
            logger.error(
                "VPN client archive cleanup failed after deletion; remove "
                "the orphaned archive from the selected store manually."
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
