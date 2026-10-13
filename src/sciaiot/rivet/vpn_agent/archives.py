"""Bounded in-memory credential ZIPs pinned to an active public generation."""

import hashlib
import io
import threading
import time
import zipfile
from collections.abc import Callable

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from sciaiot.rivet.application.vpn_control import archive
from sciaiot.rivet.application.vpn_control import schemas as s
from sciaiot.rivet.application.vpn_control.errors import ControlError, ErrorCode

from . import bounded, files
from .settings import Settings


class Source:
    """Release an immediate stream slot, including cancellation before reading."""

    def __init__(
        self, data: bytes, validate: Callable[[], None], release: Callable[[], None]
    ) -> None:
        self.data = io.BytesIO(data)
        self.validate = validate
        self.release = release
        self.closed = False

    def __next__(self) -> bytes:
        self.validate()
        chunk = self.data.read(s.MAX_CHUNK_BYTES)
        if not chunk:
            raise StopIteration
        return chunk

    def close(self) -> None:
        """Discard credential bytes and release the quota exactly once."""
        if not self.closed:
            self.closed = True
            self.data.close()
            self.release()


class Archives:
    """Generate bounded ZIPs without persistent API-readable credential files."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.slots = threading.BoundedSemaphore(s.MAX_STREAMS)

    def open(self, request: s.Request) -> archive.ArchiveStream:
        """Verify certificate/key pairing and generation before every chunk."""
        command = request.command
        if not isinstance(command, s.Archive):
            raise ControlError(ErrorCode.INVALID_INPUT)
        if not self.slots.acquire(blocking=False):
            raise ControlError(ErrorCode.EXHAUSTED)
        deadline = time.monotonic() + request.deadline_ms / 1000

        def validate() -> None:
            bounded.remaining(deadline)
            actual = next(
                (
                    item
                    for item in files.clients(self.settings, deadline)
                    if item.client == command.client
                ),
                None,
            )
            if (
                actual is None
                or actual.state != "active"
                or actual.generation != command.generation
            ):
                raise ControlError(ErrorCode.CONFLICT)

        source = None
        try:
            validate()
            payloads = {
                "ca.crt": bounded.read_file(
                    self.settings.pki_path / "ca.crt", deadline, 65536
                ),
                f"issued/{command.client}.crt": bounded.read_file(
                    self.settings.pki_path / "issued" / f"{command.client}.crt",
                    deadline,
                    65536,
                ),
                f"private/{command.client}.key": bounded.read_file(
                    self.settings.pki_path / "private" / f"{command.client}.key",
                    deadline,
                    65536,
                ),
            }
            certificate = x509.load_pem_x509_certificate(
                payloads[f"issued/{command.client}.crt"]
            )
            key = serialization.load_pem_private_key(
                payloads[f"private/{command.client}.key"], password=None
            )
            public = lambda value: value.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            if public(certificate.public_key()) != public(key.public_key()):
                raise ControlError(ErrorCode.INTEGRITY)
            output = io.BytesIO()
            with zipfile.ZipFile(
                output, "w", compression=zipfile.ZIP_DEFLATED
            ) as container:
                for name, payload in payloads.items():
                    container.writestr(name, payload)
            data = output.getvalue()
            output.close()
            if not 0 < len(data) <= s.MAX_ARCHIVE_BYTES:
                raise ControlError(ErrorCode.EXHAUSTED)
            validate()
            source = Source(data, validate, self.slots.release)
            manifest = s.ArchiveManifest(
                request_id=request.request_id,
                client=command.client,
                generation=command.generation,
                size=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
            )
            return archive.ArchiveStream(source, manifest, request, time.monotonic)
        except BaseException:
            if source is not None:
                source.close()
            else:
                self.slots.release()
            raise
