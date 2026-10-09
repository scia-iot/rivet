"""Explicit bounded stream ownership independent of files or transport."""

import hashlib
from collections.abc import Callable, Iterator
from types import TracebackType
from typing import Protocol, Self

from . import schemas, wire
from .errors import ControlError, ErrorCode


class ChunkSource(Protocol):
    """Adapter-owned binary source with bounded blocking IO and cancellation."""

    def __next__(self) -> bytes:
        """Return one bounded chunk within the adapter's remaining deadline."""
        ...

    def close(self) -> None:
        """Cancel IO and release the archive slot, including before first read."""
        ...


class ArchiveStream(Iterator[bytes]):
    """Own the source immediately; close on error, exhaustion or cancellation.

    Consumers must use a context manager, exhaust and verify before publishing
    their private staged archive. Earlier chunks are unverified until EOF.
    The injected clock measures elapsed seconds; adapters must separately
    enforce blocking IO timeouts because this wrapper cannot preempt next().
    """

    def __init__(
        self,
        source: ChunkSource,
        manifest: schemas.ArchiveManifest,
        request: schemas.Request,
        clock: Callable[[], float],
    ) -> None:
        self._source = source
        self._closed = False
        self.verified = False
        self._size = 0
        self._digest = hashlib.sha256()
        self._clock = clock
        try:
            request = wire.decode_request(wire.encode(request))
            response = schemas.Response(
                request_id=request.request_id,
                result=manifest,
            )
            wire.decode_response(wire.encode(response), request)
            self.manifest = manifest
            self._deadline = clock() + request.deadline_ms / 1000
        except Exception:  # noqa: BLE001 - redact all adapter boundary failures
            self.close()
            raise ControlError(ErrorCode.INTEGRITY) from None

    def __next__(self) -> bytes:
        if self._closed:
            raise StopIteration
        try:
            self._check_deadline()
            try:
                chunk = next(self._source)
            except StopIteration:
                self._check_deadline()
                if (
                    self._size != self.manifest.size
                    or self._digest.hexdigest() != self.manifest.sha256
                ):
                    raise ControlError(ErrorCode.INTEGRITY) from None
                self.verified = True
                self.close()
                raise
            self._check_deadline()
            if not isinstance(chunk, bytes) or not 0 < len(chunk) <= (
                schemas.MAX_CHUNK_BYTES
            ):
                raise ControlError(ErrorCode.INTEGRITY)
            self._size += len(chunk)
            if self._size > self.manifest.size:
                raise ControlError(ErrorCode.INTEGRITY)
            self._digest.update(chunk)
            return chunk
        except StopIteration:
            raise
        except ControlError:
            self.close()
            raise
        except Exception:  # noqa: BLE001 - redact all adapter boundary failures
            self.close()
            raise ControlError(ErrorCode.UNAVAILABLE) from None

    def _check_deadline(self) -> None:
        if self._clock() >= self._deadline:
            raise ControlError(ErrorCode.TIMEOUT)

    def close(self) -> None:
        """Cancel/release exactly once, including an entirely unread stream."""
        if not self._closed:
            self._closed = True
            try:
                self._source.close()
            except Exception:  # noqa: BLE001 - redact all adapter boundary failures
                # Cleanup must not disclose transport or credential diagnostics.
                self.verified = False

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
