"""Bounded HTTP/JSON client over an authenticated Linux Unix socket."""

import socket
import struct
import threading
import time
import uuid
from collections.abc import Callable

from sciaiot.rivet.application.vpn_control import archive, wire
from sciaiot.rivet.application.vpn_control import schemas as s
from sciaiot.rivet.application.vpn_control.errors import (
    ControlError,
    ErrorCode,
    problem_status,
)

from .settings import BackendSettings, validate_socket_path


class SocketBody:
    """A fixed-length, deadline-bounded body owning its connection."""

    def __init__(
        self,
        connection: socket.socket,
        prefix: bytes,
        length: int,
        deadline: float,
        release: Callable[[], None],
    ) -> None:
        self.connection = connection
        self.prefix = prefix
        self.remaining = length
        self.deadline = deadline
        self.release = release
        self.closed = False

    def _timeout(self) -> None:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ControlError(ErrorCode.TIMEOUT)
        self.connection.settimeout(remaining)

    def read(self, size: int) -> bytes:
        """Read exactly a bounded number of bytes within the total deadline."""
        if size < 0 or size > self.remaining:
            raise ControlError(ErrorCode.INTEGRITY)
        result = bytearray()
        try:
            while len(result) < size:
                self._timeout()
                if self.prefix:
                    chunk = self.prefix[: size - len(result)]
                    self.prefix = self.prefix[len(chunk) :]
                else:
                    chunk = self.connection.recv(
                        min(size - len(result), s.MAX_CHUNK_BYTES)
                    )
                if not chunk:
                    raise ControlError(ErrorCode.INTEGRITY)
                result.extend(chunk)
            self.remaining -= size
            return bytes(result)
        except TimeoutError:
            raise ControlError(ErrorCode.TIMEOUT) from None
        except OSError:
            raise ControlError(ErrorCode.UNAVAILABLE) from None

    def verify_end(self) -> None:
        """Reject bytes beyond the declared body on a Connection: close reply."""
        self._timeout()
        try:
            if self.prefix or self.connection.recv(1):
                raise ControlError(ErrorCode.INTEGRITY)
        except TimeoutError:
            raise ControlError(ErrorCode.TIMEOUT) from None
        except OSError:
            raise ControlError(ErrorCode.UNAVAILABLE) from None

    def __next__(self) -> bytes:
        if self.closed:
            raise StopIteration
        if self.remaining == 0:
            self.verify_end()
            raise StopIteration
        return self.read(min(self.remaining, s.MAX_CHUNK_BYTES))

    def close(self) -> None:
        """Cancel pending reads and release the connection and stream slot."""
        if not self.closed:
            self.closed = True
            try:
                self.connection.close()
            finally:
                self.release()


class AgentVpnControl:
    """Speak protocol 1.0 only to a configured kernel-authenticated peer.

    Each call negotiates readiness within the original total deadline. No
    mutation is automatically replayed after transport uncertainty.
    """

    def __init__(self, socket_path: str, *, peer_uid: int | None = None) -> None:
        self.socket_path = validate_socket_path(socket_path)
        if peer_uid is None:
            peer_uid = BackendSettings.from_environment().peer_uid
        if type(peer_uid) is not int or not 0 <= peer_uid < 2**32 - 1:
            raise ValueError("A trusted agent peer UID is required.")
        self.peer_uid = peer_uid
        self._streams = threading.BoundedSemaphore(s.MAX_STREAMS)

    def _exchange(
        self,
        request: s.Request,
        path: str,
        deadline: float,
        *,
        archive_body: bool = False,
        release: Callable[[], None] = lambda: None,
    ) -> tuple[int, str, SocketBody]:
        payload = wire.encode(request)
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ControlError(ErrorCode.TIMEOUT)
            connection.settimeout(remaining)
            connection.connect(self.socket_path)
            _, uid, _ = struct.unpack(
                "iII",
                connection.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("iII")
                ),
            )
            if uid != self.peer_uid:
                raise ControlError(ErrorCode.UNAUTHORIZED)
            connection.settimeout(max(0.001, deadline - time.monotonic()))
            headers = (
                f"POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
            ).encode("ascii")
            connection.sendall(headers + payload)
            data = bytearray()
            while b"\r\n\r\n" not in data:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ControlError(ErrorCode.TIMEOUT)
                connection.settimeout(remaining)
                chunk = connection.recv(4096)
                if not chunk:
                    raise ControlError(ErrorCode.INTEGRITY)
                data.extend(chunk)
                if len(data) > 16 * 1024:
                    raise ControlError(ErrorCode.INTEGRITY)
            raw_headers, prefix = bytes(data).split(b"\r\n\r\n", 1)
            lines = raw_headers.decode("ascii").split("\r\n")
            status = lines.pop(0).split(" ")
            if (
                len(status) < 2
                or status[0] != "HTTP/1.1"
                or len(status[1]) != 3
                or not status[1].isdigit()
            ):
                raise ControlError(ErrorCode.INTEGRITY)
            code = int(status[1])
            fields: dict[str, str] = {}
            for line in lines:
                name, value = line.split(":", 1)
                name = name.lower()
                if name in fields or not name or name.strip() != name:
                    raise ControlError(ErrorCode.INTEGRITY)
                fields[name] = value.strip()
            raw_length = fields.get("content-length", "")
            if "transfer-encoding" in fields or not raw_length.isdecimal():
                raise ControlError(ErrorCode.INTEGRITY)
            length = int(raw_length)
            maximum = (
                s.MAX_ARCHIVE_BYTES + s.MAX_JSON_BYTES + 4
                if archive_body and code == 200
                else s.MAX_JSON_BYTES
            )
            if not 0 < length <= maximum or len(prefix) > length:
                raise ControlError(ErrorCode.INTEGRITY)
            media_type = fields.get("content-type", "").split(";", 1)[0].strip()
            body = SocketBody(connection, prefix, length, deadline, release)
            return code, media_type, body
        except ControlError:
            connection.close()
            raise
        except TimeoutError:
            connection.close()
            raise ControlError(ErrorCode.TIMEOUT) from None
        except OSError, ValueError, UnicodeError:
            connection.close()
            raise ControlError(ErrorCode.UNAVAILABLE) from None

    def _json(self, request: s.Request, deadline: float) -> s.Response:
        status, media_type, body = self._exchange(request, "/v1/control", deadline)
        try:
            if media_type != "application/json":
                raise ControlError(ErrorCode.INTEGRITY)
            response = wire.decode_response(body.read(body.remaining), request)
            body.verify_end()
            expected = (
                problem_status(response.result.code)
                if isinstance(response.result, s.Failure)
                else 200
            )
            if status != expected:
                raise ControlError(ErrorCode.INTEGRITY)
            return response
        finally:
            body.close()

    def _handshake(self, deadline: float, *, require_ready: bool = True) -> None:
        budget = int((deadline - time.monotonic()) * 1000)
        if budget <= 0:
            raise ControlError(ErrorCode.TIMEOUT)
        request = s.Request(
            request_id=str(uuid.uuid4()),
            command=s.Health(),
            deadline_ms=min(budget, s.MAX_DEADLINE_MS),
        )
        response = self._json(request, deadline)
        wire.require_success(response)
        if not isinstance(response.result, s.HealthResult) or (
            require_ready and not response.result.ready
        ):
            raise ControlError(ErrorCode.UNAVAILABLE)

    def execute(self, request: s.Request) -> s.Response:
        """Return a correlated bounded result; never silently downgrade."""
        request = wire.decode_request(wire.encode(request))
        if isinstance(request.command, s.Archive):
            raise ControlError(ErrorCode.INVALID_INPUT)
        deadline = time.monotonic() + request.deadline_ms / 1000
        if not isinstance(request.command, s.Health):
            self._handshake(
                deadline,
                require_ready=not isinstance(request.command, s.LookupOperation),
            )
        response = self._json(request, deadline)
        if isinstance(response.result, s.Failure):
            raise ControlError(response.result.code)
        return response

    def open_archive(self, request: s.Request) -> archive.ArchiveStream:
        """Own the connection and slot before returning an archive iterator."""
        request = wire.decode_request(wire.encode(request))
        if not isinstance(request.command, s.Archive):
            raise ControlError(ErrorCode.INVALID_INPUT)
        if not self._streams.acquire(blocking=False):
            raise ControlError(ErrorCode.EXHAUSTED)
        body: SocketBody | None = None
        try:
            deadline = time.monotonic() + request.deadline_ms / 1000
            self._handshake(deadline)
            status, media_type, body = self._exchange(
                request,
                "/v1/archive",
                deadline,
                archive_body=True,
                release=self._streams.release,
            )
            if status != 200:
                if media_type != "application/json":
                    raise ControlError(ErrorCode.INTEGRITY)
                response = wire.decode_response(body.read(body.remaining), request)
                if not isinstance(
                    response.result, s.Failure
                ) or status != problem_status(response.result.code):
                    raise ControlError(ErrorCode.INTEGRITY)
                wire.require_success(response)
            if media_type != "application/octet-stream":
                raise ControlError(ErrorCode.INTEGRITY)
            size = struct.unpack("!I", body.read(4))[0]
            if not 0 < size <= s.MAX_JSON_BYTES:
                raise ControlError(ErrorCode.INTEGRITY)
            response = wire.decode_response(body.read(size), request)
            manifest = response.result
            if (
                not isinstance(manifest, s.ArchiveManifest)
                or body.remaining != manifest.size
            ):
                raise ControlError(ErrorCode.INTEGRITY)
            remaining = int((deadline - time.monotonic()) * 1000)
            if remaining <= 0:
                raise ControlError(ErrorCode.TIMEOUT)
            bounded = request.model_copy(update={"deadline_ms": remaining})
            return archive.ArchiveStream(body, manifest, bounded, time.monotonic)
        except Exception:
            if body is not None:
                body.close()
            else:
                self._streams.release()
            raise
