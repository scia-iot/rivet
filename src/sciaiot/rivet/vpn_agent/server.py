"""Private bounded HTTP/JSON server authenticating peers before reading bytes."""

import os
import socket
import stat
import struct
import threading
import time
from pathlib import Path
from types import TracebackType
from typing import Self

from sciaiot.rivet.application.vpn_control import schemas as s
from sciaiot.rivet.application.vpn_control import wire
from sciaiot.rivet.application.vpn_control.errors import (
    ControlError,
    ErrorCode,
    problem_status,
)

from . import bounded
from .control import ReadOnlyVpnControl
from .settings import Settings
from .writer import MutationVpnControl


class UnixAgentServer:
    """One active request and a bounded kernel backlog, with no worker leaks."""

    def __init__(
        self, settings: Settings, control: ReadOnlyVpnControl | None = None
    ) -> None:
        self.settings = settings
        self.stopped = threading.Event()
        path = Path(settings.control_socket)
        for parent in (path.parent, *path.parent.parents):
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError("Agent socket ancestry must contain real directories.")
        parent_info = path.parent.lstat()
        if (
            parent_info.st_uid != os.getuid()
            or stat.S_IMODE(parent_info.st_mode) != 0o2750
        ):
            raise ValueError(
                "Agent socket directory must be owned by agent with mode 02750."
            )
        self.control = control or (
            MutationVpnControl(settings)
            if settings.mutation_families
            else ReadOnlyVpnControl(settings)
        )
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.inode: int | None = None
        try:
            if isinstance(self.control, MutationVpnControl) and path.exists():
                old = path.lstat()
                if not stat.S_ISSOCK(old.st_mode) or old.st_uid != os.getuid():
                    raise ValueError("Refusing foreign control socket.")
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                    probe.settimeout(0.05)
                    try:
                        probe.connect(str(path))
                    except ConnectionRefusedError:
                        if path.lstat().st_ino != old.st_ino:
                            raise ValueError("Control socket changed.") from None
                        path.unlink()
                    else:
                        raise ValueError("An existing control listener is active.")
            self.listener.bind(str(path))
            self.inode = path.lstat().st_ino
            os.chmod(path, 0o660, follow_symlinks=False)
            self.listener.listen(16)
            self.listener.settimeout(0.1)
            if isinstance(self.control, MutationVpnControl):
                self.control.start()
        except Exception:
            self.shutdown()
            if isinstance(self.control, MutationVpnControl):
                self.control.close()
            raise

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.shutdown()
        if isinstance(self.control, MutationVpnControl):
            self.control.close()

    def shutdown(self) -> None:
        """Stop accepting requests and remove only this instance's socket."""
        self.stopped.set()
        self.listener.close()
        path = Path(self.settings.control_socket)
        try:
            if path.lstat().st_ino == self.inode:
                path.unlink()
        except FileNotFoundError:
            pass

    def serve_forever(self) -> None:
        """Serve fixed-deadline requests without touching VPN lifecycle state."""
        while not self.stopped.is_set():
            try:
                connection, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if self.stopped.is_set():
                    break
                raise
            with connection:
                try:
                    self.handle(connection)
                except ControlError, OSError, ValueError, UnicodeError:
                    # Malformed/unauthenticated requests have no trusted ID.
                    pass

    def handle(self, connection: socket.socket) -> None:
        """Authenticate SO_PEERCRED before consuming HTTP headers or body."""
        _, uid, _ = struct.unpack(
            "iII",
            connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("iII")
            ),
        )
        if uid != self.settings.api_uid:
            raise ControlError(ErrorCode.UNAUTHORIZED)
        deadline = time.monotonic() + 2
        data = bytearray()
        while b"\r\n\r\n" not in data:
            connection.settimeout(bounded.remaining(deadline))
            chunk = connection.recv(4096)
            if not chunk:
                raise ControlError(ErrorCode.INVALID_INPUT)
            data.extend(chunk)
            if len(data) > 16384:
                raise ControlError(ErrorCode.EXHAUSTED)
        raw_headers, prefix = bytes(data).split(b"\r\n\r\n", 1)
        lines = raw_headers.decode("ascii").split("\r\n")
        route = lines.pop(0)
        if route not in {"POST /v1/control HTTP/1.1", "POST /v1/archive HTTP/1.1"}:
            raise ControlError(ErrorCode.UNAVAILABLE)
        headers: dict[str, str] = {}
        for line in lines:
            name, value = line.split(":", 1)
            name = name.lower()
            if name in headers or not name or name.strip() != name:
                raise ControlError(ErrorCode.INVALID_INPUT)
            headers[name] = value.strip()
        length = headers.get("content-length", "")
        if (
            not length.isdecimal()
            or len(length) > 7
            or "transfer-encoding" in headers
            or headers.get("content-type") != "application/json"
            or headers.get("connection", "").lower() != "close"
        ):
            raise ControlError(ErrorCode.INVALID_INPUT)
        size = int(length)
        if not 0 < size <= s.MAX_JSON_BYTES or len(prefix) > size:
            raise ControlError(ErrorCode.EXHAUSTED)
        body = bytearray(prefix)
        while len(body) < size:
            connection.settimeout(bounded.remaining(deadline))
            chunk = connection.recv(min(65536, size - len(body)))
            if not chunk:
                raise ControlError(ErrorCode.INVALID_INPUT)
            body.extend(chunk)
        request = wire.decode_request(bytes(body))
        deadline = time.monotonic() + request.deadline_ms / 1000
        archive_started = False
        try:
            if route == "POST /v1/archive HTTP/1.1":
                with self.control.open_archive(request) as stream:
                    manifest = wire.encode(
                        s.Response(
                            request_id=request.request_id, result=stream.manifest
                        )
                    )
                    size = 4 + len(manifest) + stream.manifest.size
                    connection.settimeout(bounded.remaining(deadline))
                    archive_started = True
                    connection.sendall(
                        (
                            f"HTTP/1.1 200 Result\r\nContent-Type: application/octet-stream\r\nContent-Length: {size}\r\nConnection: close\r\n\r\n"
                        ).encode()
                        + struct.pack("!I", len(manifest))
                        + manifest
                    )
                    for chunk in stream:
                        connection.settimeout(bounded.remaining(deadline))
                        connection.sendall(chunk)
                return
            response = self.control.execute(request)
        except ControlError as error:
            if archive_started:
                return
            response = s.Response(
                request_id=request.request_id, result=s.Failure(code=error.code)
            )
        payload = wire.encode(response)
        status = (
            problem_status(response.result.code)
            if isinstance(response.result, s.Failure)
            else 200
        )
        connection.settimeout(bounded.remaining(deadline))
        connection.sendall(
            (
                f"HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
            ).encode()
            + payload
        )
