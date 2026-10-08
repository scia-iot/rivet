"""Protected local daemon ingestion; no API callback or VPN availability gate."""

import hashlib
import os
import socket
import stat
import struct
import threading
import time
import uuid
from pathlib import Path

from sciaiot.ovpncp.application.vpn_control import schemas as s
from sciaiot.ovpncp.application.vpn_control.errors import ControlError, ErrorCode

from . import bounded
from .events import EventSpool
from .settings import Settings


def session_identity(session: s.Session, management_socket: Path) -> str:
    """Bind a hook session to a daemon socket incarnation and observed tuple."""
    metadata = management_socket.lstat()
    epoch = f"{metadata.st_dev}:{metadata.st_ino}:{metadata.st_ctime_ns}"
    identity = f"{session.client}|{session.remote_address}|{session.remote_port}|{session.address}|{session.connected_at}"
    return str(
        uuid.UUID(
            bytes=hashlib.sha256((epoch + identity).encode()).digest()[:16], version=4
        )
    )


class Ingress:
    """Persist authenticated hook events in an independent bounded worker."""

    def __init__(self, settings: Settings, spool: EventSpool) -> None:
        if settings.event_socket is None:
            raise ValueError("Events require an explicit private daemon socket.")
        self.settings = settings
        self.spool = spool
        self.path = Path(settings.event_socket)
        for ancestor in (self.path.parent, *self.path.parent.parents):
            if not stat.S_ISDIR(ancestor.lstat().st_mode):
                raise ControlError(ErrorCode.UNAUTHORIZED)
        metadata = self.path.parent.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o2770
            or metadata.st_gid != settings.management_gid
        ):
            raise ControlError(ErrorCode.UNAUTHORIZED)
        self.stopped = threading.Event()
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.inode: int | None = None
        try:
            if self.path.exists():
                old = self.path.lstat()
                if not stat.S_ISSOCK(old.st_mode) or old.st_uid != os.getuid():
                    raise ControlError(ErrorCode.UNAUTHORIZED)
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                    probe.settimeout(0.05)
                    try:
                        probe.connect(str(self.path))
                    except ConnectionRefusedError:
                        if self.path.lstat().st_ino != old.st_ino:
                            raise ControlError(ErrorCode.CONFLICT) from None
                        self.path.unlink()
                    else:
                        raise ControlError(ErrorCode.CONFLICT)
            self.listener.bind(str(self.path))
            self.inode = self.path.lstat().st_ino
            os.chmod(self.path, 0o660)
            self.listener.listen(100)
            self.listener.settimeout(0.1)
        except BaseException:
            self.listener.close()
            if (
                self.inode is not None
                and self.path.exists()
                and self.path.lstat().st_ino == self.inode
            ):
                self.path.unlink()
            raise
        self.thread = threading.Thread(
            target=self._run, name="vpn-daemon-events", daemon=True
        )
        self.dirty = True
        self._gap_marker = b""
        self.thread.start()

    def close(self) -> None:
        """Stop the local producer worker before the journal closes."""
        self.stopped.set()
        self.listener.close()
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            raise ControlError(ErrorCode.TIMEOUT)
        if self.path.exists() and self.path.lstat().st_ino == self.inode:
            self.path.unlink()

    def _run(self) -> None:
        while not self.stopped.is_set():
            try:
                gap_path = self.path.parent / "producer-gap"
                try:
                    marker = bounded.read_file(gap_path, time.monotonic() + 0.1, 128)
                except FileNotFoundError:
                    marker = b""
                if self.dirty or marker != self._gap_marker:
                    self.spool.gap()
                    self.dirty = False
                    self._gap_marker = marker
                connection, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError, ControlError:
                self.dirty = True
                self.stopped.wait(0.1)
                continue
            with connection:
                try:
                    _, uid, gid = struct.unpack(
                        "iII",
                        connection.getsockopt(
                            socket.SOL_SOCKET,
                            socket.SO_PEERCRED,
                            struct.calcsize("iII"),
                        ),
                    )
                    if (uid, gid) != (
                        self.settings.event_uid
                        if self.settings.event_uid is not None
                        else self.settings.management_uid,
                        self.settings.management_gid,
                    ):
                        raise ControlError(ErrorCode.UNAUTHORIZED)
                    deadline = time.monotonic() + 0.2
                    data = bytearray()
                    while b"\n" not in data:
                        connection.settimeout(bounded.remaining(deadline))
                        chunk = connection.recv(4096)
                        if not chunk or len(data) + len(chunk) > 4096:
                            raise ControlError(ErrorCode.INVALID_INPUT)
                        data.extend(chunk)
                    event = s.Event.model_validate_json(bytes(data))
                    if (
                        event.sequence != 0
                        or event.event == "gap"
                        or event.session is None
                    ):
                        raise ControlError(ErrorCode.INVALID_INPUT)
                    if event.session.session_id != session_identity(
                        event.session, Path(self.settings.management_socket)
                    ):
                        raise ControlError(ErrorCode.INTEGRITY)
                    self.spool.produce(event)
                    connection.sendall(b"ok\n")
                except Exception:  # noqa: BLE001 - never let producer diagnostics escape
                    self.dirty = True
