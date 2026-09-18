"""Serialized protected OpenVPN management UDS, fixed read commands only."""

import hashlib
import ipaddress
import socket
import stat
import struct
import threading
import uuid
from pathlib import Path

from sciaiot.ovpncp.application.vpn_control import schemas as s
from sciaiot.ovpncp.application.vpn_control.errors import ControlError, ErrorCode

from . import bounded
from .settings import Settings


class Management:
    """Authenticate the listener creator before sending any management bytes."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.lock = threading.Lock()
        self.epoch = uuid.uuid4().hex

    def read(self, command: str, deadline: float) -> str:
        """Read version, current state, or status 3 with a total deadline."""
        if command not in {"version", "state", "status 3"}:
            raise ControlError(ErrorCode.INVALID_INPUT)
        if not self.lock.acquire(timeout=bounded.remaining(deadline)):
            raise ControlError(ErrorCode.TIMEOUT)
        try:
            path = Path(self.settings.management_socket)
            for ancestor in (path.parent, *path.parent.parents):
                if not stat.S_ISDIR(ancestor.lstat().st_mode):
                    raise ControlError(ErrorCode.UNAUTHORIZED)
            parent = path.parent.lstat()
            sock = path.lstat()
            if (
                not stat.S_ISDIR(parent.st_mode)
                or parent.st_mode & 0o007
                or parent.st_gid != self.settings.management_gid
                or not stat.S_ISSOCK(sock.st_mode)
            ):
                raise ControlError(ErrorCode.UNAUTHORIZED)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(bounded.remaining(deadline))
                connection.connect(str(path))
                _, uid, gid = struct.unpack(
                    "iII",
                    connection.getsockopt(
                        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("iII")
                    ),
                )
                if (uid, gid) != (
                    self.settings.management_uid,
                    self.settings.management_gid,
                ):
                    raise ControlError(ErrorCode.UNAUTHORIZED)
                connection.sendall((command + "\n").encode("ascii"))
                result = bytearray()
                while b"END" not in result.splitlines():
                    connection.settimeout(bounded.remaining(deadline))
                    chunk = connection.recv(65536)
                    if not chunk:
                        raise ControlError(ErrorCode.UNAVAILABLE)
                    result.extend(chunk)
                    if len(result) > bounded.MAX_BYTES:
                        raise ControlError(ErrorCode.EXHAUSTED)
                lines = result.decode("utf-8").splitlines()
                return "\n".join(
                    line for line in lines if line != "END" and not line.startswith(">")
                )
        finally:
            self.lock.release()

    def sessions(self, deadline: float) -> tuple[s.Session, ...]:
        """Parse header-addressed status 3 records without logging addresses."""
        content = self.read("status 3", deadline)
        header: list[str] | None = None
        sessions: list[s.Session] = []
        for line in content.splitlines():
            fields = line.split("\t")
            if fields[:2] == ["HEADER", "CLIENT_LIST"]:
                if header is not None or len(fields[2:]) != len(set(fields[2:])):
                    raise ControlError(ErrorCode.INTEGRITY)
                header = fields[2:]
                mandatory = {
                    "Common Name",
                    "Real Address",
                    "Virtual Address",
                    "Connected Since (time_t)",
                    "Client ID",
                    "Peer ID",
                }
                if not mandatory.issubset(header):
                    raise ControlError(ErrorCode.INTEGRITY)
            if fields[0] != "CLIENT_LIST":
                continue
            if header is None or len(fields) != len(header) + 1:
                raise ControlError(ErrorCode.INTEGRITY)
            record = dict(zip(header, fields[1:], strict=True))
            remote, port = record["Real Address"].rsplit(":", 1)
            remote = str(ipaddress.ip_address(remote.strip("[]")))
            identity = "|".join(
                record[key]
                for key in (
                    "Common Name",
                    "Real Address",
                    "Connected Since (time_t)",
                    "Client ID",
                    "Peer ID",
                )
            )
            digest = hashlib.sha256((self.epoch + identity).encode()).digest()[:16]
            sessions.append(
                s.Session(
                    session_id=str(uuid.UUID(bytes=digest, version=4)),
                    client=record["Common Name"],
                    address=record["Virtual Address"],
                    remote_address=remote,
                    remote_port=int(port),
                    connected_at=int(record["Connected Since (time_t)"]) * 1_000_000,
                )
            )
            if len(sessions) > bounded.MAX_RECORDS:
                raise ControlError(ErrorCode.EXHAUSTED)
        if header is None:
            raise ControlError(ErrorCode.INTEGRITY)
        return tuple(sorted(sessions, key=lambda item: item.session_id))
