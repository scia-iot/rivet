"""Serialized protected OpenVPN management UDS with fixed typed commands."""

import contextlib
import hashlib
import ipaddress
import socket
import stat
import struct
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path

from sciaiot.rivet.application.vpn_control import schemas as s
from sciaiot.rivet.application.vpn_control.errors import ControlError, ErrorCode

from . import bounded
from .settings import Settings


class Management:
    """Authenticate the listener creator before sending any management bytes."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.lock = threading.Lock()
        self.epoch = uuid.uuid4().hex
        self.socket_epoch = ""
        self.normalize: Callable[[s.Session, int], s.Session] | None = None

    @contextlib.contextmanager
    def _connection(self, deadline: float) -> Iterator[socket.socket]:
        path = Path(self.settings.management_socket)
        for ancestor in (path.parent, *path.parent.parents):
            if not stat.S_ISDIR(ancestor.lstat().st_mode):
                raise ControlError(ErrorCode.UNAUTHORIZED)
        parent = path.parent.lstat()
        if (
            parent.st_mode & 0o007
            or parent.st_gid != self.settings.management_gid
            or not stat.S_ISSOCK(path.lstat().st_mode)
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
            metadata = path.lstat()
            self.socket_epoch = (
                f"{metadata.st_dev}:{metadata.st_ino}:{metadata.st_ctime_ns}"
            )
            yield connection

    def _send(
        self,
        connection: socket.socket,
        command: str,
        deadline: float,
        *,
        write: bool = False,
    ) -> str:
        connection.settimeout(bounded.remaining(deadline))
        connection.sendall((command + "\n").encode("ascii"))
        result = bytearray()
        while True:
            connection.settimeout(bounded.remaining(deadline))
            chunk = connection.recv(65536)
            if not chunk:
                raise ControlError(ErrorCode.UNAVAILABLE)
            result.extend(chunk)
            if len(result) > bounded.MAX_BYTES:
                raise ControlError(ErrorCode.EXHAUSTED)
            lines = result.decode("utf-8").splitlines()
            if write and any(line.startswith("ERROR:") for line in lines):
                raise ControlError(ErrorCode.UNAVAILABLE)
            if (write and any(line.startswith("SUCCESS:") for line in lines)) or (
                not write and "END" in lines
            ):
                return "\n".join(
                    line for line in lines if line != "END" and not line.startswith(">")
                )

    def read(self, command: str, deadline: float) -> str:
        """Read only fixed observations after peer identity verification."""
        if command not in {"version", "state", "status 3"}:
            raise ControlError(ErrorCode.INVALID_INPUT)
        if not self.lock.acquire(timeout=bounded.remaining(deadline)):
            raise ControlError(ErrorCode.TIMEOUT)
        try:
            with self._connection(deadline) as connection:
                return self._send(connection, command, deadline)
        finally:
            self.lock.release()

    def disconnect(self, client: str, session_id: str, deadline: float) -> None:
        """Inspect and kill one exact client ID on the same daemon connection."""
        if not self.lock.acquire(timeout=bounded.remaining(deadline)):
            raise ControlError(ErrorCode.TIMEOUT)
        try:
            with self._connection(deadline) as connection:
                sessions = self._sessions(self._send(connection, "status 3", deadline))
                target = next(
                    (
                        item
                        for item in sessions
                        if item.session_id == session_id and item.client == client
                    ),
                    None,
                )
                if target is None:
                    return
                client_id = self._client_ids[target.session_id]
                self._send(connection, f"client-kill {client_id}", deadline, write=True)
                while True:
                    remaining = self._sessions(
                        self._send(connection, "status 3", deadline)
                    )
                    if not any(item.session_id == session_id for item in remaining):
                        break
                    time.sleep(min(0.02, bounded.remaining(deadline)))
        finally:
            self.lock.release()

    def reload(self, deadline: float) -> None:
        """Reconnect clients to consume projected state while preserving the tunnel."""
        if not self.lock.acquire(timeout=bounded.remaining(deadline)):
            raise ControlError(ErrorCode.TIMEOUT)
        try:
            with self._connection(deadline) as connection:
                self._send(connection, "signal SIGUSR1", deadline, write=True)
        finally:
            self.lock.release()

    def sessions(self, deadline: float) -> tuple[s.Session, ...]:
        """Parse header-addressed status 3 records without logging addresses."""
        return self._sessions(self.read("status 3", deadline))

    def _sessions(self, content: str) -> tuple[s.Session, ...]:
        self._client_ids: dict[str, int] = {}
        header: list[str] | None = None
        sessions: list[s.Session] = []
        records = 0
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
            records += 1
            if records > bounded.MAX_RECORDS:
                raise ControlError(ErrorCode.EXHAUSTED)
            record = dict(zip(header, fields[1:], strict=True))
            # OpenVPN reports non-halted TLS handshakes before assigning an
            # address (multi.c uses IA_EMPTY_IF_UNDEF). They are not VPN sessions
            # and must not invalidate an otherwise complete active snapshot.
            if record["Virtual Address"] == "":
                continue
            remote, port = record["Real Address"].rsplit(":", 1)
            remote = str(ipaddress.ip_address(remote.strip("[]")))
            identity = f"{record['Common Name']}|{remote}|{int(port)}|{record['Virtual Address']}|{int(record['Connected Since (time_t)']) * 1_000_000}"
            client_id = record["Client ID"]
            if (
                not client_id.isascii()
                or not client_id.isdecimal()
                or not 0 <= int(client_id) < 2**32
            ):
                raise ControlError(ErrorCode.INTEGRITY)
            digest = hashlib.sha256((self.socket_epoch + identity).encode()).digest()[
                :16
            ]
            self._client_ids[str(uuid.UUID(bytes=digest, version=4))] = int(client_id)
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
            if self.normalize is not None:
                sessions[-1] = self.normalize(sessions[-1], int(client_id))
            else:
                distinct = hashlib.sha256(
                    (
                        self.socket_epoch
                        + identity
                        + "|"
                        + client_id
                        + "|"
                        + record["Peer ID"]
                    ).encode()
                ).digest()[:16]
                sessions[-1] = sessions[-1].model_copy(
                    update={"session_id": str(uuid.UUID(bytes=distinct, version=4))}
                )
            self._client_ids[sessions[-1].session_id] = int(client_id)
        if header is None:
            raise ControlError(ErrorCode.INTEGRITY)
        return tuple(sorted(sessions, key=lambda item: item.session_id))
