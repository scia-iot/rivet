"""Bounded no-follow reads and fixed read-only system observations."""

import hashlib
import os
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from pathlib import Path

from sciaiot.rivet.application.vpn_control.errors import ControlError, ErrorCode

MAX_BYTES = 1024 * 1024
MAX_RECORDS = 10_000


def remaining(deadline: float) -> float:
    """Return the remaining total budget, rejecting an elapsed deadline."""
    value = deadline - time.monotonic()
    if value <= 0:
        raise ControlError(ErrorCode.TIMEOUT)
    return value


def read_file(path: Path, deadline: float, maximum: int = MAX_BYTES) -> bytes:
    """Read a stable regular file without following any path-component links."""
    remaining(deadline)
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    descriptor = -1
    try:
        for part in path.parts[1:-1]:
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
            )
            os.close(directory)
            directory = child
        descriptor = os.open(
            path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        before = os.fstat(descriptor)
        if before.st_nlink != 1:
            raise ControlError(ErrorCode.INTEGRITY)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ControlError(ErrorCode.EXHAUSTED)
        result = bytearray()
        while True:
            remaining(deadline)
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
            if len(result) > maximum:
                raise ControlError(ErrorCode.EXHAUSTED)
        after = os.fstat(descriptor)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ControlError(ErrorCode.CONFLICT)
        return bytes(result)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory)


def revision(data: bytes) -> int:
    """Content revision, never a mutation journal generation or secret digest."""
    return int.from_bytes(hashlib.sha256(data).digest()[:8]) & (2**63 - 1)


def observe(kind: str, device: str, deadline: float) -> bytes:
    """Execute one fixed read-only command with bounded output and cleanup."""
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}", device) is None:
        raise ControlError(ErrorCode.INVALID_INPUT)
    remaining(deadline)
    commands = {
        "routes": ["/usr/sbin/ip", "-N", "-j", "-4", "route", "show"],
        "link": ["/usr/sbin/ip", "-j", "link", "show", "dev", device],
        "rules": ["/usr/sbin/iptables-nft-save", "-t", "filter"],
        "backend": ["/usr/sbin/iptables-nft-save", "--version"],
    }
    if kind not in commands:
        raise ControlError(ErrorCode.INVALID_INPUT)
    return command(commands[kind], deadline)


def command(
    arguments: list[str], deadline: float, input_data: bytes | None = None
) -> bytes:
    """Run internally constructed argument arrays with bounded output/deadline.

    This private helper is never exposed as a wire operation; callers must
    construct arguments from validated domain commands and deployment settings.
    """
    staged = tempfile.TemporaryFile() if input_data is not None else None  # noqa: SIM115 - closed before child output handling
    if staged is not None:
        assert input_data is not None
        if len(input_data) > MAX_BYTES:
            staged.close()
            raise ControlError(ErrorCode.EXHAUSTED)
        staged.write(input_data)
        staged.seek(0)
    try:
        process = subprocess.Popen(
            arguments,
            stdin=staged if staged is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
            env={
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LC_ALL": "C",
                "EASYRSA_NO_VARS": "1",
            },
        )
    finally:
        if staged is not None:
            staged.close()
    try:
        assert process.stdout is not None
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            result = bytearray()
            while True:
                if not selector.select(remaining(deadline)):
                    raise ControlError(ErrorCode.TIMEOUT)
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    break
                result.extend(chunk)
                if len(result) > MAX_BYTES:
                    raise ControlError(ErrorCode.EXHAUSTED)
            if process.wait(timeout=remaining(deadline)) != 0:
                raise ControlError(ErrorCode.UNAVAILABLE)
            return bytes(result)
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        if process.stdout is not None:
            process.stdout.close()
