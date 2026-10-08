"""Drop root while retaining only NET_ADMIN across agent child execs.

Docker does not populate ambient capabilities for a non-root container user.
No application code or operator configuration is loaded before the drop.
"""

import ctypes
import os
import sys
from pathlib import Path

_NET_ADMIN = 12
_NET_ADMIN_MASK = 1 << _NET_ADMIN


class _Header(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _Data(ctypes.Structure):
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]


def _prctl(*args: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(*args) != 0:
        raise OSError(ctypes.get_errno(), "Privilege transition failed")


def _net_admin_only() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.capset.argtypes = [ctypes.POINTER(_Header), ctypes.POINTER(_Data)]
    libc.capset.restype = ctypes.c_int
    header = _Header(0x20080522, 0)  # Linux capability ABI v3, current thread.
    data = (_Data * 2)()
    data[0] = _Data(_NET_ADMIN_MASK, _NET_ADMIN_MASK, _NET_ADMIN_MASK)
    if libc.capset(ctypes.byref(header), data) != 0:
        raise OSError(ctypes.get_errno(), "Capability transition failed")


def _verify() -> None:
    status = {}
    for line in Path("/proc/self/status").read_text().splitlines():
        key, _, value = line.partition(":")
        status[key] = value.strip()
    for key in ("CapInh", "CapPrm", "CapEff", "CapAmb"):
        if int(status[key], 16) != _NET_ADMIN_MASK:
            raise RuntimeError("Unexpected runtime capabilities")
    if (
        os.getresuid() != (65532, 65532, 65532)
        or os.getresgid() != (65532, 65532, 65532)
        or os.getgroups() != [65531]
        or status["NoNewPrivs"] != "1"
    ):
        raise RuntimeError("Unexpected runtime identity")


def bootstrap(*, health: bool = False) -> None:
    """Establish the fixed agent identity and exec its module.

    Args:
        health: Run the fixed local health check instead of the daemon.

    Raises:
        OSError: A kernel privilege transition or exec fails.
        RuntimeError: The starting or resulting identity is unexpected.
    """
    if os.geteuid() != 0:
        raise RuntimeError("Bootstrap requires initial root identity")
    _prctl(38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS
    _prctl(8, 1, 0, 0, 0)  # PR_SET_KEEPCAPS
    os.setgroups([65531])
    os.setresgid(65532, 65532, 65532)
    os.setresuid(65532, 65532, 65532)
    _net_admin_only()
    _prctl(8, 0, 0, 0, 0)
    _prctl(47, 2, _NET_ADMIN, 0, 0)  # PR_CAP_AMBIENT_RAISE
    _verify()
    target = (
        ["/opt/agent/agent_health.py"]
        if health
        else ["-m", "sciaiot.ovpncp.vpn_agent.cli"]
    )
    os.execv(sys.executable, [sys.executable, *target])


def main() -> None:
    """Fail closed with a fixed diagnostic if privileges cannot be dropped."""
    try:
        if sys.argv[1:] == ["--health"]:
            bootstrap(health=True)
        elif not sys.argv[1:]:
            bootstrap()
        else:
            raise ValueError("Unsupported bootstrap arguments")
    except OSError, RuntimeError, KeyError, ValueError:
        print(
            "Agent privilege bootstrap failed; check the image and Compose "
            "user/capability configuration.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
