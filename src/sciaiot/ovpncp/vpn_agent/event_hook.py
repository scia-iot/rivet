"""Bounded trusted daemon hook; ingestion loss never fails a VPN connection."""

import argparse
import os
import socket
import struct
import time
import uuid
from pathlib import Path

from sciaiot.ovpncp.application.vpn_control import schemas as s

from .ingress import session_identity
from .mutations import atomic_write


def main() -> None:
    """Normalize only required environment fields, report locally, always exit zero."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("--management-socket", required=True)
    parser.add_argument("--agent-uid", required=True, type=int)
    args, _ = parser.parse_known_args()
    path = Path(args.socket)
    try:
        kind = {"client-connect": "connect", "client-disconnect": "disconnect"}[
            os.environ["script_type"]
        ]
        session = s.Session(
            session_id=str(uuid.uuid4()),
            client=os.environ["common_name"],
            address=os.environ["ifconfig_pool_remote_ip"],
            remote_address=os.environ.get(
                "trusted_ip", os.environ.get("trusted_ip6", "")
            ),
            remote_port=int(os.environ["trusted_port"]),
            connected_at=int(os.environ["time_unix"]) * 1_000_000,
        )
        session = session.model_copy(
            update={
                "session_id": session_identity(session, Path(args.management_socket))
            }
        )
        event = s.Event.model_validate(
            {
                "sequence": 0,
                "event_id": str(uuid.uuid4()),
                "occurred_at": time.time_ns() // 1000,
                "event": kind,
                "session": session,
            }
        )
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(0.2)
            connection.connect(str(path))
            _, uid, _ = struct.unpack(
                "iII",
                connection.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("iII")
                ),
            )
            if uid != args.agent_uid:
                raise ValueError("Untrusted producer listener")
            connection.sendall(event.model_dump_json().encode() + b"\n")
            if connection.recv(3) != b"ok\n":
                raise ValueError("Producer acknowledgement missing")
    except Exception:  # noqa: BLE001 - daemon lifecycle never depends on ingestion
        try:
            atomic_write(
                path.parent / "producer-gap",
                uuid.uuid4().hex.encode(),
                time.monotonic() + 0.1,
                mode=0o640,
            )
        except Exception:  # noqa: BLE001, S110 - daemon never depends on ingestion
            pass


if __name__ == "__main__":
    main()
