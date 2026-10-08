"""Real authenticated management sessions receive only exact typed writes."""

import socket
import threading
import time
from pathlib import Path

from sciaiot.ovpncp.vpn_agent.management import Management
from tests.support.agent import STATUS, settings


def test_disconnect_inspects_exact_session_on_same_socket_and_reload_is_controlled(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o770)
    configured = settings(tmp_path)
    commands: list[tuple[int, str]] = []
    active = True
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(configured.management_socket)
    listener.listen()
    listener.settimeout(2)

    def serve() -> None:
        nonlocal active
        with listener:
            for connection_number in range(4):
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(2)
                    buffered = bytearray()
                    while True:
                        chunk = connection.recv(1024)
                        if not chunk:
                            break
                        buffered.extend(chunk)
                        while b"\n" in buffered:
                            line, _, tail = buffered.partition(b"\n")
                            buffered[:] = tail
                            command = line.decode()
                            commands.append((connection_number, command))
                            if command == "status 3":
                                content = (
                                    STATUS
                                    if active
                                    else STATUS.replace("10.8.0.10", "").replace(
                                        "alpha", "UNDEF"
                                    )
                                )
                                connection.sendall((content + "\nEND\n").encode())
                            elif command == "client-kill 0":
                                active = False
                                connection.sendall(b"SUCCESS: client killed\n")
                            elif command == "signal SIGUSR1":
                                connection.sendall(b"SUCCESS: signal sent\n")
                            else:
                                connection.sendall(b"ERROR: unexpected\n")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    manager = Management(configured)
    session = manager.sessions(time.monotonic() + 2)[0]
    manager.disconnect("other-client", session.session_id, time.monotonic() + 2)
    assert active
    manager.disconnect(session.client, session.session_id, time.monotonic() + 2)
    manager.reload(time.monotonic() + 2)
    thread.join(2)
    assert not thread.is_alive()
    assert commands == [
        (0, "status 3"),
        (1, "status 3"),
        (2, "status 3"),
        (2, "client-kill 0"),
        (2, "status 3"),
        (3, "signal SIGUSR1"),
    ]
