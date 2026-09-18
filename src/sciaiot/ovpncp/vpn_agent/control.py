"""Read-only protocol dispatcher; no privileged mutation command is wired."""

import grp
import json
import os
import pwd
import time
from typing import Any

from sciaiot.ovpncp.application.vpn_control import archive, wire
from sciaiot.ovpncp.application.vpn_control import schemas as s
from sciaiot.ovpncp.application.vpn_control.errors import ControlError, ErrorCode

from . import bounded, files, network
from .management import Management
from .settings import Settings

READ_KINDS = frozenset(
    {
        "health",
        "server_config",
        "list_clients",
        "get_client",
        "list_routes",
        "list_access",
        "list_sessions",
    }
)


class ReadOnlyVpnControl:
    """Bound independent observations and redact all OS/parser failures."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.management = Management(settings)

    def execute(self, request: s.Request) -> s.Response:
        """Reject unsupported commands before observing files or sockets."""
        request = wire.decode_request(wire.encode(request))
        if request.command.kind not in READ_KINDS:
            raise ControlError(ErrorCode.UNAVAILABLE)
        deadline = time.monotonic() + min(request.deadline_ms / 1000, 10)
        try:
            result = self._read(request.command, deadline)
            bounded.remaining(deadline)
            return wire.decode_response(
                wire.encode(s.Response(request_id=request.request_id, result=result)),
                request,
            )
        except ControlError:
            raise
        except TimeoutError:
            raise ControlError(ErrorCode.TIMEOUT) from None
        except Exception:  # noqa: BLE001 - redact privileged boundary failures
            raise ControlError(ErrorCode.UNAVAILABLE) from None

    def open_archive(self, request: s.Request) -> archive.ArchiveStream:
        """Phase 3 never packages or exposes credential bytes."""
        raise ControlError(ErrorCode.UNAVAILABLE)

    def _health(self, deadline: float) -> s.HealthResult:
        config = files.configuration(self.settings, deadline)
        options = files.directives(
            bounded.read_file(self.settings.config_path, deadline)
        )
        expected = {
            "management": [[self.settings.management_socket, "unix"]],
            "management-client-user": [[pwd.getpwuid(os.getuid()).pw_name]],
            "management-client-group": [[grp.getgrgid(os.getgid()).gr_name]],
        }
        if any(options.get(key) != value for key, value in expected.items()) or any(
            key.startswith("management-") and key not in expected for key in options
        ):
            raise ControlError(ErrorCode.UNAUTHORIZED)
        version = self.management.read("version", deadline)
        if not any(
            line.startswith("OpenVPN Version: OpenVPN 2.6.")
            for line in version.splitlines()
        ):
            raise ControlError(ErrorCode.VERSION_MISMATCH)
        state = self.management.read("state", deadline)
        connected = any(
            len(fields := line.split(",")) >= 3
            and fields[1:3] == ["CONNECTED", "SUCCESS"]
            for line in state.splitlines()
        )
        links = json.loads(bounded.observe("link", config.device, deadline))
        ready = (
            connected
            and config.device_type == "tun"
            and isinstance(links, list)
            and len(links) == 1
            and links[0].get("ifname") == config.device
            and "UP" in links[0].get("flags", [])
        )
        if b"(nf_tables)" not in bounded.observe("backend", config.device, deadline):
            raise ControlError(ErrorCode.UNAVAILABLE)
        network.routes(self.settings, config, deadline)
        network.access(self.settings, config, deadline)
        return s.HealthResult(ready=ready, generation=config.generation)

    def _page(
        self, command: s.Page, items: tuple[Any, ...], revision: int
    ) -> tuple[tuple[Any, ...], str | None]:
        offset = 0
        if command.cursor is not None:
            pieces = command.cursor.split("_")
            if (
                len(pieces) != 2
                or pieces[0] != str(revision)
                or not pieces[1].isdigit()
            ):
                raise ControlError(ErrorCode.CONFLICT)
            offset = int(pieces[1])
            if offset <= 0 or offset >= len(items):
                raise ControlError(ErrorCode.CONFLICT)
        page = items[offset : offset + command.limit]
        end = offset + len(page)
        return page, f"{revision}_{end}" if end < len(items) else None

    def _read(self, command: s.Command, deadline: float) -> s.Result:
        if isinstance(command, s.Health):
            return self._health(deadline)
        if isinstance(command, s.ServerConfig):
            return files.configuration(self.settings, deadline)
        if isinstance(command, (s.ListClients, s.GetClient)):
            clients = files.clients(self.settings, deadline)
            if isinstance(command, s.GetClient):
                for item in clients:
                    if item.client == command.client:
                        return s.ClientResult(item=item)
                raise ControlError(ErrorCode.NOT_FOUND)
            generation = bounded.revision(
                b"".join(item.model_dump_json().encode() for item in clients)
            )
            page, cursor = self._page(command, clients, generation)
            return s.ClientsResult(
                items=page, generation=generation, next_cursor=cursor
            )
        if isinstance(command, s.ListSessions):
            sessions = self.management.sessions(deadline)
            generation = bounded.revision(
                b"".join(item.model_dump_json().encode() for item in sessions)
            )
            page, cursor = self._page(command, sessions, generation)
            return s.SessionsResult(
                items=page, generation=generation, next_cursor=cursor
            )
        config = files.configuration(self.settings, deadline)
        if isinstance(command, s.ListRoutes):
            routes = network.routes(self.settings, config, deadline)
            generation = bounded.revision(
                b"".join(item.model_dump_json().encode() for item in routes)
            )
            page, cursor = self._page(command, routes, generation)
            return s.RoutesResult(items=page, generation=generation, next_cursor=cursor)
        if isinstance(command, s.ListAccess):
            access, pushes = network.access(self.settings, config, deadline)
            generation = bounded.revision(
                b"".join(item.model_dump_json().encode() for item in (*access, *pushes))
            )
            combined = tuple(
                (
                    access[index] if index < len(access) else None,
                    pushes[index] if index < len(pushes) else None,
                )
                for index in range(max(len(access), len(pushes)))
            )
            page, cursor = self._page(command, combined, generation)
            return s.AccessResult(
                items=tuple(item[0] for item in page if item[0] is not None),
                pushes=tuple(item[1] for item in page if item[1] is not None),
                generation=generation,
                next_cursor=cursor,
            )
        raise ControlError(ErrorCode.UNAVAILABLE)
