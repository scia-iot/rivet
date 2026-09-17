"""Legacy host adapter and narrowly scoped local compatibility projections.

Only this adapter imports privileged OpenVPN/network utilities. Host mode
retains its historical staged deletion transaction and public path fields;
these local compatibility values never enter the agent wire protocol.
"""

import hashlib
import ipaddress
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from sciaiot.ovpncp.application.vpn_control import archive, wire
from sciaiot.ovpncp.application.vpn_control import schemas as s
from sciaiot.ovpncp.application.vpn_control.errors import ControlError, ErrorCode
from sciaiot.ovpncp.data.network import RestrictedNetwork
from sciaiot.ovpncp.utils import iproute, iptables, openvpn

from .fake import FakeState, FakeVpnControl, MemorySource


class HostVpnControl(FakeVpnControl):
    """Adapt validated logical commands to the existing host implementation.

    The transitional host runtime preserves legacy behavior; it does not
    claim the production agent's crash-safe privileged mutation journal.
    API-side durable orchestration is used for the agent backend.
    """

    def __init__(
        self,
        state: FakeState | None = None,
        *,
        device: str = "tun0",
        subnet_mask: str = "255.255.255.0",
        archive_directory: str = "/opt/ovpncp/certs",
    ) -> None:
        super().__init__(state)
        self.device = device
        self.subnet_mask = subnet_mask
        self.archive_directory = archive_directory
        self.certificate_details: dict[str, dict[str, Any]] = {}
        self.removals: dict[str, Any] = {}
        self._route_cache: dict[str, list[str]] = {}

    def execute(self, request: s.Request) -> s.Response:
        """Redact parser/filesystem failures at the privileged host boundary."""
        try:
            return super().execute(request)
        except ControlError:
            raise
        except Exception:  # noqa: BLE001 - fixed privileged boundary error
            raise ControlError(ErrorCode.UNAVAILABLE) from None

    def configuration(self) -> dict[str, Any]:
        """Return the historical local-only server projection, including paths."""
        return dict(openvpn.get_server_config())

    def health(self) -> dict[str, Any]:
        """Return the historical service-manager status/time/period projection."""
        return dict(openvpn.get_status())

    def route_lines(self, device: str) -> list[str]:
        """Preserve historical route text in the host public API only."""
        result = list(iproute.list(device))
        self._route_cache[device] = result
        return result

    def discovered_names(self) -> list[str]:
        """Preserve invalid-candidate skip counts without exporting raw paths."""
        return list(openvpn.list_client_certs())

    def read_certificate(self, client: str) -> dict[str, Any]:
        """Return legacy metadata, including its missing-certificate sentinel."""
        cached = self.certificate_details.pop(client, None)
        return cached if cached is not None else dict(openvpn.read_client_cert(client))

    def client_revoked(self, client: str) -> bool:
        """Read local CA revocation evidence for legacy discovery."""
        return bool(openvpn.client_is_revoked(client))

    def client_address(self, client: str) -> str | None:
        """Read the historical optional CCD address projection."""
        return openvpn.read_client_ip(client)

    def _metadata(self, client: str) -> s.ClientMetadata:
        details = openvpn.read_client_cert(client)
        if not details:
            raise ControlError(ErrorCode.NOT_FOUND)
        content = Path(
            openvpn.easyrsa_dir, "pki", "issued", f"{client}.crt"
        ).read_bytes()
        certificate = x509.load_pem_x509_certificate(content)
        address = openvpn.read_client_ip(client)
        return s.ClientMetadata(
            client=client,
            generation=self.state.generation,
            state="revoked" if openvpn.client_is_revoked(client) else "active",
            issuer=details["issued_by"],
            subject=details["issued_to"],
            certificate_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
            not_before=int(details["issued_on"].timestamp() * 1_000_000),
            not_after=int(details["expires_on"].timestamp() * 1_000_000),
            assignment=s.Assignment(address=address) if address else None,
        )

    def _read(self, command: s.Command) -> s.Result:
        if isinstance(command, s.Health):
            return s.HealthResult(
                ready=self.health()["status"] == "active (running)",
                generation=self.state.generation,
            )
        if isinstance(command, s.ServerConfig):
            config = self.configuration()
            network_address, mask = config["server"].split()
            network = ipaddress.IPv4Network(f"{network_address}/{mask}")
            device = config["dev"]
            keepalive = [
                int(value) for value in config.get("keepalive", "10 120").split()
            ]
            return s.ConfigResult(
                generation=self.state.generation,
                device=f"{device}0" if device in {"tun", "tap"} else device,
                network=str(network),
                server_address=str(next(network.hosts())),
                device_type="tun" if device.startswith("tun") else "tap",
                ccd_exclusive=bool(config.get("ccd_exclusive", False)),
                keepalive=(keepalive[0], keepalive[1]),
                port=int(config["port"]),
                protocol=config["proto"],
                topology=config.get("topology", "net30"),
                persist_key=bool(config.get("persist_key", False)),
                persist_tun=bool(config.get("persist_tun", False)),
                data_ciphers=tuple(config["data_ciphers"].split(":"))
                if config.get("data_ciphers")
                else None,
                fallback_cipher=config.get("data_ciphers_fallback"),
                verbosity=int(config["verb"]) if "verb" in config else None,
                explicit_exit_notify=int(config["explicit_exit_notify"])
                if "explicit_exit_notify" in config
                else None,
            )
        if isinstance(command, s.GetClient):
            return s.ClientResult(item=self._metadata(command.client))
        if isinstance(command, s.ListClients):
            items = [
                self._metadata(name)
                for name in self.discovered_names()
                if openvpn.is_valid_name(name) and openvpn.read_client_cert(name)
            ]
            page, cursor = self._page(command, items)
            return s.ClientsResult(
                items=page, next_cursor=cursor, generation=self.state.generation
            )
        if isinstance(
            command, (s.ListRoutes, s.ListAccess, s.ListSessions, s.PollEvents)
        ):
            raise ControlError(ErrorCode.UNAVAILABLE)
        return super()._read(command)

    def _mutate(self, request: s.Request) -> s.MutationResult:
        """Keep host uncertainty truthful; legacy commands are not atomic."""
        operation_id = request.operation_id
        assert operation_id is not None
        if operation_id in self.state.expired:
            raise ControlError(ErrorCode.EXPIRED_OPERATION)
        digest = wire.intent_digest(request)
        previous = self.state.journal.get(operation_id)
        if previous is not None:
            if previous.intent_sha256 != digest:
                raise ControlError(ErrorCode.CONFLICT)
            return previous
        if (
            len(self.state.journal) + len(self.state.expired)
            >= self.state.max_operations
        ):
            raise ControlError(ErrorCode.EXHAUSTED)
        if request.expected_generation != self.state.generation:
            raise ControlError(ErrorCode.CONFLICT)
        if self.fault == "failed":
            result = s.MutationResult(
                operation_id=operation_id,
                generation=self.state.generation,
                intent_sha256=digest,
                state="failed",
                failure=ErrorCode.NOT_FOUND,
                client=getattr(request.command, "client", None),
            )
        else:
            try:
                self._apply(request.command)
            except Exception:  # noqa: BLE001 - preserve uncertain host effects
                result = s.MutationResult(
                    operation_id=operation_id,
                    generation=self.state.generation,
                    intent_sha256=digest,
                    state="unknown",
                    client=getattr(request.command, "client", None),
                )
            else:
                self.state.generation += 1
                result = s.MutationResult(
                    operation_id=operation_id,
                    generation=self.state.generation,
                    intent_sha256=digest,
                    state="partial" if self.fault == "partial" else "succeeded",
                    completed=("pki",) if self.fault == "partial" else (),
                    client=getattr(request.command, "client", None),
                )
        self.state.journal[operation_id] = result
        if self.fault == "lost_reply":
            raise ControlError(ErrorCode.UNKNOWN_OUTCOME)
        return result

    def _apply(self, command: s.Command) -> None:
        if isinstance(command, s.ChangeClient):
            if command.action == "issue":
                if not openvpn.build_client(command.client):
                    raise ControlError(ErrorCode.UNAVAILABLE)
            elif command.action == "renew":
                details = openvpn.renew_client_cert(command.client)
                if not details:
                    raise ControlError(ErrorCode.UNAVAILABLE)
                self.certificate_details[command.client] = details
            elif command.action == "revoke":
                if (
                    not openvpn.revoke_client(command.client)
                    or not openvpn.generate_crl()
                ):
                    raise ControlError(ErrorCode.UNAVAILABLE)
            else:
                self.removals[command.client] = openvpn.stage_client_file_removal(
                    command.client, self.archive_directory
                )
        elif isinstance(command, s.SetAssignment):
            if command.assignment is None:
                openvpn.unassign_client_ip(command.client)
            else:
                openvpn.assign_client_ip(
                    command.client, command.assignment.address, self.subnet_mask
                )
                if command.assignment.network is not None:
                    assigned_network = ipaddress.IPv4Network(command.assignment.network)
                    openvpn.add_iroute(
                        command.client,
                        f"{assigned_network.network_address} {assigned_network.netmask}",
                    )
        elif isinstance(command, s.SetRoute):
            if command.present:
                iproute.add(command.route.network, command.route.gateway, self.device)
            else:
                target = next(
                    (
                        line
                        for line in (
                            self._route_cache.get(self.device)
                            or self.route_lines(self.device)
                        )
                        if line.split(maxsplit=1)[0] == command.route.network
                    ),
                    None,
                )
                if target is None:
                    raise ControlError(ErrorCode.NOT_FOUND)
                iproute.delete(target, self.device)
        elif isinstance(command, s.SetAccess):
            intent = command.intent
            network = RestrictedNetwork(
                source_name=intent.source_client,
                destination_name=intent.destination_client,
                source_virtual_address=intent.source_address,
                destination_virtual_address=intent.destination_address,
                private_network_addresses=",".join(
                    item.removesuffix("/32") for item in intent.private_networks
                ),
                start_time=datetime.now(timezone.utc),
            )
            rules = network.iptable_rules()
            if network.private_network_addresses:
                rules += network.private_iptable_rules()
            if command.present:
                iptables.apply_rules(
                    "FORWARD", len(iptables.list_rules("FORWARD")), rules
                )
            else:
                iptables.drop_rules("FORWARD", rules)
        elif isinstance(command, s.SetPushRoutes):
            if command.routes:
                # Host compatibility retains the existing push renderer.
                values = [
                    f"{item.network.removesuffix('/32')} 255.255.255.255 {item.gateway}"
                    for item in command.routes
                ]
                openvpn.push_client_routes(command.client, values)
            else:
                openvpn.pull_client_routes(command.client)
        else:
            # Legacy runtime has no management socket/event spool contract.
            raise ControlError(ErrorCode.UNAVAILABLE)

    def package_legacy(self, client: str, directory: str) -> None:
        """Preserve legacy packaging's public cache and mocked side effects."""
        openvpn.package_client_cert(client, directory)

    def open_archive(self, request: s.Request) -> archive.ArchiveStream:
        """Return a bounded owned host archive without exporting PKI paths."""
        request = self._validate(request)
        command = request.command
        if not isinstance(command, s.Archive):
            raise ControlError(ErrorCode.INVALID_INPUT)
        started = time.monotonic()
        with self.state.lock:
            if command.generation != self.state.generation or self.client_revoked(
                command.client
            ):
                raise ControlError(ErrorCode.CONFLICT)
            if self.state.streams >= s.MAX_STREAMS:
                raise ControlError(ErrorCode.EXHAUSTED)
            self.state.streams += 1
        released = False

        def release() -> None:
            nonlocal released
            with self.state.lock:
                if not released:
                    released = True
                    self.state.streams -= 1

        def validate() -> None:
            with self.state.lock:
                if self.state.generation != command.generation or self.client_revoked(
                    command.client
                ):
                    raise ControlError(ErrorCode.CONFLICT)

        try:
            with tempfile.TemporaryDirectory(prefix="ovpncp-archive-") as directory:
                openvpn.package_client_cert(command.client, directory)
                with Path(directory, f"{command.client}.zip").open("rb") as stream:
                    content = stream.read(s.MAX_ARCHIVE_BYTES + 1)
            if not 0 < len(content) <= s.MAX_ARCHIVE_BYTES:
                raise ControlError(ErrorCode.INTEGRITY)
            remaining = request.deadline_ms - int((time.monotonic() - started) * 1000)
            if remaining <= 0:
                raise ControlError(ErrorCode.TIMEOUT)
            source = MemorySource(content, release, validate)
            manifest = s.ArchiveManifest(
                request_id=request.request_id,
                client=command.client,
                generation=command.generation,
                size=len(content),
                sha256=hashlib.sha256(content).hexdigest(),
            )
            return archive.ArchiveStream(
                source,
                manifest,
                request.model_copy(update={"deadline_ms": remaining}),
                time.monotonic,
            )
        except ControlError:
            release()
            raise
        except Exception:  # noqa: BLE001 - fixed privileged boundary error
            release()
            raise ControlError(ErrorCode.UNAVAILABLE) from None
