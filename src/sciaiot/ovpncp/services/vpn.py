"""Application VPN workflows, projections, and durable remote operation intent."""

import hashlib
import ipaddress
import json
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from sqlalchemy import delete, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlmodel import Session, col, select

from sciaiot.ovpncp import dependencies
from sciaiot.ovpncp.adapters.vpn.host import HostVpnControl
from sciaiot.ovpncp.adapters.vpn.shadow import ShadowHostVpnControl
from sciaiot.ovpncp.application import client_name
from sciaiot.ovpncp.application.vpn_control import schemas as s
from sciaiot.ovpncp.application.vpn_control import wire
from sciaiot.ovpncp.application.vpn_control.errors import ControlError, ErrorCode
from sciaiot.ovpncp.data.network import RestrictedNetwork
from sciaiot.ovpncp.data.server import Server
from sciaiot.ovpncp.data.vpn import (
    VpnArchiveCleanup,
    VpnStep,
    VpnStepAttempt,
    VpnWorkflow,
)
from sciaiot.ovpncp.services.vpn_recovery import recover_response


def validate_name(name: str) -> None:
    """Validate a logical client name without importing privileged helpers."""
    if not is_valid_name(name):
        raise ValueError("The VPN client name is invalid.")


def is_valid_name(name: object) -> bool:
    """Return whether a value fits the constrained client identity domain."""
    return client_name.is_valid_name(name)


def request(command: s.Command, **kwargs: Any) -> s.Request:
    """Construct a fresh correlation identity, separate from operation IDs."""
    return s.Request(request_id=str(uuid.uuid4()), command=command, **kwargs)


def config_projection(config: s.ConfigResult) -> dict[str, Any]:
    """Preserve public field shapes while hiding all agent-private paths."""
    network = ipaddress.IPv4Network(config.network)
    result: dict[str, Any] = {
        name: "agent-managed"
        for name in (
            "ca",
            "cert",
            "key",
            "dh",
            "status",
            "log",
            "client_config_dir",
            "ifconfig_pool_persist",
        )
    }
    result.update(
        {
            "server": f"{network.network_address} {network.netmask}",
            "dev": config.device,
            "port": str(config.port),
            "proto": config.protocol,
            "topology": config.topology,
            "ccd_exclusive": config.ccd_exclusive,
            "keepalive": " ".join(str(item) for item in config.keepalive),
            "persist_key": config.persist_key,
            "persist_tun": config.persist_tun,
            "client_connect": None,
            "client_disconnect": None,
            "script_security": None,
            "network_address": str(network.network_address),
            "subnet_mask": str(network.netmask),
            "ip": config.server_address,
        }
    )
    if config.data_ciphers is not None:
        result["data_ciphers"] = ":".join(config.data_ciphers)
    if config.fallback_cipher is not None:
        result["data_ciphers_fallback"] = config.fallback_cipher
    if config.verbosity is not None:
        result["verb"] = str(config.verbosity)
    if config.explicit_exit_notify is not None:
        result["explicit_exit_notify"] = str(config.explicit_exit_notify)
    return result


def get_server_config() -> dict[str, Any]:
    """Read sanitized agent settings or the local host compatibility view."""
    control = dependencies.get_vpn_control()
    if isinstance(control, HostVpnControl):
        return control.configuration()
    response = control.execute(request(s.ServerConfig()))
    wire.require_success(response)
    if not isinstance(response.result, s.ConfigResult):
        raise ControlError(ErrorCode.INTEGRITY)
    return config_projection(response.result)


def get_status() -> dict[str, Any]:
    """Project readiness into the existing public health response."""
    control = dependencies.get_vpn_control()
    if isinstance(control, HostVpnControl):
        return control.health()
    response = control.execute(request(s.Health()))
    wire.require_success(response)
    if not isinstance(response.result, s.HealthResult):
        raise ControlError(ErrorCode.INTEGRITY)
    return {
        "status": "active (running)" if response.result.ready else "inactive",
        "time": None,
        "period": None,
    }


class CompletedRemoval:
    """Remote deletion cannot undo committed PKI changes after a DB failure."""

    def restore(self) -> None:
        """Leave the durable pending workflow for same-ID reconciliation."""

    def discard(self) -> None:
        """Remote leaf cleanup is already owned by the agent operation."""


class VpnService:
    """Translate authorized business requests into typed VPN operations.

    Remote mutations persist complete desired intent and every immutable step
    before dispatch. An uncertain step is looked up under its original ID;
    a missing lookup can only resubmit that same journal-fenced intent. Business completion is committed
    in the caller's existing transaction via finish().
    """

    def __init__(self, session: Session, server: Server | None = None) -> None:
        self.session = session
        self.control = dependencies.get_vpn_control()
        self.host = isinstance(self.control, HostVpnControl)
        if isinstance(self.control, HostVpnControl):
            factory: Any = HostVpnControl
            extra = {}
            if isinstance(self.control, ShadowHostVpnControl):
                factory = ShadowHostVpnControl
                extra["agent"] = self.control.agent
            self.control = factory(
                state=self.control.state,
                **extra,
                device=server.dev if server else "tun0",
                subnet_mask=server.subnet_mask if server else "255.255.255.0",
                archive_directory=dependencies.certs_directory,
            )
        self.workflow_id: str | None = None
        self.position = 0

    @contextmanager
    def _journal(self) -> Iterator[Session]:
        """Keep SQL payloads out of public errors and privileged audit logs."""
        try:
            with Session(self.session.get_bind()) as journal:
                yield journal
        except SQLAlchemyError:
            raise ControlError(ErrorCode.UNAVAILABLE) from None

    def _read(self, command: s.Command, *, deadline: float | None = None) -> s.Result:
        remaining = (
            s.MAX_DEADLINE_MS
            if deadline is None
            else int((deadline - time.monotonic()) * 1000)
        )
        if remaining <= 0:
            raise ControlError(ErrorCode.TIMEOUT)
        result = self.control.execute(
            request(command, deadline_ms=min(remaining, s.MAX_DEADLINE_MS))
        )
        wire.require_success(result)
        return result.result

    def _pages(
        self, command: s.ListClients | s.ListRoutes
    ) -> Iterator[s.ClientsResult | s.RoutesResult]:
        """Bound complete snapshots by time, count, cursor and generation."""
        deadline = time.monotonic() + 60
        seen: set[str] = set()
        generation: int | None = None
        total = 0
        while True:
            page = self._read(command, deadline=deadline)
            if not isinstance(page, (s.ClientsResult, s.RoutesResult)):
                raise ControlError(ErrorCode.INTEGRITY)
            if generation is not None and generation != page.generation:
                raise ControlError(ErrorCode.CONFLICT)
            generation = page.generation
            total += len(page.items)
            if total > 10_000:
                raise ControlError(ErrorCode.EXHAUSTED)
            yield page
            cursor = page.next_cursor
            if cursor is None:
                return
            if cursor in seen or not page.items:
                raise ControlError(ErrorCode.INTEGRITY)
            seen.add(cursor)
            command = command.model_copy(update={"cursor": cursor})

    def _begin(self, resource: str, desired: dict[str, Any]) -> str:
        if self.host:
            self.workflow_id = str(uuid.uuid4())
            return self.workflow_id
        canonical = json.dumps(desired, sort_keys=True, separators=(",", ":"))
        resource = hashlib.sha256(resource.encode()).hexdigest()
        with self._journal() as journal:
            pending = journal.exec(
                select(VpnWorkflow).where(
                    VpnWorkflow.resource == resource, VpnWorkflow.completed == False
                )
            ).all()
            if len(pending) > 1 or (pending and pending[0].desired_json != canonical):
                raise ControlError(ErrorCode.CONFLICT)
            if pending:
                workflow = pending[0]
            else:
                workflow = VpnWorkflow(
                    id=str(uuid.uuid4()),
                    resource=resource,
                    active_resource=resource,
                    desired_json=canonical,
                )
                journal.add(workflow)
                journal.commit()
                journal.refresh(workflow)
            self.workflow_id = workflow.id
        self.position = 0
        return self.workflow_id

    def _retry_rejected(
        self, journal: Session, step: VpnStep, command: s.Command
    ) -> tuple[VpnStep, s.Request, bool]:
        """Retain rejection evidence before a separately authorized fresh attempt.

        Called only for a validated terminal failed result with no effects. A
        partial/unknown/expired result can never reach this replacement path.
        """
        health = self._read(s.Health())
        if not isinstance(health, s.HealthResult) or not health.ready:
            raise ControlError(ErrorCode.UNAVAILABLE)
        assert step.response_json is not None
        original = request(
            command,
            operation_id=str(uuid.uuid4()),
            expected_generation=health.generation,
        )
        assert original.operation_id is not None
        replacement = VpnStep(
            id=original.operation_id,
            workflow_id=step.workflow_id,
            position=step.position,
            request_json=wire.encode(original).decode(),
        )
        try:
            journal.add(
                VpnStepAttempt(
                    id=step.id,
                    workflow_id=step.workflow_id,
                    position=step.position,
                    request_json=step.request_json,
                    response_json=step.response_json,
                )
            )
            removed = journal.connection().execute(
                delete(VpnStep).where(
                    col(VpnStep.id) == step.id,
                    col(VpnStep.response_json) == step.response_json,
                )
            )
            if removed.rowcount != 1:
                raise ControlError(ErrorCode.CONFLICT)
            journal.expunge(step)
            journal.add(replacement)
            journal.commit()
            journal.refresh(replacement)
            return replacement, original, False
        except IntegrityError:
            journal.rollback()
            active = journal.exec(
                select(VpnStep).where(
                    VpnStep.workflow_id == self.workflow_id,
                    VpnStep.position == self.position,
                )
            ).one()
            saved = wire.decode_request(active.request_json.encode())
            if saved.command != command:
                raise ControlError(ErrorCode.CONFLICT) from None
            return active, saved, True

    def _mutate(self, command: s.Command) -> None:
        if self.host:
            assert isinstance(self.control, HostVpnControl)
            response = self.control.execute(
                request(
                    command,
                    operation_id=str(uuid.uuid4()),
                    expected_generation=self.control.state.generation,
                )
            )
            wire.require_success(response)
            return
        assert self.workflow_id is not None
        with self._journal() as journal:
            step = journal.exec(
                select(VpnStep).where(
                    VpnStep.workflow_id == self.workflow_id,
                    VpnStep.position == self.position,
                )
            ).one_or_none()
            existing = step is not None
            if step is None:
                health = self._read(s.Health())
                if not isinstance(health, s.HealthResult) or not health.ready:
                    raise ControlError(ErrorCode.UNAVAILABLE)
                original = request(
                    command,
                    operation_id=str(uuid.uuid4()),
                    expected_generation=health.generation,
                )
                step = VpnStep(
                    id=original.operation_id,
                    workflow_id=self.workflow_id,
                    position=self.position,
                    request_json=wire.encode(original).decode(),
                )
                journal.add(step)
                try:
                    journal.commit()
                except IntegrityError:
                    journal.rollback()
                    step = journal.exec(
                        select(VpnStep).where(
                            VpnStep.workflow_id == self.workflow_id,
                            VpnStep.position == self.position,
                        )
                    ).one()
                    original = wire.decode_request(step.request_json.encode())
                    if original.command != command:
                        raise ControlError(ErrorCode.CONFLICT) from None
                    existing = True
                journal.refresh(step)
            else:
                original = wire.decode_request(step.request_json.encode())
                if original.command != command:
                    raise ControlError(ErrorCode.CONFLICT)
            cached = (
                wire.decode_response(step.response_json.encode(), original)
                if step.response_json is not None
                else None
            )
            if (
                cached is not None
                and isinstance(cached.result, s.MutationResult)
                and cached.result.state == "failed"
            ):
                step, original, existing = self._retry_rejected(journal, step, command)
                cached = (
                    wire.decode_response(step.response_json.encode(), original)
                    if step.response_json is not None
                    else None
                )
            terminal = (
                cached is not None
                and isinstance(cached.result, s.MutationResult)
                and cached.result.state in {"succeeded", "failed", "expired"}
            )
            if terminal:
                assert cached is not None
                response = cached
            elif existing:
                response = recover_response(
                    self.control, original, deadline_ms=original.deadline_ms
                )
            else:
                response = self.control.execute(original)
            step.response_json = wire.encode(response).decode()
            journal.add(step)
            journal.commit()
        wire.require_success(response)
        self.position += 1

    def finish(self, *, resource_id: str | None = None) -> None:
        """Stage workflow completion in the caller's business transaction."""
        if not self.host and self.workflow_id is not None:
            try:
                result = self.session.connection().execute(
                    update(VpnWorkflow)
                    .where(
                        col(VpnWorkflow.id) == self.workflow_id,
                        col(VpnWorkflow.completed) == False,
                    )
                    .values(
                        completed=True, active_resource=None, resource_id=resource_id
                    )
                )
            except SQLAlchemyError:
                raise ControlError(ErrorCode.UNAVAILABLE) from None
            if result.rowcount != 1:
                raise ControlError(ErrorCode.CONFLICT)

    def change_client(
        self,
        name: str,
        action: Literal["issue", "renew", "revoke", "delete"],
        *,
        desired: dict[str, Any] | None = None,
    ) -> None:
        """Apply one authorized lifecycle operation with durable retry intent."""
        command = s.ChangeClient(client=name, action=action)
        self._begin(f"client:{name}", desired or command.model_dump(mode="json"))
        self._mutate(command)
        if not self.host and action in {"renew", "revoke", "delete"}:
            with self._journal() as journal:
                cleanup = journal.get(VpnArchiveCleanup, name) or VpnArchiveCleanup(
                    client=name
                )
                cleanup.pending = True
                journal.add(cleanup)
                journal.commit()
                try:
                    Path(dependencies.certs_directory, f"{name}.zip").unlink(
                        missing_ok=True
                    )
                except OSError:
                    pass
                else:
                    cleanup.pending = False
                    journal.add(cleanup)
                    journal.commit()

    def certificate(self, name: str) -> dict[str, Any]:
        """Map bounded observed metadata to existing public certificate fields."""
        if isinstance(self.control, HostVpnControl):
            return self.control.read_certificate(name)
        item = self._read(s.GetClient(client=name))
        if not isinstance(item, s.ClientResult):
            raise ControlError(ErrorCode.INTEGRITY)
        return self._certificate_details(item.item)

    @staticmethod
    def _certificate_details(item: s.ClientMetadata) -> dict[str, Any]:
        """Convert exact microsecond metadata from one consistent observation."""
        epoch = datetime(1970, 1, 1, tzinfo=UTC)
        return {
            "issued_by": item.issuer,
            "issued_to": item.subject,
            "issued_on": epoch + timedelta(microseconds=item.not_before),
            "expires_on": epoch + timedelta(microseconds=item.not_after),
        }

    def discoveries(self) -> list[tuple[str, dict[str, Any], str | None] | None]:
        """Preserve import skip counts without exposing invalid wire identities."""
        if isinstance(self.control, HostVpnControl):
            items: list[tuple[str, dict[str, Any], str | None] | None] = []
            for name in self.control.discovered_names():
                if not is_valid_name(name) or self.control.client_revoked(name):
                    items.append(None)
                    continue
                details = self.control.read_certificate(name)
                items.append(
                    (name, details, self.control.client_address(name))
                    if details
                    else None
                )
            return items
        discovered: list[tuple[str, dict[str, Any], str | None] | None] = []
        for page in self._pages(s.ListClients()):
            if not isinstance(page, s.ClientsResult):
                raise ControlError(ErrorCode.INTEGRITY)
            for item in page.items:
                discovered.append(
                    (
                        item.client,
                        self._certificate_details(item),
                        item.assignment.address if item.assignment else None,
                    )
                    if item.state == "active"
                    else None
                )
        return discovered

    def removal(self, name: str) -> Any:
        """Stage legacy deletion or apply one remote revocation-safe deletion."""
        self.change_client(name, "delete")
        if isinstance(self.control, HostVpnControl):
            return self.control.removals[name]
        return CompletedRemoval()

    def assignment(
        self, name: str, address: str | None, network: str | None = None
    ) -> None:
        """Record and apply a whole owned CCD assignment in one typed step."""
        assignment = (
            s.Assignment(
                address=address,
                network=str(ipaddress.IPv4Network(network, strict=False))
                if network
                else None,
            )
            if address is not None
            else None
        )
        command = s.SetAssignment(client=name, assignment=assignment)
        self._begin(f"client:{name}", command.model_dump(mode="json"))
        self._mutate(command)

    def route_lines(self, device: str) -> list[str]:
        """Project managed routes or preserve local host route strings."""
        if isinstance(self.control, HostVpnControl):
            return self.control.route_lines(device)
        values: list[str] = []
        for page in self._pages(s.ListRoutes()):
            if not isinstance(page, s.RoutesResult):
                raise ControlError(ErrorCode.INTEGRITY)
            values.extend(f"{item.network} via {item.gateway}" for item in page.items)
        return values

    def pending_route_removal(self, network: str) -> bool:
        """Allow same-intent recovery after actual removal but failed DB commit."""
        if self.host:
            return False
        resource = hashlib.sha256(f"route:{network}".encode()).hexdigest()
        with self._journal() as journal:
            pending = journal.exec(
                select(VpnWorkflow).where(VpnWorkflow.active_resource == resource)
            ).one_or_none()
            return (
                pending is not None
                and json.loads(pending.desired_json).get("present") is False
            )

    def route(self, network: str, gateway: str, present: bool) -> None:
        """Ensure/remove an API-owned canonical route with a stable logical ID."""
        network = str(ipaddress.IPv4Network(network))
        # UUID4-format deterministic ownership, separate from each operation ID.
        digest = hashlib.sha256(f"route:{network}".encode()).digest()[:16]
        route_id = str(uuid.UUID(bytes=digest, version=4))
        command = s.SetRoute(
            route=s.ManagedRoute(route_id=route_id, network=network, gateway=gateway),
            present=present,
        )
        self._begin(f"route:{network}", command.model_dump(mode="json"))
        self._mutate(command)
        self.finish()
        if not self.host:
            self.session.commit()

    def network(self, network: RestrictedNetwork, present: bool) -> None:
        """Persist complete paired access/push intent before the first effect."""
        desired = {
            "source": network.source_name,
            "destination": network.destination_name,
            "source_address": network.source_virtual_address,
            "destination_address": network.destination_virtual_address,
            "private": network.private_network_addresses,
            "present": present,
            "network_id": network.id if not present else None,
        }
        workflow_id = self._begin(
            f"network:{network.source_name}:{network.destination_name}", desired
        )
        access_id = workflow_id
        if not present and not self.host:
            # The successful creation intent is retained as ownership evidence.
            with self._journal() as journal:
                workflows = journal.exec(
                    select(VpnWorkflow).where(
                        VpnWorkflow.completed == True,
                        VpnWorkflow.resource_id == str(network.id),
                    )
                ).all()
                for workflow in workflows:
                    previous = json.loads(workflow.desired_json)
                    if (
                        previous.get("source") == network.source_name
                        and previous.get("destination") == network.destination_name
                        and previous.get("private") == network.private_network_addresses
                        and previous.get("present") is True
                    ):
                        access_id = workflow.id
                if access_id == workflow_id:
                    raise ControlError(ErrorCode.CONFLICT)
        destinations = tuple(
            str(ipaddress.IPv4Network(value, strict=True))
            for value in network.private_network_addresses.split(",")
            if value
        )
        intent = s.AccessIntent(
            access_id=access_id,
            source_client=network.source_name,
            destination_client=network.destination_name,
            source_address=network.source_virtual_address,
            destination_address=network.destination_virtual_address,
            private_networks=destinations,
        )
        pushes = s.SetPushRoutes(
            client=network.source_name,
            intent_id=access_id,
            routes=tuple(
                s.PushRoute(network=value, gateway=network.destination_virtual_address)
                for value in destinations
            )
            if present
            else (),
        )
        if not present and destinations:
            self._mutate(pushes)
        self._mutate(s.SetAccess(intent=intent, present=present))
        if present and destinations:
            self._mutate(pushes)
