"""Feature-gated privileged dispatch backed by an exclusive durable ledger."""

import contextlib
import json
import shlex
import threading
import time
from collections.abc import Iterator

from sciaiot.rivet.application.vpn_control import archive, wire
from sciaiot.rivet.application.vpn_control import schemas as s
from sciaiot.rivet.application.vpn_control.errors import ControlError, ErrorCode

from . import bounded, files
from .access_mutations import AccessMutations
from .archives import Archives
from .control import READ_KINDS, ReadOnlyVpnControl
from .events import EventSpool
from .ingress import Ingress
from .journal import Journal
from .mutations import CcdMutations, atomic_write, read_optional
from .pki import PkiMutations
from .route_mutations import RouteMutations
from .settings import Settings

FAMILIES = {
    "set_assignment": "assignments",
    "set_route": "routes",
    "set_access": "access",
    "set_push_routes": "access",
    "change_client": "pki",
    "ack_events": "events",
    "disconnect": "management",
    "reload": "management",
}


class MutationVpnControl(ReadOnlyVpnControl):
    """Retain every accepted intent before dispatching a privileged effect."""

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        if settings.journal_path is None:
            raise ValueError("Mutation control requires a durable journal.")
        self.journal = Journal(settings.journal_path)
        try:
            self._sync_anchor()
        except BaseException:
            self.journal.close()
            raise
        self.management.epoch = self.journal.identity
        self.ccd = CcdMutations(settings, self.journal)
        self.routes = RouteMutations(settings, self.journal)
        self.access = AccessMutations(settings, self.journal)
        self.pki = PkiMutations(settings, self.journal)
        self.archives = Archives(settings)
        self._closed = False
        self._writer = threading.RLock()
        self._admissions = threading.BoundedSemaphore(s.MAX_QUEUED_OPERATIONS)
        self.events = EventSpool(self.journal)
        self.management.normalize = self.events.normalize
        try:
            self.ingress = (
                Ingress(settings, self.events)
                if "events" in settings.mutation_families
                else None
            )
        except BaseException:
            self.journal.close()
            raise
        self._stopped = threading.Event()
        self._maintenance: threading.Thread | None = None

    def _health(self, deadline: float) -> s.HealthResult:
        try:
            self._validate_runtime(deadline)
            result = super()._health(deadline)
            ready = result.ready and not self.journal.pending()
        except ControlError:
            ready = False
        return s.HealthResult(ready=ready, generation=self.journal.generation)

    def close(self) -> None:
        """Release durable state only after dispatch has stopped."""
        self._stopped.set()
        if self._maintenance is not None:
            self._maintenance.join(timeout=32)
            if self._maintenance.is_alive():
                raise ControlError(ErrorCode.TIMEOUT)
        with self._writer:
            if not self._closed:
                self._closed = True
                if self.ingress is not None:
                    self.ingress.close()
                self.journal.close()

    def execute(self, request: s.Request) -> s.Response:
        """Validate, durably accept, apply, then return correlated evidence."""
        request = wire.decode_request(wire.encode(request))
        deadline = time.monotonic() + request.deadline_ms / 1000
        command = request.command
        try:
            with self._admit(deadline):
                if isinstance(command, s.LookupOperation):
                    result: s.Result = self.journal.lookup(command.operation_id)
                elif isinstance(command, s.PollEvents):
                    if "events" not in self.settings.mutation_families:
                        raise ControlError(ErrorCode.UNAVAILABLE)
                    result = self.events.poll(command)
                elif command.kind in READ_KINDS:
                    result = self._read(command, deadline)
                    if isinstance(result, (s.HealthResult, s.ConfigResult)):
                        result = result.model_copy(
                            update={"generation": self.journal.generation}
                        )
                elif command.kind in FAMILIES:
                    if FAMILIES[command.kind] not in self.settings.mutation_families:
                        raise ControlError(ErrorCode.UNAVAILABLE)
                    result = self.journal.accept(request)
                    self._sync_anchor()
                    if result.state in {"pending", "partial", "unknown"}:
                        result = self._apply(request, deadline)
                else:
                    raise ControlError(ErrorCode.UNAVAILABLE)
                return wire.decode_response(
                    wire.encode(
                        s.Response(request_id=request.request_id, result=result)
                    ),
                    request,
                )
        except ControlError:
            raise
        except Exception:  # noqa: BLE001 - redact privileged diagnostics
            raise ControlError(ErrorCode.UNAVAILABLE) from None

    def _apply(self, request: s.Request, deadline: float) -> s.MutationResult:
        assert request.operation_id is not None
        try:
            self._sync_anchor()
            if not isinstance(request.command, (s.AckEvents, s.Disconnect)):
                self._validate_runtime(deadline)
            if isinstance(request.command, s.SetAssignment):
                self.ccd.assignment(request, deadline)
            elif isinstance(request.command, s.SetPushRoutes):
                self.ccd.pushes(request, deadline)
            elif isinstance(request.command, s.SetRoute):
                self.routes.apply(request, deadline)
            elif isinstance(request.command, s.SetAccess):
                self.access.apply(request, deadline)
            elif isinstance(request.command, s.ChangeClient):
                self.pki.apply(request, deadline)
            elif isinstance(request.command, s.Disconnect):
                self.journal.stage(request.operation_id, "management", b"disconnect")
                self.management.disconnect(
                    request.command.client, request.command.session_id, deadline
                )
                self.journal.checkpoint(request.operation_id, "sessions")
            elif isinstance(request.command, s.Reload):
                self._reload(request.operation_id, deadline)
            elif isinstance(request.command, s.AckEvents):
                self.events.acknowledge(request.command.through)
                self.journal.checkpoint(request.operation_id, "events")
            else:
                raise ControlError(ErrorCode.UNAVAILABLE)
            bounded.remaining(deadline)
        except ControlError as error:
            # A staged preimage means a replacement might have happened. Preserve
            # the unresolved fence until actual-state reconciliation can prove it.
            if all(
                self.journal.evidence(request.operation_id, name) is None
                for name in ("ccd", "routes", "access", "pki", "management", "pushes")
            ):
                return self.journal.finish(request.operation_id, error.code)
            return self.journal.lookup(request.operation_id)
        return self.journal.finish(request.operation_id)

    def reconcile(self) -> None:
        """Reconcile exact retained intents without allocating new identities."""
        with self._writer:
            for request in self.journal.pending():
                if FAMILIES[request.command.kind] in self.settings.mutation_families:
                    try:
                        self._apply(request, time.monotonic() + 30)
                    except ControlError, OSError, ValueError:
                        # Retain the original evidence and fence on uncertainty.
                        pass
            self.journal.expire()

    @contextlib.contextmanager
    def _admit(self, deadline: float) -> Iterator[None]:
        if not self._admissions.acquire(blocking=False):
            raise ControlError(ErrorCode.EXHAUSTED)
        acquired = False
        try:
            acquired = self._writer.acquire(timeout=bounded.remaining(deadline))
            if not acquired:
                raise ControlError(ErrorCode.TIMEOUT)
            yield
        finally:
            if acquired:
                self._writer.release()
            self._admissions.release()

    def open_archive(self, request: s.Request) -> archive.ArchiveStream:
        """Package only active generations when the PKI family is enabled."""
        request = wire.decode_request(wire.encode(request))
        if "pki" not in self.settings.mutation_families:
            raise ControlError(ErrorCode.UNAVAILABLE)
        try:
            with self._admit(time.monotonic() + request.deadline_ms / 1000):
                return self.archives.open(request)
        except ControlError:
            raise
        except Exception:  # noqa: BLE001 - redact credential/parser failures
            raise ControlError(ErrorCode.UNAVAILABLE) from None

    def _validate_runtime(self, deadline: float) -> None:
        config = files.configuration(self.settings, deadline)
        options = files.directives(
            bounded.read_file(self.settings.config_path, deadline)
        )
        forbidden = {
            "client-to-client",
            "server-ipv6",
            "ifconfig-ipv6",
            "ifconfig-ipv6-pool",
            "route-ipv6",
            "push-ipv6",
            "compress",
            "comp-lzo",
            "secret",
            "tls-auth",
            "tls-crypt",
            "tls-crypt-v2",
        }
        pushed = [shlex.split(" ".join(entry)) for entry in options.get("push", [])]
        if (
            options.get("allow-compression", [["no"]]) != [["no"]]
            or any(entry and entry[0] in forbidden for entry in pushed)
            or config.device_type != "tun"
            or config.topology != "subnet"
            or "disable-dco" not in options
            or forbidden.intersection(options)
        ):
            raise ControlError(ErrorCode.UNAVAILABLE)
        if "assignments" in self.settings.mutation_families and (
            self.settings.projection_path is None
            or options.get("client-config-dir")
            != [[str(self.settings.projection_path / "ccd")]]
        ):
            raise ControlError(ErrorCode.UNAVAILABLE)
        if "pki" in self.settings.mutation_families and (
            self.settings.projection_path is None
            or options.get("crl-verify")
            != [[str(self.settings.projection_path / "crl.pem")]]
        ):
            raise ControlError(ErrorCode.UNAVAILABLE)

    def start(self) -> None:
        """Run periodic retained-intent reconciliation independently of API traffic."""
        if self._maintenance is None:
            self._maintenance = threading.Thread(
                target=self._maintain, name="vpn-agent-recovery", daemon=True
            )
            self._maintenance.start()

    def _maintain(self) -> None:
        while not self._stopped.is_set():
            try:
                self.reconcile()
            except ControlError, OSError, ValueError:
                pass
            self._stopped.wait(1)

    def _sync_anchor(self) -> None:
        anchor = self.settings.config_path.parent / ".ovpncp-journal-identity"
        previous = read_optional(anchor, time.monotonic() + 5)
        desired = {"identity": self.journal.identity, "revision": self.journal.revision}
        if previous:
            saved = json.loads(previous)
            if (
                not isinstance(saved, dict)
                or set(saved) != {"identity", "revision"}
                or saved["identity"] != desired["identity"]
                or type(saved["revision"]) is not int
                or not 0 <= saved["revision"] <= self.journal.revision
            ):
                raise ControlError(ErrorCode.INTEGRITY)
            if saved == desired:
                return
        elif self.journal.revision != 0:
            raise ControlError(ErrorCode.INTEGRITY)
        atomic_write(
            anchor, json.dumps(desired, sort_keys=True).encode(), time.monotonic() + 5
        )

    def _network_snapshot(self, deadline: float) -> bytes:
        config = files.configuration(self.settings, deadline)
        routes = json.loads(bounded.observe("routes", config.device, deadline))
        rules = bounded.observe("rules", config.device, deadline).decode().splitlines()
        normalized_rules = [
            shlex.split(line)[:2] if line.startswith(":") else shlex.split(line)
            for line in rules
            if line.startswith((":", "-A "))
        ]
        return json.dumps(
            {
                "routes": sorted(json.dumps(route, sort_keys=True) for route in routes),
                "rules": normalized_rules,
            },
            sort_keys=True,
        ).encode()

    def _reload(self, operation_id: str, deadline: float) -> None:
        started = self.journal.evidence(operation_id, "management")
        if started is None:
            options = files.directives(
                bounded.read_file(self.settings.config_path, deadline)
            )
            if (
                options.get("persist-key") != [[]]
                or options.get("persist-tun") != [[]]
                or {"remap-usr1", "up-restart"}.intersection(options)
            ):
                raise ControlError(ErrorCode.UNAVAILABLE)
            self.journal.stage(
                operation_id, "reload_network", self._network_snapshot(deadline)
            )
            self.journal.stage(operation_id, "management", b"reload")
            self.management.reload(deadline)
            self.journal.stage(operation_id, "reload_ack", b"accepted")
        elif self.journal.evidence(operation_id, "reload_ack") is None:
            raise ControlError(ErrorCode.UNKNOWN_OUTCOME)
        self.journal.checkpoint(operation_id, "reload")
        while True:
            bounded.remaining(deadline)
            try:
                healthy = super()._health(deadline).ready
                unchanged = self._network_snapshot(deadline) == self.journal.evidence(
                    operation_id, "reload_network"
                )
                if healthy and unchanged:
                    return
            except ControlError, OSError, ValueError:
                pass
            time.sleep(min(0.05, bounded.remaining(deadline)))
