"""Strict immutable version 1.0 commands and results with bounded values."""

import ipaddress
import itertools
from typing import Annotated, Literal, Self

import pydantic

from sciaiot.rivet.application import client_name

from .errors import ErrorCode

MAX_JSON_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_CHUNK_BYTES = 64 * 1024
MAX_STREAMS = 4
MAX_PAGE = 100
MAX_QUEUED_OPERATIONS = 100
MAX_DEADLINE_MS = 60_000
MAX_DEPTH = 20

Name = Annotated[str, pydantic.Field(pattern=client_name.CLIENT_NAME_PATTERN)]
Identifier = Annotated[
    str,
    pydantic.Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    ),
]
Generation = Annotated[int, pydantic.Field(ge=0, le=2**63 - 1)]
Timestamp = Annotated[int, pydantic.Field(ge=0, le=253402300799999999)]
Digest = Annotated[str, pydantic.Field(pattern=r"^[0-9a-f]{64}$")]
Token = Annotated[str, pydantic.Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")]


def _ipv4(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        raise ValueError("invalid IPv4 address") from None


def _network(value: str) -> str:
    try:
        return str(ipaddress.IPv4Network(value, strict=True))
    except ValueError:
        raise ValueError("invalid IPv4 network") from None


def _remote_ip(value: str) -> str:
    try:
        if "%" in value:
            raise ValueError("scoped transport address unsupported")
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise ValueError("invalid transport address") from None


RemoteIP = Annotated[str, pydantic.AfterValidator(_remote_ip)]
IPv4 = Annotated[str, pydantic.AfterValidator(_ipv4)]
Network = Annotated[str, pydantic.AfterValidator(_network)]


class Model(pydantic.BaseModel):
    """Reject coercion/unknown fields and avoid accidental object logging."""

    model_config = pydantic.ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
    )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(<redacted>)"

    def __str__(self) -> str:
        return self.__repr__()


class Health(Model):
    """Read readiness and negotiate the exact supported protocol."""

    kind: Literal["health"] = "health"


class ServerConfig(Model):
    """Read only sanitized profile transport and pool metadata."""

    kind: Literal["server_config"] = "server_config"


class Page(Model):
    """Bound an opaque snapshot cursor; adapters reject stale cursors."""

    cursor: Token | None = None
    limit: Annotated[int, pydantic.Field(ge=1, le=MAX_PAGE)] = MAX_PAGE


class ListClients(Page):
    """Discover existing certificate/CCD metadata without importing bytes."""

    kind: Literal["list_clients"] = "list_clients"


class GetClient(Model):
    """Read one existing logical client."""

    kind: Literal["get_client"] = "get_client"
    client: Name


class ChangeClient(Model):
    """Issue, renew, revoke or remove leaf state, retaining CA history."""

    kind: Literal["change_client"] = "change_client"
    client: Name
    action: Literal["issue", "renew", "revoke", "delete"]


class Assignment(Model):
    """Desired CCD address and optional owned iroute; never file contents."""

    address: IPv4
    network: Network | None = None


class SetAssignment(Model):
    """Replace this client's owned assignment, or remove it with null."""

    kind: Literal["set_assignment"] = "set_assignment"
    client: Name
    assignment: Assignment | None


class ManagedRoute(Model):
    """Logical ownership key plus an IPv4 route on configured TUN."""

    route_id: Identifier
    network: Network
    gateway: IPv4


class SetRoute(Model):
    """Ensure/remove only this exact owned route; reject foreign conflicts."""

    kind: Literal["set_route"] = "set_route"
    route: ManagedRoute
    present: bool


class ListRoutes(Page):
    """Inspect managed routes with stable paginated snapshots."""

    kind: Literal["list_routes"] = "list_routes"


def _private_network(value: str) -> str:
    network = ipaddress.IPv4Network(value)
    if not any(
        network.subnet_of(ipaddress.IPv4Network(block))
        for block in (
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        )
    ):
        raise ValueError("RFC 1918 network required")
    return value


PrivateNetwork = Annotated[Network, pydantic.AfterValidator(_private_network)]


class AccessIntent(Model):
    """Paired client access and optional private-network return intent."""

    access_id: Identifier
    source_client: Name
    destination_client: Name
    source_address: IPv4
    destination_address: IPv4
    private_networks: Annotated[
        tuple[PrivateNetwork, ...], pydantic.Field(max_length=100)
    ] = ()

    @pydantic.model_validator(mode="after")
    def distinct_clients(self) -> Self:
        """Disallow a self-pair which cannot represent restricted access."""
        if self.source_client == self.destination_client:
            raise ValueError("distinct clients required")
        return self


class SetAccess(Model):
    """Ensure/remove the complete paired owned access intent atomically."""

    kind: Literal["set_access"] = "set_access"
    intent: AccessIntent
    present: bool


class PushRoute(Model):
    """Typed IPv4 push via an exact gateway, owned by an access intent."""

    network: Network
    gateway: IPv4


class SetPushRoutes(Model):
    """Replace only pushes owned by an intent, preserving unrelated CCD."""

    kind: Literal["set_push_routes"] = "set_push_routes"
    client: Name
    intent_id: Identifier
    routes: Annotated[tuple[PushRoute, ...], pydantic.Field(max_length=100)]


class ListAccess(Page):
    """Inspect owned rules and pushed routes for actual/desired reconciliation."""

    kind: Literal["list_access"] = "list_access"


class ListSessions(Page):
    """Read live state, separate from API-owned connection history."""

    kind: Literal["list_sessions"] = "list_sessions"


class PollEvents(Page):
    """Read durable events after an acknowledged sequence."""

    kind: Literal["poll_events"] = "poll_events"
    after: Generation = 0


class AckEvents(Model):
    """Acknowledge only after the API commits its deduplicated history."""

    kind: Literal["ack_events"] = "ack_events"
    through: Generation


class Disconnect(Model):
    """Disconnect one exact observed session, never a management string."""

    kind: Literal["disconnect"] = "disconnect"
    client: Name
    session_id: Identifier


class Reload(Model):
    """Publish/reload a validated generation; full restart is deployment-owned."""

    kind: Literal["reload"] = "reload"


class LookupOperation(Model):
    """Resolve the original durable operation ID, including expired IDs."""

    kind: Literal["lookup_operation"] = "lookup_operation"
    operation_id: Identifier


class Archive(Model):
    """Package one active client generation into a bounded binary stream."""

    kind: Literal["archive"] = "archive"
    client: Name
    generation: Generation


Command = Annotated[
    Health
    | ServerConfig
    | ListClients
    | GetClient
    | ChangeClient
    | SetAssignment
    | SetRoute
    | ListRoutes
    | SetAccess
    | SetPushRoutes
    | ListAccess
    | ListSessions
    | PollEvents
    | AckEvents
    | Disconnect
    | Reload
    | LookupOperation
    | Archive,
    pydantic.Field(discriminator="kind"),
]
MUTATION_KINDS = frozenset(
    {
        "change_client",
        "set_assignment",
        "set_route",
        "set_access",
        "set_push_routes",
        "ack_events",
        "disconnect",
        "reload",
    }
)


class Request(Model):
    """Request identity differs from the durable mutation operation identity."""

    version: Literal["1.0"] = "1.0"
    request_id: Identifier
    command: Command
    operation_id: Identifier | None = None
    expected_generation: Generation | None = None
    deadline_ms: Annotated[int, pydantic.Field(ge=1, le=MAX_DEADLINE_MS)] = (
        MAX_DEADLINE_MS
    )

    @pydantic.model_validator(mode="after")
    def mutation_identity(self) -> Self:
        """Require an ID and compare-and-set generation for every mutation."""
        mutation = self.command.kind in MUTATION_KINDS
        if mutation != (self.operation_id is not None):
            raise ValueError("operation identity does not match command")
        if mutation != (self.expected_generation is not None):
            raise ValueError("generation does not match command")
        return self


class HealthResult(Model):
    """Readiness fails closed on missing capabilities or incompatible state."""

    kind: Literal["health"] = "health"
    ready: bool
    protocol: Literal["1.0"] = "1.0"
    generation: Generation


Cipher = Annotated[str, pydantic.Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")]


class ConfigResult(Model):
    """Only logical nonsecret fields needed by the current shared profile."""

    kind: Literal["server_config"] = "server_config"
    generation: Generation
    device: Annotated[str, pydantic.Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$")]
    network: Network
    server_address: IPv4
    device_type: Literal["tun", "tap"]
    ccd_exclusive: bool
    keepalive: tuple[
        Annotated[int, pydantic.Field(ge=1, le=65535)],
        Annotated[int, pydantic.Field(ge=1, le=65535)],
    ]
    port: Annotated[int, pydantic.Field(ge=1, le=65535)]
    protocol: Literal[
        "udp",
        "udp4",
        "udp6",
        "tcp",
        "tcp4",
        "tcp6",
        "tcp-server",
        "tcp4-server",
        "tcp6-server",
    ]
    topology: Literal["subnet", "net30", "p2p"]
    persist_key: bool
    persist_tun: bool
    data_ciphers: (
        Annotated[tuple[Cipher, ...], pydantic.Field(min_length=1, max_length=16)]
        | None
    ) = None
    fallback_cipher: Cipher | None = None
    verbosity: Annotated[int, pydantic.Field(ge=0, le=11)] | None = None
    explicit_exit_notify: Annotated[int, pydantic.Field(ge=0, le=65535)] | None = None


class ClientMetadata(Model):
    """Public leaf fingerprint/validity and CCD data; never PEM or paths."""

    client: Name
    generation: Generation
    state: Literal["active", "revoked", "deleted"]
    issuer: Annotated[str, pydantic.Field(min_length=1, max_length=1024)]
    subject: Annotated[str, pydantic.Field(min_length=1, max_length=1024)]
    certificate_sha256: Digest
    not_before: Timestamp
    not_after: Timestamp
    assignment: Assignment | None = None

    @pydantic.model_validator(mode="after")
    def validity(self) -> Self:
        """Reject reversed certificate lifetimes."""
        if self.not_after <= self.not_before:
            raise ValueError("invalid certificate lifetime")
        return self


class ClientResult(Model):
    """One authoritative client observation."""

    kind: Literal["get_client"] = "get_client"
    item: ClientMetadata


class ClientsResult(Model):
    """A bounded snapshot page for transactional API discovery/import."""

    kind: Literal["list_clients"] = "list_clients"
    items: Annotated[tuple[ClientMetadata, ...], pydantic.Field(max_length=MAX_PAGE)]
    next_cursor: Token | None = None
    generation: Generation


class RoutesResult(Model):
    """A bounded managed route page; foreign routes are never adopted."""

    kind: Literal["list_routes"] = "list_routes"
    items: Annotated[tuple[ManagedRoute, ...], pydantic.Field(max_length=MAX_PAGE)]
    next_cursor: Token | None = None
    generation: Generation


class Session(Model):
    """Validated session observation used for exact disconnect/reconciliation."""

    session_id: Identifier
    client: Name
    address: IPv4
    remote_address: RemoteIP
    remote_port: Annotated[int, pydantic.Field(ge=1, le=65535)]
    connected_at: Timestamp


class SessionsResult(Model):
    """A bounded consistent live-session snapshot."""

    kind: Literal["list_sessions"] = "list_sessions"
    items: Annotated[tuple[Session, ...], pydantic.Field(max_length=MAX_PAGE)]
    next_cursor: Token | None = None
    generation: Generation


class Event(Model):
    """Persistent sequence with duplicate identity; gap means reconcile."""

    sequence: Generation
    event_id: Identifier
    occurred_at: Timestamp
    event: Literal["connect", "disconnect", "gap"]
    session: Session | None = None

    @pydantic.model_validator(mode="after")
    def session_required(self) -> Self:
        """Require a session except for durable spool-gap markers."""
        if (self.event == "gap") != (self.session is None):
            raise ValueError("invalid event session")
        return self


class EventsResult(Model):
    """At most one page from the durable event spool."""

    kind: Literal["poll_events"] = "poll_events"
    items: Annotated[tuple[Event, ...], pydantic.Field(max_length=MAX_PAGE)]
    next_cursor: Token | None = None

    @pydantic.model_validator(mode="after")
    def ordered(self) -> Self:
        """Reject duplicate or unordered sequence numbers within a page."""
        sequences = tuple(item.sequence for item in self.items)
        if any(a >= b for a, b in itertools.pairwise(sequences)):
            raise ValueError("invalid event order")
        return self


class OwnedPushes(Model):
    """Actual CCD push routes owned by one durable access intent."""

    intent_id: Identifier
    client: Name
    routes: Annotated[tuple[PushRoute, ...], pydantic.Field(max_length=100)]


class AccessResult(Model):
    """Bounded paired snapshots of owned access and client push realization."""

    kind: Literal["list_access"] = "list_access"
    items: Annotated[tuple[AccessIntent, ...], pydantic.Field(max_length=MAX_PAGE)]
    pushes: Annotated[tuple[OwnedPushes, ...], pydantic.Field(max_length=MAX_PAGE)]
    generation: Generation
    next_cursor: Token | None = None


class MutationResult(Model):
    """Durable effect ledger: partial effects are not successful completion."""

    kind: Literal["mutation"] = "mutation"
    operation_id: Identifier
    generation: Generation
    state: Literal["pending", "succeeded", "failed", "partial", "unknown", "expired"]
    failure: ErrorCode | None = None
    intent_sha256: Digest
    completed: Annotated[
        tuple[
            Literal[
                "pki", "crl", "ccd", "routes", "access", "sessions", "events", "reload"
            ],
            ...,
        ],
        pydantic.Field(max_length=8),
    ] = ()
    client: Name | None = None

    @pydantic.model_validator(mode="after")
    def failure_state(self) -> Self:
        """Known failed outcomes are durable and have no committed effects."""
        if (self.state == "failed") != (self.failure is not None):
            raise ValueError("invalid failure outcome")
        if self.state == "partial" and not self.completed:
            raise ValueError("partial state requires committed effects")
        if self.state in {"failed", "pending"} and self.completed:
            raise ValueError("uncommitted state contains effects")
        if len(self.completed) != len(set(self.completed)):
            raise ValueError("duplicate effect")
        return self


class ArchiveManifest(Model):
    """Bind ZIP bytes to a request, active client and credential generation."""

    kind: Literal["archive"] = "archive"
    request_id: Identifier
    client: Name
    generation: Generation
    size: Annotated[int, pydantic.Field(ge=1, le=MAX_ARCHIVE_BYTES)]
    sha256: Digest
    media_type: Literal["application/zip"] = "application/zip"


class Failure(Model):
    """Fixed error code only, with no arbitrary detail or backend output."""

    kind: Literal["error"] = "error"
    code: ErrorCode


Result = Annotated[
    HealthResult
    | ConfigResult
    | ClientResult
    | ClientsResult
    | RoutesResult
    | AccessResult
    | SessionsResult
    | EventsResult
    | MutationResult
    | ArchiveManifest
    | Failure,
    pydantic.Field(discriminator="kind"),
]


class Response(Model):
    """Typed result whose correlation is checked against the original request."""

    version: Literal["1.0"] = "1.0"
    request_id: Identifier
    result: Result
