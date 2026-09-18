# VPN control protocol 1.0

Status: Phase 1 and Phase 2 complete; independent engineering/security review
accepted 2026-09-17.
Runtime routes now use the application seam; no actual agent listener is
installed. See [backend configuration and limitations](vpn-backends.md).
Phases 3–4 implement/verify the actual agent. The accepted
[Phase 0 decisions](container-architecture-decisions.md) remain authoritative.
The complete public mapping is [the route matrix](vpn-control-route-matrix.md).

## Application boundary and wire framing

`application.vpn_control.port.VpnControl` is a synchronous typed Protocol with
`execute(Request) -> Response` and `open_archive(Request) -> ArchiveStream`.
The package depends only on the standard library and existing Pydantic. It
imports no routes, FastAPI, database, file or process implementation. Phase 2
wires adapters through API startup and dependency injection.

The agent client uses POST `/v1/control` with `application/json` request
and response over `/run/ovpn-agent/agent.sock`. The version is also required in
the JSON envelope; only exact `1.0` is supported. POST `/v1/archive` accepts the
same envelope with an Archive command. It returns a framed binary body:
4-byte unsigned network-order JSON manifest length, the Response JSON
containing ArchiveManifest, then exactly `manifest.size` ZIP bytes. Length is
checked before allocation (1 MiB maximum); trailing bytes are an integrity
failure. HTTP errors carry bounded Response/Failure JSON, never HTML/debug
output. No base64 credential content, external URL, redirect or server path
is part of either endpoint. The Phase 2 client implements this framing; the
production server remains a later phase. Framed successful replies use application/octet-stream.

API performs verified Entra authentication, route permissions and local
ownership before using the port. Agent independently admits only the configured
API Unix peer UID obtained from kernel credentials on that connection. Socket
permissions/group membership alone are insufficient. No request contains UID,
principal, token, role or permission claims. The tests-only harness injects
trusted-peer denial out of band; this is not an authorization field in JSON.

Both sides strictly validate. Models are frozen, reject unknown fields and
coercion, and redact their str/repr. `wire.encode` revalidates objects before
serialization, including objects forged through Pydantic `model_copy` or
`model_construct`. `decode_request` rejects duplicate keys at every depth,
non-UTF-8, nonfinite numbers, wrong types, unknown commands and excessive depth
before Pydantic sees input. Exceptions are fixed ControlError codes with
suppressed source diagnostics. Do not log Pydantic `.errors()` dictionaries,
model dumps, raw JSON, archive bytes or exception chains from an adapter.

`wire.decode_response(data, request)` checks request ID, command/result type,
operation ID, canonical intent fingerprint, client identity and generation.
It also enforces requested page size and event cursor ordering. In AccessResult,
the requested limit applies separately to each of items and pushes (at most
twice the limit across the two collections); both share one snapshot cursor. Lookup results
bind to the original operation ID; the API additionally compares its stored
fingerprint/client/generation because the lookup request contains no original
payload. A valid error envelope is returned as Failure so callers can inspect
it. `wire.require_success` prevents pending, failed, partial, unknown or expired
mutation results from becoming synchronous public success.

## Closed command vocabulary

| Command | Result | Meaning |
| --- | --- | --- |
| Health | HealthResult | Readiness plus exact protocol/generation; readiness requires compatible backend, peer policy and validated state. |
| ServerConfig | ConfigResult | Sanitized logical transport, subnet/address and device metadata only. |
| ListClients / GetClient | ClientsResult / ClientResult | Existing public certificate validity, fingerprint, revoked/deleted state and CCD assignment. List discovery supports API import without transmitting keys. |
| ChangeClient | MutationResult | `issue`, `renew`, `revoke`, `delete`; serialized PKI/CRL and related session/leaf effects. |
| SetAssignment | MutationResult | Set/remove owned CCD address and optional iroute; preserve unrelated approved directives. |
| ListRoutes / SetRoute | RoutesResult / MutationResult | Observe or ensure/remove exact route ID, canonical network and gateway on configured TUN. |
| ListAccess / SetAccess | AccessResult / MutationResult | Observe or ensure/remove complete paired client access plus bounded RFC1918 destination networks. Inspection includes owned client pushes. |
| SetPushRoutes | MutationResult | Replace pushes owned by one intent/client with explicit network/gateway pairs; empty tuple removes only that intent's pushes. |
| ListSessions / Disconnect | SessionsResult / MutationResult | Snapshot actual sessions; disconnect exact session ID/client only. |
| PollEvents / AckEvents | EventsResult / MutationResult | Persisted sequence/cursor delivery and explicit post-DB-commit acknowledgment. |
| Reload | MutationResult | Publish/reload validated state generation, never full daemon/service restart. |
| LookupOperation | MutationResult or Failure | Query durable state of the SAME ID after uncertainty; not a request to execute it. |
| Archive | ArchiveManifest plus owned stream | Active client credential ZIP, bound to request/client/credential generation. |

Commands carry no shell, executable, argv, environment, arbitrary path, raw
OpenVPN directive, file content or generic configuration dictionary. Routes
and rules do not accept chain names, line numbers, interface overrides,
protocol numbers or firewall syntax. Deployment selects validated interface,
`iptables-nft`, routing protocol marker and anchor placement. Agent rejects
foreign ownership, overlaps, unavailable addresses, invalid active-client
state and stale generation, without changing administrator rules/routes/CCD.
The API checks address-pool and business ownership too; neither replaces agent
actual-state validation. Tunnel/address/route intent is IPv4 for the Phase 0
reference. Remote transport addresses support IPv4 or IPv6 without zone IDs.

Client names preserve `[A-Za-z0-9_-]{1,255}`. Linux interface identity is bounded
to 15 safe characters, including `tun-server`; device family is separate, never
inferred by appending `0`. Canonical networks reject host bits. Restricted
private destinations must lie wholly inside 10/8, 172.16/12 or 192.168/16;
loopback/link-local/public ranges are not accepted as RFC1918. General managed
routes and CCD networks remain canonical IPv4, with deployment/pool overlap
policy enforced by adapters. Existing comma-separated private destinations
map to a bounded tuple. API normalizes existing client CIDR input into canonical
network intent before crossing the port; identity names are never rewritten.

All timestamps are integer microseconds since Unix epoch UTC, from zero
through `253402300799999999` (last microsecond of year 9999). This preserves
current Python datetime precision without float rounding. Certificate issuer,
subject, not_before/not_after project to CertBase issued_by/issued_to/issued_on/
expires_on. Session carries tunnel address, remote address and port, and exact
connect time; Event adds exact occurrence/disconnect time. API formats the
existing remote endpoint string (IPv6 uses brackets), preserving its public
response field shape. Client certificate generation is the issuance/renewal
revision; it is not the unrelated global state revision.

## Durable mutation, retry and partial-failure semantics

Every mutation requires a UUIDv4 operation ID and an expected global generation;
request ID is per delivery. The operation ID is also the idempotency key; there
is no second independent deduplication key. Reads forbid operation/generation fields. Before
calling the agent, API commits desired intent, original immutable payload,
operation ID, expected generation and pending workflow state in one DB
transaction. Agent serializes conflicting mutations through one writer and
persists accepted intent before effects, then persists effect ledger/result
before acknowledgment. Every new completed mutation advances the global
revision once. Duplicate delivery of the same ID never advances it again.
Reads use stable snapshots and never acquire write authority.

`wire.intent_digest` hashes canonical sorted JSON of exact version, typed
command including defaults, and expected generation. Request ID and deadline
are delivery properties, excluded from the fingerprint. Operation ID binds
permanently to this digest. Reusing it with a different action, client, route,
payload or generation yields conflict before effects. A different ID with a
stale generation also conflicts. Canonical immutable tuples prevent mutable
nested intent from changing after admission. Server capability/readiness is
checked before mutation; a version mismatch never downgrades to another command.

Ledger states are pending, succeeded, failed, partial, unknown and expired.
`failed` is a known terminal pre-effect failure with a fixed failure code and
no completed effects; persist it and return it unchanged on duplicate lookup.
`pending` also has no committed effects. `partial` names committed effect
families (`pki`, `crl`, `ccd`, `routes`, `access`, `sessions`, `events`, `reload`)
and requires reconciliation rather than successful completion. `unknown`
means crash/timeout evidence cannot determine the outcome. `expired` is
permanently fenced; it never means safe to execute again. Agents may return
Failure/expired_operation when the full result has aged out but its tombstone
remains. Failed result generation stays at the admitted generation; success
is exactly expected+1; partial/unknown report the last proven generation.

On unavailable, exhausted or timeout: reads may retry within the original
overall deadline using bounded backoff; mutations query the SAME operation ID.
Unknown outcome also queries that ID. Partial/expired outcomes reconcile
persisted desired state with actual PKI/CRL/CCD/routes/rules and journal evidence.
Never generate a new ID merely to bypass uncertainty. Lookup not_found does
not prove no effect if a previously admitted operation is uncertain; restore
or inspect durable admission evidence before deciding. Only a proven rejected,
pre-effect operation may be replaced by a separately authorized new intent.

Keep full operation payload/results at least 35 days. After that, compact to
a durable non-reusable-ID tombstone; do not silently discard the fence.
Compact tombstones survive restart and coordinated restore for the deployment
lifetime. Capacity pressure refuses new admissions before exhaustion; it is
not permission to evict replay protection. Later journal implementations may
propose a reviewed epoch/fencing compaction protocol, but version 1.0 does not
have one. Restored generations/IDs remain fenced until reconciled with the
API recovery set. CA revocation evidence outlives certificate validity.

API commits observed completion after agent success. DB failure leaves the
original pending workflow for reconciliation. It must not blindly undo a
committed revocation, issue a replacement certificate or delete CA history.
Reversible CCD/route/access/profile effects can use a new, separately recorded
compensation intent with the current generation after checking ownership.
Revocation/renewal old-generation archive invalidation and local/Blob cleanup
are separate durable API steps. Cleanup failure remains a tracked orphan;
no business record or revoked credential is resurrected.

## Stable failures and bounds

| Error code | Protocol HTTP status | Caller action |
| --- | --- | --- |
| invalid_input | 422 | Correct the validated input; no raw rejected value is returned. |
| unauthorized | 403 | Correct trusted peer authorization/API policy; no retry escalation. |
| not_found | 404 | Check logical identity or reconcile uncertain operation evidence. |
| conflict | 409 | Refresh observed state; never repurpose an existing operation ID. |
| unavailable / exhausted | 503 | Retry bounded reads; query original mutation ID. |
| timeout | 504 | Same distinction; request deadline does not prove cancellation. |
| version_mismatch | 503 | Upgrade compatible components; mutations remain disabled. |
| partial_failure / unknown_outcome | 503 | Reconcile effects / query original operation ID. |
| expired_operation | 409 | Reconcile; same ID can never execute again. |
| integrity | 502 | Reject response/archive and reconcile if a write was involved. |

`errors.problem_status` is framework-independent. Future public route adapters
retain current documented response shapes and domain-specific 400/404/409/412,
201/204, and RFC 7807 behavior; this internal transport status table does not
rewrite current public statuses. Use fixed actionable public messages, never
agent output or addresses. No public async/202 migration is authorized.

Bounds preserve Phase 0: each JSON body/manifest <=1 MiB, ZIP <=16 MiB, nonempty
chunks <=64 KiB, four simultaneous streams, pages <=100 items and operation/
stream deadline <=60 seconds. Parser depth is <=20. Lists inside access/push
intent are <=100; all strings/identifiers have finite schema bounds. Agent
execution queue is capped at 100 admitted waiting operations plus one active
writer; no unbounded backlog. Admission above the cap is exhausted before
effects. Transport caps both Content-Length and bytes actually read before
allocation, enforces total deadlines on all blocking operations, and refuses
unbounded chunked bodies. Pure codec helpers cannot enforce socket timeouts.

ArchiveStream takes immediate source ownership, even before its first read.
Use its context manager. EOF, malformed/empty/oversized chunk, size/digest/
request/client/generation mismatch, expired deadline, source failure and caller
cancellation close exactly once. Constructor failure closes too. EOF verifies
size and SHA-256; `verified` remains false on cancellation or failed cleanup.
The source's close must cancel pending IO and release the four-stream quota.
An adapter must enforce its own blocking-read deadline: this pure iterator
cannot interrupt a blocked next(). Deadline runs from admission, including
packaging; the transport must pass the remaining budget to the wrapper.

Do not publish partial bytes as a completed archive. API writes to private
bounded staging, exhausts and verifies the stream, then atomically commits or
serves the authorized download. On failure it removes staged bytes and releases
the source; browser cancellation closes API storage/transport resources too.
The agent constructs exactly `ca.crt`, `issued/NAME.crt`, `private/NAME.key`,
never CA key/history. Packaging pins active credential generation; renewal,
revocation or deletion cancels/invalidate old generation handles before delivery.
Recheck generation immediately before public publication; an earlier download
permission decision does not override a later revocation. ZIP file-membership
and actual PKI coherence checks belong to future packaging adapters, not this
opaque-byte stream verifier. The tests use synthetic bytes, not real keys/ZIPs.

## Public projection and compatibility

Health handshake requires exact 1.0 before normal control use. Unknown fields,
commands and all other versions fail closed, including 1.1; there is no implicit
minor-version tolerance. Additive changes need a new explicitly negotiated
version with conformance fixtures; incompatible changes need a new major
version. Public REST remains unchanged while internal adapters roll out.

ConfigResult carries explicit transport protocol (udp/udp4/udp6/tcp/tcp4/tcp6
and server variants), device family/identity, port, pool network, server address,
topology, persistence, ccd_exclusive, keepalive, optional cipher list/fallback,
verbosity and UDP exit notification. Cipher names allow existing dots/dashes;
notification is 0..65535. Absence of optional profile options is preserved.
IPv6 transport does not authorize an IPv6 tunnel or unreviewed TAP deployment.
Adapters fail readiness when actual configuration requires unsupported secret
transport/compression delivery or conflicts with accepted reference semantics.

Current ServerBase still has required string fields ca/cert/key/dh/status/log/
client_config_dir/ifconfig_pool_persist plus optional hook paths. Future host
adapter keeps existing host responses during transition. Agent-backed public
projection preserves field names/types using fixed logical redacted markers
such as `agent-managed` for required private path strings and null for optional
hook paths. It never exports real host paths or secrets. Nonpath fields derive
from ConfigResult: port/proto/verb/notify become existing strings; dev is the
observed interface; network_address/subnet_mask derive from canonical subnet;
ip is server_address; keepalive joins its bounded pair. `script_security` is
null (deployment-owned hooks), not arbitrary configuration. This deliberate
sanitization preserves public field shape while private path values have no
meaning in the agent architecture; Phase 2 must add projection contract tests.

Shared profile stays API-owned, credential-free, <=1 MiB, named
`ovpncp-client.ovpn`, `application/x-openvpn-profile`, `Cache-Control: no-store`.
Remote endpoint remains explicit validated API input; agent never chooses it.
Certificate ZIP remains NAME.zip, application/zip, no-store. Optional Blob
storage, cleanup, archive cache versions and all business ownership remain API
concerns; no SAS URL or Blob credentials cross the port.

Events are durable, sequence-ordered, uniquely identified and replayable.
Agent retains 100,000 events or 24 hours with a 128 MiB cap. Overflow emits a
durable gap marker and requires a ListSessions snapshot reconciliation; never
block OpenVPN on API availability. API commits event IDs/history then AckEvents;
duplicates do not recreate history. Cursors are opaque <=128-character tokens
bound to a stable snapshot/generation; expired/stale cursor is conflict.
Connection history stays API-owned with 90-day retention. Authenticated manual
POST/PUT connection endpoints remain clients:write. Legacy loopback bypass
exists only in unchanged host runtime; it is never agent peer authorization.

## Conformance use and remaining runtime proof

`tests/vpn_control_conformance.py` exposes Harness and reusable core, validation/version/peer authorization, known-failure, uncertain/partial
failure and archive assertions. A future fake/host/agent test fixture provides a
VpnControl plus out-of-band fault, restart and expiry controls backed by
isolated mocks/disposable state. Run the same assertions for each adapter.
The tests-only reference models durable IDs/generation and synthetic archive
ownership; it is not the production fake or proof of OS persistence, real PKI,
network rendering, peer credentials or socket deadlines. Those adapter/runtime
proofs remain required in Phases 2–6. Ordinary tests perform no privileged IO.

## Phase 3 runtime subset

The read-only agent implements health, server_config, list_clients, get_client,
list_routes, list_access and list_sessions only. All other commands receive
fixed unavailable failures; no archive endpoint exists. Its content-derived
observation revisions and agent-lifetime session IDs cannot authorize writes.
See [agent operation](vpn-agent.md) for peer checks, limits and ownership
inspection. Full vocabulary remains the Phase 4 contract, not an assertion
that read-only observation implements durable mutations or events.
