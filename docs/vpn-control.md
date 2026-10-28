# VPN control

The public API authorizes business operations and sends typed requests to
the private VPN agent. This guide covers agent operation, the internal
wire protocol, and the mapping from public routes to agent commands.
For process ownership and backend selection, see [architecture](architecture.md).

- [Agent operation](#agent-operation)
- [Control protocol](#control-protocol)
- [API route mapping](#api-route-mapping)

## Agent operation

`rivet-agent` (also `python -m sciaiot.rivet.vpn_agent`) serves a private Unix
socket. Both native and container deployments use this agent behind an
unprivileged API. It is observation-only until mutation families are explicitly
enabled. With no `RIVET_AGENT_MUTATIONS`, writes and archives return
`unavailable`; reads still require a valid deployment and owned network baseline.

Enabled commands use `POST /v1/control`; credential streams use
`POST /v1/archive`. Malformed uncorrelated requests are closed. See
[the protocol](#control-protocol) for wire details and
[backends](architecture.md#application-backends) for host/shadow compatibility behavior.

### Explicit configuration

The agent loads these variables once at startup. No request can select a file,
executable, command argument, identity or environment variable.

| Variable | Meaning |
| --- | --- |
| `RIVET_AGENT_CONFIG` | Absolute server configuration file; single-file syntax. |
| `RIVET_AGENT_PKI` | Absolute public PKI observation root containing `ca.crt`, `index.txt`, and `issued/*.crt`. Private keys are opened only for explicitly enabled PKI lifecycle/archive operations. |
| `RIVET_AGENT_CCD` | Absolute CCD observation directory. |
| `RIVET_MANAGEMENT_SOCKET` | Canonical private OpenVPN management Unix socket. |
| `RIVET_MANAGEMENT_UID` | Expected listener creator UID from Linux `SO_PEERCRED`; OpenVPN startup UID may be 0 even after dropping privileges. |
| `RIVET_MANAGEMENT_GID` | Expected listener primary GID and private parent directory GID. |
| `RIVET_API_UID` | The sole API peer UID allowed to send control requests. |
| `RIVET_AGENT_SOCKET` | Defaults to `/run/ovpn-agent/agent.sock`. |
| `RIVET_AGENT_OWNERSHIP` | Owned intent manifest; read-only in observation mode, agent-written for enabled network families. |

Prepare the control parent directory with agent ownership, control group, mode
02750. The read-only server refuses an existing socket. A writer holding the exclusive
journal lock probes an owned stale socket and removes it only after connection
refusal; a live or foreign socket is refused. It creates its own mode 0660 socket,
and removes only that socket on shutdown. API mounts the directory read-only.
Linux peer credentials are checked before reading any HTTP header/body. Agent
client independently authenticates the server UID before sending bytes.
Directories and observation files cannot be symlinks, including ancestors.
Observation files must be regular with exactly one hard link, are opened
no-follow, have bounded reads,
and are rejected if their size/mtime/ctime changes during a read. Client
inventories require two identical bounded observations to detect cross-file
drift; network inspection rechecks its ownership inventory before publication.

OpenVPN configuration must contain exactly one `management <socket> unix`,
`management-client-user <agent-user>` and `management-client-group
<agent-primary-group>`. Account names resolve to the running agent identity.
Other `management-*` options fail readiness, including management signal,
client mode, hold and password querying. The management parent must exclude
other-user access and have the explicit runtime group. Both peer UID and GID
are verified before sending one of the fixed `version`, `state`, or `status 3`
commands. Exchanges are serialized and connections are closed after each.
There is no TCP fallback. Readiness requires OpenVPN 2.6, `CONNECTED,SUCCESS`,
the configured TUN link up, the explicit `nf_tables` compatibility backend,
and successful verification of all declared owned network state.

### Read-only observation and ownership limits

Configuration includes/inline blocks, unnumbered `dev tun`, ambiguous scalar
options and unsupported typed values fail closed. Configuration is projected
into protocol fields; private paths and raw options never leave the agent.
Only signed client-auth leaf certificates directly issued by the configured
CA are discovered. Names must match certificate CNs and the CA index must
contain each observed serial. State is observed from the CA index; server
certificates are excluded. CCD address and optional single iroute are typed.
This is observation, not complete migration/PKI validation or a recovery set.
Use the migration toolkit for complete authenticated migration and restore evidence.

An absent ownership manifest means zero owned routes/rules/pushes. Legacy
network entries are never automatically adopted. The strict manifest is:

```json
{
  "version": "1.0",
  "routes": [],
  "access": [],
  "pushes": []
}
```

Rows use protocol `ManagedRoute`, `AccessIntent` and `OwnedPushes` schemas.
Duplicate ownership identities, unknown fields and duplicate JSON keys fail.
The operator must review this inventory and explicitly allocate its route
protocol. Read-only fixtures use **200** unless `RIVET_AGENT_ROUTE_PROTOCOL`
is supplied; the read-only service creates neither markers nor a journal. Each route must actually match device, destination,
gateway, unicast type and the configured protocol. Matching foreign routes are rejected.

The expected filter chain is `OVPNCP_FORWARD`, reached from exactly the owned
FORWARD anchors `-i <dev>`/`-o <dev>` with comments
`ovpncp:anchor:ingress`/`ovpncp:anchor:egress`. Each access pair has source and
destination `/32` ACCEPT rules with comments
`ovpncp:<access_id>:forward`/`ovpncp:<access_id>:reverse`. Optional private
networks use source `/32` to private network and the reverse, with comments
`ovpncp:<access_id>:private:<zero-based-index>:forward`/`reverse`.
Every owned ACCEPT rule also requires `-i <dev> -o <dev>` and uses
`-m comment --comment <marker> -j ACCEPT`; anchors jump to the owned chain.
These grants cover client pairs and private networks routed behind a VPN peer,
with both packet directions traversing the configured TUN. They do not grant
forwarding between a TUN and a host LAN or Docker bridge. Missing, duplicate,
incomplete or unexpected owned-chain rules fail inspection. Older owned
ACCEPT rules without both interface selectors fail validation and require an
explicit stopped-writer upgrade review; they are never silently adopted.
Read-only observation ignores foreign rules outside the owned namespace;
access mutation applies the foreign-policy proof described below.
Declared pushes must belong to a declared access intent/client and occur
exactly once in that client's CCD. No packet is sent and no rule is changed.

Observation revisions are content-derived 63-bit values over typed public
observations, not monotonically increasing mutation journal generations.
Health carries the sanitized configuration revision.
Client revisions include certificate state and assignment; page revisions
cover the complete observed collection. Cursors bind collection revision and
offset and fail after observed drift. Session IDs derive from the management socket incarnation and normalized
client/transport/tunnel/connection-time fields. Agent restarts preserve the IDs
while the same daemon socket remains; replacing the daemon socket changes them. Traffic counters
do not change session revisions. Observation-only mode does not authorize session disconnects.

Each control connection permits one request. Header/body receipt has a two
second total budget, read-only observation is capped at ten seconds, and mutations/archives use
the validated request deadline (maximum 60 seconds). One active request and a kernel backlog of 16 avoid
unbounded threads. JSON, individual files, management and subprocess output
are bounded to 1 MiB (certificates 64 KiB); inventories have at most 10,000
records and 16 MiB of certificate bytes. Pages contain at most 100 items.
Subprocess output is bounded while reading, with deadline kill/reap and closed
pipes. Observation uses only `ip` read commands and
`iptables-nft-save` filter/version reads. Firewall inspection requires the
deployment's reviewed NET_ADMIN grant, even with mutation families disabled.

### Installation

Use [native installation](deployment.md#native-installation) for the exact matching
`sciaiot-rivet-agent` release or [container builds](builds.md#build-and-publish-artifacts) for the
first-party agent image. The image includes Pydantic, cryptography, iproute2,
iptables, and the reviewed Easy-RSA release. It excludes FastAPI and Azure
integrations, exposes no TCP listener, and needs no TUN device or cloud secrets.
The image bootstrap drops root before application execution; use the exact
capabilities and mounts in [container deployment](deployment.md#container-deployment).

### Mutation configuration

Enable families individually in this order, verifying and retaining rollback
state after each: `assignments`, `routes`, `access`, `pki`, then `events` and
`management`. `RIVET_AGENT_MUTATIONS` is a comma-separated list; the empty
(default) list leaves the agent read-only. Unknown names fail startup.

| Variable | Mutation requirement |
| --- | --- |
| `RIVET_AGENT_JOURNAL` | Existing private agent-owned durable directory; required for every enabled family. |
| `RIVET_AGENT_PROJECTION` | Agent-written minimal runtime root, mounted read-only by OpenVPN. Precreate `ccd/`; required by assignment and PKI deployment. |
| `RIVET_AGENT_ROUTE_PROTOCOL` | Explicit operator-allocated integer 1–255; required for route writes. No production default is reserved. Protocol 200 is only the disposable/read-only fixture convention. |
| `RIVET_AGENT_EASYRSA` | Trusted absolute Easy-RSA executable; default `/usr/share/easy-rsa/easyrsa`. Renewal currently supports the verified 3.1.7 command semantics. |
| `RIVET_AGENT_EVENT_SOCKET` | Separate protected local daemon-ingress Unix socket; required when `events` is enabled. Never mount it in the API. |

The mutation profile supports OpenVPN 2.6, numbered IPv4 TUN, topology subnet
and explicit `disable-dco`. `client-to-client`, TAP, IPv6 tunnel directives,
compression and static/TLS shared-key modes unsupported by the profile/archive
contract fail closed. Management writes are exact observed-session `client-kill`
and controlled `signal SIGUSR1`, requiring explicit `persist-tun` and
`persist-key` and rejecting `remap-usr1` or `up-restart`. This soft reconnect
applies projected CCD/CRL to subsequent connections, preserves the tunnel,
and does not reread static server configuration. Static configuration changes
and full restarts remain deployment-owned. Completion requires restored
health and unchanged routes/firewall; uncertainty stays journaled for recovery.
A reload reconnects clients and belongs in a maintenance window. These signal
semantics follow the [OpenVPN 2.6 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual.html).

Point `client-config-dir` at `PROJECTION/ccd` and `crl-verify` at
`PROJECTION/crl.pem`. Canonical CCD and complete PKI remain agent-private.
Preprovision only the server/CA certificates, server key, reviewed server
configuration and CRL in the OpenVPN projection; never expose the CA key,
client private keys, index or serial files. Generated CCD/CRL files are 0640
with the configured OpenVPN runtime GID. Verify actual mount and capability grants on the selected deployment engine.

Before enabling access mutation or admitting VPN traffic, deployment must
review and provision the empty `OVPNCP_FORWARD` baseline: both marked TUN
FORWARD anchors first, and `-m comment --comment ovpncp:terminal-deny -j DROP`
last in the owned chain. This avoids an initially permissive forwarding window
and a readiness/bootstrap deadlock. Do this only on reviewed disposable or
operator-authorized target state. The agent atomically rebuilds only its owned
chain and exact anchors using `iptables-nft-restore --noflush`. It never adds an
established-connection bypass. Before granting access, the agent checks
foreign FORWARD rules and reachable user chains with a bounded, conservative
parser. A positive exact input or output interface different from the VPN TUN
proves that a rule cannot match the owned TUN-to-TUN grants. Other reachable
rules must have provably nonrestrictive behavior. Applicable DROP/REJECT,
unsupported targets or control flow, ambiguous syntax, cycles and incomplete
observations fail closed with a conflict. Docker chain names alone grant no
exception: ordinary bridge-specific rules pass only because their interface
constraints exclude the VPN peer traffic.

Administrator restrictions that could apply to those grants still require
operator review; the agent will not prepend an ACCEPT ahead of them. Foreign
rules, routes and unmarked CCD directives are preserved, never adopted. The
interface and chain-traversal semantics follow the
[iptables manual](https://man7.org/linux/man-pages/man8/iptables.8.html).

CCD writes replace only exact `# ovpncp:begin:OWNER` / `# ovpncp:end:OWNER`
blocks. Existing unmarked assignments conflict rather than becoming implicitly
owned. Import discovers their metadata without rewriting them. A migration or
explicit operator-reviewed adoption step is required before changing such an
assignment. Route changes require exact inventory identity, destination,
gateway, device and allocated protocol; no generic route replacement occurs.
The public server-route API uses the server's usable VPN address as its next
hop, matching the host backend. OpenVPN's CCD `iroute` selects the client
behind that destination. The agent accepts this next hop as well as usable
client addresses in the VPN pool; network/broadcast addresses, gateways
outside the pool and destinations overlapping the pool remain invalid.
Push blocks are bound to an existing access intent and its allowed networks.

For an existing or migrated installation, importing clients does not establish
ownership of their CCD assignments or kernel routes. If assigning or
unassigning an address returns `409` with type `/errors/vpn/conflict`, have
an operator inspect the canonical CCD assignment markers, the matching
OpenVPN projection, and pending operation evidence. Unmarked `ifconfig-push`
or `iroute` directives, malformed ownership markers, or divergent projected
files require explicit review before adoption. For a route conflict, compare
the live route with the agent ownership inventory, including destination,
gateway, interface and protocol. Preserve the API workflows and agent journal
while resolving discrepancies; deleting them discards recovery evidence.
The conflict code alone cannot identify which check failed. Refresh state
and resolve the discrepancy before retrying the same API request.

### Durable intent and recovery

SQLite FULL-synchronous transactions commit immutable operation ID, canonical
intent digest and expected generation before external effects. A process-held
exclusive lock prevents two agent writers. A UUID in the database is also
fsynced into `.ovpncp-journal-identity` on the separate configuration volume;
a missing/replaced journal with a retained configuration marker fails closed. The marker also records
the monotonic acceptance revision before effects, so restoring an older journal
under newer configuration evidence is refused.
Back up and restore these volumes as one coordinated recovery set.

File/network mutations persist exact before/after evidence before applying,
verify actual realization and then checkpoint committed effects. Easy-RSA is
the sole CA implementation. Issuance and renewal/revocation command starts are
fenced durably: after a lost reply the agent inspects certificate/index evidence
and never blindly repeats an irreversible step. A crash with inconclusive
partial Easy-RSA artifacts remains fenced for operator recovery. The complete
PKI must be backed up before maintenance; journal evidence is not a PKI backup.
Names starting with `-` or longer than 240 characters are rejected at the
Easy-RSA boundary to avoid option parsing and filesystem component overflow.

A background job reconciles retained intents once per second. New conflicting
writes are rejected before effects with durable failure evidence; accepted
uncertain operations block later writers. Lookup remains available while
readiness is false. API recovery queries the original ID; an explicit API retry
may resubmit the exact original ID/command/generation after a genuine missing
lookup. Background API recovery never starts missing PKI work with its short
lookup budget. A fresh ID is permitted only after durable proof of terminal
pre-effect failure, with the old attempt retained in the API database.

Retain full operations/evidence for at least 35 days; bounded maintenance then
compacts at most 1,000 terminal rows per cycle to lifetime ID/digest tombstones.
The ledger has a 1 GiB SQLite page limit and stops new admission at 896 MiB used
pages or under 128 MiB filesystem free space, reserving completion/event room.
Exhaustion never evicts replay fences. Increase reviewed storage capacity and
recover pending work instead of deleting the journal. At most 100 waiting
operations are admitted with total-deadline lock acquisition.

Credential ZIPs are bounded to 16 MiB and four concurrent streams, with
64 KiB chunks and fixed-length framed transport. Members are `ca.crt`,
`issued/NAME.crt`, and `private/NAME.key`. Packaging verifies the certificate/key
pair and active public generation, rechecking it before each chunk and EOF;
renewal, revocation, deletion or relevant metadata drift invalidates the stream.
Cancellation releases unread streams. API storage publishes only after full
length/digest verification and retains its existing authorization checks.

### Local connection events

Install the package and `rivet-vpn-event` entry point in native OpenVPN
environments. The OpenVPN image supplies its own reviewed wrapper, which sets
`PYTHONPATH` explicitly before loading the event module. OpenVPN strips inherited
Python variables; an arbitrary source-only module command is not equivalent. Verify
both hooks before admitting VPN clients. Import/argument/deployment failures
outside the hook entry point are configuration errors, not an API-outage mode.

Precreate the separate event-socket parent as agent-owned, runtime-group,
mode 02770; the socket is 0660. OpenVPN receives access to this mount, never to
the operation journal. Configure `script-security 2` and use this reviewed
command for both `client-connect` and `client-disconnect`, substituting trusted
deployment paths and numeric UID:

```text
/usr/local/bin/rivet-vpn-event --socket /run/ovpn-events/events.sock --management-socket /run/openvpn/management.sock --agent-uid 65532
```

The local hook validates only required daemon environment fields and checks
the agent peer UID before sending bounded JSON. Set `RIVET_OPENVPN_UID` to the post-drop hook UID when it differs from the
management-listener creator UID; otherwise the listener UID is the default.
The ingress worker verifies that daemon UID and runtime GID before reading and durably commits before acknowledging.
Connect/disconnect events are captured directly, including sessions shorter
than a polling interval. Producer occurrence timestamps are retained. Each hook connect receives a
unique durable session ID; live observations bind it to the exact daemon
Client ID. A same-second reconnect cannot alias an earlier disconnect target. A total
200 ms local exchange budget bounds each hook; loss of agent/API connectivity
returns success to OpenVPN and writes a local loss marker. Agent startup or
loss markers produce durable gaps and require API snapshot reconciliation.
There is no loopback HTTP callback, role bypass or remote network dependency.

The spool retains up to 100,000 events or 24 hours, with a 128 MiB allocation
budget (120 MiB payload ceiling plus page/index reserve). Overflow replaces
retained history with an explicit durable gap; sequences never reset. API
commits event receipts, connection history and cursor before an immutable
acknowledgement intent. Completed acknowledgement evidence and acknowledged
receipts have 90-day retention with bounded cleanup; pending acknowledgement
intents are retained until resolved. Enable API ingestion with `RIVET_VPN_EVENTS=1` and
workflow lookup reconciliation with `RIVET_VPN_RECONCILE=1`, only in agent mode;
both default off. A gap records incomplete history and obtains live sessions.
Durable session bindings are capped at 10,000. Missing disconnect hooks can
retain stale bindings across daemon crashes; exhausting that bound refuses new
bindings and records producer loss instead of silently reusing identities.
Investigate hook continuity and reconcile the journal before re-enabling event
ingestion; do not delete the journal to clear capacity.

### Family rollback

Freeze new writes, retain all API/agent intent and event records, reconcile
accepted operations and verify actual state before disabling a family or
switching `RIVET_VPN_BACKEND` to `host`. Never run legacy and agent writers
concurrently. Keep the journal/configuration identity and CA revocation history;
rollback must not resurrect credentials. Verify host-compatible CCD, route,
firewall and archive behavior explicitly. An uncertain PKI/reload operation
requires operator resolution before resuming writes. No production host, cloud
or container deployment is changed by these instructions or unit tests.



### Verification tools

Unit tests use disposable signed PKI, mocked system commands, and local Unix
sockets. Live observation/mutation tests are explicitly invoked on authorized
disposable infrastructure. The namespace wrappers
`tests/integration/run_vpn_agent_namespace.sh` and
`tests/integration/run_vpn_mutation_namespace.sh` require private mount/network/PID
attestation; never run their Python fixtures directly on a host. Follow the
[integration guide](../tests/integration/README-container.md) and the
[migration namespace procedure](data-management.md#reproducible-rehearsal).

## Control protocol

The API and private agent implement this contract. See
[architecture](architecture.md) for trust boundaries,
[backends](architecture.md#application-backends) for adapter differences, and
[the route matrix](#api-route-mapping) for public authorization.

### Application boundary and wire framing

`application.vpn_control.port.VpnControl` is a synchronous typed Protocol with
`execute(Request) -> Response` and `open_archive(Request) -> ArchiveStream`.
The package depends only on the standard library and existing Pydantic. It
imports no routes, FastAPI, database, file or process implementation. Startup wires adapters through API startup and dependency injection.

The agent client uses POST `/v1/control` with `application/json` request
and response over `/run/ovpn-agent/agent.sock`. The version is also required in
the JSON envelope; only exact `1.0` is supported. POST `/v1/archive` accepts the
same envelope with an Archive command. It returns a framed binary body:
4-byte unsigned network-order JSON manifest length, the Response JSON
containing ArchiveManifest, then exactly `manifest.size` ZIP bytes. Length is
checked before allocation (1 MiB maximum); trailing bytes are an integrity
failure. HTTP errors carry bounded Response/Failure JSON, never HTML/debug
output. No base64 credential content, external URL, redirect or server path
is part of either endpoint. The client and feature-gated agent implement this framing. Framed successful replies use application/octet-stream.

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

### Closed command vocabulary

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
actual-state validation. Tunnel/address/route intent is IPv4 for the reference deployment. Remote transport addresses support IPv4 or IPv6 without zone IDs.

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

### Durable mutation, retry and partial-failure semantics

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

### Stable failures and bounds

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

`errors.problem_status` is framework-independent. Unwrapped `ControlError`
failures, including client address assignment/unassignment and server route
listing/addition/removal, use these statuses in RFC 7807 responses with a
stable `/errors/vpn/<code>` type and fixed actionable detail. Expected agent
failures no longer escape as unhandled ASGI exceptions. Existing boundary
validation, domain-specific HTTP errors and other workflow-specific error
responses retain their statuses. Agent diagnostics are never included in the
detail. No public async/202 migration is authorized.

Protocol bounds: each JSON body/manifest <=1 MiB, ZIP <=16 MiB, nonempty
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
permission decision does not override a later revocation. The agent archive
adapter constructs the fixed ZIP membership and checks certificate/key pairing
and active generation. The stream verifier checks framing and integrity without
interpreting ZIP contents; its unit tests use synthetic bytes. Agent archive
tests separately exercise packaging and credential validation.

### Public projection and compatibility

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
client_config_dir/ifconfig_pool_persist plus optional hook paths. The host
adapter keeps existing host responses for compatibility. Agent-backed public
projection preserves field names/types using fixed logical redacted markers
such as `agent-managed` for required private path strings and null for optional
hook paths. It never exports real host paths or secrets. Nonpath fields derive
from ConfigResult: port/proto/verb/notify become existing strings; dev is the
observed interface; network_address/subnet_mask derive from canonical subnet;
ip is server_address; keepalive joins its bounded pair. `script_security` is
null (deployment-owned hooks), not arbitrary configuration. This deliberate
sanitization preserves public field shape while private path values have no
meaning in the agent architecture; projection contract tests cover this boundary.

Shared profile stays API-owned, credential-free, <=1 MiB, named
`rivet-client.ovpn`, `application/x-openvpn-profile`, `Cache-Control: no-store`.
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
exists only in host/shadow runtime; it is never agent peer authorization.

### Conformance and runtime coverage

`tests/vpn_control_conformance.py` provides reusable core, validation, peer,
known-failure, uncertain/partial-failure, and archive assertions. The fake,
mocked host, and synthetic Unix-peer adapters exercise these without privileged
host I/O. Durable storage, real PKI, network rendering, and deployment grants
also require the [explicit integration harnesses](../tests/integration/README-container.md).

### Observation-only mode

The read-only agent implements health, server_config, list_clients, get_client,
list_routes, list_access and list_sessions only. All other commands receive
fixed unavailable failures when mutation families are disabled. Its
content-derived observation revisions do not authorize writes.
See [agent operation](#agent-operation) for peer checks, limits and ownership
inspection. The full vocabulary requires the corresponding mutation families; observation
alone does not enable durable writes or events.


### Enabled mutation families

Explicit mutation families enable the full typed vocabulary and framed archives.
Health/config use the durable mutation generation; client/archive metadata keeps
content-derived generation fencing. Every accepted intent and exact per-effect
before/after evidence is persisted before effects. Known pre-effect rejections
remain queryable, uncertain writes remain fenced, and Lookup negotiates protocol
without requiring readiness. No arbitrary executable, path or raw command is
accepted over the wire.

The agent implements owned CCD/projection edits, allocated-protocol routes,
paired firewall rules with terminal denial, Easy-RSA lifecycle, bounded archives,
local protected daemon events, exact-session disconnect and controlled reload.
Reload uses SIGUSR1 with validated persist-tun/persist-key, then verifies daemon
health and unchanged network state. It does not reread static configuration;
static configuration changes and full restart remain deployment-owned.
Read [agent operation](#agent-operation) for required bootstrap, compatibility limits,
retention, privileged execution boundaries, failure recovery and family rollback.
New artifacts and production deployments require [release verification](builds.md#release-verification).

## API route mapping

The 48 public method/path pairs map to the application interface below. Internal paths omit the reverse proxy's
single `/api` prefix. Existing response schemas/statuses remain the public
contract; the [protocol](#control-protocol) describes internal operations.

Every management permission is the exact dependency in authorization.py.
Delegated sysadmin and app-only ServiceAdmin have all management permissions;
device_user has no management permissions. Self-service uses verified principal
plus explicit local ownership/grants, never role-based shortcuts. Shared-profile
download accepts each authenticated current role, including app-only admin.
A Device AccessGrant is API business visibility, not a VPN firewall rule;
UserClient ownership is separate from both. The /networks routes intentionally
use server permissions, and administrative credential download intentionally
requires clients:write. Do not infer permissions from HTTP method names.

The two connection endpoints retain clients:write for authenticated callers.
Their existing precise local-hook exception remains only in unchanged host
behavior during transition. Agent daemon events use trusted UDS polling;
there is no JSON impersonation, unauthenticated agent callback or loopback
bypass in the target. Existing ownership/not-found/precondition behavior stays.

All mutating agent workflows use pending API intent, durable per-step operation
IDs, generation compare-and-set and recorded completion before public success.
Multiple calls in one row are distinct durable steps; no cross-process atomic
transaction is implied. Unknown outcome always queries the original ID before
compensation. Reversible compensation is a new recorded intent with current
generation and ownership checks. Never reverse committed revocation, remove
CA history, or touch administrator-owned routes/rules/unrelated CCD pushes.
Read rows have no desired-state mutation unless explicitly stated.

Audit column names are planned application audit event types, not new runtime
logging. Each event records opaque request/operation IDs, opaque local actor/
resource IDs, outcome code, generation and effect/compensation status; no raw
issuer/subject/token/name/address/path/PEM/ZIP/SAS URL. Record denied/failed
attempts with the same safe action type and fixed outcome. For downloads record
started/completed/cancelled without bytes or credentials. Local grants/ownership
changes are auditable without implying any agent call. All API DB-only changes
use their existing transaction boundaries.

| Method | Path | Permission / ownership | Domain owner | Desired-state change | Agent calls | Compensation / recovery | Audit event |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `POST` | `/server` | server:write | API Server/profile; agent actual config | Create server/address pool and profile generation | ServerConfig | Restore prior profile and roll back DB initialization | `server.initialize` |
| `GET` | `/server` | server:read | API Server read model | None | None (ServerConfig during reconciliation) | None | `server.read` |
| `PUT` | `/server/client-config` | server:write | API shared profile | Replace profile using explicit remote endpoint | ServerConfig | Restore prior atomic profile if DB generation commit fails | `profile.replace` |
| `GET` | `/server/health` | server:read | Agent actual health; API projection | None | Health | None | `server.health` |
| `GET` | `/server/assignable-virtual-addresses` | server:read | API address-pool ownership | None | None | None | `address.list` |
| `GET` | `/server/routes` | server:read | Agent owned route snapshot; API projection | None | ListRoutes | None | `route.list` |
| `POST` | `/server/routes` | server:write | API route intent; agent owned routes | Persist route present | SetRoute(present=true) | Restore prior owned intent after proven outcome; reconcile uncertain ID | `route.ensure` |
| `DELETE` | `/server/routes` | server:write | API route intent; agent owned routes | Persist route absent | SetRoute(present=false) | Restore only prior owned route if desired transaction fails | `route.remove` |
| `POST` | `/clients` | clients:write | API Client/Cert; agent PKI | Persist pending new client/operation | ChangeClient(issue), GetClient | Reconcile issued identity; never issue twice after DB failure | `client.create` |
| `GET` | `/clients` | clients:read | API Client records | None | None | None | `client.list` |
| `GET` | `/clients/{client_name}` | clients:read | API Client/Cert/address/history | None | None (GetClient during reconciliation) | None | `client.read` |
| `PUT` | `/clients/{client_name}/package-cert` | clients:write | API archives; agent active credential generation | Record package/cache generation | GetClient, Archive | Remove incomplete staged archive; retain previous valid generation | `certificate.package` |
| `GET` | `/clients/{client_name}/download-cert` | clients:write | API authorized archive delivery | No business change; validate archive generation | GetClient, Archive (fresh verified agent stream) | Close/cancel stream, discard partial staging | `certificate.download` |
| `PUT` | `/clients/{client_name}/renew-cert` | clients:write | API Cert/archive records; agent PKI/CRL | Persist renewal and invalidate old archive generation | ChangeClient(renew), GetClient | Reconcile committed renewal/CRL; never restore invalidated credential | `certificate.renew` |
| `PUT` | `/clients/{client_name}/revoke` | clients:write | API revoked state; agent PKI/CRL/sessions | Persist revocation and archive invalidation | ChangeClient(revoke), ListSessions; Disconnect if reconciliation requires | Never undo committed revocation; reconcile DB and archive cleanup | `client.revoke` |
| `DELETE` | `/clients/{client_name}` | clients:write | API relationships/history/archives; agent revoked leaf/CCD | Require revoked client; persist deletion workflow | ChangeClient(delete) | Restore staged reversible leaf cleanup only before commit; never CA history; retry Blob orphan cleanup | `client.delete` |
| `PUT` | `/clients/{client_name}/assign-ip` | clients:write | API exclusive pool ownership; agent owned CCD | Persist assignment for active client plus canonical CIDR | SetAssignment(address, optional network) | Restore previous owned assignment after proven outcome; preserve unrelated CCD | `address.assign` |
| `DELETE` | `/clients/{client_name}/unassign-ip` | clients:write | API pool ownership; agent owned CCD | Release assigned address | SetAssignment(null) | Restore previous owned assignment if desired DB commit fails | `address.unassign` |
| `POST` | `/clients/{client_name}/connections` | clients:write; legacy host hook exception | API Connection history | Persist authorized manual connect history | None; agent daemon ingestion uses PollEvents/AckEvents separately | DB rollback; event ingestion deduplicates before acknowledgment | `connection.start` |
| `PUT` | `/clients/{client_name}/connections` | clients:write; legacy host hook exception | API Connection history | Close matching active history record | None; agent daemon ingestion uses PollEvents/AckEvents separately | DB rollback; missing active connection remains 404 | `connection.end` |
| `POST` | `/clients/import` | clients:write | API import/upsert; agent existing metadata | Transactional client/cert/address and optional device upsert; preserve skip/conflict counts | ListClients; GetClient when needed | Roll back failed DB item/transaction; no issuance or source PKI changes | `client.import` |
| `POST` | `/networks` | server:write | API RestrictedNetwork intent/history; agent paired access/pushes | Persist active network with both assigned clients and bounded private destinations | SetAccess(present=true), SetPushRoutes where needed | Restore prior owned intent/pushes; record partial steps and reconcile | `network.create` |
| `GET` | `/networks` | server:read | API RestrictedNetwork records/filter | None | None (ListAccess during reconciliation) | None | `network.list` |
| `GET` | `/networks/{network_id}` | server:read | API RestrictedNetwork record | None | None | None | `network.read` |
| `DELETE` | `/networks/{network_id}` | server:write | API network history; agent owned access/pushes | Close active intent; already closed is idempotent | SetAccess(present=false), SetPushRoutes removing only this intent | Restore prior owned intent only if still desired; reference-count shared pushes/routes | `network.close` |
| `GET` | `/me` | authenticated | API verified principal/local User | Strict auto-registration only when current delegated-user policy permits | None | Rollback failed registration; no role/permission escalation | `principal.read` |
| `GET` | `/me/client-config` | authenticated (all three current roles) | API shared profile | None | None | Close file response on cancellation | `profile.download` |
| `GET` | `/me/clients` | authenticated + local User | API UserClient ownership filter | None | None | None | `self.client.list` |
| `GET` | `/me/devices` | authenticated + local User | API AccessGrant filter | None | None | None | `self.device.list` |
| `GET` | `/me/devices/{device_id}` | authenticated + exact AccessGrant | API granted device lookup | None | None | None | `self.device.read` |
| `PUT` | `/me/clients/{client_name}/package-cert` | authenticated + exact UserClient + active client | API self-service archive; agent generation | Record package/cache generation after ownership check | GetClient, Archive | Discard staged bytes; preserve previous valid generation | `self.certificate.package` |
| `GET` | `/me/clients/{client_name}/download-cert` | authenticated + exact UserClient + active client | API self-service archive delivery | No business change; check active ownership/generation | GetClient, Archive (fresh verified agent stream) | Close/cancel and discard partial staging | `self.certificate.download` |
| `POST` | `/devices` | devices:write | API DeviceService | Create device with validated optional client link | None | DB transaction rollback | `device.create` |
| `GET` | `/devices` | devices:read | API DeviceService | None | None | None | `device.list` |
| `GET` | `/devices/{device_id}` | devices:read | API DeviceService | None | None | None | `device.read` |
| `PATCH` | `/devices/{device_id}` | devices:write | API DeviceService | Update metadata/client link subject to uniqueness | None | DB transaction rollback | `device.update` |
| `DELETE` | `/devices/{device_id}` | devices:write | API DeviceService | Remove device and grants; retain VPN client | None | DB transaction rollback | `device.delete` |
| `POST` | `/users` | users:write | API UserService | Create stable issuer/subject mapping | None | DB transaction rollback | `user.create` |
| `GET` | `/users` | users:read | API UserService | None | None | None | `user.list` |
| `GET` | `/users/{user_id}` | users:read | API UserService | None | None | None | `user.read` |
| `PATCH` | `/users/{user_id}` | users:write | API UserService | Update local display name | None | DB transaction rollback | `user.update` |
| `DELETE` | `/users/{user_id}` | users:write | API UserService | Remove user/grants/client links; retain VPN clients | None | DB transaction rollback | `user.delete` |
| `PUT` | `/users/{user_id}/devices/{device_id}` | access:grant | API AccessService | Idempotently grant device access; 201 on creation | None | DB transaction rollback | `grant.ensure` |
| `DELETE` | `/users/{user_id}/devices/{device_id}` | access:grant | API AccessService | Revoke device access | None | DB transaction rollback | `grant.revoke` |
| `GET` | `/users/{user_id}/devices` | access:read | API AccessService | None | None | None | `grant.list` |
| `PUT` | `/users/{user_id}/clients/{client_id}` | users:write | API UserClientService | Exclusively link client; 201 on creation | None | DB transaction rollback | `ownership.link` |
| `DELETE` | `/users/{user_id}/clients/{client_id}` | users:write | API UserClientService | Unlink client ownership | None | DB transaction rollback | `ownership.unlink` |
| `GET` | `/users/{user_id}/clients` | users:read | API UserClientService | None | None | None | `ownership.list` |

The API read models still own users, clients, cert metadata, address allocation,
connection history and restricted-network history. Agent observations feed
reconciliation/import; they never replace business authorization. ServerConfig
projection preserves required public fields using sanitized logical markers
for agent-private paths, as specified in the protocol's compatibility section.
Profile generation preserves the current explicit remote endpoint and atomic
initialization rollback. Public certificate and shared-profile cache/download
headers, filenames, media types and size limits remain unchanged.

Background reconciliation uses Health/ServerConfig, ListClients/GetClient,
ListRoutes, ListAccess, ListSessions and LookupOperation, without creating
additional public routes. Event polling commits deduplicated history before
AckEvents and resolves gap markers through a session snapshot. Reload and exact
Disconnect are internal lifecycle/reconciliation steps, not new operator APIs.
