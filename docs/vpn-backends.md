# VPN application backends

Phase 2 introduced the application seam. Phase 3 adds a separate read-only
agent and opt-in `shadow` comparison; see [agent operation](vpn-agent.md).
Phase 4 adds feature-gated privileged mutations, durable intent recovery and
local daemon event ingestion. Keep existing deployments on the default `host`
backend until the deployment/cutover gates in the
[upgrade plan](container-architecture-upgrade-plan.md) are accepted.

## Configuration

| Setting | Default | Meaning |
| --- | --- | --- |
| `RIVET_VPN_BACKEND` | `host` | Exactly `host`, `shadow` or `agent`; invalid or empty values fail startup. |
| `RIVET_AGENT_SOCKET` | `/run/ovpn-agent/agent.sock` | Canonical absolute ASCII filesystem socket path, at most 107 bytes; traversal, control characters and URLs are rejected. |
| `RIVET_AGENT_UID` | unset | Numeric trusted agent UID; required with `agent` or `shadow`. The client checks Linux `SO_PEERCRED` before transmitting any request bytes. |

No TCP fallback, redirects, token forwarding, privilege escalation or automatic
mutation replay is supported. Configured settings are validated at startup;
restart the API to change its backend. Agent mode also removes the legacy
loopback connection-hook authentication exception and skips installing host
hook scripts. Agent daemon events use a protected local producer and durable
UDS polling, never an anonymous callback to the business API. Shadow mode retains the host hooks and loopback
exception because all legacy VPN behavior remains host-owned.

The API uses a synchronous typed port. Blocking workflow handlers run in the
ASGI worker pool, leaving the event loop available during agent outages. The
wire client negotiates exact protocol 1.0, applies one total deadline of at
most 60 seconds (including handshake), accepts fixed-length bounded HTTP
bodies, and checks correlated responses. Framed archive replies use
`application/octet-stream`; their inner manifest retains `application/zip`.
Unconsumed archives own and release their connection and one of four slots.

## Compatibility and ownership

All 48 public method/path pairs, schemas, permissions, HTTP statuses and
RFC 7807 responses remain unchanged. Shared profiles remain API-owned;
remote hosts still come from explicit administrator input. Agent server views
use `agent-managed` for private path fields and null optional hook paths.
Absent optional profile settings remain absent from generated profiles; their
required legacy server-view string fields use empty strings. The observed
interface and server address are retained exactly. The server address is
excluded from allocation even when it is not the subnet's first host.
Agent-mode pool initialization rejects networks larger than 65,536 addresses
before enumeration. Complete discovery and route snapshots are capped at
10,000 records and 60 seconds; repeated cursors and generation drift fail
before import changes are committed.

`HostVpnControl` retains a narrow local compatibility interface for raw server
configuration, service status/time/period, route lines, discovery skip counts,
legacy certificate metadata/cache packaging, and staged deletion rollback.
These values never cross the wire. Main lifecycle, address, access/push and
route mutations use typed `execute` calls in every backend. The host port also
provides bounded `open_archive`; existing host cache packaging retains its
historical helper behavior and archive layout. Unsupported host management
socket/event/actual-state snapshot operations return `unavailable`, rather
than fabricating agent observations.

The legacy host's command sequence is not crash atomic. Its process-local
replay ledger reports uncertain effects as `unknown`, retains IDs, and refuses
new admissions after 10,000 retained results/tombstones. Restart loses that
ledger; shared conformance explicitly retains fixture state and is not proof
of host crash recovery. Selecting `host` remains the transition rollback. Freeze control writes and
reconcile every pending agent workflow first; retain all operation tables and
verify that the legacy host configuration and permissions are still usable.
Changing the backend flag must never bypass uncertain remote effects.
Never use a restart or a new operation ID to resolve an uncertain agent write.

## Durable remote workflows and archives

Three new API-owned tables store workflow intent, exact per-step requests and
observed responses, and pending local archive cleanup. They are created by
the existing table initialization; existing business tables are unchanged.
Back up these tables with the application database. They contain desired
network metadata, not credentials, and must not appear in logs.

Before dispatch, the API commits immutable desired intent and the original
operation ID/generation in an independent journal transaction. A unique active
resource fence rejects a changed request while an earlier intent is unresolved;
a unique workflow/step position prevents concurrent duplicate dispatch IDs.
Business completion claims the workflow once, atomically in the business
transaction. A failed business commit leaves original intent available.

Retrying the exact authorized request queries an uncertain step by its
original operation ID, including pending, partial or unknown responses.
Fingerprint, client and generation are rechecked against the stored request.
Only a successful result advances the workflow. On a genuine `not_found`,
an explicit API retry may resubmit only the exact original ID, command and
generation to the durable agent. Expired IDs and uncertain evidence never
authorize a new ID or changed intent. Proven terminal pre-effect failures are
retained in `VpnStepAttempt` before an explicit retry allocates a new attempt. A pending route deletion can be
reconciled even if the route has already disappeared; an ordinary missing
route retains its existing 404 response. Restricted-network ownership links
to its exact creation workflow, preserving separate access/push intent IDs.
Opt-in `RIVET_VPN_RECONCILE=1` performs bounded background lookups; it does not
dispatch missing operations with its short lookup budget. The agent independently
reconciles accepted intents. `RIVET_VPN_EVENTS=1` commits durable event receipts,
history and cursor before immutable acknowledgements. Both flags default off
and require agent mode. Inconclusive PKI/reload outcomes remain fenced for
operator recovery; no automatic guess or CA rollback is permitted.

Agent-backed certificate downloads always obtain fresh active-generation
metadata, consume and verify a bounded archive, then recheck generation before
returning the public ZIP. Partial bytes are never published. Optional Azure
uploads and cleanup remain API concerns; Azure cached bytes cannot replace
that verified agent response. Host Azure behavior is unchanged. Old local
archives are invalidated after renewal/revocation/deletion, with failed local
cleanup retained separately. Existing best-effort Blob orphan cleanup remains
an operator responsibility until the later reconciliation phase. Neither
archive bytes nor SAS URLs or storage credentials cross JSON control messages.

## Verification boundary

The deterministic in-process fake supports the complete command vocabulary,
finite state, exact-ID replay, ownership checks, bounded pages and archive
cancellation. It is injected directly in application tests; `fake` is not a
production environment setting. Shared core, validation, failure and archive
conformance runs against it, the host adapter with mocked privileged helpers,
and the agent client talking to a synthetic test-only Unix-socket peer.
These tests never touch host firewall/routes, live PKI, VPN services or Azure.
Phase 3 adds actual read-only agent and management-socket verification on a
disposable real OpenVPN host; see [agent operation](vpn-agent.md). Exact
container grants and production deployment still require the later phase
gates. Phase 4 adds mocked privileged failure injection, real cryptographic
archive tests and explicitly isolated mutation rehearsals; see the plan for
verified evidence and remaining limits.
