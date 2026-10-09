# VPN agent operation

The agent defaults to the Phase 3 read-only observer. Phase 4 adds explicit,
individually enabled mutation families, durable recovery and local daemon event
ingestion. Keep production on `host` until the remaining deployment/cutover gates
are accepted; the implementation and disposable rehearsals do not authorize a
production cutover.

`rivet-agent` (also `python -m sciaiot.rivet.vpn_agent`) serves a private
Unix socket only. With no `RIVET_AGENT_MUTATIONS`, writes and archives return
`unavailable`. Enabled families use `POST /v1/control`; credential streams use
`POST /v1/archive`. Malformed uncorrelated requests are closed.

Keep production on `host`. An operator can opt into `shadow` on a prepared
disposable deployment to compare reads while retaining every legacy response
and mutation path. Shadow calls have a 500 ms total client budget and report
only command kind and `match`, `mismatch` or `unavailable`; no values, names,
addresses, hashes, paths, credentials or exception details are logged. Agent
loss leaves the original host result intact. After a failed comparison, that
shadow adapter defers further attempts for five seconds, bounding repeated
outage delay during a legacy discovery workflow. No management write is sent.
Agent-only lifecycle workflows require the matching enabled Phase 4 families.

## Explicit configuration

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

## Read-only observation and ownership limits

Configuration includes/inline blocks, unnumbered `dev tun`, ambiguous scalar
options and unsupported typed values fail closed. Configuration is projected
into protocol fields; private paths and raw options never leave the agent.
Only signed client-auth leaf certificates directly issued by the configured
CA are discovered. Names must match certificate CNs and the CA index must
contain each observed serial. State is observed from the CA index; server
certificates are excluded. CCD address and optional single iroute are typed.
This is observation, not complete migration/PKI validation or a recovery set.
Use the M0 toolkit for complete authenticated migration and restore evidence.

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
do not change session revisions. No session IDs authorize disconnect in Phase 3.

Each control connection permits one request. Header/body receipt has a two
second total budget, read-only observation is capped at ten seconds, and mutations/archives use
the validated request deadline (maximum 60 seconds). One active request and a kernel backlog of 16 avoid
unbounded threads. JSON, individual files, management and subprocess output
are bounded to 1 MiB (certificates 64 KiB); inventories have at most 10,000
records and 16 MiB of certificate bytes. Pages contain at most 100 items.
Subprocess output is bounded while reading, with deadline kill/reap and closed
pipes. The only fixed executables are `ip` read commands and
`iptables-nft-save` filter/version reads. Firewall inspection requires the
deployment's reviewed NET_ADMIN grant, even though no mutation is implemented.

## Image and verification

`deploy/agent/Dockerfile` is the minimal first-party development image. Build
from the repository root with `docker build -f deploy/agent/Dockerfile .`.
It contains protocol/agent code, Pydantic, cryptography, iproute2 and iptables;
it excludes the API and Azure integrations. Its Phase 3 package set is a
read-only baseline; a mutation deployment also needs the reviewed Easy-RSA
installation and local hook package in the OpenVPN workload. Complete image
assembly remains Phase 5. It declares
the nonroot `ovpn-agent:ovpn-runtime` identity 65532:65532; allocate compatible
deployment identities or derive a reviewed image with the desired account IDs.
It exposes no TCP port. Deploy with read-only root, no-new-privileges, bounded
tmpfs, only reviewed capabilities and service-specific read-only state mounts.
It needs no TUN device, database, cloud credentials or container-runtime socket.
Immutable base/dependency pinning, SBOM, signature, scanning and exact image
runtime grant evidence remain Phase 5/6 gates. A Dockerfile alone is not that
proof; no local/remote builder was available during Phase 3 verification.

Unit tests use disposable signed public PKI, fake network observations and
real local Unix sockets. The separate
`tests/integration/run_vpn_agent_namespace.sh` rehearsal requires the same
private mount/network/PID namespace attestation as M0 and synthetic state.
Only run it on explicitly authorized disposable infrastructure. It does not
authorize production state access or changes. Rollback consists of stopping
the agent and setting the API backend back to `host`; VPN lifecycle and all
legacy state remain host-owned throughout this phase.

The verified namespace command has this form. Set all three paths to reviewed
absolute paths outside `/tmp`, `/run` and live OpenVPN roots; prepare the
optional evidence directory as root-owned mode 0700. The interpreter must have
this repository's development dependencies. This is an explicitly privileged
verification command for a disposable authorized host, not agent deployment:

```sh
agent_repository=/absolute/reviewed/checkout
agent_python=/absolute/python314/venv/bin/python
agent_evidence=/absolute/private/evidence
sudo -n timeout --signal=TERM --kill-after=10s 600s \
  unshare --mount --net --pid --fork --kill-child --propagation private \
  /bin/sh "$agent_repository/tests/integration/run_vpn_agent_namespace.sh" \
  "$agent_python" "$agent_repository" /usr/share/easy-rsa/easyrsa \
  "$agent_evidence"
```


## Phase 4 mutation configuration

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
with the configured OpenVPN runtime GID. The deployment must verify its actual
mount and capability grants in Phases 5–6.

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
Push blocks are bound to an existing access intent and its allowed networks.

## Durable intent and recovery

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

## Local connection events

Install the package and `rivet-vpn-event` entry point in the OpenVPN workload
as well as the agent. OpenVPN strips inherited `PYTHONPATH`; source-only module
commands without an installed package are not a supported deployment. Verify
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

## Family rollback

Freeze new writes, retain all API/agent intent and event records, reconcile
accepted operations and verify actual state before disabling a family or
switching `RIVET_VPN_BACKEND` to `host`. Never run legacy and agent writers
concurrently. Keep the journal/configuration identity and CA revocation history;
rollback must not resurrect credentials. Verify host-compatible CCD, route,
firewall and archive behavior explicitly. An uncertain PKI/reload operation
requires operator resolution before resuming writes. No production host, cloud
or container deployment is changed by these instructions or unit tests.


## Phase 4 verification

The accepted 2026-09-19 disposable rehearsal exercised all mutation families
against OpenVPN 2.6.19 and Easy-RSA 3.1.7, including two-client TUN packet
allow/deny, soft reload preserving network state, real events, agent crash and
same-ID replay. A UID/GID 65534 API service process with zero capabilities,
no protected mounts and no local subprocess access also passed. All seven
before/after host fingerprints matched. The complete local suite passed 685
tests with 90% coverage; Ruff and mypy passed, and public OpenAPI was unchanged.

See [Phase 4 evidence](container-architecture-upgrade-plan.md#phase-4-verification-evidence-2026-09-19)
for the exact checks, private evidence location, and remaining Phase 5/6 scope.
The explicit namespace runner is
`tests/integration/run_vpn_mutation_namespace.sh`; never run its Python fixture
directly on a host. It requires the same isolation attestation as the Phase 3
runner and creates only synthetic namespace-owned VPN resources.
