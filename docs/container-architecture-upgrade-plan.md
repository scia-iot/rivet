# Container Architecture Upgrade Plan

Status: Phase M0 and Phases 0–4 complete; Phase 5 implementation complete,
release verification deferred; Phase 6 complete; Phase 7 migration complete,
same-host Compose recovery verified; off-host recovery acceptance pending;
Phases 8–10 deferred to real deployment.
Last updated: 2026-10-07

This document is the source of truth for introducing a container-first
production architecture for ovpncp and OpenVPN. The current UAT topology is not
a target constraint. Complete the phases in order and update the status table
and completion log after every phase.

Azure changes are instructions and reviewed artifacts only. An operator must
apply all Azure resource, routing, DNS, identity, and secret changes manually.

## Objectives

- Isolate the public web tier, business API, privileged VPN control operations,
  and OpenVPN data plane.
- Keep the ovpncp API container unprivileged and remove its direct access to
  host commands, /dev/net/tun, OpenVPN PKI, CCD files, firewall state, and the
  container runtime.
- Put privileged operations behind a small, versioned, allowlisted VPN-agent
  contract.
- Preserve the existing REST API, Entra roles, client lifecycle, fixed address,
  route, access-rule, import, certificate, and shared-profile behavior.
- Make every mutation idempotent, observable, reconcilable, and safe to retry.
- Support a simple single-node production deployment first without preventing
  a later Kubernetes or high-availability deployment.
- Provide tested backup, cutover, and rollback procedures before production
  traffic moves.
- Build and rehearse a portable OpenVPN migration toolkit before replacing the
  existing OpenVPN deployment.

## Non-goals

- Adding another VPN protocol, identity provider, cloud provider, or PKI
  implementation.
- Horizontally scaling one OpenVPN tunnel subnet in the first production
  release.
- Giving ovpncp access to Docker, containerd, Kubernetes, or host service
  manager sockets.
- Replacing current business authorization or delegating authorization to the
  VPN agent.
- Reworking every existing API and UI flow during containerization.
- Reusing the UAT deployment topology or treating UAT data as production seed.
- Migrating, cloning, or upgrading the ovpncp backend, its database or archive
  storage, or the UI through the OpenVPN migration toolkit.

## Recommended baseline decisions

These defaults let implementation begin while keeping later platform choices
open. Phase 0 must record any deliberate change as an architecture decision.

- **First runtime:** Docker Compose on a dedicated Linux VM. This is the
  lowest-complexity environment for one stateful VPN workload and real TUN
  integration.
- **VPN topology:** OpenVPN and the agent share one network namespace so both
  observe the same TUN device, routes, and firewall rules. The Compose
  reference uses host networking on a dedicated VPN VM and accepts the reduced
  network isolation explicitly.
- **API placement:** A separate unprivileged container prevents an API
  compromise from directly granting network administration.
- **Local control protocol:** Versioned HTTP/JSON over a Unix-domain socket is
  typed, testable, filesystem-restricted, and needs no new RPC dependency.
- **External web edge:** Application Gateway sends private HTTP to Nginx and
  retains same-origin UI and /api routing with edge TLS.
- **External VPN edge:** Standard Load Balancer or a dedicated public IP serves
  the Layer 4 UDP workload.
- **Initial availability:** One active OpenVPN workload avoids conflicting
  tunnel pools, CCD writers, routes, and session state.
- **Desired state:** The ovpncp database remains authoritative for business
  ownership and requested configuration.
- **Actual VPN state:** Agent-owned persistent volumes and the shared VPN
  network namespace remain inaccessible to the API.
- **Kubernetes portability:** Transport and runtime adapters allow a later
  same-Pod or internal mTLS agent deployment without Kubernetes-first code.
- **Migration format:** A versioned logical bundle remains independent of
  source and target filesystem paths, service managers, and container runtime.

An external transactional database is required before running multiple API
replicas. SQLite may remain only for a single-instance reference deployment.

## Target architecture

~~~mermaid
flowchart LR
    browser[Administrators and device users]
    vpn_clients[OpenVPN clients]
    entra[Azure Entra ID]
    appgw[Azure Application Gateway<br/>HTTPS]
    udplb[Azure Standard Load Balancer<br/>UDP 1194]

    subgraph web[Unprivileged web tier]
        nginx[Nginx<br/>static UI and /api proxy]
        api[ovpncp API<br/>business rules and RBAC]
    end

    subgraph vpn[Stateful VPN workload]
        agent[VPN agent<br/>allowlisted privileged operations]
        openvpn[OpenVPN daemon<br/>TUN data plane]
        namespace[(Shared network namespace<br/>TUN, routes, firewall)]
        agent_runtime[(API-agent socket volume)]
        openvpn_runtime[(OpenVPN management socket volume)]
        vpnstate[(Agent-private encrypted state<br/>config, PKI, CCD, CRL)]
        projection[(Minimal runtime projection)]
    end

    database[(Application database)]
    storage[(Certificate archive storage)]

    browser --> appgw --> nginx
    nginx --> api
    browser <--> entra
    api -. token metadata .-> entra
    api <--> database
    api <--> storage
    api -->|HTTP/JSON over UDS| agent_runtime
    agent_runtime --> agent
    vpn_clients --> udplb --> openvpn
    agent -->|management UDS| openvpn_runtime
    openvpn_runtime --> openvpn
    api -->|cursor-based event polling over UDS| agent_runtime
    agent -. event IDs and snapshots .-> api
    agent --> namespace
    openvpn --> namespace
    agent --> vpnstate
    agent --> projection
    projection -->|read-only| openvpn
~~~

Application Gateway remains the HTTP/HTTPS edge for the UI and API. It must not
be treated as the UDP edge. The VPN endpoint uses a Layer 4 UDP frontend with
health probes and network rules specific to OpenVPN.

## Component and trust boundaries

- **Nginx/UI:** Accepts private traffic from Application Gateway. It runs
  non-root without capabilities or mutable state and uses a read-only root
  filesystem.
- **ovpncp API:** Accepts /api traffic from Nginx only. It has no Linux
  capabilities, TUN device, VPN/PKI mount, or container-runtime socket. It can
  reach only the agent UDS, application database, and bounded archive storage.
- **VPN agent:** Has no public ingress or container-runtime socket. It receives
  NET_ADMIN only where proven necessary and owns server configuration, CCD,
  CRL, PKI operations, routes, and firewall rules.
- **OpenVPN:** Reads only the minimal runtime projection, never full PKI.
  Accepts only the UDP VPN frontend. It receives /dev/net/tun and
  only the capabilities required for tunnel initialization. It owns bounded
  runtime/status files and daemon state.
- **Database:** Accepts only the API workload identity and stores application
  entities, desired network state, and operation records.
- **Archive storage:** Accepts only the API workload identity and stores
  per-client credential archives, never the shared profile.

The OpenVPN process should drop its startup privileges where supported. Both
privileged containers must drop all unused capabilities, use a read-only root
filesystem, use bounded writable volumes or tmpfs, and run under a seccomp and
mandatory-access-control profile. Never use full privileged mode as the
steady-state configuration.

## VPN-agent responsibilities

The agent is a narrow system adapter, not a second business API. It must not
know Entra users, application roles, device ownership, or access-grant policy.
The ovpncp API authenticates and authorizes the caller, determines the desired
operation, and sends only a typed command.

The agent owns:

- reading and validating the active OpenVPN server configuration;
- OpenVPN status, connection status, reload, and controlled disconnect through
  a protected Unix-domain management socket;
- safe Easy-RSA client discovery, creation, renewal, revocation, deletion, and
  bounded credential archive streaming;
- atomic CCD, CRL and configuration file operations; shared-profile generation
  remains API-owned using the sanitized configuration projection (Phase 0 D6);
- TUN-scoped routes and firewall rules;
- normalized connection events and actual-state snapshots;
- redacted audit events and stable machine-readable error codes.

The agent must never provide:

- an arbitrary shell, command, executable, path, environment-variable, SQL, or
  container-runtime operation;
- a generic file read/write endpoint;
- externally reachable TCP ingress;
- authentication or authorization decisions on behalf of the public API;
- raw command output, private keys, tokens, or internal paths in errors or logs.

## Initial agent contract

The exact schema is finalized in Phase 1. The initial operation groups are:

- **Server:** Read health, sanitized configuration, and current generation;
  perform a controlled reload.
- **Connections:** Read a bounded active/history snapshot; disconnect one
  validated client.
- **Clients and PKI:** Discover certificate identities and inspect metadata;
  create, renew, revoke, delete, and package credentials.
- **Addresses:** Inspect a CCD assignment; assign or unassign one validated
  address.
- **Routes:** List managed routes; ensure or remove one validated internal
  route.
- **Access rules:** List rules owned by ovpncp; ensure or remove one validated
  rule.
- **Shared profile:** Return sanitized client-compatible server settings; API
  owns atomic credential-free profile storage (Phase 0 D6).

Contract requirements:

- Version every route under /v1 and perform a protocol-version handshake.
- Require a caller-generated operation ID and idempotency key for mutations.
- Validate names, addresses, networks, ports, protocols, ciphers, paths, and
  state transitions again inside the agent.
- Serialize conflicting mutations and return a conflict rather than racing.
- Use fixed error codes such as invalid_input, not_found, conflict,
  openvpn_unavailable, state_mismatch, and operation_failed.
- Bound request, response, archive, and log sizes.
- Never accept an argv list or shell text from the API.
- Use argument arrays with fixed executables for unavoidable system tools.
- Make ensure/remove operations safe when repeated after a timeout or crash.
- Expose readiness only after the management socket, required state volumes,
  TUN device, and configured rule backend are usable.

The Unix socket should live at /run/ovpn-agent/agent.sock on an ephemeral
shared runtime volume. Agent owns the setgid directory (02750), group
`ovpn-control`; the socket is explicitly 0660 and API mounts the directory RO.
Agent checks the configured API peer UID. A future remote-agent transport must use mutually authenticated encryption and
the same application-level contract.

The OpenVPN management socket uses a different runtime volume shared only by
OpenVPN (RW) and the agent (RO). The API must never mount or reach it directly.
OpenVPN uses primary GID `ovpn-runtime` before and after its UID/group drop;
deployment precreates runtime directories `ovpn-openvpn:ovpn-runtime` 02770.
The management socket is 0777 because OpenVPN overrides umask for bind; private
parent traversal, mount isolation and agent UID/runtime primary-GID peer checks
protect it. Deployment precreates status/pool files 0660 and startup validates them;
OpenVPN requests 0600 on creation, so umask 0007 alone is insufficient. PID files
may remain root-owned ephemeral state without agent access.
The [Phase 0 identity and mount policy](container-architecture-decisions.md)
defines exact grants and later image/runtime verification gates.

## State and consistency model

The API database stores desired business state. The agent reports actual VPN
state. The agent never writes application tables directly.

Every mutation follows this sequence:

1. Validate and authorize the external request in ovpncp.
2. Commit a durable pending operation record and the intended state.
3. Send an idempotent command to the agent.
4. Let the agent stage, validate, and atomically apply local changes.
5. Commit the observed result and mark the operation complete.
6. Reconcile any timed-out or indeterminate operation by operation ID.

Do not attempt a distributed filesystem/network/database transaction. Use
idempotency, atomic local replacement, compensating actions, and reconciliation
instead. Only one active writer may manage a VPN instance.

Connection events flow from the agent to the API with unique event IDs. The API
deduplicates them before updating connection history. Event delivery must be
at-least-once and bounded; losing API connectivity must not stop the VPN data
plane.

## Persistent and ephemeral storage

Use separate mounts so compromise of one component does not expose unrelated
state:

- vpn-config: server configuration and agent-owned generated fragments;
- vpn-pki: agent-private CA material, issued certificates, private keys and CRL;
- vpn-runtime-projection: agent-written, OpenVPN-read-only minimum server/CA
  certificate, server key, CRL, approved config/CCD and required transport files;
  never the full PKI, CA key, client keys, index or serial state;
- vpn-ccd: agent-private canonical per-client fixed-address configuration;
- agent-runtime: ephemeral API-agent socket shared only by those containers;
- openvpn-runtime: bounded ephemeral management socket, PID, and status data;
  OpenVPN RW and agent RO, never API;
- vpn-pool-state: OpenVPN RW pool persistence, agent RO for coordinated backup;
- agent-journal: agent-private durable operations and bounded event spool;
- api-profile: API-owned credential-free shared profile, never Blob storage;
- api-data: only when a single API instance still uses SQLite;
- external database: required for multiple API replicas;
- archive storage: encrypted client ZIP packages with existing authorization.

Back up configuration, PKI, CCD, CRL, application database, and the exact image
digests as one operational recovery set. This combined recovery set is not the
Phase M0 migration bundle. Test restoration before cutover. Never transform or
delete the only PKI copy during migration.

## OpenVPN migration boundary

The migration toolkit is completed before the architecture phases. Its scope
is only OpenVPN identity and configuration state, migrated without cloning a
source machine. It does not migrate or deploy the ovpncp backend or UI.

The portable bundle includes:

- a versioned manifest with OpenVPN, Easy-RSA, and crypto-library versions;
- the complete Easy-RSA PKI, including its CA certificate and key, index,
  serial state, issued certificates, requests, private keys, CRL, and required
  Easy-RSA configuration;
- the server certificate and key, DH parameters, active CRL, and any referenced
  TLS authentication or encryption keys;
- server configuration and recursively referenced configuration fragments;
- client-config-dir entries and optional ifconfig-pool persistence;
- file hashes, logical ownership, required modes, certificate fingerprints,
  serials, validity, and revocation state.

It deliberately excludes:

- logs, status files, PID files, sockets, caches, and transient connections;
- raw iptables, nftables, route, NAT, and cloud-network state;
- executable hook scripts, which are inventoried and hashed but replaced by
  reviewed target-version code;
- the ovpncp application, database, configuration, archive storage, and
  authentication state;
- UI source, build artifacts, configuration, and hosting state.

The importer translates logical bundle entries to reviewed target paths. It
must never copy source absolute paths, service definitions, users, group IDs,
or host-specific networking into the target blindly. Backend and UI artifacts
must be rejected if they appear in a migration bundle.

## Network design

- Keep UI/API traffic same-origin through Nginx /api.
- Permit Nginx-to-API traffic only on the internal container network.
- Give the VPN agent no published port.
- Share the OpenVPN network namespace only with the agent components that need
  to observe or mutate TUN, route, or firewall state.
- Publish only OpenVPN UDP and the Nginx HTTP backend required by the Azure
  edge. Do not publish the API or management socket directly.
- Enable IP forwarding deliberately and document every host, container, cloud
  route, security rule, and NAT boundary.
- Keep VPN tunnel address pools distinct from container, host, peered VNet, and
  client-side networks.
- Validate return routing from every protected subnet before production.
- Load the TUN kernel module on the host or node; do not grant a container
  module-loading capability.

For the Compose reference deployment, the VPN agent uses the OpenVPN service's
host network namespace and a shared socket volume. No unrelated workload may
run on that dedicated node. For Kubernetes, co-located containers in one Pod
share a network namespace. If the API scales separately, replace the UDS
transport adapter with a private mTLS transport rather than sharing a
cross-node filesystem socket.

## Delivery phases

| Phase | Outcome | Status | Depends on |
| --- | --- | --- | --- |
| M0 | Portable OpenVPN migration toolkit | complete (documented stopped-target profile) | none |
| 0 | Decisions, threat model, and measurable requirements | complete | M0 |
| 1 | Privileged-operation interfaces and agent contract | complete | Phase 0 |
| 2 | Agent client, fake agent, and legacy host adapter | complete | Phase 1 |
| 3 | Read-only VPN agent in shadow mode | complete | Phase 2 |
| 4 | All privileged mutations moved behind the agent | complete | Phase 3 |
| 5 | Reproducible OpenVPN, agent, API, and UI images | implementation complete; release verification deferred | Phase 4 |
| 6 | Compose reference and VPN integration | complete; isolated and actual host/bridge verification passed | Phase 5 |
| 7 | Target OpenVPN migration and recovery execution | migration and same-host Compose recovery verified; off-host acceptance assigned to operator | Phase 6 |
| 8 | Azure edge and network deployment plan | deferred to real deployment; reassess target conditions | Phase 7 |
| 9 | Production cutover and rollback drill | deferred to real deployment | Phase 8 |
| 10 | Optional high availability and scaling | deferred; assess only if real deployment requires HA | stable Phase 9 |

### Phase M0: portable OpenVPN migration toolkit

Implement one typed command-line tool with explicit subcommands instead of
unrelated shell fragments:

- inventory: discover and report source state without reading secret contents
  into logs;
- export: create the versioned logical bundle from approved roots;
- validate: authenticate and fully validate a bundle without changing a target;
- import: stage and activate a validated bundle on an explicit target;
- verify: compare source and target semantic state without exposing secrets;
- rollback: restore the target snapshot created immediately before activation.

Inventory and export requirements:

- Treat the configured OpenVPN and Easy-RSA roots as explicit trusted inputs.
- Resolve configuration includes and file directives without following paths
  outside approved roots. Reject traversal, unsafe symlinks, device files,
  FIFOs, and unexpected hard links.
- Use a complete Easy-RSA PKI snapshot. Copying only certificates and keys is
  insufficient because index and serial state are required for continued
  issuance and revocation.
- Freeze certificate, CRL, CCD, and configuration mutations while the snapshot
  is taken. Existing VPN data-plane connections may continue if consistency can
  be guaranteed.
- Bound the number and total size of files and reject changes detected while
  the snapshot is being created.
- Create staging directories with mode 0700 and artifacts with mode 0600.
- Require approved authenticated encryption before a bundle leaves the source
  security boundary. Record checksums inside the protected manifest as an
  additional consistency check.
- Produce only redacted console output. Host addresses, client identities,
  private paths, certificate material, and keys stay inside the protected
  bundle.

Validation and import requirements:

- Default to validation or dry-run behavior; require an explicit apply option
  for target mutation.
- Refuse a non-empty target unless an exact migration-owned destination and
  rollback snapshot have been established.
- Parse the archive safely and reject absolute paths, parent traversal,
  symlinks, hard links, device nodes, duplicate entries, excessive sizes, and
  unexpected file types.
- Verify every manifest hash before staging and again before activation.
- Verify CA and server certificate fingerprints, certificate/private-key
  matches, certificate chains, Easy-RSA index and serial consistency, CRL
  signature and freshness, and issued/revoked client status.
- Compare source and target OpenVPN, Easy-RSA, OpenSSL, option, cipher, and
  plugin compatibility. Fail on a semantic difference unless an explicit,
  reviewed transformation covers it.
- Map logical ownership to target users and groups; never restore arbitrary
  numeric source IDs.
- Render target-specific paths into a staged server configuration rather than
  editing the source configuration in place.
- Validate the complete staged tree before stopping or starting a target
  OpenVPN process.
- Take a target snapshot, activate state with same-filesystem atomic renames,
  and retain the snapshot until connectivity and PKI mutation tests pass.
- Never apply source firewall or route dumps. Emit a redacted comparison report
  and recreate reviewed network intent through the target control plane.

Verification requirements:

- Unit tests use temporary roots and fixtures for complete, incomplete,
  malicious, old-version, revoked-client, TLS-key, and CCD configurations.
- Property and boundary tests cover archive traversal, link attacks, duplicate
  entries, races, size limits, corrupt encryption, and manifest tampering.
- A disposable-host test migrates into a clean OpenVPN installation and proves
  that an existing client connects without receiving new credentials.
- The target must issue a new test certificate, revoke it, generate a CRL, and
  preserve all pre-existing revocations after import.
- Source and target comparison must match CA identity, server identity, client
  serial/status inventory, CCD assignments, and semantic server options.
- Rollback must restore the exact pre-import target hashes and service state.
- Export and dry-run validation must leave all source files and runtime state
  unchanged.

Exit criteria:

- A migration from representative legacy fixtures and one disposable real
  server passes export, validate, import, verify, connectivity, PKI mutation,
  and rollback checks.
- The bundle schema, compatibility policy, encryption procedure, operator
  prompts, non-interactive flags, and recovery steps are documented.
- The architecture phases consume the toolkit's sanitized inventory and bundle
  rather than introducing another migration mechanism.

Rollback: export never mutates source state; import restores its mandatory
pre-activation target snapshot.

### M0 completion evidence — 2026-09-10

Phase M0 is **complete for the documented stopped-target migration profile**.
The implemented CLI, encryption/schema contract, compatibility policy and
operator/recovery procedure are in [OpenVPN migration](openvpn-migration.md).

Implemented: typed six-command CLI; authenticated AES-256-GCM logical bundles;
bounded no-follow source/archive handling; complete current Easy-RSA PKI and
configuration capture; encrypted-key support; independent hash, certificate,
index, serial and CRL checks; observed option/cipher compatibility policy;
redacted output; dry-run default; migration-owned staged activation, mandatory
journal/snapshot and exact rollback; and opt-in offline/isolated network
rehearsal code with resource limits and optional private failure evidence.

An independent Easy-RSA 3.2.1 source-commit integration with OpenSSL 3.5.4
passed encrypted migration, real target issuance/revocation/CRL generation,
preservation of earlier credentials/revocations, rollback and source hashes.
Its OpenVPN metadata was explicitly a declared offline assumption.

The real namespace-isolated rehearsal then passed at
`2026-09-10T07:11:20.779121+00:00` on an approved remote Linux server using
OpenVPN 2.6.19, packaged Easy-RSA 3.1.7, OpenSSL 3.0.13 and Python 3.14.3.
It observed actual OpenVPN capabilities, connected an existing client over UDP
with unchanged credentials, observed its migrated CCD address on TUN, issued
and revoked a new target certificate, retained old revocations, restored exact
nonempty pre-import target state and its initially stopped process state, and
left source hashes unchanged. Every proof returned true. Before/after checks
also matched live host links, addresses, routes, policy rules, normalized
IPv4/IPv6 firewall configuration and the existing OpenVPN process identity and
start time. The live-host marker stayed absent. No live PKI/configuration was
read or migrated, and no Azure or live service/network changes were made.

Compatibility limits remain explicit and fail closed: the current target is
initially stopped and owned by the migration operator. Separately owned runtime
mount layouts and previously running service control require another reviewed
adapter. `cd`, inline OpenVPN blocks, TLS-crypt-v2, CRL directories, plugins,
intermediate/external CAs and complex transformations require reviewed support
before those profiles can be migrated. These limits do not authorize a live
source migration or production cutover. Phase 0 can now consume this toolkit's
sanitized inventory and bundle contract; later phases retain their own gates.

### Phase 0: decisions and threat model

Artifact: [architecture decisions and threat model](container-architecture-decisions.md).
All deliverables are complete. Independent engineering/security review accepted
the decisions, non-goals and precise capabilities/mounts on 2026-09-14. No
production, business or operator approval is implied. Phase 1 is complete; image inspection and runtime proof remain required in Phases 5–6.

Deliverables:

- Record the runtime, database, firewall backend, state ownership, service
  identities, image registry, secret delivery, and backup decisions.
- Define availability, recovery-time, recovery-point, capacity, connection
  count, throughput, and maintenance-window targets.
- Consume the M0 inventory of every OpenVPN directive, script, file, system
  command, route, firewall mutation, secret, and external dependency.
- Draw data flows and trust boundaries for API commands, certificate bytes,
  connection events, Azure authentication, and VPN packets.
- Decide whether profile storage remains API-owned or moves to agent-owned
  storage while preserving the current download contract.

Exit criteria:

- Decisions and non-goals are approved.
- No required current operation lacks a target owner.
- Security review agrees on the minimum capabilities and mounts.

Rollback: documentation only.

### Phase 1: interfaces and protocol

Status: complete; independent engineering review accepted 2026-09-16.
Runtime integration remains Phase 2.
Artifacts: [protocol](vpn-control-protocol.md),
[48-route matrix](vpn-control-route-matrix.md), unused
`application/vpn_control` port/schemas/helpers and reusable tests-only adapter
conformance assertions.

Deliverables:

- Define a typed VpnControl application port independent of FastAPI routes,
  subprocesses, files, and the runtime.
- Define versioned agent request/response schemas, stable error mapping,
  idempotency semantics, compatibility rules, and bounded archive streaming.
- Map every current route to permissions, desired-state changes, agent calls,
  compensating actions, and audit events.
- Add a protocol conformance suite shared by fake, host, and agent adapters.

Exit criteria:

- Contract tests cover success, validation, authorization, timeout, retry,
  conflict, partial failure, redaction, and version mismatch.
- No new runtime behavior or privileged operation is introduced.

Rollback: remove the unused interfaces and schemas.

### Phase 2: application seam and legacy adapter

Status: complete; independent engineering/security review accepted 2026-09-17.
See [backend configuration, recovery and compatibility limits](vpn-backends.md).

Deliverables:

- Route all existing business services through VpnControl.
- Preserve current host behavior in a HostVpnControl adapter.
- Add an AgentVpnControl client and a deterministic in-process fake.
- Add OVPNCP_VPN_BACKEND=host|agent, defaulting to host during the adapter
  transition, plus
  a validated agent socket setting.
- Remove direct utility imports from route handlers.

Exit criteria:

- Existing API/OpenAPI behavior and full test coverage remain unchanged.
- Fake-agent tests can exercise every business workflow without privileged
  host operations.
- Static checks identify direct privileged calls outside approved adapters.

Rollback: freeze control writes, reconcile pending agent workflows, preserve
operation tables, and verify legacy host configuration/permissions before
selecting the host adapter. A backend change must not bypass uncertain effects.

### Phase 3: read-only agent and shadow comparison

Status: complete; independent engineering/security review and disposable real
OpenVPN shadow verification accepted 2026-09-18.

Implementation and operational limits: [read-only agent](vpn-agent.md).

Deliverables:

- Add a separate ovpncp-vpn-agent entry point and minimal container image.
- Read server configuration and status through bounded parsers.
- Integrate the protected OpenVPN management Unix socket for readiness,
  connection state, and version checks.
- Implement read-only client discovery, address, route, and owned-rule
  inspection.
- Run both adapters in shadow mode: return the legacy result while comparing a
  redacted agent result.

Exit criteria:

- Shadow results match on a disposable real OpenVPN host.
- Agent loss produces a fixed unavailable response without affecting OpenVPN.
- No mutating agent endpoint exists yet.

Rollback: stop the agent and retain the host adapter.

### Phase 4: privileged mutations

Status: complete; local quality gates and disposable real OpenVPN mutation
verification accepted 2026-09-19. Implementation committed as `501cd05`
(`feat(vpn): complete phase 4 privileged agent mutations`). See the
[Phase 4 evidence](#phase-4-verification-evidence-2026-09-19) and
[agent operations](vpn-agent.md#phase-4-mutation-configuration).

Move one operation family at a time, with a feature flag and rollback after
each family:

1. API-owned atomic shared profile via sanitized agent settings, and agent-owned
   CCD address assignment.
2. Managed routes.
3. Firewall/access rules.
4. Client import and certificate creation, renewal, revocation, and deletion.
5. Connection-event delivery and controlled disconnect/reload.

Deliverables:

- Operation journal, idempotency keys, serialized conflicting writes, and an
  actual-versus-desired reconciliation job.
- Strict ownership markers for routes and firewall rules so the agent cannot
  remove administrator-owned state.
- Streamed, bounded certificate archives without exposing the PKI mount to the
  API.
- Failure injection around file replacement, command errors, agent crashes,
  API timeouts, duplicate delivery, and database commit failures.

Exit criteria:

- The API process needs no root, network capability, protected OpenVPN mount,
  or subprocess access.
- All agent commands are allowlisted, validated, idempotent, and covered by
  success and failure tests.
- Switching back to the host adapter remains documented until Phase 6.

Rollback: disable the transitioned family and reconcile with the host adapter.

### Phase 5: container images and supply chain

Status: implementation complete; release verification deferred under the
operator-approved sequence below. All four images tagged
`phase5-hardening-20260924` are
cached in `faureciaiot-b8c8fwavbhdudve2.azurecr.io`. New immutable digests were
inspected and the disposable UDP/CCD, allow/deny, replay and agent restart
rehearsal passes against them with unchanged host VPN/network state.
Rescans and updated SBOMs confirm the removed packaging/XML payloads are absent;
no critical or secret findings were reported. High findings remain (44 agent,
45 API, 44 OpenVPN, 59 web), with no scanner-listed fixes in that scan. A
[20-advisory review](container-vulnerability-review.md) records applicability
and unresolved exposure; no exceptions have been approved. The operator
deferred provenance and trusted signing handoff on 2026-09-24. Those items
remain open release evidence, but do not block functional verification or
portable build work. On 2026-09-27 the operator also deferred the first hosted
GitHub Actions run and its artifact verification until all architecture phases
are finished. That follow-up does not block P5 closure or phase progression;
local workflow validation and existing image evidence remain recorded. The
remaining vulnerability applicability/release review is also deferred until
before the GHCR release, per the operator's subsequent 2026-09-27 decision.
It no longer blocks architecture phase progression. Existing optional
Entra/Azure integrations remain intact. This status records implementation
completion and scheduling changes, not security release approval.
Source OpenSSL 3.0.13 differs from image 3.5.7; migration compatibility and
container target mapping remain required. No production cutover has occurred.

See [portable build instructions](container-builds.md),
[image details](container-images.md), and the [deployment reference](container-deployment.md). The Compose artifact from
Phase 6 is prepared early at the operator's request. Its first disposable
container rehearsal and the 2026-09-27 extended credential lifecycle/API
outage rehearsal passed with unchanged host state. Full runtime integration
and exit criteria remain pending.

Deliverables:

- Maintain first-party Dockerfiles for OpenVPN, the VPN agent, API, and
  Nginx/UI; do not depend on an unreviewed community VPN image.
- Pin base images and OpenVPN packages by immutable version or digest.
- Use multi-stage builds, non-root users where possible, read-only root
  filesystems, explicit health checks, and no build tools in runtime images.
- Produce an SBOM, vulnerability report, provenance, and signed image digest.
- Add image and Compose configuration checks to CI, with portable GitHub
  Actions builds and configurable registry publishing. Keep deployment settings
  at runtime and retain existing optional Entra/Azure integrations.

Exit criteria:

- Builds are reproducible from a clean checkout. The first hosted GitHub
  Actions run and verification of its artifacts are deferred until all phases
  are finished by the operator's 2026-09-27 decision; they are not a phase
  progression gate.
- Critical or high applicable vulnerabilities are resolved or explicitly
  accepted with expiry. By the operator's 2026-09-27 decision, this remains a
  pre-GHCR release requirement rather than a phase progression gate. Refresh
  scans and applicability evidence against the actual release image digests.
- Image inspection confirms the expected user, capabilities, mounts, ports,
  entry point, and no embedded credentials.

Deferred release sequence (operator-approved 2026-09-27):

1. Finish the remaining architecture phases using the recorded implementation
   and functional verification evidence.
2. Before the GHCR release, refresh image scans, finish advisory applicability
   decisions, and resolve applicable findings or record acceptance with expiry.
   Rebuild and verify changed images as needed.
3. With the GitHub Actions/GHCR release, generate and verify build provenance,
   SBOM attestations and image signatures against the expected repository,
   workflow identity, source revision and published digests. Verify the first
   hosted workflow's artifacts. These controls are not yet implemented in full
   or verified; using GHCR alone does not establish trust.

Rollback: retain the last verified image digests.

### Phase 6: Compose reference deployment

Status: complete on 2026-09-30, using the requested `gpt-6-sol` agent
at `xhigh` effort. Isolated Compose integration passed readiness, signed
HTTP/RBAC through Nginx, UDP/CCD, credential lifecycle, CRL enforcement and
API/web upgrade/rollback with surviving VPN traffic. The subsequent actual
host/bridge rehearsal passed with the corrected agent image on the
operator-approved existing `sciaiot-openvpn` host using fresh synthetic state.
It verified allowed/denied flows and selected-service upgrade/rollback without
restarting the VPN data plane. Cleanup, source-state fingerprints and all
eleven stopped-host comparisons passed; both original services were restored.
This fulfills the accepted reference deployment verification on a provisioned
Linux host; it does not claim pristine-OS installation or source migration.
P5 release checks remain deferred under the operator-approved schedule.
Production migration and cutover belong to Phase 7.

Deliverables:

- Compose services for Nginx/UI, API, VPN agent, and OpenVPN.
- OpenVPN and agent network-namespace sharing, /dev/net/tun, minimal
  capabilities, isolated networks, runtime sockets, persistent volumes, and
  resource limits.
- Startup ordering based on readiness rather than fixed sleeps.
- A disposable integration environment that creates a real client, connects
  over UDP, reaches an allowed network, rejects a forbidden flow, reconnects,
  and verifies revoke/delete behavior.
- Upgrade and restart tests proving the VPN data plane survives API downtime.

Exit criteria:

- All application checks pass plus privileged container integration tests.
- No container is fully privileged or mounts the container-runtime control
  socket.
- A clean host can deploy, verify, upgrade, and roll back from documented
  commands.

Rollback: redeploy the previous Compose bundle and image digests.

### Phase 7: target OpenVPN migration and recovery execution

Status: started on 2026-09-30 with the requested `gpt-6-sol` agent at `xhigh`
effort. The OpenVPN-only migration, unchanged-client connection, encrypted
checkpoint restore and exact nonempty rollback passed on the approved test host
on 2026-10-01. On 2026-10-02 the operator authorized persistent cutover of
`sciaiot-openvpn`, accepting downtime. The approved repaired VPN copy is now
imported into the persistent four-service container deployment; original source
files remain preserved and legacy services are stopped.
Migration implementation and test-server cutover are complete. The authorized
same-host Compose recovery drill passed on 2026-10-07, including coordinated
API/agent state and real client connectivity. Off-host/VM-loss recovery and
production RPO acceptance remain with the operator. Keep backend/database/
archive/authentication/UI artifacts outside M0.

Deliverables:

- Select an approved source and use the Phase M0 toolkit to create a fresh
  encrypted bundle while certificate, CRL, CCD, and configuration mutations
  are frozen.
- Validate the bundle against the exact Phase 6 OpenVPN image digest,
  configuration model, and target path and ownership map.
- Import the OpenVPN bundle into a clean disposable target with the Phase M0
  tool, then run its semantic verification and unchanged-client connectivity
  tests.
- Produce a reconciliation report comparing the manifest with imported
  OpenVPN configuration, PKI, revocation, CCD, and server option state.
- Full OpenVPN restore and rollback rehearsal on a separate disposable host.
- Confirm that no backend, database, archive, authentication, or UI artifact
  was read from the source or written to the target by the migration tool.

Exit criteria:

- Existing clients connect using unchanged credentials, and a newly issued
  test client can be revoked, in the restored test deployment.
- Revocation, CCD address assignments, and semantic OpenVPN server options
  match the inventory.
- Phase M0 verification reports no unexplained OpenVPN or PKI drift.
- Recovery objectives from Phase 0 are met.

Rollback: use the Phase M0 target snapshot, keep the source unchanged, and
discard the failed disposable target only after collecting redacted evidence.

### Phase 8: Azure edge and network instructions

Status: deferred by the operator to real deployment. Reassess the actual target
platform, topology, ingress, identity and network requirements then. The Azure
items below remain reference material, not an approved target design or work
to execute against the current test server.

Prepare operator-reviewed instructions or infrastructure definitions, but do
not apply them automatically.

Deliverables:

- Application Gateway backend, health probe, listener, TLS, WAF, and /api
  routing for the web tier.
- Standard Load Balancer UDP rule and health probe for OpenVPN.
- Public/private DNS records, NSGs, IP forwarding, user-defined routes, VNet
  peering, egress, and return-route documentation.
- Workload identity and secret-delivery plan for Entra metadata, database, and
  archive storage.
- External smoke test covering browser login, API authorization, UDP VPN
  connection, protected-route access, and revocation.

Exit criteria:

- Azure changes have peer review and an explicit operator execution order.
- No management, API, database, agent, or OpenVPN management port is public.
- End-to-end return routing and failure health probes are verified.

Rollback: restore the prior backend targets, rules, routes, and DNS values from
the operator runbook.

### Phase 9: production cutover

Status: deferred by the operator to real deployment. Prepare the cutover,
acceptance and rollback procedure for that environment's conditions and
maintenance constraints; the test-server migration is not production approval.

Deliverables:

- Freeze control-plane mutations and take the verified recovery set.
- Deploy exact signed image digests and import only OpenVPN state with the
  Phase M0 toolkit and verified checksums. Backend and UI rollout remains a
  separate deployment activity.
- Start one writer, reconcile actual state, and run internal health checks.
- Run an external canary client before switching the main endpoint.
- Switch the reviewed Azure backend/DNS path, then exercise sign-in, client
  create/import, address assignment, profile/credential download, connection,
  access enforcement, revoke, and delete.
- Monitor connection failures, agent errors, reconciliation drift, route/rule
  changes, latency, resource use, and certificate operations through the
  agreed observation window.

Exit criteria:

- Acceptance tests and recovery objectives pass.
- No unexplained desired/actual drift remains.
- The rollback drill has been performed, not merely documented.

Rollback: freeze new writes, restore the prior endpoint and recovery set, start
the prior single writer, and reconcile before reopening mutations.

### Phase 10: optional high availability

Status: deferred to real deployment planning, and only if availability or
scaling requirements justify it. No HA implementation is currently requested.

Do not start this phase until the single-workload production deployment is
stable and HA requirements are measurable.

Required design topics:

- unique or coordinated tunnel address pools;
- connection-aware UDP distribution and drain behavior;
- shared PKI and CRL propagation without concurrent unsafe writers;
- per-instance CCD, route, firewall, and reconciliation ownership;
- database and event-delivery HA;
- node failure, region failure, and client reconnect expectations.

Exit criteria must include multi-node failure injection and proof that two
instances cannot create conflicting network or certificate state.

## Verification strategy

Each phase runs the repository checks from AGENTS.md plus the smallest relevant
additional layer:

- unit tests for validation, commands, paths, state transitions, and redaction;
- shared agent contract tests against fake, host, and real agent adapters;
- API authorization tests proving device_user, sysadmin, and ServiceAdmin
  behavior remains unchanged;
- unprivileged container tests in ordinary CI;
- explicitly isolated privileged network-namespace tests on a dedicated runner;
- real OpenVPN client tests on disposable infrastructure;
- migration tests for complete PKI capture, safe archive extraction, manifest
  integrity, version compatibility, source immutability, semantic comparison,
  unchanged-client connectivity, and exact target rollback;
- failure tests for restart, timeout, duplicate command/event, partial file
  write, unavailable database/storage, and stale agent version;
- image configuration, vulnerability, SBOM, signature, and secret scans;
- backup restore, upgrade, and rollback drills.

Ordinary unit tests must never modify the developer host's routes, firewall,
TUN devices, OpenVPN state, container runtime, or real cloud resources.

## Principal risks and controls

- **API compromise becomes host compromise:** Use an unprivileged API, no
  VPN/PKI mounts or container-runtime socket, and a narrow agent contract.
- **Agent command injection:** Apply domain validation, fixed executable
  allowlists, argument arrays, and no generic command or path operation.
- **Excess container privilege:** Drop all capabilities, add only the required
  networking capability, avoid full privileged mode, and use a dedicated
  host or node.
- **Split-brain VPN writers:** Require a single writer identity, lease or lock,
  operation journal, and reconciliation.
- **API/agent version drift:** Require a startup handshake, supported-version
  range, and fail-closed mutation behavior.
- **Partial database, filesystem, or network failure:** Use idempotency, atomic
  local writes, compensating action, and actual-state reconciliation.
- **PKI loss or disclosure:** Use an agent-only encrypted mount, redaction,
  encrypted backup, tested restore, and key rotation procedure.
- **Incomplete PKI migration breaks future issuance or revocation:** Snapshot
  the complete Easy-RSA PKI under a mutation freeze, validate index and serial
  consistency, and prove new issuance and revocation on the target.
- **Corrupt or hostile migration bundle changes target state:** Require
  authenticated encryption, bounded safe extraction, manifest validation,
  dry-run by default, staged activation, and a mandatory target snapshot.
- **UDP traffic sent to an unhealthy instance:** Tie the Layer 4 health probe
  to agent/OpenVPN readiness and an external canary.
- **Upgrade disconnects active clients:** Use a maintenance window, graceful
  drain where possible, a canary, and retained rollback images.
- **Container or VNet subnet collision:** Maintain a central address inventory
  and run overlap checks before deployment.

## Definition of complete

The upgrade is complete only when:

- the Phase M0 toolkit has migrated representative legacy fixtures and a real
  disposable server, retained existing client credentials and revocations,
  exercised target PKI mutations, and restored the pre-import target exactly;
- the public API runs without root, NET_ADMIN, /dev/net/tun, OpenVPN/PKI
  mounts, or arbitrary subprocess access;
- no API route directly calls systemctl, OpenVPN tools, Easy-RSA, routing, or
  firewall commands;
- the VPN agent has no public ingress and exposes only the reviewed versioned
  operations;
- OpenVPN and agent containers have the minimum capabilities and writable
  mounts demonstrated by tests;
- desired and actual state reconcile after process, container, and host
  restarts;
- a real external client passes connection, routing, access, revoke, and delete
  tests;
- backup restore, upgrade, and rollback have all been exercised;
- production images are pinned, scanned, inventoried, and signed;
- Azure changes were manually reviewed and applied in the documented order;
- operator, security, recovery, and developer documentation is current.

## Completion log

Append one entry per completed phase without rewriting earlier history:

~~~text
YYYY-MM-DD - Phase M0 or N completed
Implementation:
- ...
Verification:
- command/check: result
Operational changes:
- ...
Deferred:
- ...
~~~

### 2026-09-10 — Phase M0 completed

Implementation:
- Portable typed OpenVPN migration CLI and authenticated logical bundle.
- Strict PKI/configuration validation and documented compatibility boundary.
- Default dry-run, staged offline activation and exact mandatory rollback.
- Private mount/network/PID namespace rehearsal with bounded resources.

Verification:
- `pytest --cov=src/sciaiot/ovpncp --cov-report=term-missing`: 392 tests passed,
  91% overall coverage; migration package 88%, every migration module above 80%.
- `ruff format --check .`: 71 files pass; `ruff check .`: passes.
- `mypy --exclude '^build/' .`: 62 files pass. The exclusion avoids the existing
  ignored duplicate build package; all source and test modules are checked.
- `sh -n tests/integration/run_migration_namespace.sh` and `git diff --check`:
  pass.
- Independent real Easy-RSA offline migration and PKI mutation passed.
- Real OpenVPN UDP/TUN/CCD, unchanged-client credentials, target PKI mutations,
  preservation of existing revocations and exact nonempty rollback passed at
  2026-09-10T07:11:20.779121+00:00.
- Live host network/firewall and pre-existing OpenVPN process remained unchanged.

Operational changes:
- Only explicitly approved verification staging and synthetic isolated state.
- No live OpenVPN PKI/configuration, service, host network or Azure changes.

Supported boundary:
- Initially stopped migration-owned targets and documented compatible profiles;
  no live-source migration or production cutover approval is implied.

### 2026-09-14 — Phase 0 completed

Implementation:
- Recorded concrete reference architecture, measurable acceptance targets,
  state/identity/capability/mount decisions and a threat model.
- Inventoried all 48 API routes, current privileged operations, dependencies,
  secrets, hooks, files and every M0 source directive allowlist.
- Selected API-owned shared profile, minimal OpenVPN projection, durable event
  polling and owned CCD/network intent while preserving current contracts.

Verification:
- Route AST and documented owner rows cover all 48 routes.
- Exact M0 directive sets match: files 10, hooks 9, runtime 10, logical 88, CCD 8.
- All five local documentation links resolve; `git diff --check` passes.
- Independent engineering/security review accepted the implementation baseline,
  including primary groups, precreated status/pool files, socket confinement,
  minimal projection and enforcement in both TUN directions.
- Documentation-only changes; application/runtime checks were not rerun.

Operational changes:
- Documentation only; no application, host network, PKI or Azure changes.

Deferred:
- Phase 1 protocol work remains planned. Exact image/runtime grant verification
  remains required in Phases 5–6; Phase 0 does not claim that proof has run.
- Production SLAs, actual resource choices and operator/cutover approval remain
  later gates.

### 2026-09-16 — Phase 1 completed

Implementation:
- Unused typed VpnControl application port and immutable version 1.0 command/
  result schemas, independent of FastAPI, files, subprocesses and runtime.
- Bounded strict JSON decoding, correlation, redacted fixed errors, canonical
  idempotency binding, conservative retry and synchronous-success checks.
- Explicit archive source ownership, deadline/size/digest verification and
  cancellation/cleanup, including cancellation before the first read.
- Complete 48-route permission/domain/intent/agent/compensation/audit matrix.
- Reusable tests-only conformance harness and independent security review tests.

Verification:
- `pytest --cov=src/sciaiot/ovpncp --cov-report=term-missing`: 491 tests passed
  (including 99 new protocol/review tests), 92% overall application coverage;
  every new application module has 100% statement coverage.
- `ruff format --check .`: 84 files pass; `ruff check .`: passes.
- `mypy --exclude '^build/' .`: 72 files pass. Existing ignored duplicate
  build/lib package still prevents plain `mypy .`; no source exclusion added.
- `mypy --no-incremental --exclude '^build/' .`: 72 files pass during review.
- `git diff --check`: passes. Independent AST audit exactly matches all 48
  mounted route method/path pairs; new local documentation links resolve.
- Initial tests failed because the application port package was absent.
  Behavior tests exposed missing conformance support and forged-model
  serialization; independent review reproduced unsafe corrupt-write retry.
  All were fixed and the final complete suite passed.
- Independent engineering review accepted schema compatibility, ownership,
  correlation, retry, archive lifetime, route matrix and scope.

Operational changes:
- None. No runtime wiring, privileged operations, real PKI/host/network/Azure
  changes, new dependency, branch, commit or pull request.

Deferred:
- Phase 2 application seam and fake/host/agent adapters remain unstarted.
- OS peer checks, durable actual journals, real PKI/ZIP generation, bounded
  blocking transport/queue enforcement and host/network effects require later
  adapter/runtime proofs; pure contract tests do not claim those proofs.

### 2026-09-17 — Phase 2 completed

Delivered:
- Application VPN service routes lifecycle, address, route and restricted-network
  operations through typed VpnControl adapters. Route handlers have no direct
  utility imports; a static AST test rejects privileged imports/calls outside
  approved adapters and the existing utility/migration boundaries.
- Default HostVpnControl preserves legacy public projections, import skip
  counts, certificate cache behavior and staged deletion rollback through
  narrowly documented local compatibility methods. Unsupported agent-only
  observations fail explicitly; uncertain host effects are not marked failed
  before effects. Its finite process-local ledger is not a crash journal.
- AgentVpnControl implements bounded HTTP/JSON and framed archive transport
  over UDS, exact protocol handshake, kernel peer UID verification before
  request bytes, correlation/integrity checks, total deadlines, fixed-length
  bodies, four-stream ownership, cancellation and fixed redacted failures.
- Deterministic fake implements typed state/ownership, bounded snapshots,
  exact-ID replay, generation fencing and credential invalidation. Shared
  conformance exercises actual fake/host/agent classes with disposable mocks
  and a synthetic test-only Unix-socket peer.
- OVPNCP_VPN_BACKEND defaults to host. Explicit agent selection requires a
  validated canonical socket path and trusted OVPNCP_AGENT_UID; invalid
  configuration fails closed. Agent mode skips host hook installation and
  disables the legacy loopback authentication exemption.
- API-owned workflow/step/cleanup tables persist complete desired intent and
  exact per-step requests before remote dispatch. Unique active-resource and
  step fences prevent changed or concurrent duplicate intents. Conditional
  completion in the business transaction prevents duplicate business rows.
  Uncertain retries query the original ID and validate retained evidence.
- Agent profile/pool projection preserves public shapes with private path
  markers and exact observed interface/server address. Pool allocation is
  finite and excludes the actual server address. Discovery/route snapshots
  reject repeated cursors, generation drift and count/deadline exhaustion.
- Agent archive downloads consume and verify fresh active-generation bytes,
  recheck before publication, and prevent Azure cache replacement. Local
  invalidation cleanup remains tracked. Blocking workflows run in workers;
  raw SQL/exception payloads are excluded from public errors and logs.
- README, deployment environment example, protocol, route matrix and backend
  operation/rollback documentation are synchronized.

Verification:
- `pytest --cov=src/sciaiot/ovpncp --cov-report=term-missing -q`: 555 tests
  passed in 23.30 seconds, including all 491 baseline tests and 64 additional
  Phase 2 checks; overall coverage 91%.
- New substantive modules: AgentVpnControl 86%, FakeVpnControl 84%,
  HostVpnControl 81%, settings 89%, VpnService 90%; workflow models and worker
  dispatch 100%. Certificate archive service coverage is 97%.
- `ruff format --check .`: 98 files pass; `ruff check .`: passes.
- `mypy --exclude '^build/' .`: 85 source files pass. The pre-existing ignored
  build/lib duplicate still prevents plain `mypy .`; no source exclusion added.
- Independent full OpenAPI comparison exactly matches the pre-Phase-2
  baseline: 32 paths, 48 method/path operations, all component schemas and
  permission/response metadata unchanged.
- All 22 independent review regressions pass. Shared adapter conformance
  covers success, validation, known failures, partial/lost replies, replay
  fences, archives, unread cancellation and quotas. Additional synthetic UDS
  checks cover peer denial before bytes, response correlation, redirects,
  oversized bodies, framing failures, deadlines and fixed error handling.
- TDD/review reproduced and fixed missing adapters, pagination cursor parsing,
  revoked unread archives, unresolved-result retry, duplicate workflow
  completion, server-address allocation, and invalid fake access ownership.
  Worker responsiveness, SQL redaction, huge-pool refusal and unchanged host
  API behavior are covered. The logging assertion now requires fixed redacted
  failure text instead of raw exception content.
- Independent engineering/security review accepted the completed application
  seam, bounds, retry evidence, compatibility exceptions and phase scope.

Operational limits and remaining phases:
- No actual agent server, deployment, live VPN/PKI/firewall/route operation,
  Azure mutation, new dependency, branch change, commit or pull request.
- At the Phase 2 handoff, Phase 3 remained planned. Actual agent
  management-socket/event integration,
  PKI packaging, durable privileged journal, crash/restart and runtime image
  proof remain Phases 3–6. Retained fixture state is not OS crash-durability
  evidence. Host rollback preserves its documented legacy limitations.
- Freeze writes and reconcile pending agent operations before switching
  backends; retain recovery records and verify the legacy host environment.
  Background reconciliation, uncertain-operation operator resolution and Blob
  orphan cleanup automation remain later phases. Agent downloads deliberately
  use fresh verified bytes while host Azure behavior remains unchanged.

### 2026-09-18 — Phase 3 completed

Implementation:
- Separate `ovpncp-vpn-agent` and module entry points implement only seven
  bounded read operations. Protected HTTP/JSON UDS authenticates the API UID
  before reading headers/body; there is no TCP listener or archive endpoint.
  Mutations, event acknowledgements, disconnect and reload are unavailable.
- Protected OpenVPN management UDS verifies listener UID/GID before sending
  only version, state and status 3. Readiness requires OpenVPN 2.6, connected
  state, configured TUN link, nf_tables capability and complete declared owned
  network realization. No management signal/client-mode fallback exists.
- Sanitized configuration, directly verified public certificate/index/CCD
  discovery, bounded session snapshots, protocol-200 route inspection and
  exact paired owned-rule/push inspection. Read-only typed ownership inventory
  never adopts foreign state. Content revisions/cursors reject observed drift;
  no privileged mutation generation or journal is claimed.
- Strict regular-file/no-symlink/no-hardlink reads, bounded command output
  while consuming, deadlines, child kill/reap, socket cleanup and finite
  connections/records/pages. API metadata, credentials and exception details
  never enter shadow logs or agent error bodies.
- Opt-in `shadow` preserves every host result, hook and mutation path while
  comparing typed observations with a 500 ms budget and five-second outage
  cooldown. Host remains the default. API OpenAPI is unchanged.
- Minimal first-party agent Dockerfile excludes API/cloud/mutation utilities.
  README, backend/protocol/agent operation docs and environment example are
  synchronized. Phase 4 remains planned.

Verification:
- `pytest --cov=src/sciaiot/ovpncp --cov-report=term-missing -q`: 605 tests
  passed in 24.34 seconds; overall coverage 91%. New substantive modules:
  shadow 93%, bounded readers 96%, CLI 93%, control 96%, files 96%, management
  92%, network 91%, server 90%, settings 100%.
- `ruff format --check .`: 114 files pass; `ruff check .`: passes.
- `mypy --no-incremental --exclude '^build/' .`: 100 source files pass.
  The existing ignored duplicate build/lib still prevents plain `mypy .`;
  no application/test source exclusion was introduced.
- `sh -n tests/integration/run_vpn_agent_namespace.sh` and `git diff --check`:
  pass. Exact Docker COPY source subset imports in an isolated interpreter
  without API, SQLModel, Azure or mutation utility code.
- Independent OpenAPI comparison exactly matches the Phase 2 baseline:
  32 paths and 48 method/path operations, schemas and metadata unchanged.
- Independent security regressions cover incomplete management headers,
  namespace refusal before fixture construction, and unexpected hardlinks.
  TDD/review also reproduced and fixed failed-start socket cleanup and actual
  iproute filtered output omitting the device field.
- Final separate-process agent plus real OpenVPN 2.6.19 server/client passed
  in private mount/network/PID namespaces on the authorized verification host.
  Real active/revoked public PKI/CCD, live sessions, protocol-200 owned route
  versus foreign route, paired rules/pushes, and all legacy/shadow comparisons
  matched. Unsupported mutation returned unavailable. PKI/config/CCD and
  namespace route/rule fingerprints remained unchanged during observation.
- Terminating only the agent produced fixed unavailable results; both VPN
  processes survived and a real client across a nested network namespace
  retained TUN connectivity before and after agent loss. The reproducible
  bounded `sudo timeout ... unshare ... run_vpn_agent_namespace.sh` command is
  recorded in [agent operation](vpn-agent.md).
- Host addresses, links, routes, rules, IPv4/IPv6 firewall and the pre-existing
  OpenVPN process PID/start time matched the recorded pre-verification state.
  Independent engineering/security review accepted the Phase 3 boundary.

Operational changes and limits:
- Only explicitly authorized synthetic disposable verification state and
  private staging/evidence were created. No live VPN configuration/PKI,
  service, host firewall/routes, Azure resources, branch, commit or PR changed.
- The remote rehearsal proves read-only process/UDS behavior as root inside
  isolated namespaces. It does not prove the final nonroot container identity,
  mount, capability or confinement grants; those remain Phases 5–6.
- No Docker/Podman/Buildah/BuildKit builder was available locally or remotely.
  The minimal image definition and independent source import were checked,
  but no image build/runtime test ran. Pinning, signatures, SBOM, scanning and
  reproducible image gates remain Phase 5.
- Durable privileged mutations, packaging, event spool/acknowledgement,
  disconnect/reload, crash recovery and reconciliation remain Phase 4.
  No production agent deployment or cutover is authorized by this completion.

### Phase 4 verification evidence (2026-09-19)

- Implemented each opt-in family: atomic API profile and owned CCD assignment,
  managed routes, paired access and owned pushes, certificate lifecycle and
  credential streaming, durable connection events, exact-session disconnect,
  and controlled soft reload. Host mode remains the default; rollback is
  documented in [agent operations](vpn-agent.md#family-rollback).
- The agent retains immutable operation IDs and intent digests, serializes
  conflicting writes, journals before effects, reconciles actual state, and
  keeps expired-ID tombstones. Uncertain results retain their original fences.
- The API commits deduplicated history before acknowledgement, validates
  retained acknowledgement intent, separates same-second sessions, and bounds
  completed acknowledgement/history retention. Background workflow recovery
  queries existing IDs; an explicit API retry may resubmit only the same
  unresolved intent, or replace a proven pre-effect failure with retained proof.
- Local checks: `ruff format --check .`, `ruff check .`, and
  `mypy --no-incremental --exclude '^build/' .` pass. The mypy exclusion avoids
  the pre-existing duplicate source tree in ignored `build/lib`.
- `pytest --cov=src/sciaiot/ovpncp --cov-report=term-missing --tb=short`:
  **685 passed, 90% overall coverage**. All substantive new agent modules exceed
  80% coverage. Failure tests cover replacement and command errors, lost replies,
  partial effects, restart recovery, duplicate operations, database failures,
  stream invalidation, producer gaps, and same-second reconnect identity.
- Public OpenAPI exactly matches the retained Phase 2 baseline: 32 paths,
  48 operations. No public endpoint or response schema changed.
- Disposable verification on `fdsadmin@sciaiot-openvpn` used OpenVPN 2.6.19,
  Easy-RSA 3.1.7, a fresh synthetic CA, two real VPN clients, and attested mount,
  PID and network namespaces. Host OpenVPN paths were masked before execution.
  The runner is `tests/integration/run_vpn_mutation_namespace.sh`; its executable
  proof is `tests/integration/vpn_mutation_rehearsal.py`.
- Real checks passed for issuance/renewal/revocation/deletion, verified credential
  ZIPs, CCD/CRL projection, owned route and firewall updates, preservation of
  explicitly unrelated administrator state, packet allow/deny despite a broad
  established-connection accept, real disconnect events, and history-before-ack.
- Controlled reload uses SIGUSR1 with required persistence options and verifies
  readiness plus unchanged route/firewall state. Static configuration reload and
  full service restart remain deployment-owned. Agent SIGKILL/restart preserved
  completed operation results; exact replay caused no duplicate effect, and
  real VPN traffic survived agent loss.
- `tests/integration/vpn_api_probe.py` exercised API services at UID/GID 65534
  with zero effective/permitted/inheritable capabilities inside a chroot. Only
  API-owned data, the control socket and read-only entropy were exposed; no
  OpenVPN/PKI files or executable filesystem were available, and local process
  calls were forbidden. Discovery, profile generation, certificate issue/delete,
  and credential streaming passed.
- Final private evidence: `/home/fdsadmin/.ovpncp-p4-pm_12vyb/last-result.log`
  and `evidence-ourky57x/host-before.json` / `host-after.json`. All seven host
  fingerprints matched: routes, links, addresses, policy rules, IPv4 firewall,
  IPv6 firewall, and existing OpenVPN process identities. Every earlier
  disposable attempt also left these host fingerprints unchanged.
- Operational bounds remain explicit: 10,000 durable session bindings; missing
  disconnect hooks can retain stale bindings and exhaust capacity, producing
  loss/gap evidence rather than aliasing sessions. Image confinement, packaging
  and production rollout verification remain in Phases 5 and 6.

### 2026-09-22 — Phase 5 artifact handoff (phase remains in progress)

- Prepared four first-party multi-stage Dockerfiles, immutable base/source
  pins, fixed Debian snapshot and hashed CPython dependency closures.
- Prepared separate build and deployment Compose files, non-root application
  identities, explicit capability/mount limits, a private bridge, protected
  socket directories and non-destructive empty-state preparation.
- UI images are environment-agnostic: Entra tenant/client/scope are validated
  runtime settings rendered in tmpfs and served without caching before browser
  authentication initializes. Container builds require no Entra arguments and
  cannot embed local environment files; missing/invalid runtime settings fail
  closed. Static frontend deployment and local development remain supported.
- Added container entrypoint/health/secret-boundary tests and CI validation of
  image definitions and Compose configuration. An empty-environment event-hook
  regression check covers OpenVPN's removal of inherited Python variables.
- Build and runtime configuration instructions are in `docs/container-images.md`
  and `docs/container-deployment.md`; operator values are documented in
  `deploy/container.env.example`.
- Both manifests passed `compose config --quiet` with synthetic settings using
  the official checksum-verified Compose v5.5.1 standalone CLI. No Docker
  engine, image build, image push, VPN service or host network was started.
- Final local quality gates passed: `ruff format --check .` (151 files),
  `ruff check .`, `mypy --no-incremental --exclude '^build/' .` (134 source
  files), and `pytest --cov=src/sciaiot/ovpncp --cov=deploy/containers
  --cov-report=term-missing` (729 passed; 90% combined coverage, 94% container
  helper coverage). `git diff --check` passed. Hash-locked binary dependency
  resolution passed for the AMD64 API and ARM64 agent; no packages were
  installed into the application environment by these dry-run checks.
- UI runtime correction checks passed: `npm run lint`, `npm run typecheck`,
  `npm run test` (178), `npm run test:production` (8),
  `CI=true npm run test:e2e` (5), `npm run test:e2e:production-guard` and
  `npm run test:container`. Isolated builds reject embedded deployment values;
  Chromium proved identical assets use two runtime Entra configurations and
  fail closed for missing/invalid configuration. Fifteen Python tests exercise
  the actual POSIX runtime renderer, injection rejection and file permissions.
- The operator reported an Azure UI build failure at `npm ci`: TypeScript 6
  conflicted with `openapi-typescript`'s TypeScript 5 peer dependency. The
  local `.npmrc` bypass had hidden the conflict. TypeScript is pinned to 5.9.3,
  the npm lockfile is regenerated, and the local bypass is disabled. A clean
  install without `.npmrc` or reused `node_modules`, followed by
  `npm run build:container` using the Dockerfile's exact copied input files,
  passed. Docker and CI explicitly enable peer dependency resolution. Fresh
  dependency verification also passed `npm run lint`, `npm run typecheck`,
  `npm run api:check`, `npm run test` (178), `npm run test:production` (8),
  and `npm ls typescript`. The navigation test now declares its local-admin
  auth fixture explicitly instead of relying on local dotenv. Ruff formatting,
  lint, mypy and all 44 focused container tests passed. Azure retry remains
  pending; no successful UI image is claimed.
- Successful operator builds, locally or using the supplied Azure ACR commands
  for `faureciaiot`, remain pending. Record all four immutable
  image references and build evidence before remote verification on
  `fdsadmin@sciaiot-openvpn`. SBOM/provenance retention, vulnerability scanning,
  signing, final layer inspection, effective capabilities and real container
  VPN tests remain unverified; Phase 5 is not complete. Phase 6 runtime proof
  and migration/cutover remain pending.

### 2026-09-23 — Remote image/migration preflight

- Operator reports `ovpncp-agent`, `ovpncp-api`, `ovpncp-openvpn`, and
  `ovpncp-web` built in `faureciaiot` and authorizes verification/migration on
  `fdsadmin@sciaiot-openvpn`.
- Read-only checks confirm Azure VM `openvpn`, x86_64, Docker 29.8.1, Compose
  v5.5.1, no running containers and no cached ovpncp images. The existing
  `openvpn@server.service` is active; source OpenVPN is 2.6.19 with OpenSSL
  3.0.13. No VPN service, firewall, PKI, cloud identity or container was changed.
- The operator corrected the login server to
  `faureciaiot-b8c8fwavbhdudve2.azurecr.io` and supplied agent tag
  `phase5-20260922052553`. A remote `sudo -n docker pull` reached that registry
  but failed with authentication required. No user/root Docker login was
  found. The Azure managed-identity endpoint returns HTTP 400 `invalid_request`
  with identity-not-found status. Root Docker pull authentication has been
  requested; no image has been pulled or verified. Tags for the other three
  images remain unverified.
- Read-only migration review confirms that current M0 only supports stopped
  targets owned by the migration operator and exact component versions. The
  authoritative-state/runtime-projection container split needs a tested target
  adapter before importing live source state. Existing namespace harnesses do
  not isolate containers created by the host Docker daemon.
- Next gates: resolve registry access and immutable digests; test image imports,
  hooks, identities and actual non-root agent network capabilities in isolated
  containers; complete disposable container connectivity/recovery and migration
  adapter evidence before live cutover. Phases 5–7 remain incomplete.

### 2026-09-23 — Cached-image runtime verification

- The operator pulled all four images. Inspection confirms AMD64 images with
  tag `phase5-20260922052553` in
  `faureciaiot-b8c8fwavbhdudve2.azurecr.io`; previous authentication blockage no
  longer prevents using the cached images. Recorded repository digests:

  | Repository | Digest |
  | --- | --- |
  | `ovpncp-agent` | `sha256:107c7297ea196086fdeb05e40efcc559f2c531e2e7c62499abd76d08c5f6c1f8` |
  | `ovpncp-api` | `sha256:5e9fc7086070ff032c16694622ffd02d4f2ed91362dd1b7f5a048a5159410f3b` |
  | `ovpncp-openvpn` | `sha256:d8b900e3891dbe5d7d77b8765a266b0f8b3c6f81a4ec4ba72775cfb839a100d1` |
  | `ovpncp-web` | `sha256:c0e580ca2a81c3b1b35318981481f39ed9475ea2372ccafa88dde9b46016f4c9` |

- Actual agent probe used `--network none`, no mounts, read-only root,
  `cap_drop=ALL`, `NET_ADMIN`, no-new-privileges, AppArmor and configured
  UID/GIDs. UID 65532 had empty permitted/effective/inheritable/ambient
  capability sets; only its bounding set contained NET_ADMIN. Actual child
  `iptables-nft-save` and `ip link set lo up` returned permission failures.
  This blocks deploying the original image; the correction is recorded below.
- OpenVPN 2.6.19 runs and the absolute event-hook executable succeeds under an
  empty environment. The image links OpenSSL 3.5.7, unlike source 3.0.13;
  current exact-version migration validation must not be bypassed.
- API dependency imports pass as UID 65531. API and UI reject missing
  authentication settings. Nginx starts as UID 101 with synthetic public Entra
  configuration; HTTP health, SPA and runtime-config responses pass, including
  no-store headers and the expected runtime scope. No ports were published;
  tests used private network namespaces and no production state mounts.
- Disposable containers were removed; no running containers remain and the
  host VPN stays active. An initial raw `iptables-save` digest comparison was
  inconclusive because it included timestamp comments/counters. A repeat
  isolated-container check normalizing those fields found unchanged host rules.
- Full VPN connectivity/recovery, container target migration mapping and
  release SBOM/provenance/scanning/signature evidence remain pending. No live
  cutover or production PKI modification occurred.

### 2026-09-23 — Agent capability correction (rebuild pending)

- Phase 5 agent (`gpt-6-astra`, medium effort) added a fixed-purpose stdlib
  bootstrap. It starts with NET_ADMIN/SETUID/SETGID, drops all real/effective/
  saved IDs to UID/GID 65532, sets only supplementary group 65531 and retains
  NET_ADMIN alone in permitted/effective/inheritable/ambient sets. It verifies
  those identities and no-new-privileges before executing application code.
  The root bootstrap uses isolated Python mode; daemon and Docker health
  checks both pass through the same privilege drop. Dockerfile, Compose,
  regression tests and deployment identity documentation are updated.
- A bounded probe streamed the exact bootstrap source into the cached agent
  image, using the corrected startup identity/capabilities, no network access
  and no host mounts. Only the fixed post-drop exec target was replaced by
  a diagnostic Python child. That child showed UID/GID 65532, groups [65531],
  NET_ADMIN-only masks `0x1000`, and no-new-privileges enabled. Actual
  `iptables-nft-save` and `ip link set lo up` child commands both succeeded.
  Attempts to regain UID 0 or change supplementary groups were denied.
  The bounding set retains SETUID/SETGID (`0x10c0`); neither is permitted,
  effective, inheritable or ambient after the drop.
- This proves the bootstrap on the target kernel; it does not claim that a
  rebuilt image or the full agent service has been verified. Rebuild only
  `ovpncp-agent` with the updated Dockerfile and pair it with updated Compose.
  The three other cached image digests remain available for further testing.
- The API additionally started with synthetic Entra configuration, disabled
  background work, private tmpfs state and no network access. Its HTTP health
  check confirmed authentication denial as expected; the container and state
  were removed afterward.
- Local gates passed: `ruff format --check .` (153 files), `ruff check .`,
  `mypy --no-incremental --exclude '^build/' .` (136 source files),
  `pytest --cov=src/sciaiot/ovpncp --cov=deploy/containers
  --cov-report=term-missing` (746 passed, 90% combined coverage, 98% bootstrap
  coverage), and `git diff --check`. Both Compose manifests passed
  `config --quiet` with synthetic settings using Compose v5.5.1.
- Rebuilt-image verification, full disposable VPN integration, source/target
  OpenSSL compatibility and container migration mapping remain outstanding.
  No production VPN cutover, source PKI change or host service restart occurred.

### 2026-09-23 — Rebuilt agent image verified

- The operator built and pulled `ovpncp-agent:phase5-agent-capfix-20260923`.
  Its repository digest is
  `sha256:2c9c0aaf0fc9637f8d509879ec6abe69e1f43c47025e9544acb43d1d5e450c4d`.
  Inspection confirms root bootstrap entrypoint and health check, both using
  isolated Python. Bootstrap file SHA-256 matches the workspace:
  `b8d9d2be2d7327852f1107d7e95bf15bbb6d26f9a3e27c0a878e7707e338c248`.
- The image's own bootstrap passed real `iptables-nft-save` and `ip link`
  child-command probes with no host networking or production state mounts.
  Its unmodified entrypoint then started a read-only agent with an ephemeral
  control-socket directory. PID 1 had all UID/GID slots 65532, supplementary
  group 65531, NET_ADMIN-only permitted/effective/inheritable/ambient sets and
  no-new-privileges enabled. Its socket was owned 65532:65531 with mode 0660.
- The first diagnostic process lacked access to the protected socket directory;
  repeating with the Compose supplementary group and observing as daemon UID
  passed. Both disposable containers were removed. The host VPN stays active.
- Phase 6 disposable container integration preparation is in progress. This
  image-level proof does not yet establish full VPN integration or migration
  readiness; source state has not been imported or changed.

### 2026-09-24 — Container integration and scan follow-up

- Phase 6 agent (`gpt-6-astra`, high effort) added the explicitly invoked
  disposable Docker rehearsal, safety regressions and invocation documentation.
  Initial full checks passed: 759 tests, Ruff formatting/lint and mypy.
- Two remote attempts established real two-client UDP/CCD/session behavior,
  default-denied peer traffic and typed access mutation/replay. Allowed ping
  still failed despite both allow-rule counters advancing. Packet diagnosis
  continues; no allowed-flow success or Phase 6 completion is claimed.
  Both cleanups and all host-network/VPN invariance checks passed.
- Trivy 0.74.0 scans and post-build CycloneDX SBOMs now exist for all four
  digests. No embedded secrets were reported. High findings remain in all
  images; the web image also has one critical libxml2 finding. Detailed counts,
  exact digests, private evidence locations, applicability limits and primary
  sources are in [image verification](container-image-verification.md).
- Phase 5 agent (`gpt-6-astra`, medium effort) prepared removal of unnecessary
  pip/ensurepip payloads from Python images and unused XML modules/libraries
  from the web image. No application dependency locks changed. Rebuild/rescan,
  remaining finding review, provenance and signing are still required.
- Source OpenSSL compatibility and the container migration target adapter
  remain outstanding. No source PKI import, production cutover or live VPN
  service restart has occurred.

### 2026-09-24 — Disposable container rehearsal passed

- Attempt 3's redacted packet types confirmed an echo reply plus an ICMP host
  redirect. The one-packet ping counted the redirect as an error before the
  reply. The harness now configures redirect emission only in its disposable
  server namespace, before creating TUN; strict traffic assertions are unchanged.
  Production gateway redirect policy is documented as an operator-owned
  prerequisite. No live host sysctl was changed.
- Attempt 4 passed real two-client UDP/CCD/session behavior, default deny,
  agent-managed allow, denial after access removal, exact mutation replay and
  data-plane survival through agent SIGKILL/restart. Cleanup passed. Host links,
  addresses, IPv4/IPv6 routes/rules/firewall, VPN PID/service and server config
  were unchanged. Detailed evidence/limits are in
  [image verification](container-image-verification.md).
- Exact Dockerfile packaging cleanup instructions passed in disposable writable
  copies of all three Python images, including application imports. The exact
  web purge/guard passed, followed by HTTP health, SPA and runtime-config
  checks as UID 101. Cached images were not modified. Rebuild/rescan all four
  images before claiming the scanner findings removed from deployed digests.
- Final local gates passed: Ruff formatting (157 files), lint, mypy (138 source
  files), the full coverage suite (776 passed; 90%) and whitespace checks.
- Full Phase 6 remains incomplete: complete HTTP/RBAC/web integration,
  credential lifecycle/CRL/reconnect, recovery and production Compose topology
  need further proof. Release provenance/signature/finding review, exact-version
  migration compatibility and the container target adapter also remain open.
  No production migration or cutover occurred.

## Reference material

- Docker devices and Linux capabilities:
  <https://docs.docker.com/engine/containers/run/>
- Docker host networking:
  <https://docs.docker.com/engine/network/drivers/host/>
- OpenVPN management interface:
  <https://openvpn.net/community-docs/management-interface.html>
- Kubernetes Pod network and volume sharing:
  <https://kubernetes.io/docs/concepts/workloads/pods/>
- Azure Application Gateway protocol limitations:
  <https://learn.microsoft.com/azure/application-gateway/application-gateway-faq>
- Azure Load Balancer TCP/UDP frontend behavior:
  <https://learn.microsoft.com/azure/virtual-network/ip-services/configure-public-ip-load-balancer>
- Easy-RSA PKI structure and operating model:
  <https://github.com/OpenVPN/easy-rsa/blob/master/doc/EasyRSA-Readme.md>
- Easy-RSA renewal, revocation, and full-PKI backup guidance:
  <https://github.com/OpenVPN/easy-rsa/blob/master/doc/EasyRSA-Renew-and-Revoke.md>
- Easy-RSA advanced configuration:
  <https://github.com/OpenVPN/easy-rsa/blob/master/doc/EasyRSA-Advanced.md>


### 2026-09-27 — Portable builds and extended remote rehearsal

- The operator confirmed portable builds/deployment as the scope and retained
  the existing optional Entra/Azure integrations. Provenance and signing handoff
  are deferred; they are not treated as completed or used to block functional
  verification. Phase 5 remains in progress.
- The extended disposable harness passed against the four-image hardening
  release (agent, API and OpenVPN participate in the VPN harness). Three real
  UDP clients proved typed credential issuance, verified archive delivery,
  exact CCD assignment, reconnect, signed CRL projection, denied revoked-client
  handshakes, denied revoked archives, disconnect and deletion. VPN peer traffic
  survived stopping/restarting both the real HTTP API and typed probe, as well
  as agent SIGKILL/restart. Actual API HTTP checks rejected unauthenticated
  requests. These checks do not prove valid-token RBAC or web integration.
- Cleanup passed. Before/after normalized host links, addresses, IPv4/IPv6
  routes, policy rules and firewalls matched; the host VPN PID, active state and
  server configuration matched. Private results are retained as
  `lifecycle-20260927-result.json` and `lifecycle-20260927-invariance.json` under
  `/home/fdsadmin/.ovpncp-p6-container-jmpe6950`.
- Exact-image applicability probes confirmed python-jose selects cryptography
  backends in the API. Nginx and curl do not link Expat, TIFF, X11, XML or ACL
  libraries. Standard systemd-homed/tiffcrop executable paths are absent; no
  Archive/Tar.pm was found under the checked library/share directories. These
  findings narrow specific paths and do not approve a blanket vulnerability
  exception. See the vulnerability review for limits.
- Full Phase 6 remains incomplete: authenticated HTTP/RBAC and web edge,
  renewal, crash-during-mutation, reboot/restore and the production host-network
  Compose topology need further verification. Source OpenSSL compatibility and
  the container migration target mapping remain Phase 7 prerequisites. No
  source PKI import, production service change or cutover occurred.

- The Phase 5 agent (`gpt-6-astra`, medium effort) added
  `.github/workflows/containers.yml`: all four AMD64 images build with SBOM
  attestations on PR/push/manual events and export OCI artifacts plus digest
  metadata. Publishing is explicit manual opt-in from the default branch.
  GHCR is the default; external registries, including root-level ACR
  repositories, use configurable targets and separate credentials. GitHub
  tokens are never used for external registry login. No workflow deploys.
- Local validation passed: `ruff format --check .` (160 files), `ruff check .`,
  `mypy --no-incremental --exclude '^build/' .` (139 source files), and
  `pytest --cov=src/sciaiot/ovpncp --cov-report=term-missing` (799 passed, 90%).
  Plain `mypy .` encounters duplicate modules in generated `build/lib`; that
  unrelated build output was retained and excluded from the successful check.
  Official checksum-verified actionlint v1.7.7 validated the new workflow with
  ShellCheck disabled. A hosted Actions run and publication have not occurred.


### 2026-09-27 — GitHub verification deferred until after all phases

- The operator deferred the first hosted GitHub Actions build and artifact
  verification until all architecture phases are finished. Keep the workflow
  and local checks in place; no push, dispatch or publication is required to
  close P5 or progress through the remaining phases.
- This is a scheduling change, not evidence that the hosted workflow passed.
  Track its first run/artifact verification as a post-phase follow-up alongside
  the already deferred provenance/signing handoff. The remaining vulnerability
  review is unchanged; P5 is still in progress.


### 2026-09-27 — P5 implementation complete; release checks rescheduled

- The operator agreed to address the remaining image vulnerabilities before
  the GHCR release, after completing the architecture phases. That review is
  now deferred and does not block phase progression. No advisory was waived,
  resolved or accepted merely by moving its review date.
- Provenance and signing generation/verification are grouped with the first
  GitHub Actions/GHCR release, as separately agreed by the operator. Existing
  SBOMs and scans remain evidence for their recorded digests and scan dates.
- P5 is recorded as implementation complete with release verification deferred.
  This supersedes the earlier in-progress status caused by those review gates;
  it does not claim signed images, a successful hosted run, security release
  approval, full P6 integration or production migration.


### 2026-09-28 — Phase 6 implementation started

- The operator requested Phase 6 using `gpt-6-sol` at `xhigh` effort.
- Continue from the existing Compose reference and passing disposable
  three-client rehearsal. Evaluate remaining readiness, integrated service,
  upgrade/rollback and clean-host workflow requirements without reclassifying
  the earlier partial proof as a complete deployment test.
- Preserve the live source VPN while verifying disposable fixtures. No
  production migration, cutover, cloud resource change or publication is
  included in this phase's implementation work.


### 2026-09-29 — Phase 6 isolated Compose proof passed

- Added the actual Compose service integration runner and synthetic TLS/JWKS
  fixture. Real image entrypoints, health checks and API token verification
  remain active. The source manifest is strictly checked before its network
  attachments are replaced with owned, isolated namespaces.
- Fixed readiness ordering (OpenVPN, agent, API, web) and quoted each complete
  tmpfs option string so YAML does not split its comma-separated options into
  additional mounts. Documented clean-host startup and selected-service
  API/web upgrade and rollback commands.
- The first Compose attempt reached healthy services and passed signed HTTP
  checks, then timed out inspecting a Docker image. The small host showed
  memory pressure; the precise timeout cause was not established. Manual
  cleanup removed all 20 attested test containers and synthetic state, and
  all eleven host invariance comparisons matched.
- Reduced helper overhead: sleeping anchors/probes use `/bin/sleep`, helper
  health checks are disabled, and expected image IDs are cached once. Real
  service health checks and strict actual-image comparisons remain enabled.
- The next run passed readiness, signed HTTP/RBAC, persistent API identity,
  three real UDP clients, CCD, allowed/denied flows, replay, agent recovery,
  credential issuance/archive/reconnect/revoke/delete and CRL enforcement.
  API/web outage, recreation, a distinct API-image upgrade and rollback all
  preserved VPN traffic and OpenVPN/agent process identities.
- Cleanup passed. All eleven comparisons of host networking, firewall and
  production VPN state matched. No test containers remained in a subsequent
  inventory. No production import or cutover occurred.
- Exact image identities, private evidence paths and the existing invalid-JWT
  error-status limitation are recorded in
  [container image verification](container-image-verification.md).
- Local gates passed: Ruff formatting (163 files), Ruff lint, mypy (142 source
  files, existing generated `build/` excluded), and 812 tests with 90% combined
  application/container coverage. Focused harness tests: 45 passed.
- `full_phase6: false` and `production_network_topology: false` remain accurate.
  The outstanding Phase 6 exit check is a clean-host run of the documented
  commands using the actual host/bridge topology. It cannot be run alongside
  the production VPN on the current source host.


### 2026-09-29 — Existing-host maintenance verification authorized

- The operator selected `sciaiot-openvpn` for actual-topology verification
  and explicitly authorized stopping its source VPN. This server is also
  intended for later migration testing.
- Use fresh synthetic deployment state on this existing Linux/Docker host;
  do not describe it as a newly installed operating system. Preserve the
  source VPN/application state for Phase 7. Stop both source writers during
  the test and restore the existing services afterward.
- Prepare and verify an encrypted maintenance backup before the host-network
  test. Compare the stopped-host network and firewall state after cleanup;
  temporarily changed redirect settings must be restored. Only attested
  test containers, network and firewall entries may be removed.
- This authorization allows the remaining reference topology check without
  a second VM. Verification is still pending until the actual run completes;
  source PKI migration and production cutover are not implied.


### 2026-09-29 — Actual-topology access-policy conflict found

- Two authorized maintenance attempts verified encrypted source backups and
  restored both source services afterward. The first exposed a null Docker
  network-inventory field; the runner now handles it with a regression test.
- The second reached healthy host/bridge services, signed HTTP and real UDP
  clients, then failed at access mutation. Read-only inspection confirms the
  existing agent guard rejects Docker's broad FORWARD jumps. Do not remove
  Docker policy or silently exempt chains by name to pass the test.
- The stopped-host comparison identified only a newly initialized empty raw
  table as different after cleanup. Its ACCEPT-only empty contents were
  verified; excluding it reproduced the original firewall hash exactly.
  Source files and other host state were preserved, and both source services
  are active again. See the detailed private evidence references in
  [container image verification](container-image-verification.md).
- Phase 6 remains in progress while the forwarding-policy integration is
  resolved. No migration or source PKI import occurred.


### Proposed Phase 6 forwarding-policy correction

The actual Docker bridge rehearsal exposed a mismatch between the intended
peer-to-peer VPN access model and its firewall rule shape. Tighten owned access
ACCEPT rules to require both input and output to be the configured TUN. This
covers VPN client pairs and private networks routed behind a VPN peer; it does
not grant VPN-to-host-LAN or VPN-to-container-bridge forwarding.

Before a mutation, inspect reachable foreign filter chains conservatively.
A positive exact input or output interface different from the TUN proves a
rule cannot match these TUN-to-TUN flows. Otherwise, allow only nonrestrictive
terminal/logging behavior or a bounded proof through declared user chains.
Reject matching DROP/REJECT, unsupported targets/control flow, ambiguous
interface matching, cycles and incomplete observations. No Docker chain name
alone grants an exception, and no foreign rule is removed or reordered.

This preserves rejection of administrator restrictions that could apply to the
agent's allowed flows while accommodating Docker rules confined to bridges.
Existing owned rules without both TUN selectors must fail validation rather
than be silently adopted. This changes the agent's realized-rule contract and
requires a rebuilt image plus renewed privileged verification. The source
host remains on its restored original services during implementation.
The matching and chain-traversal basis is the
[iptables manual](https://man7.org/linux/man-pages/man8/iptables.8.html).


### 2026-09-30 — Forwarding-policy fix and local image build

- The requested `gpt-6-sol` / `xhigh` agent implemented the correction above.
  Owned grants require both TUN selectors in canonical `iptables-save` order;
  bounded foreign-chain inspection accommodates bridge-only Docker rules and
  rejects applicable restrictions, ambiguous syntax and incomplete snapshots.
  Existing unqualified owned grants fail validation.
- Local validation: 848 tests passed with 90% combined application/container
  coverage; Ruff formatting and lint passed. Mypy passed 144 source files with
  `--exclude '^build/'`; plain `mypy .` finds a duplicate package in generated
  `build/lib`. `git diff --check` passed.
- The normal agent Dockerfile built successfully on `sciaiot-openvpn`, using
  its pinned dependencies. The resulting local-only reference is
  `ovpncp.local/ovpncp-agent@sha256:ed2acbab21303bc49afbac419cdc1f7dcb67e4cb01336124c3ed611a87f6d82f`.
  Build context hashes and logs are retained privately under
  `/var/lib/ovpncp-p6-agent-build-hsb6nu2s`. No image was published.
- The fresh actual-topology maintenance rehearsal passed with this digest.
  Evidence is retained at `/var/lib/ovpncp-p6-host-8js5885e`: verified encrypted
  backup of 102 source entries, readiness, signed HTTP/RBAC, UDP allow/deny,
  API/web upgrade/rollback and unchanged VPN process identities with surviving
  traffic. The API changed to a distinct immutable image and back; web was
  recreated with changed runtime settings and rolled back.
- Cleanup passed, source files and metadata matched, and all eleven stopped
  host-state comparisons passed both after cleanup and before restoration.
  Both `ovpncp.service` and `openvpn@server.service` are active again.
- Together with the earlier isolated credential/lifecycle proof, this closes
  Phase 6 under the operator-approved existing-host verification scope. Each
  runner retains `full_phase6: false` because it proves only its own subset;
  phase completion is based on the combined evidence. Phase 7 is not started.
  No source state was imported and no image was published. P5 release evidence
  remains deferred to the agreed GHCR schedule.


### 2026-09-30 — Native deployment support deferred until after upgrade

The operator agreed to address native Linux/PyPI deployment support after the
architecture upgrade. The intended follow-up is a complete native deployment
of the same unprivileged API and separate VPN agent used by containers;
retaining the legacy direct-host backend is not required for that design.

Scope that follow-up around Python package installation, host OpenVPN and
system dependencies, event hooks, systemd units, socket permissions, setup and
upgrade tooling, documentation, and native integration verification. Publishing
an API package or agent entry point alone does not establish support for the
complete deployment. Container and native deployment are alternative operating
models, not different feature tiers.

This work is deferred and does not expand the current phase exit criteria.
Finish the architecture and migration work before implementing native setup;
no PyPI removal or legacy-backend retirement is authorized by this decision.


### 2026-09-30 — Phase 7 started; source reconciliation required

- The operator requested Phase 7 with `gpt-6-sol` at `xhigh` effort. The
  implementation agent owns the M0 container-target adapter and tests; native
  deployment support remains deferred until after the architecture upgrade.
- Read-only checks on the approved `sciaiot-openvpn` source found the original
  application, OpenVPN and Nginx active, with no containers remaining. Source
  versions are OpenVPN 2.6.19, Easy-RSA 3.1.7 and OpenSSL 3.0.13. The pinned
  container uses OpenSSL 3.5.7, requiring a reviewed compatibility extension;
  exact-version rejection remains the default.
- The current CA and server certificate are unexpired, and the PKI CRL is
  current. However, the server configuration omits `crl-verify`, and six issued
  certificates signed by the current CA are absent from both the current and
  previous CA indices. All six have private-key files and four have CCD files.
  These are unexplained source inconsistencies, not artifacts to discard or
  certificates to mark valid by inference. The operator was asked for an
  authoritative CA-index backup or issuance/revocation history. The operator
  confirmed none is available: this test server was restored from another
  server. Reconciliation must therefore use an explicit conservative policy,
  not an inferred valid status. The operator approved repairing an isolated
  copy by explicitly revoking the six unindexed certificates, then testing
  migration with indexed valid clients. Original source files remain intact.
- Source references also include a pool file and two OpenVPN event hooks
  outside the approved OpenVPN tree. Any source-boundary extension must allow
  only explicitly approved pool/hook files; it must not expose the backend
  directory, database, environment, archives or authentication configuration to
  the migration tool. Hooks remain hash-only inventory with reviewed target
  replacements, never executable migration payloads.
- The target adapter must derive private authoritative state and the minimal
  daemon-readable projection from the authenticated M0 bundle, preserve the
  exact runtime ownership/mode contract, and retain mandatory rollback. It
  must not make the entire migration tree accessible to OpenVPN or create an
  unrelated second import path.
- Adapter implementation and valid-fixture verification may proceed while
  source history is investigated. No source file was changed, no source
  service stopped, and no migration or recovery success is claimed yet.


### Phase 7 approved isolated-source reconciliation

Before M0 export, briefly freeze the original application and VPN writers,
verify an encrypted OpenVPN-only recovery copy and source fingerprints, and
capture a private isolated copy. Restore the original services before doing
PKI repair. This preparation is separate from the migration toolkit.

In the isolated copy, use OpenSSL's CA revocation command to explicitly add
revoked records for the six unindexed certificates and generate a signed CRL.
Preserve existing index records, certificates and private-key bytes, and verify
CRL rejection for all six. Add `crl-verify` to the copied server configuration
and remap only source file references into the captured copy; retain the
original hashes and a private reconciliation audit. This is an approved change
in the test copy, not a claim that the missing historical status was recovered.
The procedure passed a synthetic fixture matching the observed record counts
before execution. The command contract follows the
[OpenSSL 3.0 CA documentation](https://docs.openssl.org/3.0/man1/openssl-ca/).

M0 must still validate the complete repaired source and reject unexplained
PKI/configuration drift. No original source CRL or index is replaced, and no
restored test deployment may become the production endpoint in this phase.


### 2026-09-30 — Isolated source reconciliation passed

- Private preparation evidence is retained under
  `/var/lib/ovpncp-p7-source-r6s2gwm2`. A brief writer freeze captured and
  verified all 75 entries of an encrypted OpenVPN-only recovery set. Frozen
  source fingerprints matched; both original services were restored active
  before repairs to the isolated copy began.
- The first isolated repair stopped safely when OpenSSL detected two distinct
  certificates sharing one unindexed serial. The original source was not
  affected. A repeat started from the verified recovery capture and retained
  the failed copy for inspection.
- The final isolated copy revokes five distinct serials covering all six
  formerly unindexed certificates. CRL checks reject all six. One conflicting
  certificate is retained in private quarantine outside the active copied PKI,
  with a recorded hash and reason; all original credential bytes remain in
  recovery evidence. Three valid index rows and the previous revocation are
  unchanged. The copied configuration now enforces the CRL.
- The conservative collision handling also passed a synthetic fixture before
  the repeat. No migration validator was relaxed to accept conflicting
  certificates, and no original index, CRL, key, certificate or config was
  replaced. The copied source has an explicit reconciliation history rather
  than silently discarding an unexplained record.
- Cached target image observations confirm OpenVPN 2.6.19/OpenSSL 3.5.7 and
  agent Easy-RSA 3.1.7/OpenSSL 3.5.7. Although target `--help` omits
  `data-ciphers-fallback`, a non-networking parser probe accepted that option
  with `AES-256-CBC`, which is also listed among available target ciphers.
  Actual M0 export and target migration/recovery verification remain pending.


### Phase 7 source export validation finding

The committed M0 inventory accepted the repaired copy: 50 logical files,
180,312 bytes, two hook replacements required, with log/status directives
excluded. Evidence is retained at `/var/lib/ovpncp-p7-export-a666xw_b`.
Encrypted export then rejected a certificate/index subject comparison before
writing a bundle. Read-only diagnosis found that the five newly revoked index
rows contain the correct single common name followed by other distinguished
name attributes. The validator incorrectly requires the common name to be the
last attribute. Correct that parser with regression tests for field order,
escaping and ambiguous duplicate names; preserve the authentic certificate and
index bytes. Target migration and recovery remain unverified at this point.


### Phase 7 copied server identity reconciliation approved

After the subject-parser fix, M0 reached a separate source inconsistency: the
configured server certificate is absent from the CA index and issued inventory.
No indexed valid certificate has server-authentication usage. The operator
explicitly approved issuing a replacement server certificate under the copied
CA with the same server common name, preserving existing client credentials and
all original server files.

The isolated procedure creates a fresh server key and server-authentication
certificate, explicitly retires the superseded unindexed server in the copied
index/CRL, verifies both server purpose and revoked rejection, and checks that
all prior client credential bytes and index records remain unchanged. Only the
copied configuration switches to the new indexed server identity. This
procedure passed a synthetic fixture before remote execution; its private
audit records the old and new identities. M0 will compare the reconciled copy's
server fingerprint, not claim that the original live server identity migrated
unchanged. No production endpoint or original source credential is replaced.


### 2026-09-30 — Reconciled source export passed

The approved copied-server replacement passed on the test host: server purpose
and the unchanged common name were verified, the superseded server was revoked
in the copied CRL, and all nine prior index rows and existing client credential
bytes were preserved. Two index rows were added for the retired and replacement
server identities. Private evidence is retained in
`/var/lib/ovpncp-p7-source-r6s2gwm2/server-repair-result.json` and its adjacent
private reconciliation audit. The original application and VPN services remain
active; neither original server credentials nor client credentials were changed.

Authenticated M0 export then succeeded with 52 logical files (175,183 bytes)
from the repaired, quiescent copy. The encrypted bundle, private key file,
redacted export result and helper-code hashes are retained under
`/var/lib/ovpncp-p7-export-3q6mzyet`. The source inventory requires two reviewed
hook replacements and excludes runtime log/status directives. This establishes
the migration baseline; container import, connectivity, restore and rollback
evidence are still pending.


### Phase 7 pinned target capability evidence

A fresh confined probe of the cached pinned images confirmed OpenVPN 2.6.19,
Easy-RSA 3.1.7 and OpenSSL 3.5.7, with the reviewed event-hook SHA-256 unchanged.
It observed 233 option names and 64 cipher names; an explicit successful
`--data-ciphers-fallback AES-256-CBC --show-ciphers` invocation supplements the
help output, which omits that option. The redacted observations are retained at
`/var/lib/ovpncp-p7-capabilities-zc2cyg7j/capabilities.json`. Probe containers had
no network, no capabilities, read-only roots and no writable host mounts.

The focused migration regression suite passed 106 tests before the final
container-policy hardening and live rehearsal. Final quality gates and recovery
acceptance remain pending.


### 2026-10-01 — Actual bundle target preflight passed

The interrupted read-only preflight completed successfully; its result was
recovered from `/var/lib/ovpncp-p7-preflight-4npu1srp/preflight-result.json`.
The authenticated source bundle passed the pinned container policy and mapped
to 63 target files. All eight client-authentication certificates present in
the issued inventory had the required usage extension and compatible
filename/common-name values. This count includes revoked certificates; it is
not a count of valid connection candidates. Both original services were
confirmed active with zero running test containers. Live connection and
recovery rehearsal remain pending.


### 2026-10-01 — Stopped container import and verification passed

The actual bundle was imported into a separate private disposable target using
the pinned API image as an offline migration helper. An initial attempt stopped
before activation when metadata verification detected missing setgid directory
bits. Running the helper as `0:65532` with supplementary group `65531` preserves
those fixed runtime modes using only `CHOWN`, `FOWNER` and `DAC_OVERRIDE`; no
additional capability was needed. This is a helper invocation requirement, not
a relaxation of the target ownership check.

The retry at `/var/lib/ovpncp-p7-import-xkp2n72l/import-result.json` passed
activation and full M0 verification: 63 target files, 43 PKI files, seven revoked
serials, five CCD entries and zero unexplained drift. CA identity, the approved
replacement server identity, client serial status, CCD and server options all
matched the authenticated repaired-copy baseline. The target remains stopped
with rollback retained. No original source service was stopped for this check.
Live connectivity and recovery acceptance remain pending.


### 2026-10-01 — First live migration rehearsal and checkpoint finding

The bounded run at `/var/lib/ovpncp-p7-run-w12rkdrp` completed actual import and
verification, unchanged-client UDP/TUN connectivity with the imported CCD
assignment, VPN restart/reconnect, new target issuance/revocation and an
authenticated encrypted checkpoint of the stopped target. It then failed at
restore-policy validation; restore and rollback were not reached.

Read-only diagnosis found exactly one missing capability observation:
`disable-dco`, which the adapter adds to the runtime configuration. The pinned
daemon had accepted the option in the live run, but its help output omits it.
The validator correctly refused to assume availability during checkpoint
restore. A fresh explicit `--disable-dco --show-ciphers` probe passed, and
updated immutable observations at
`/var/lib/ovpncp-p7-capabilities-_182q2s3/capabilities.json` contain 234 option
names, 64 cipher names and explicit fallback/DCO-option probe results. Add a
regression to reject missing generated-option evidence before initial import.

The maintenance guard confirmed unchanged source files, all eleven stopped-host
network/sysctl comparisons, complete test-container cleanup and both original
services restored active. No endpoint cutover occurred. The local full suite
passed 875 tests with 90% overall coverage (86% for the new adapter); formatting,
lint and mypy checks also passed before this capability regression fix.

The broader coordinated recovery acceptance still needs a separate encrypted
recovery set for fresh test API data, agent journals/ownership and deployment
metadata alongside M0's OpenVPN-only bundle. Earlier Phase 6 evidence does not
cover that whole-state restore. No source backend, archive, authentication or
UI data will be imported by M0.


### 2026-10-01 — OpenVPN migration, restore and rollback passed

The second bounded run at `/var/lib/ovpncp-p7-run-uiers0wr` passed the complete
OpenVPN rehearsal. Its private evidence root is
`/var/lib/ovpncp-p7-run-uiers0wr/ovpncp-p7-cee8bf7eea21-86ack0b8`; the parent
`maintenance-status.json` and `rehearsal-result.json` contain redacted results.

- Authenticated M0 import and semantic/CCD reconciliation passed.
- An indexed valid client connected with unchanged certificate/key/CA bytes
  and received its imported CCD address.
- VPN restart and client reconnect took 4.373 seconds against the 300-second
  objective.
- New target issuance/revocation and a stopped-writer encrypted checkpoint
  passed. The restored deployment retained that acknowledged revocation.
- Client reconnect after starting the restored VPN took 3.940 seconds. This
  measures VPN startup/reconnect, not full VM restore time.
- Exact rollback restored a distinct nonempty prior generation derived from
  the post-revocation checkpoint. The revoked credential remained revoked
  after rollback, and another new issuance/revocation then passed.
- All eleven host network/sysctl comparisons passed, original source files
  remained unchanged, both original services were restored active and all
  test containers were removed. No production endpoint was selected.

The result explicitly records full VM/API restore and coordinated API/agent RPO
as not tested. A separate operator recovery set and disposable Compose drill
are now being implemented for those remaining checks, using fresh synthetic API
state. The M0 tool and bundle remain restricted to OpenVPN state. Phase 7 is not
yet marked complete.


### 2026-10-02 — Persistent test-server migration

The operator explicitly requested stopping existing services and leaving the
migrated deployment running on `sciaiot-openvpn`; downtime was accepted. This
supersedes the earlier rehearsal-only restoration of legacy services. No Azure
resources, DNS, or cloud ingress rules were changed.

- Deployment and private evidence root:
  `/var/lib/ovpncp-phase7-deployment`.
- The authenticated bundle from the approved repaired isolated source passed
  validation, dry-run, stopped import and verification. All 63 target files
  matched: 43 PKI files, seven revoked serials, five CCD entries, one source
  configuration, and zero unexplained drift.
- OpenVPN, agent, API and web use the pinned images from the successful
  rehearsal, including the corrected locally cached agent. All four reached
  healthy state in the reference host/bridge topology.
- Separate deployment steps reused existing Entra API/SPA/scope settings and
  the shared client endpoint. The existing optional storage credential is
  mounted as a private file. M0 did not read or write those settings.
- The API database is fresh. The tested private operator initializer imported
  three active clients, one active fixed-address assignment, and skipped six
  inactive discoveries. Legacy users, device links, access grants, database
  records and archive files were not copied. The five migrated CCD files
  include entries associated with revoked credentials, which remain revoked.
- The container web service takes the existing IPv4 HTTP port 80. UI HTTP 200,
  matching runtime Entra settings and unauthenticated API rejection with 401
  passed. Real Entra browser sign-in remains an external verification step.
- A client using unchanged CA/certificate/key bytes connected in 1.025 seconds,
  received the imported CCD address, pinged the VPN gateway and appeared in
  agent sessions. The temporary canary was removed. This tests a local bridge
  client on the approved VM, not the Azure public UDP path.
- The owned VPN firewall starts with its exact two TUN anchors and terminal
  deny. API event consumption and operation reconciliation were enabled after
  inventory initialization; existing access rules were not silently adopted.
- A deployment-specific systemd controller owns startup ordering. Its release
  sets container restart policies to `no`, creates the Docker bridge before
  attesting/repositioning only the owned anchors, and starts VPN services only
  after the default-deny baseline exists. Original application/Nginx boot
  activation is disabled and the generated legacy OpenVPN instance is masked.
  Original source/configuration bytes and private rollback evidence remain.

The hardened systemd controller completed a controlled stop/start successfully;
`activation-result.json` confirms the unit is active/enabled and legacy
services remain stopped. The repeated unchanged-client check passed in 1.022
seconds. `final-audit.json` confirms all four containers are healthy, use the
expected images and runtime UIDs, have read-only roots and no privileged or
runtime-socket grants, and have actual Docker restart policies set to `no`.
The owned anchors remain first and the original VPN source fingerprint is
unchanged. `verification-before-lifecycle.json` retains the initial canary
result, and `verification-result.json` records the post-restart result. These
checks do not claim a real host reboot or Docker-daemon restart.

The local final gates passed: 895 tests, 90% overall coverage, Ruff formatting
and lint, mypy over 153 files with generated `build/` excluded, and
`git diff --check`. The new recovery-set module also handles committed SQLite
WAL contents by backing up a bounded private scratch copy, without asking
SQLite to write side files beside read-only source volumes.

This persistent migration does not close the coordinated full API/agent
recovery or VM-loss/RPO acceptance criteria. The encrypted recovery-set core
has unit coverage; a live whole-state restore and the Phase 0 off-host recovery
objectives remain outstanding. Image signing/provenance and remaining release
vulnerability review remain deferred to the agreed GHCR release work. No
Phase 7 commit has been requested or made.


### Operator handoff — remaining Phase 7 recovery acceptance

After reviewing the remaining recovery scope, the operator stated, "I'll
handle all of that." Remaining manual backup, whole-application restore,
off-host/VM-loss recovery, recovery-time and recovery-point verification, and
host/Docker restart checks are assigned to the operator. Automated scheduling
is not required for this handoff; the agreed recovery objectives remain the
acceptance reference.

Migration implementation and persistent test-server cutover are complete.
The later test-host authorization extended this handoff to an agent-run,
coordinated Compose restore. That same-host check is now verified; the
remaining off-host and production acceptance scope stays with the operator.


### Deployment scope handoff — Phases 8–10

The operator confirmed that Phases 8, 9 and 10 will be handled during real
deployment under potentially different conditions. They are outside the
current architecture implementation scope and are deferred, not completed.
Their existing deliverables remain reference material to reassess against the
actual deployment. No further deployment or HA work is authorized by this
handoff, and the current test-server deployment is unchanged.

Core architecture implementation and test-server migration through Phase 7 are
complete. Same-host Compose recovery is verified; remaining off-host recovery
acceptance is operator-owned. The deferred Phase 5 release checks remain
associated with the future GHCR release.

### Coordinated Compose recovery verification — 2026-10-07

The operator authorized disruptive verification on `sciaiot-openvpn` and
waived test-server data preservation requirements. The drill still retained
the previous state privately. With writers stopped, it captured encrypted M0
VPN state, a separately encrypted API/agent recovery set, and an encrypted
deployment-settings/secret capsule linked to those artifacts and image IDs.

The corrected procedure restored into fresh directories while the original
bind-mounted state was unavailable, recreated the Compose deployment and
owned firewall/route state, and reached four healthy services in 96.732 seconds.
SQLite logical contents matched; profile/archive and intent files matched
byte-for-byte. Acknowledged certificate revocation and operation history were
retained, and a nonempty owned route was observed. Three tampered or mismatched
recovery-set cases were rejected before extraction. An unchanged real VPN
client connected with its expected CCD address, passed gateway traffic and
appeared in the agent session inventory. The disposable route was subsequently
removed through the agent before native host verification.

The first restore attempt exposed an operator-script secret-file ownership
error. After correcting its owner/mode, the entire restore was repeated into
another fresh generation; the failed attempt and final evidence are retained
privately under `/var/lib/ovpncp-verification-20261006`. API SQLite mode was
also tightened to `0600` before capture, as required by the recovery-set tool.

The route canary exposed a product observation bug: iproute2 rendered protocol
186 as `bgp`, preventing reconciliation. Route observations now request numeric
values with `ip -N`; regression tests and the real acknowledged operation pass.
This test server uses a locally patched agent image; no image was published.

This verifies a coordinated same-host restore with cached pinned images. It
does not establish full VM rebuild, off-host key recovery, production RPO,
nonempty access-grant restoration, or real Entra browser authentication.
Phases 8–10 and the agreed GHCR release checks remain deferred.
