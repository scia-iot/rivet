# Container Architecture Upgrade Plan

Status: Phase M0 complete for the documented stopped-target profile; Phase 0 complete
Last updated: 2026-09-14

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
| 1 | Privileged-operation interfaces and agent contract | planned | Phase 0 |
| 2 | Agent client, fake agent, and legacy host adapter | planned | Phase 1 |
| 3 | Read-only VPN agent in shadow mode | planned | Phase 2 |
| 4 | All privileged mutations moved behind the agent | planned | Phase 3 |
| 5 | Reproducible OpenVPN, agent, API, and UI images | planned | Phase 4 |
| 6 | Compose reference and VPN integration | planned | Phase 5 |
| 7 | Target OpenVPN migration and recovery execution | planned | Phase 6 |
| 8 | Azure edge and network deployment plan | planned | Phase 7 |
| 9 | Production cutover and rollback drill | planned | Phase 8 |
| 10 | Optional high availability and scaling | deferred | stable Phase 9 |

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
production, business or operator approval is implied. Phase 1 remains planned;
image inspection and runtime proof remain required in Phases 5–6.

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

Rollback: select the host adapter.

### Phase 3: read-only agent and shadow comparison

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

Deliverables:

- Maintain first-party Dockerfiles for OpenVPN, the VPN agent, API, and
  Nginx/UI; do not depend on an unreviewed community VPN image.
- Pin base images and OpenVPN packages by immutable version or digest.
- Use multi-stage builds, non-root users where possible, read-only root
  filesystems, explicit health checks, and no build tools in runtime images.
- Produce an SBOM, vulnerability report, provenance, and signed image digest.
- Add image and Compose configuration checks to CI.

Exit criteria:

- Builds are reproducible from a clean checkout.
- Critical or high applicable vulnerabilities are resolved or explicitly
  accepted with expiry.
- Image inspection confirms the expected user, capabilities, mounts, ports,
  entry point, and no embedded credentials.

Rollback: retain the last verified image digests.

### Phase 6: Compose reference deployment

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
