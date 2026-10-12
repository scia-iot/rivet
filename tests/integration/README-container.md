# Disposable container VPN rehearsal

`vpn_container_rehearsal.py` is an explicitly invoked integration tool, never
an ordinary pytest test. It uses a freshly generated synthetic CA and three real
OpenVPN UDP clients. Run it only after reviewing its code on a rootful Linux
Docker host with cached immutable images and no user-namespace remapping.

Required host tools: Python 3.12+, Docker, `nsenter`, `ip`, `sysctl`,
`iptables-nft`, `ping`, and `/dev/net/tun`. The application and dependencies
execute in the cached images; host Python uses only its standard library.
AppArmor `docker-default` and Docker's default seccomp policy remain enabled.
Keep these repository-relative files together when staging the runner:

- `tests/integration/vpn_container_rehearsal.py`
- `deploy/containers/prepare_state.py`
- `deploy/containers/server.conf.example`

Example invocation, replacing all placeholders with reviewed cached digests:

```bash
sudo -n timeout --signal=TERM --kill-after=120s 15m \
  python3 tests/integration/vpn_container_rehearsal.py \
  --agent-image 'registry.example/rivet-agent@sha256:<64-hex-digest>' \
  --openvpn-image 'registry.example/rivet-openvpn@sha256:<64-hex-digest>' \
  --api-image 'registry.example/rivet-api@sha256:<64-hex-digest>'
```

The runner explicitly selects the local rootful Docker socket and uses
`--pull=never`. It creates four `--network none` anchors, attests their network
namespace identities against host PID 1 and each other, then holds namespace
file descriptors open. All three veth pairs are created wholly inside the disposable
server namespace; their peer ends are moved to the pinned client namespaces.
Every address, route, forwarding, firewall and packet command enters one of
those namespaces with `nsenter`. There is no Docker bridge creation, host
network container, published port, host interface, or host firewall mutation.

The disposable server is explicitly configured as a VPN gateway: after enabling
forwarding and before creating the TUN, it sets namespace-local
`net.ipv4.conf.all.send_redirects=0` and
`net.ipv4.conf.default.send_redirects=0`. The future TUN inherits the latter.
Linux sends redirects when either the `all` or interface-specific setting is
true, so both effective settings must be disabled; see the
[Linux kernel IP sysctl documentation](https://kernel.org/doc/html/latest/networking/ip-sysctl.html).
This prevents a TUN-to-TUN flow from advertising the destination client as a
direct gateway. A host redirect can make the strict single-packet ping fail
before accepting its echo reply; the test requires a successful ping.
Production redirect policy is operator-owned: review and configure both the
`all` and actual TUN settings, including creation/restart defaults, on the
intended VPN gateway. This runner never changes those host settings, and the
agent does not provision gateway sysctls.

Agent and OpenVPN containers share the server anchor; three client containers
share the separate client anchors. Server and agent use their actual image
entrypoints, read-only roots and the deployment capability/UID contracts.
The API-image probe runs as UID/GID 65531 with no capabilities or TUN. It has a
read-only agent socket mount and a separate API-owned private credential-export
fixture, never agent PKI or runtime projection mounts. It checks its identity,
capabilities and protected-path isolation before every typed request. The
actual HTTP API also starts through its image entrypoint, with private tmpfs
state and synthetic public Entra settings in a separate `--network none`
namespace. Its unauthenticated health request must return 401/403. Nginx and
valid-token Entra authorization are outside this proof.

The proof checks real client connectivity to the server, exact live tunnel
addresses matching CCD, both live management sessions, denied peer traffic,
agent-managed allowed peer traffic, and denied traffic after removing access
while a broad established-flow accept exists behind the TUN anchors. It checks
immediate same-ID mutation replay and surviving tunnel traffic across agent
SIGKILL/restart. It stops both the real HTTP API and the typed probe, requires
VPN peer traffic to survive, then restarts them and repeats HTTP denial,
agent readiness and live traffic checks.

Through the nonroot agent, the probe issues a fresh identity, assigns CCD and
verifies a framed credential archive before exporting exactly its CA, leaf
certificate and key to the private API fixture. A third real client connects
and reconnects using this archive. Revocation must update the runtime CRL,
whose signature and revoked certificate serial are verified. After a typed
session disconnect and fresh client process, repeated reconnect attempts must
produce network traffic but no authenticated session or tunnel connectivity;
the original clients must still pass traffic. Revoked archive access is denied.
Deletion must remove the identity from typed discovery and its private key
from authoritative PKI. Same-ID replay is checked for these mutations.

It reports `full_phase6: false`: valid-token HTTP/RBAC, web edge, certificate
renewal, crash-during-mutation recovery, reboot, backup/restore, migration,
production host-network Compose and release evidence need separate verification.

State is newly created under a private `rivet-p6-<run-id>-*` temporary directory.
No source PKI, certificate store, database, host VPN configuration or production
socket is read or mounted. Raw daemon logs are disabled, subprocess diagnostics
are suppressed, and failures report only fixed stage/program/action, exit code
and source-frame locations. A failed peer-flow probe also reports before/after
TUN packet/error/drop counters, forwarding/reverse-path-filter flags, route-to-TUN
booleans and counters for the exact owned allow/deny rules. These observations
run only in pinned disposable namespaces; rule text, route addresses and
interface identities are excluded. Ping output is reduced to counts and fixed
diagnostic flags. A four-second AF_PACKET observer runs inside the pinned source
client namespace and reports only ICMP direction/type/code counts; packet
payloads and addresses are never written or returned. The observer needs the
invoking root process to have NET_RAW and is always killed/reaped if interrupted.
Output never includes private material or addresses.

On success or handled failure/signal, cleanup verifies each container's run
label and removes its immutable ID before deleting synthetic state. If cleanup
is uncertain, it retains state and emits the run ID with `cleanup: incomplete`.
Inspect exactly that run's labelled objects before manually cleaning up. A
SIGKILL of the orchestrator, Docker outage or host crash can leave resources;
the outer timeout first sends TERM and reserves time for cleanup. Independently
compare normalized host addresses/links/routes/policy rules/firewall and the
pre-existing OpenVPN service/process identity before and after remote execution.
Do not treat `full_phase6: false` or missing cleanup evidence as completion.

Safety regressions can run without Docker:

```bash
pytest -q tests/test_container_rehearsal.py
```

## Compose and signed-HTTP rehearsal

`compose_phase6_rehearsal.py` extends the disposable VPN proof with the
reviewed deployment Compose manifest, all four cached service images, the
Nginx edge, and real API authorization. Stage these additional files beside
the files listed above:

- `tests/integration/compose_phase6_rehearsal.py`
- `tests/integration/container_http_fixture.py`
- `deploy/compose.yml`

Invoke it from the staged repository root with the exact reviewed digests:

```bash
sudo -n timeout --signal=TERM --kill-after=120s 20m \
  python3 -m tests.integration.compose_phase6_rehearsal \
  --compose deploy/compose.yml \
  --agent-image 'registry.example/rivet-agent@sha256:<64-hex-digest>' \
  --openvpn-image 'registry.example/rivet-openvpn@sha256:<64-hex-digest>' \
  --api-image 'registry.example/rivet-api@sha256:<64-hex-digest>' \
  --web-image 'registry.example/rivet-web@sha256:<64-hex-digest>' \
  --upgrade-api-image 'registry.example/rivet-api@sha256:<64-hex-digest>'
```

The host also needs the Docker Compose plugin. The runner renders the source
manifest with synthetic values, checks its exact services, grants, bind paths,
readiness dependencies, images and network topology, then writes a private
Compose bundle. It replaces host and bridge attachments with run-owned,
attested `--network none` namespace anchors before starting any service.
The isolated HTTP namespace uses an anchor-local hosts file for `api` and
`login.microsoftonline.com`; it has no published port or host route. The
runner never applies the source Compose manifest to the host.
Disposable anchors and typed probes sleep without starting idle Python
interpreters. Helper containers disable inherited image health checks; the
four real Compose services keep their image health checks and startup order.
The runner inspects each cached image digest once before launch and compares
each service container's actual image ID with that recorded value afterward.

The HTTP fixture creates a disposable TLS CA and a separate JWT signing key.
Only the public CA is mounted into the API container. A loopback HTTPS server
serves synthetic Entra JWKS at the normal discovery URL, and the API verifies
signed tokens through its normal configuration. The probe requests Nginx
health and runtime configuration, sends requests through `/api`, checks
`sysadmin`, `device_user` and app-only `ServiceAdmin` permissions, and checks
anonymous, delegated service-admin, wrong-audience, expired, tampered and
unknown-role denial. For a tampered signature, the rehearsal accepts 401 or
500 with a problem-response content type. It does not retain the exact status;
it checks that neither the original nor tampered JWT appears in the response
body.

The run stops and restarts API and web, then recreates those two services from
an upgrade bundle and rolls back to the original bundle. It records immutable
container IDs and host PIDs for OpenVPN and agent, checks that both survive
each control-plane change, and proves real peer traffic at each stage. The
reported `phase6_compose_lifecycle: passed` refers to this isolated topology.
`production_network_topology: false` and `full_phase6: false` remain explicit:
the run does not validate production host networking, backup/restore,
migration, reboot, or all release gates. Use the same host-state comparison and
cleanup review described above before interpreting the result.

Local safety regressions for this extension are:

```bash
pytest -q tests/test_compose_phase6_rehearsal.py tests/test_container_compose.py
```

## Opt-in actual host and bridge topology

`compose_phase6_host_rehearsal.py` is a separate, root-only maintenance tool.
Stage it alongside both runners and the HTTP fixture above. A maintenance
wrapper must first stop the source application and OpenVPN services, make and
verify a private encrypted backup of their frozen state, and record the stopped
host's network and firewall baseline. The runner rechecks that both services
are inactive and requires an explicit `--ssh-peer` IPv4 address whose route
does not use a TUN or TAP. It never imports source state or starts those units.

Use the same `--compose` and four immutable image arguments as the isolated
runner, plus `--upgrade-api-image` and `--ssh-peer`. Invoke the module as
`python3 -m tests.integration.compose_phase6_host_rehearsal` only through a
reviewed maintenance wrapper with a bounded timeout. The wrapper must restore
source services only after the runner reports successful cleanup, a fresh
inventory finds no test containers, bridge or `OVPNCP_FORWARD` chain, and the
stopped-host baseline and source-state fingerprints match.

This variant preserves the rendered services' host networking for OpenVPN and
agent, the private Compose bridge for API and web, and the loopback web port.
It creates only fresh synthetic VPN state, a unique TUN, a token-scoped bridge
and container project, and a firewall chain that must be absent at preflight.
The synthetic OpenVPN server binds only the bridge gateway. Test clients and
the local HTTPS JWKS helper use attested bridge namespaces; a fixed unprivileged
HTTP probe reaches the web port through host loopback. The runner changes
`net.ipv4.conf.all.send_redirects` only while the source VPN is stopped and
restores its recorded value. It removes exact test-owned firewall rules and
the attested bridge, then requires the host firewall baseline to match before
reporting cleanup. An uncertain cleanup retains the synthetic state and run ID
for manual review.

This runner uses fresh deployment state on an existing host; it does not test
pristine OS provisioning. It checks actual host/bridge Compose startup, signed web/API
access, real UDP clients and access rules, and selected API/web upgrade and
rollback while checking VPN process and traffic survival. Migration, reboot,
restore and source-data cutover remain separate work.

Local ownership regressions are:

```bash
pytest -q tests/test_compose_phase6_host_rehearsal.py
```

## Opt-in encrypted OpenVPN migration rehearsal

`phase7_container_rehearsal.py` reuses the isolated Compose network
namespaces. It requires a separately prepared, authenticated OpenVPN-only
bundle, its private key and independently observed pinned-image capabilities.
It does not read the legacy application database or archive. A reviewed root
maintenance guard must verify an SSH route outside the VPN, preserve and
fingerprint the original OpenVPN-only state, stop source application and VPN
services for memory headroom, then restore and compare them after all
disposable containers and namespaces are removed.

Place `migration.bundle`, `migration.key` and `capabilities.json` as root-owned
mode-0600 regular files in a root-owned mode-0700 input directory. Stage the
reviewed migration package and migration helper beside this runner, with the
pinned `vpn_event.sh`. Use a separate root-owned mode-0700 parent for retained
evidence. Invoke `python3 -m tests.integration.phase7_container_rehearsal`
through the bounded guard with `--input-dir`, `--private-parent`, and immutable
`--openvpn-image`, `--agent-image`, and `--api-image` references. The runner
requires all three image references to equal the independently reviewed
`image_refs` entries in the capability record. Use immutable digest references
under your chosen registry or namespace; no image from an earlier testing
environment is required.

The runner imports and semantically verifies the M0 bundle into a private
Compose VPN mount generation. It connects one indexed valid client with
unchanged credentials and checks its CCD address, times a VPN restart and
reconnect, issues and revokes a new test client, freezes the target and exports
an encrypted M0 checkpoint, restores that checkpoint into a nonempty target,
reconnects the unchanged client, and verifies the acknowledged revocation.
It then rolls back to an exact previous VPN generation with the same revoked
state, compares full hashes, modes and owners, and proves a further new
client can be issued and revoked after rollback. `progress.json` and the final
redacted JSON identify the private evidence root. The maintenance guard owns
source service restoration and host invariance checks.

This rehearsal establishes only OpenVPN state and VPN reconnect behavior.
Full-VM restore, application/API data recovery, and coordinated agent
network-policy RPO need separate [recovery acceptance](../../docs/data-management.md#backup-and-recovery)
evidence.

## Native host and coordinated Compose verification

`native_host_rehearsal.py` is a separate, explicitly invoked Linux host test.
It stages installed-wheel systemd services, verifies process/socket/firewall
and HTTP boundaries, and provides typed canary mutations and marker-owned
cleanup. It changes host services and must only run on an authorized test
host after stopping conflicting deployments and reviewing its fixed paths.
It is not part of ordinary pytest execution. See the
[native deployment guide](../../docs/deployment.md#native-installation) for the supported
installation layout.

Coordinated Compose recovery is a separate operator procedure. Follow
[recovery](../../docs/data-management.md#backup-and-recovery) to capture matching encrypted VPN/API/agent
state, protect deployment settings, restore into fresh generations, and verify
the complete stack. The guide distinguishes prior same-host evidence from
remaining off-host and production acceptance checks.
