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
  --agent-image 'registry.example/ovpncp-agent@sha256:<64-hex-digest>' \
  --openvpn-image 'registry.example/ovpncp-openvpn@sha256:<64-hex-digest>' \
  --api-image 'registry.example/ovpncp-api@sha256:<64-hex-digest>'
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
direct gateway. An earlier rehearsal observed the actual echo reply plus a
host redirect; the redirect made the strict single-packet ping fail before
accepting its echo reply. The test continues to require a successful ping.
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

State is newly created under a private `ovpncp-p6-<run-id>-*` temporary directory.
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
