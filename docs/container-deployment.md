# Container deployment reference

This reference deploys four services on a dedicated Linux host. Select the
host, registry, immutable image digests, private state root, public VPN
endpoint and runtime credentials for each deployment. No named testing host
or private image registry is required by the repository.

The reference topology, migration and coordinated same-host Compose recovery
have passed verification. The recovery drill restored encrypted VPN, API,
agent and deployment state into fresh directories with original state
unavailable; four services became healthy in 96.7 seconds and unchanged-client
connectivity passed. See the [phase evidence](container-architecture-upgrade-plan.md)
for scope and limitations. VM-loss/off-host recovery, production RPO,
host/Docker restart, real browser sign-in and external UDP ingress require
verification in the selected deployment environment.

Build and publish current images using the [portable build guide](container-builds.md).
Earlier privately cached verification images are not deployable release
references. Refresh vulnerability scans and complete release review, signing
and provenance checks before the deferred GHCR release.

Own startup ordering in the deployment: establish and verify the scoped VPN
firewall baseline before OpenVPN accepts traffic. A previous test deployment
used a private systemd controller and disabled Docker automatic restarts;
that controller is not a repository-provided installation script. Review the
reference restart policies against your startup mechanism and verify reboot
and Docker-daemon restart behavior. Existing owned access rules without both
TUN selectors require explicit stopped-writer upgrade review as described in
[the agent guide](vpn-agent.md).

## Topology and prerequisites

`deploy/compose.build.yml` is independent of runtime state. The separate
`deploy/compose.yml` implements the reviewed dedicated-Linux-VM topology:
OpenVPN and the agent use host networking; API and Nginx share a bridge. Only
Nginx publishes an HTTP backend port, bound to loopback by default. OpenVPN
binds its configured UDP address directly. The API has no published port,
network capability, management socket, VPN mount or container-runtime socket.

Builds and registry selection are provider-independent; see
[portable builds](container-builds.md). Docker Engine with Compose is required
on the eventual Linux target. This reference is portable across compatible
Linux hosts, not across kernels or rootless/runtime security models. The
reference assumes rootful Docker without user-namespace remapping, AppArmor
with `docker-default`, the default seccomp policy, `/dev/net/tun`, and the
`iptables-nft` host backend. Check these against the target before starting.
Verify effective `NET_ADMIN` for the non-root agent and its child commands on
the actual engine; declaration in Compose alone is not runtime proof. Do not
work around a failed check with `privileged`, root API, or broader capabilities.

The private bridge uses `172.30.250.0/28`, Nginx `.2`, API `.3`. Review overlap
with host, VPN and client routes. If changed, update the bridge, both static
addresses and `OVPNCP_PROXY_IP` together. The API trusts forwarded headers only
from that Nginx address. The bridge permits outbound Entra/storage connections;
it is not an air-gapped network. A deployment-owned reverse proxy terminates
public TLS. Bind HTTP
to a reviewed private host address only after limiting ingress to the trusted
gateway subnet; never publish this backend directly to the Internet.

Every service has a read-only root, dropped default capabilities,
`no-new-privileges`, bounded tmpfs, process/memory/CPU limits and bounded logs.
OpenVPN receives only `NET_ADMIN`, `SETUID`, `SETGID` and `/dev/net/tun`; the
agent bootstrap receives the same three capabilities, then drops to UID/GID
65532 with only `NET_ADMIN` in its permitted, effective, inheritable and ambient
sets before loading application code. SETUID/SETGID remain only in the bounding
set; `no-new-privileges` prevents regaining them. API and web receive no
capabilities. OpenVPN
startup is independent of agent/API health, so a control-plane outage does not
restart the data plane. Health checks do not replace a real VPN canary.

## State and identity contract

These numeric IDs are local image contracts, never imported source IDs:

| Service | UID | Primary GID | Additional group |
| --- | --- | --- | --- |
| API | 65531 | 65531 (`ovpn-control`) | none |
| Agent | 0 initially; 65532 after bootstrap | 65532 (`ovpn-runtime`) | 65531 |
| OpenVPN | 0 initially; 65530 after drop | 65532 | none required |
| Nginx | 101 | 101 | none |

Use a new absolute directory on encrypted local storage, beneath a trusted
existing parent. `deploy/containers/prepare_state.py` is an operator tool for
that future target. It creates empty directories and empty status/pool files
with the reviewed permissions. It refuses existing roots, relative paths and
symlink traversal. It does not generate a CA, import a database, adopt existing
files, change network policy or start services. A failed partial initialization
must be inspected rather than retried over existing state.

For a new disposable target, an operator can run:

```bash
sudo python3 deploy/containers/prepare_state.py /srv/ovpncp
```

Do not run this command over a source installation or use it to prepare a
migration recovery set. A migration must preserve and map the complete
reviewed recovery set using the M0 workflow, with its own rollback evidence.
Compose uses explicit bind directories with `create_host_path: false`, so
missing state never becomes a silently created root-owned directory.

| State directory | Grants and purpose |
| --- | --- |
| `api-data`, `api-profile`, `api-archives` | API-owned 0700; database, shared profile and local certificate archives |
| `vpn-config`, `vpn-pki`, `vpn-ccd`, `vpn-journal` | Agent-only 0700; authoritative state, journal and revision identity |
| `vpn-projection` and `ccd/` | Agent-owned 0750, files 0640, runtime GID; OpenVPN mounts read-only |
| `vpn-pool` | OpenVPN-owned 02770; `ipp.txt` 0660; agent mounts read-only |
| `management-socket` | OpenVPN-owned 02770; `status.log` 0660; agent mounts read-only |
| `agent-socket` | Agent/control 02750; API mounts read-only; socket explicitly 0660 |
| `event-socket` | Agent/runtime 02770; agent and OpenVPN writable for the durable event-loss marker |

The runtime socket directories use separate private host directories. Clear
stale runtime sockets only while their owning services are stopped; preserve
any `producer-gap` until the event consumer has processed it. Never recursively
change permissions on an imported recovery set. Back up authoritative state,
API state and pool state consistently with writers frozen as specified in the
architecture plan; copying an active directory is not recovery evidence.

## Provisioning before remote verification

`deploy/containers/server.conf.example` is a review template, not a runnable
production default. Select the bind address, non-conflicting numbered TUN and
subnet, and transport parameters against the source inventory. Copy the
reviewed config into agent-private `vpn-config/server.conf` (0600) and runtime
`vpn-projection/server.conf` (0640), both owned by 65532:65532. Keep both copies
consistent; static config changes require deployment-owned restart.

Provision the complete CA state only in `vpn-pki`. Place only CA certificate,
server certificate/key, CRL and projected CCD in `vpn-projection`, using the
paths in the template. Never project the CA private key, client private keys,
CA database, serials or requests. Preserve source certificates/keys during
migration. The image contains Easy-RSA 3.1.7 but never auto-generates or replaces
PKI. Install the reviewed shared client profile in
`api-profile/client.ovpn`, API-owned 0600; see `deploy/client.ovpn.example`.
The example uses `ccd-exclusive`; review every admitted client and its CCD.

Before admitting traffic or enabling mutations, review host forwarding,
source route ownership and the empty deny-by-default `OVPNCP_FORWARD` baseline
as described in [the agent guide](vpn-agent.md#phase-4-mutation-configuration).
Review ICMP redirect emission for kernel-forwarded TUN peer traffic as part
of that gateway policy. Linux enables redirects when either `conf.all` or the
interface setting enables them. Set `net.ipv4.conf.all.send_redirects=0` and
`net.ipv4.conf.<tun-device>.send_redirects=0` in the reviewed host configuration;
review `conf.default.send_redirects=0` for newly created TUN interfaces.
The disposable rehearsal applies all/default settings only in its isolated
server namespace before creating TUN. See the
[Linux kernel documentation](https://docs.kernel.org/networking/ip-sysctl.html).
No startup script changes host forwarding/sysctls, installs NAT, or adopts
foreign rules. Allocate `OVPNCP_AGENT_ROUTE_PROTOCOL` explicitly after checking
existing route protocol use. Observation mode still requires a valid reviewed
baseline for agent readiness; a healthy process alone does not prove readiness.

Keep `OVPNCP_AGENT_MUTATIONS` empty initially. After disposable verification,
enable `assignments`, `routes`, `access`, `pki`, `events`, `management` one family
at a time with rollback evidence. Enable `OVPNCP_VPN_EVENTS=1` and
`OVPNCP_VPN_RECONCILE=1` only at the corresponding reviewed stage. Neither
background consumer nor the agent is allowed to become a second source of truth.

## Deployment handoff

Populate `deploy/container.env` with the four verified immutable image refs,
matching Entra settings, private state root and allocated route protocol.
The UI's runtime-only `OVPNCP_UI_ENTRA_TENANT_ID`,
`OVPNCP_UI_ENTRA_CLIENT_ID` (SPA registration), and `OVPNCP_UI_ENTRA_API_SCOPE`
are separate from the API's `AZURE_ENTRAID_*` settings. Nginx renders these
public values at startup; the browser loads `/runtime-config.js` before auth
initializes. The same web image can be promoted unchanged between environments.
Recreate the web container after changing its settings; no rebuild is needed. Never
put credentials in build arguments or commit this file. The reference uses
SQLite and local archives. Optional API credentials can be mounted as private
0400 files owned by UID 65531 beneath `/run/secrets` and selected through
`SQLALCHEMY_DATABASE_URI_FILE` or `AZURE_STORAGE_CONNECTION_STRING_FILE` in a
reviewed Compose override. Database drivers outside the reference SQLite
profile require a separately reviewed dependency lock/image build.

Validate the deployment configuration without starting services:

```bash
docker compose --env-file deploy/container.env -f deploy/compose.yml config --quiet
```

Before production startup, retain the exact rendered manifest, immutable image
digests, SBOM, vulnerability evidence and rollback set. Provenance/signing
handoff remains a deferred release item at the operator's request; this does
not prevent disposable functional verification. Image/UID/capability, actual
TUN/CCD, allow/deny, agent/API outage recovery and credential lifecycle/CRL
checks passed in the [disposable rehearsal](../tests/integration/README-container.md).
Signed-token authentication/RBAC through Nginx, Compose readiness and
API/web upgrade/rollback with surviving VPN traffic also passed on 2026-09-29.
That runner substitutes private network namespaces; the actual host/bridge
Compose topology subsequently passed its approved maintenance rehearsal. The
commands below remain a provisioning procedure for separately reviewed targets. Reboot/restore, migration and production cutover require their separately
reviewed later-phase rehearsals. See Phases 5–7 in the
[architecture plan](container-architecture-upgrade-plan.md).

## Clean-host startup and verification

Use a dedicated disposable Linux target first. Complete the prerequisites,
state provisioning, reviewed VPN configuration and host network policy above
before these commands. The empty-directory preparation tool is not a CA
provisioner or a migration importer. Do not run this startup sequence alongside
the source VPN on its live host; source migration belongs to Phase 7.
An explicitly approved maintenance rehearsal may reuse an existing host with
fresh deployment state: stop its source application and VPN, verify a private
source backup, then restore the original services after test cleanup. Such a
run verifies deployment on a provisioned Linux host, not OS installation.

From the repository root, with an authenticated Docker client and the reviewed
`deploy/container.env`, retain a new private release directory outside the build
context. Replace the example absolute path with an operator-owned location;
keep the directory and referenced secret files private.

```bash
umask 077
OVPNCP_RELEASE_DIR=/absolute/private/release-001
mkdir -m 700 "$OVPNCP_RELEASE_DIR"
docker compose --project-name ovpncp --env-file deploy/container.env \
  -f deploy/compose.yml config --quiet
docker compose --project-name ovpncp --env-file deploy/container.env \
  -f deploy/compose.yml config --format json \
  > "$OVPNCP_RELEASE_DIR/compose.json"
docker compose --project-name ovpncp \
  -f "$OVPNCP_RELEASE_DIR/compose.json" pull
docker compose --project-name ovpncp \
  -f "$OVPNCP_RELEASE_DIR/compose.json" create --no-build --pull never
```

Creation establishes the Docker bridge before services start. At this point,
finalize the reviewed host forwarding/firewall baseline described above.
Docker network creation can insert FORWARD rules: require the two exact
agent-owned TUN anchors to be the first two FORWARD entries, with the owned
terminal deny in place, before starting OpenVPN or enabling access mutations.
Do not flush or adopt an existing administrator-owned chain. Then start:

```bash
docker compose --project-name ovpncp \
  -f "$OVPNCP_RELEASE_DIR/compose.json" \
  up --pull never --wait --wait-timeout 240
docker compose --project-name ovpncp \
  -f "$OVPNCP_RELEASE_DIR/compose.json" \
  ps --all --format '{{.Service}}: {{.State}} / {{.Health}}'
```

The dependency chain is OpenVPN healthy, agent ready, API HTTP healthy, then
web. OpenVPN can run independently of the control panel. Health checks gate
startup, not continuous dependency recovery. No dependency restart propagation
is configured. See Docker's [startup-order documentation](https://docs.docker.com/compose/how-tos/startup-order/).

Require every service to become healthy, then verify the UI configuration,
an authenticated `/api/me` response and the role-appropriate server health
response through the private web endpoint. Use the normal Entra login/token
workflow; do not put tokens in shell history, command arguments or retained
reports. Check a real test client's UDP connection, its assigned tunnel address,
an allowed flow and a denied flow. Health checks alone do not prove these
behaviors. Record only redacted outcomes and selected image digests.

The [disposable integration runner](../tests/integration/README-container.md)
provides synthetic-client checks independently of live source state. Its
network substitutions and synthetic identity service must never become a
production Compose override.

## API and web upgrade or rollback

Prepare a second private release directory by repeating the configuration
rendering step with the candidate API/web image digests and runtime settings.
Retain the previous rendered bundle and keep the Compose project name, state
bind paths, API identity and upstream proxy contract stable. Compare the two
bundles privately: this procedure covers API/web changes only. Any database or
persistent-format change needs a compatible rollback plan before proceeding;
recreating an older image does not undo data changes.

Record the OpenVPN and agent container IDs/PIDs before the update. The following
commands select only the API and web services; they do not perform a full-stack
shutdown. Replace both example bundle paths with the retained private files.

```bash
OVPNCP_PREVIOUS_BUNDLE=/absolute/private/release-001/compose.json
OVPNCP_CANDIDATE_BUNDLE=/absolute/private/release-002/compose.json
docker compose --project-name ovpncp -f "$OVPNCP_CANDIDATE_BUNDLE" config --quiet
docker compose --project-name ovpncp -f "$OVPNCP_CANDIDATE_BUNDLE" pull api web
docker compose --project-name ovpncp -f "$OVPNCP_CANDIDATE_BUNDLE" \
  up --no-deps --force-recreate --pull never --wait --wait-timeout 240 api web
```

Repeat authenticated HTTP, UI configuration and real VPN traffic checks.
Confirm OpenVPN/agent IDs and PIDs stayed unchanged. If validation fails,
restore the previous API/web bundle with the same selected-service command:

```bash
docker compose --project-name ovpncp -f "$OVPNCP_PREVIOUS_BUNDLE" \
  up --no-deps --force-recreate --pull never --wait --wait-timeout 240 api web
```

Verify the restored image digests and repeat the same checks. Keep previous
images cached until the update is accepted. The `--no-deps` operation assumes
the VPN services already run and are healthy; it deliberately skips dependency
startup. See Docker's [`compose up` reference](https://docs.docker.com/reference/cli/docker/compose/up/).
A failed `--wait` does not automatically roll back changes.

OpenVPN or agent updates require a separate reviewed maintenance procedure;
they are not covered by API/web traffic-survival claims. Whole-stack teardown
stops VPN traffic. Do not use `compose down`, delete state directories, clear
journals or replace PKI as an API/web rollback procedure. Consistent source
capture, restoration and production cutover remain Phases 7–9.
