# Deployment

Set up Rivet locally, install native Linux services, or deploy the four-service
Compose stack. Production deployments use an unprivileged API and a separate
VPN agent; the local section also covers isolated UI development and tests.

Choose a setup below, then apply the production HTTPS and acceptance checks
before exposing a native or container installation. Authentication settings
are in [configuration](configuration.md); artifacts are in [builds](builds.md).

- [Local development](#local-development)
- [Native installation](#native-installation)
- [Container deployment](#container-deployment)
- [Production ingress and verification](#production-ingress-and-verification)

## Local development

Use CPython 3.14+, npm, and a Node version accepted by
[frontend/package.json](../frontend/package.json). Real OpenVPN/route/firewall
flows require a disposable Linux host with the reviewed permissions. Ordinary
unit tests and controlled browser E2E tests do not need a VPN or real Entra
tenant and do not change host policy.

### Prepare the checkout

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pip install -e .
cd frontend
npm ci --ignore-scripts --no-audit --no-fund --legacy-peer-deps=false
```

The development requirements include API/cloud test dependencies; the plain
published core package intentionally does not. Source, generated schemas,
deployment templates, and tests use `sciaiot.rivet` and `RIVET_*` names.

### Unit and browser tests

From the repository root:

```bash
ruff format --check .
ruff check .
mypy .
pytest --cov=src/sciaiot/rivet --cov-report=term-missing
```

From `frontend/`:

```bash
npm run api:check
npm run lint
npm run typecheck
npm run test
npm run test:production
npx playwright install chromium
CI=true npm run test:e2e
CI=true npm run test:container
```

The E2E runner owns a loopback-only controlled API and temporary test identity.
It never calls the live VPN implementation. Its auth seam is restricted to
Vite development in explicit `e2e` mode and is excluded from built artifacts.
`test:container` verifies that one static build accepts different public
runtime settings and rejects missing/invalid configuration; it needs Chromium,
not Docker. [Frontend development](../frontend/README.md) describes generation
and production-build checks.

### Interactive UI without a VPN

Copy `frontend/.env.example` to `frontend/.env.local`. For work on the
unauthenticated shell only, set `VITE_AUTH_DISABLED=true` and run
`npm run dev`. The persistent warning indicates this local UI mode. It does
not disable backend authentication or provide working management operations.
Use the controlled E2E suite for deterministic API/UI flows.

### Authenticated full stack

Provision the separate agent/OpenVPN stack on a disposable Linux host using
[native installation](#native-installation) or a reviewed container deployment.
Run the API as the unprivileged OS identity configured in `RIVET_API_UID` on
the agent. That account needs its API state/profile directory and access to
the protected agent socket; it must not own or mount VPN PKI state. Do not
change ownership of an existing deployment to make a checkout work.

Set the five required Entra backend values from
[configuration](configuration.md#entra-registrations-and-roles), using separate
API and SPA registrations. Supply the matching API-agent settings before
running the development API:

```bash
export RIVET_VPN_BACKEND=agent
export RIVET_AGENT_SOCKET=/run/ovpn-agent/agent.sock
export RIVET_AGENT_UID=REPLACE_WITH_AGENT_UID
export HOST=127.0.0.1
export PORT=8000
export RIVET_ROOT_PATH=""
rivet
```

Replace the UID and load reviewed Entra values before executing this example.
Use the checkout virtual environment from the configured API account.
`rivet` rejects root, missing authentication, or a host backend. It is not
a shortcut to launch a privileged all-in-one development server.

In `frontend/.env.local`, configure public browser values:

```dotenv
VITE_AUTH_DISABLED=false
VITE_ENTRA_TENANT_ID=<tenant-id>
VITE_ENTRA_CLIENT_ID=<spa-client-id>
VITE_ENTRA_API_SCOPE=api://<api-client-id>/access_as_user
VITE_API_BASE_URL=/api
```

Register `http://localhost:5173/` as an Entra SPA redirect URI and use that
origin consistently. Start `npm run dev` in another terminal. Vite proxies
`/api` to `127.0.0.1:8000` and removes the prefix; the local API root path stays
empty. `/docs` and `/openapi.json` are available directly from the local API.

First delegated sign-in creates a local User through `/me` when automatic
registration is enabled (the default). With it disabled, an administrator
must provision the verified issuer/subject mapping. App-only identities are
never auto-registered.

Initialize the shared profile through **Server** using the active agent's
configuration and an explicit reachable VPN endpoint. An HTTP development
address or tunnel address is not the public VPN endpoint. Profile generation
and limits are documented in [configuration](configuration.md#generate-the-shared-openvpn-client-profile).

### Compatibility development and troubleshooting

`host` and `shadow` remain lower-level source adapters for explicitly reviewed
legacy work. They can invoke privileged local helpers and use legacy hooks;
they are not accepted by the native `rivet` entry point. See
[backends](architecture.md#application-backends), and never run legacy and agent writers together.

- Authentication misconfiguration: check all five required settings and
  distinct role values before restarting; do not print their private values.
- `401`: check issuer, API audience, delegated scope, and expiry.
- `/me` `403`: check registration policy, local identity, and role assignment.
- Proxy failure: check the API listener and Vite's target.
- Agent unavailable: check trusted peer IDs, socket permissions, daemon
  readiness, and the owned network baseline before enabling writes.
- State permission failure: use the intended service account and isolated
  API directories; do not grant the API access to agent PKI.

## Native installation

This is the supported systemd layout for native releases on a dedicated
Linux VPN host. Use one exact `sciaiot-rivet` release in two root-owned virtual
environments: `sciaiot-rivet[api]` for the unprivileged HTTP API and `sciaiot-rivet-agent`
for the privileged VPN agent, OpenVPN event hook, migration CLI and scoped
firewall boot guard. The Python wheel does not contain the browser UI. Nginx
serves a separately built static UI and proxies `/api` to loopback FastAPI.

Build and publish the matching artifacts before installation; see
[builds](builds.md#native-python-and-ui-artifacts) and
[release readiness](builds.md#release-verification). The complete authentication and
shared-profile contract is in [configuration](configuration.md).

The release wheel and UI artifact must carry the same reviewed release tag.
The API/agent wire protocol is part of that one wheel version. Upgrade and
rollback both environments together; keep the previous wheels, UI release,
database backup, agent journal and ownership/projection state until verified.

### Platform and accounts

Use CPython 3.14+, OpenVPN 2.6, Easy-RSA 3.1.7, `iproute2`,
`iptables-nft`, Nginx, and systemd. The bounded native units assume the
executables `/usr/sbin/openvpn`, `/usr/sbin/iptables-nft-save`, and
`/usr/sbin/iptables-nft-restore`; inspect your packages before installation.
Use a complete CPython build: embedded Python runtimes shipped with other
tools may omit standard-library extensions needed by SQLite. Before creating
virtual environments, check the exact interpreter you will use:

```shell
python3.14 -c 'import sqlite3, ssl, venv'
```

Use a dedicated host network namespace. Review the chosen TUN device, VPN
subnet, interface forwarding policy and route protocol against local policy.

Create distinct system identities on a fresh host. If any name already
exists, inspect its UID, GID and memberships before proceeding; do not
reassign a live identity. Record the numeric results for the env files.

```shell
sudo groupadd --system ovpn-control
sudo groupadd --system ovpn-runtime
sudo useradd --system --no-create-home --shell /usr/sbin/nologin \
  --gid ovpn-control ovpn-api
sudo useradd --system --no-create-home --shell /usr/sbin/nologin \
  --gid ovpn-runtime --groups ovpn-control ovpn-agent
sudo useradd --system --no-create-home --shell /usr/sbin/nologin \
  --gid ovpn-runtime ovpn-openvpn
id ovpn-api
id ovpn-agent
id ovpn-openvpn
```

Install the exact release twice; an agent base install must not resolve
FastAPI, SQLModel, Uvicorn, `python-jose` or Azure libraries. Add
`[api,azure]`, `[api,mysql]` or `[api,postgres]` to the API environment when
those integrations are used. The old `security` extra remains an API alias.
`pip install sciaiot-rivet-agent` selects the matching core release without
API dependencies. Its `rivet` API command tells the operator to install
`sciaiot-rivet[api]`. Do not install the unrelated PyPI package `rivet`.

```shell
RIVET_VERSION='REPLACE_WITH_PUBLISHED_VERSION'
sudo install -d -o root -g root -m 0755 /usr/local/lib/rivet
sudo sh -eu -c '
  umask 022
  python3.14 -m venv /usr/local/lib/rivet/api-venv
  python3.14 -m venv /usr/local/lib/rivet/agent-venv
  /usr/local/lib/rivet/api-venv/bin/python -m pip install "sciaiot-rivet[api]==$1"
  /usr/local/lib/rivet/agent-venv/bin/python -m pip install "sciaiot-rivet-agent==$1"
' sh "$RIVET_VERSION"
sudo /usr/local/lib/rivet/api-venv/bin/python -m pip check
sudo /usr/local/lib/rivet/agent-venv/bin/python -m pip check
```

The release and both virtual environments remain root-owned and unwritable
by the API and agent. Use `umask 022` for this code installation so both
service users can traverse the wheel and dependency directories; an inherited
`umask 077` can leave the service unable to import the package. Private env
and state files below use explicit restrictive modes. Do not put the venvs
below `/opt/rivet` or
`/var/lib/ovpn-agent`, which are runtime state.

### Export and review deployment assets

The installed wheel carries the service units, tmpfiles rule, env examples,
OpenVPN example, Nginx template and validated public UI config renderer.
Export to a new private directory, inspect each file, then install the
reviewed copies. The exporter refuses existing files, symlinks and
untrusted writable destinations; it does not modify system services.

```shell
RIVET_TEMPLATES="$PWD/native-templates"
/usr/local/lib/rivet/agent-venv/bin/rivet-export-native \
  "$RIVET_TEMPLATES"
sudo install -d -o root -g root -m 0755 /etc/rivet
sudo install -m 0644 "$RIVET_TEMPLATES/rivet.conf" \
  /etc/tmpfiles.d/rivet.conf
sudo install -m 0644 "$RIVET_TEMPLATES"/*.service \
  /etc/systemd/system/
sudo install -o root -g root -m 0600 \
  "$RIVET_TEMPLATES/api.env.example" /etc/rivet/api.env
sudo install -o root -g ovpn-runtime -m 0640 \
  "$RIVET_TEMPLATES/agent.env.example" /etc/rivet/agent.env
sudoedit /etc/rivet/api.env
sudoedit /etc/rivet/agent.env
```

Replace every `REPLACE_WITH_*` value. `RIVET_AGENT_UID` is the numeric
`ovpn-agent` UID; `RIVET_API_UID` is the numeric `ovpn-api` UID;
`RIVET_OPENVPN_UID` is the numeric `ovpn-openvpn` UID;
`RIVET_MANAGEMENT_GID` is the numeric `ovpn-runtime` GID. The OpenVPN
management listener is created by the root-started process with that primary
GID, so `RIVET_MANAGEMENT_UID=0`. Set exact Entra tenant/API UUIDs and role
names. Missing authentication or an agent UID makes native API startup fail.
Systemd reads the root-only API env file before dropping to `ovpn-api`; the
agent's `ovpn-control` membership does not grant it access to API secrets.
Keep database/storage credentials only in this protected file or a reviewed
systemd credential source. Use `sciaiot-rivet[api,azure]` when Azure Blob Storage is
configured; the Entra token validator is always an API dependency.

### Provision isolated state

The API owns only `/opt/rivet`, which holds SQLite by default, credential
archives and the generated shared client profile. Keep the API data tree
mode 0750 and its `certs` directory mode 0700. Set
`SQLALCHEMY_DATABASE_URI` in `api.env` for another database and protect its
credential. The API service masks the agent PKI, journal, OpenVPN directory
and management/event sockets, and has no Linux capabilities.

```shell
sudo install -d -o ovpn-api -g ovpn-control -m 0750 /opt/rivet
sudo install -d -o ovpn-api -g ovpn-control -m 0700 /opt/rivet/certs
sudo install -d -o ovpn-agent -g ovpn-runtime -m 0750 \
  /var/lib/ovpn-agent
sudo install -d -o ovpn-agent -g ovpn-runtime -m 0700 \
  /var/lib/ovpn-agent/config /var/lib/ovpn-agent/pki \
  /var/lib/ovpn-agent/ccd /var/lib/ovpn-agent/journal
sudo install -d -o ovpn-agent -g ovpn-runtime -m 0750 \
  /var/lib/ovpn-agent/projection \
  /var/lib/ovpn-agent/projection/ccd
sudo install -d -o ovpn-openvpn -g ovpn-runtime -m 0770 \
  /var/lib/openvpn
sudo systemd-tmpfiles --create /etc/tmpfiles.d/rivet.conf
```

The `ovpn-openvpn` process can traverse only the projected runtime
tree. Keep the canonical CA key, Easy-RSA index/serial and client private
keys under agent-private PKI, and canonical CCD under agent-private CCD.
Provision the public CA certificate, server certificate/key, CRL, projected
CCD and `server.conf` under `projection/`; use group `ovpn-runtime` and mode
0640 for runtime files. The private server key is still outside API access.
The projected `server.conf` is the **single** configuration file read by
OpenVPN and observed by the agent. Preserve the agent-created
`projection/.ovpncp-journal-identity` along with its journal on upgrade and
restore; this projection is not wholly disposable. The container recovery-set
tool is specific to its own layout and is not a generic native restore tool.

Initialize the explicit ownership manifest before the firewall guard or
agent starts:

```shell
printf '%s\n' '{"version":"1.0","routes":[],"access":[],"pushes":[]}' \
  | sudo install -o ovpn-agent -g ovpn-runtime -m 0600 /dev/stdin \
      /var/lib/ovpn-agent/config/ownership.json
```

Install and edit the reviewed `server.conf.example` into the projection:

```shell
sudo install -o ovpn-agent -g ovpn-runtime -m 0640 \
  "$RIVET_TEMPLATES/server.conf.example" \
  /var/lib/ovpn-agent/projection/server.conf
sudoedit /var/lib/ovpn-agent/projection/server.conf
sudo chown ovpn-agent:ovpn-runtime \
  /var/lib/ovpn-agent/projection/server.conf
sudo chmod 0640 /var/lib/ovpn-agent/projection/server.conf
```

Provision the matching signed public CA/server certificate, private server
key and valid CRL under projection with `ovpn-agent:ovpn-runtime` ownership
and mode 0640; create the agent-private Easy-RSA CA/index/issued/private
state under `pki/` mode 0700, with private files 0600. The server will not
start until these reviewed artifacts exist. See
[VPN agent operation](vpn-control.md#agent-operation) and [migration](data-management.md#openvpn-migration)
for the supported certificate and recovery contracts.
Replace the bind address, VPN pool and hook `REPLACE_WITH_AGENT_UID` with the
exact numeric identity. OpenVPN runs `rivet-vpn-event` from the absolute
agent virtual environment path; it needs no checkout or `PYTHONPATH`.
The agent keeps the projected CCD/CRL current after each enabled mutation.

### Safe startup and owned firewall

The packaged `rivet-forward-policy.service` runs as `ovpn-agent` with only
`CAP_NET_ADMIN`. OpenVPN **requires** this one-shot unit in its startup
transaction. It uses `iptables-nft-restore --noflush` to create only the
agent-owned `OVPNCP_FORWARD` chain, first-position `tun0` ingress/egress
anchors and terminal deny when the ownership manifest has no grants. It
never flushes foreign rules or changes the global FORWARD policy. Once
access grants exist, it verifies that the kernel rules exactly match the
manifest; if they were lost after reboot, OpenVPN stays stopped until a
reviewed recovery restores them. A foreign or partial owned chain also
stops startup. Preserve the exact journal/ownership state for recovery.

Set `RIVET_FIREWALL_DEVICE` to the same numbered TUN device in server
configuration; the guard parses the actual server configuration and rejects
a mismatch. Review pre-existing FORWARD and NAT rules and ensure they do not
bypass the two first-position anchors. Enable IPv4 forwarding and disable
ICMP redirects persistently before starting the listener; the guard verifies
all three values:

```shell
printf '%s\n' 'net.ipv4.ip_forward = 1' \
  'net.ipv4.conf.all.send_redirects = 0' \
  'net.ipv4.conf.default.send_redirects = 0' \
  | sudo install -o root -g root -m 0644 /dev/stdin \
      /etc/sysctl.d/90-rivet.conf
sudo sysctl -p /etc/sysctl.d/90-rivet.conf
```

The host firewall still owns VPN UDP ingress, broader LAN forwarding and
other system rules. The scoped anchor and terminal deny persist as the
agent's reviewed ownership state; the guard recreates only the empty
baseline after a clean reboot, before OpenVPN accepts traffic. When grants
exist, restore the complete matching owned state through the reviewed
recovery procedure before restarting OpenVPN. Enable `rivet-openvpn.service`
instead of an unreviewed distro OpenVPN unit for the same configuration and
disable any duplicate listener. On a manual OpenVPN restart, stop it first,
then start the policy guard and OpenVPN together; verify the chain before
admitting clients. Automatic restart behavior depends on the host systemd
version, so monitor the guard and agent health after any restart.

```shell
sudo systemctl daemon-reload
sudo systemctl enable rivet-openvpn rivet-agent rivet
sudo systemctl start rivet-forward-policy rivet-openvpn
sudo systemctl start rivet-agent
sudo systemctl start rivet
sudo systemctl status rivet-forward-policy rivet-openvpn \
  rivet-agent rivet
sudo iptables-nft-save -t filter
```

The API's `After=`/`Wants=` ordering does not make VPN availability depend
on the API process. Stop or restart the API independently. The OpenVPN hook
records a producer gap if the agent is unavailable; reconcile events and
agent journal before enabling background consumers. Start with
`RIVET_AGENT_MUTATIONS=` empty, `RIVET_VPN_EVENTS=0` and
`RIVET_VPN_RECONCILE=0`. Enable `assignments`, `routes`, `access`, `pki`,
`events` and `management` individually after reviewing ownership, projection,
Easy-RSA, event socket, route protocol and rollback state. Allocate a unique
route protocol before enabling route writes. See [VPN agent operation](vpn-control.md#agent-operation)
for each mutation family's exact readiness contract.

### Browser UI and HTTPS proxy

The UI is not served by the wheel or API. Build a versioned static release
from the matching source tag with Node 22.22.2+ or 24.15.0+, or deploy the
matching verified UI release artifact. Use the runtime-configured Vite mode:
it contains `/api` and no tenant-specific identifiers. Keep its files
root-owned and readable to Nginx at `/srv/rivet/frontend/current`.

```shell
cd frontend
npm ci
npm run build:runtime
sudo install -d -o root -g root -m 0755 \
  "/srv/rivet/frontend/releases/${RIVET_VERSION}"
sudo cp -a dist/. "/srv/rivet/frontend/releases/${RIVET_VERSION}/"
sudo chown -R root:root "/srv/rivet/frontend/releases/${RIVET_VERSION}"
sudo chmod -R u=rwX,go=rX \
  "/srv/rivet/frontend/releases/${RIVET_VERSION}"
sudo ln -sfn "/srv/rivet/frontend/releases/${RIVET_VERSION}" \
  /srv/rivet/frontend/current
```

Set the public `RIVET_UI_ENTRA_TENANT_ID`, `RIVET_UI_ENTRA_CLIENT_ID`
and `RIVET_UI_ENTRA_API_SCOPE` to the reviewed SPA values and render
`runtime-config.js` with the exported `web-config.sh`. This script validates
UUIDs and scope characters before printing JavaScript. Keep the generated
file outside the immutable UI release and serve it with `no-store`:

```shell
RIVET_UI_ENTRA_TENANT_ID='REPLACE_WITH_TENANT_UUID' \
RIVET_UI_ENTRA_CLIENT_ID='REPLACE_WITH_SPA_APP_UUID' \
RIVET_UI_ENTRA_API_SCOPE='api://REPLACE_WITH_API_APP_UUID/access_as_user' \
  "$RIVET_TEMPLATES/web-config.sh" \
  | sudo install -o root -g root -m 0644 /dev/stdin \
      /srv/rivet/frontend/runtime-config.js
export RIVET_FRONTEND_ROOT=/srv/rivet/frontend/current
envsubst '${RIVET_FRONTEND_ROOT}' \
  < "$RIVET_TEMPLATES/nginx.conf.template" \
  | sudo install -o root -g root -m 0644 /dev/stdin \
      /etc/nginx/conf.d/rivet.conf
sudo nginx -t
sudo systemctl reload-or-restart nginx
```

TLS terminates at the trusted HTTPS gateway in the supplied Nginx topology;
allow backend port 80 only from that gateway and keep port 8000 loopback.
The Nginx template strips `/api` once, sends only the trusted forwarding
headers, disables API buffering and avoids sensitive access logs. Adapt the
upstream TLS boundary when deploying without that gateway; do not expose
plain HTTP publicly.

Verify the UI shell, `/runtime-config.js` no-store response, `/api/me`
unauthenticated RFC 7807 response, an authenticated user flow, agent socket
permissions, management peer UID/GID, firewall anchors and journal readiness
before admitting VPN clients. On rollback, stop the API and OpenVPN,
restore the matching pair of virtual environments, static UI release,
database and agent-owned state, then restart in the same guard → OpenVPN →
agent → API order. The firewall guard deliberately leaves foreign policy
untouched and refuses missing previously granted rules.

Use the explicitly invoked [native host rehearsal](../tests/integration/README-container.md#native-host-and-coordinated-compose-verification)
to verify installed-wheel identities, socket permissions, HTTP denial, and a
client's issuance, assignment, connection and revocation on an authorized test
host. Each deployment also requires its own Entra login, TLS gateway, firewall
ingress, PKI and [recovery verification](data-management.md#backup-and-recovery) under local conditions.

## Container deployment

This reference deploys four services on a dedicated Linux host. Select the
host, registry, immutable image digests, private state root, public VPN
endpoint and runtime credentials for each deployment. No named testing host
or private image registry is required by the repository.

Build all four images using the [build guide](builds.md#build-and-publish-artifacts), complete
the [release checks](builds.md#release-verification), and select exact digests.
For an existing installation, follow [migration](data-management.md#openvpn-migration) or
the [archived ovpncp upgrade procedure](archive/rivet-rename.md) before using these startup instructions.

Own service startup ordering: establish the scoped VPN firewall baseline
before OpenVPN accepts traffic. The repository supplies no container startup
controller that proves this ordering across host/Docker restarts. Review the
Compose restart policies against your mechanism and verify both restart cases.
Existing owned access rules without both TUN selectors require stopped-writer
review as described in [agent operation](vpn-control.md#agent-operation).

### Topology and prerequisites

`deploy/compose.build.yml` is independent of runtime state. The separate
`deploy/compose.yml` implements the reviewed dedicated-Linux-VM topology:
OpenVPN and the agent use host networking; API and Nginx share a bridge. Only
Nginx publishes an HTTP backend port, bound to loopback by default. OpenVPN
binds its configured UDP address directly. The API has no published port,
network capability, management socket, VPN mount or container-runtime socket.

Builds and registry selection are provider-independent; see
[portable builds](builds.md#build-and-publish-artifacts). Docker Engine with Compose is required
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
addresses and `RIVET_PROXY_IP` together. The API trusts forwarded headers only
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

### State and identity contract

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
sudo python3 deploy/containers/prepare_state.py /srv/rivet
```

Do not run this command over a source installation or use it to prepare a
migration recovery set. A migration must preserve and map the complete
reviewed recovery set using the OpenVPN migration workflow, with its own rollback evidence.
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
[recovery guide](data-management.md#backup-and-recovery); copying an active directory is not recovery evidence.

### Provision VPN state and host policy

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
as described in [the agent guide](vpn-control.md#mutation-configuration).
Review ICMP redirect emission for kernel-forwarded TUN peer traffic as part
of that gateway policy. Linux enables redirects when either `conf.all` or the
interface setting enables them. Set `net.ipv4.conf.all.send_redirects=0` and
`net.ipv4.conf.<tun-device>.send_redirects=0` in the reviewed host configuration;
review `conf.default.send_redirects=0` for newly created TUN interfaces.
The disposable rehearsal applies all/default settings only in its isolated
server namespace before creating TUN. See the
[Linux kernel documentation](https://docs.kernel.org/networking/ip-sysctl.html).
No startup script changes host forwarding/sysctls, installs NAT, or adopts
foreign rules. Allocate `RIVET_AGENT_ROUTE_PROTOCOL` explicitly after checking
existing route protocol use. Observation mode still requires a valid reviewed
baseline for agent readiness; a healthy process alone does not prove readiness.

Keep `RIVET_AGENT_MUTATIONS` empty initially. After disposable verification,
enable `assignments`, `routes`, `access`, `pki`, `events`, `management` one family
at a time with rollback evidence. Enable `RIVET_VPN_EVENTS=1` and
`RIVET_VPN_RECONCILE=1` only at the corresponding reviewed stage. Neither
background consumer nor the agent is allowed to become a second source of truth.

### Configure the deployment

Populate `deploy/container.env` with the four verified immutable image refs,
matching Entra settings, private state root and allocated route protocol.
The UI's runtime-only `RIVET_UI_ENTRA_TENANT_ID`,
`RIVET_UI_ENTRA_CLIENT_ID` (SPA registration), and `RIVET_UI_ENTRA_API_SCOPE`
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

Before startup, retain the exact rendered manifest, immutable image digests,
SBOM, release evidence, and rollback set. Verify the actual engine's grants,
TUN/CCD behavior, allowed/denied traffic, control-plane outages, and credential
lifecycle. The [integration harnesses](../tests/integration/README-container.md)
separate isolated tests from actual host/bridge maintenance tests. Neither
synthetic identity tests nor historical results replace deployment acceptance.

### Clean-host startup and verification

Use a dedicated disposable Linux target first. Complete the prerequisites,
state provisioning, reviewed VPN configuration and host network policy above
before these commands. The empty-directory preparation tool is not a CA
provisioner or a migration importer. Do not run this startup sequence alongside
the source VPN on its live host; use the stopped [migration procedure](data-management.md#openvpn-migration) instead.
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
RIVET_RELEASE_DIR=/absolute/private/release-001
mkdir -m 700 "$RIVET_RELEASE_DIR"
docker compose --project-name rivet --env-file deploy/container.env \
  -f deploy/compose.yml config --quiet
docker compose --project-name rivet --env-file deploy/container.env \
  -f deploy/compose.yml config --format json \
  > "$RIVET_RELEASE_DIR/compose.json"
docker compose --project-name rivet \
  -f "$RIVET_RELEASE_DIR/compose.json" pull
docker compose --project-name rivet \
  -f "$RIVET_RELEASE_DIR/compose.json" create --no-build --pull never
```

Creation establishes the Docker bridge before services start. At this point,
finalize the reviewed host forwarding/firewall baseline described above.
Docker network creation can insert FORWARD rules: require the two exact
agent-owned TUN anchors to be the first two FORWARD entries, with the owned
terminal deny in place, before starting OpenVPN or enabling access mutations.
Do not flush or adopt an existing administrator-owned chain. Then start:

```bash
docker compose --project-name rivet \
  -f "$RIVET_RELEASE_DIR/compose.json" \
  up --pull never --wait --wait-timeout 240
docker compose --project-name rivet \
  -f "$RIVET_RELEASE_DIR/compose.json" \
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

### API and web upgrade or rollback

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
RIVET_PREVIOUS_BUNDLE=/absolute/private/release-001/compose.json
RIVET_CANDIDATE_BUNDLE=/absolute/private/release-002/compose.json
docker compose --project-name rivet -f "$RIVET_CANDIDATE_BUNDLE" config --quiet
docker compose --project-name rivet -f "$RIVET_CANDIDATE_BUNDLE" pull api web
docker compose --project-name rivet -f "$RIVET_CANDIDATE_BUNDLE" \
  up --no-deps --force-recreate --pull never --wait --wait-timeout 240 api web
```

Repeat authenticated HTTP, UI configuration and real VPN traffic checks.
Confirm OpenVPN/agent IDs and PIDs stayed unchanged. If validation fails,
restore the previous API/web bundle with the same selected-service command:

```bash
docker compose --project-name rivet -f "$RIVET_PREVIOUS_BUNDLE" \
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
capture and restoration follow [the recovery procedure](data-management.md#backup-and-recovery); production
cutover requires acceptance in the actual environment.

## Production ingress and verification

Apply these requirements to both native and container installations. Keep
API listeners private, expose the UI through a trusted HTTPS gateway, and
verify the actual environment before admitting users or VPN clients.
Artifact selection and security evidence are covered by
[release verification](builds.md#release-verification).

### HTTPS and API boundary

Expose one HTTPS browser origin. A deployment-owned gateway terminates TLS
and forwards only trusted traffic to Nginx. Nginx serves static assets and
strips `/api` once before forwarding to FastAPI. This keeps SPA routes such
as `/devices` separate from API routes with the same names.

The supplied Nginx templates assume HTTPS has already been enforced upstream;
they send `X-Forwarded-Proto: https` and do not install TLS certificates.
Direct public HTTP is not a supported use of these templates. Keep the backend
listener on loopback or a private interface restricted to the trusted gateway.
Do not expose port 8000 to remote callers.

Native Nginx proxies to `127.0.0.1:8000`; the API trusts only loopback forwarded
headers and uses `RIVET_ROOT_PATH=/api`. Compose Nginx proxies to `api:8000`;
the API trusts only `RIVET_PROXY_IP`, which must match Nginx's static bridge
address. When changing bridge addresses, update Compose and that setting
together. Never trust arbitrary forwarded headers.

Nginx provides SPA fallback outside `/api`, no-store HTML/runtime config/API
responses, immutable caching for fingerprinted assets, browser security
headers, and disabled proxy buffering for credential downloads. Its access
logs and Uvicorn request access logs are disabled to avoid recording sensitive
paths and query strings. Application diagnostics must remain redacted.

### Optional Azure Application Gateway example

TLS terminates at Azure Application Gateway in this example. Other deployment
gateways can enforce the same trust boundary; Azure is not a build or hosting
requirement. For the native Nginx template:

- Backend protocol: `HTTP`
- Backend port: `80`
- Preserve the hostname selected by the public HTTPS listener.
- Probe `/` and require HTTP 200; separately verify authenticated API and VPN.
- Redirect public HTTP to HTTPS.
- Permit backend HTTP only from the Application Gateway subnet.

For Compose, use the reviewed `RIVET_HTTP_PORT` instead (default 8080), and
change `RIVET_HTTP_BIND` from loopback only after reviewing private ingress.
The gateway does not carry VPN UDP traffic. Configure VPN ingress, forwarding,
routes, and optional NAT separately for the actual host/cloud network.

### Deploy and verify

1. Select exact Python versions or image digests from one reviewed release.
   Prepare accounts, protected state, agent peers, and host policy using the
   chosen installation guide. Do not run host and agent writers concurrently.
2. Register the exact HTTPS origin plus `/` as the Entra SPA redirect URI.
   Render the public runtime configuration and serve immutable UI assets
   outside API-writable state. Native paths and permissions are in
   [the native UI procedure](#browser-ui-and-https-proxy).
3. Establish the reviewed owned firewall baseline before OpenVPN starts.
   Account for Docker's network-rule changes and test host/Docker restart
   ordering. Health checks do not install forwarding policy.
4. Check all service health, real Entra sign-in and `/api/me`, role-based
   denial, unchanged-client UDP connectivity, assigned address, allowed and
   denied flows, certificate revocation, and control-plane outage behavior.
5. From `frontend/`, run `npm run smoke:production` with `RIVET_BASE_URL` set
   to the public HTTPS origin. It checks static/proxy/unauthenticated boundaries;
   it does not prove real login or VPN reachability.
6. Complete a [coordinated recovery drill](data-management.md#backup-and-recovery) and retain the exact
   deployment settings, artifacts, and rollback generation privately.

### Upgrade and rollback

Retain the prior artifact set and complete compatible state. API/web-only
Compose updates can leave OpenVPN and the agent running; use the selective
commands in [container deployment](#api-and-web-upgrade-or-rollback).
Native updates replace the corresponding immutable environments/UI release
and restart only the intended services after checking compatibility.

Agent/OpenVPN changes need a separate maintenance procedure. Reverting a
binary does not undo database or PKI changes. Never restore old validity for
a revoked certificate or discard operation fences to make rollback succeed.
The [archived rename guide](archive/rivet-rename.md) covers the explicit ovpncp-to-Rivet change;
it is not an ordinary rolling update.
