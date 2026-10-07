# Native Linux installation from PyPI

This is the supported systemd layout for future native releases on a dedicated
Linux VPN host. Use one exact `ovpncp` release in two root-owned virtual
environments: `ovpncp[api]` for the unprivileged HTTP API and plain `ovpncp`
for the privileged VPN agent, OpenVPN event hook, migration CLI and scoped
firewall boot guard. The Python wheel does not contain the browser UI. Nginx
serves a separately built static UI and proxies `/api` to loopback FastAPI.

The release wheel and UI artifact must carry the same reviewed release tag.
The API/agent wire protocol is part of that one wheel version. Upgrade and
rollback both environments together; keep the previous wheels, UI release,
database backup, agent journal and ownership/projection state until verified.

## Platform and accounts

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
Plain `pip install ovpncp` intentionally supports the agent, while invoking
its `ovpncp` API command tells the operator to install `ovpncp[api]`.

```shell
OVPNCP_VERSION='REPLACE_WITH_PUBLISHED_VERSION'
sudo install -d -o root -g root -m 0755 /usr/local/lib/ovpncp
sudo sh -eu -c '
  umask 022
  python3.14 -m venv /usr/local/lib/ovpncp/api-venv
  python3.14 -m venv /usr/local/lib/ovpncp/agent-venv
  /usr/local/lib/ovpncp/api-venv/bin/python -m pip install "ovpncp[api]==$1"
  /usr/local/lib/ovpncp/agent-venv/bin/python -m pip install "ovpncp==$1"
' sh "$OVPNCP_VERSION"
sudo /usr/local/lib/ovpncp/api-venv/bin/python -m pip check
sudo /usr/local/lib/ovpncp/agent-venv/bin/python -m pip check
```

The release and both virtual environments remain root-owned and unwritable
by the API and agent. Use `umask 022` for this code installation so both
service users can traverse the wheel and dependency directories; an inherited
`umask 077` can leave the service unable to import the package. Private env
and state files below use explicit restrictive modes. Do not put the venvs
below `/opt/ovpncp` or
`/var/lib/ovpn-agent`, which are runtime state.

## Export and review deployment assets

The installed wheel carries the service units, tmpfiles rule, env examples,
OpenVPN example, Nginx template and validated public UI config renderer.
Export to a new private directory, inspect each file, then install the
reviewed copies. The exporter refuses existing files, symlinks and
untrusted writable destinations; it does not modify system services.

```shell
OVPNCP_TEMPLATES="$PWD/native-templates"
/usr/local/lib/ovpncp/agent-venv/bin/ovpncp-export-native \
  "$OVPNCP_TEMPLATES"
sudo install -d -o root -g root -m 0755 /etc/ovpncp
sudo install -m 0644 "$OVPNCP_TEMPLATES/ovpncp.conf" \
  /etc/tmpfiles.d/ovpncp.conf
sudo install -m 0644 "$OVPNCP_TEMPLATES"/*.service \
  /etc/systemd/system/
sudo install -o root -g root -m 0600 \
  "$OVPNCP_TEMPLATES/api.env.example" /etc/ovpncp/api.env
sudo install -o root -g ovpn-runtime -m 0640 \
  "$OVPNCP_TEMPLATES/agent.env.example" /etc/ovpncp/agent.env
sudoedit /etc/ovpncp/api.env
sudoedit /etc/ovpncp/agent.env
```

Replace every `REPLACE_WITH_*` value. `OVPNCP_AGENT_UID` is the numeric
`ovpn-agent` UID; `OVPNCP_API_UID` is the numeric `ovpn-api` UID;
`OVPNCP_OPENVPN_UID` is the numeric `ovpn-openvpn` UID;
`OVPNCP_MANAGEMENT_GID` is the numeric `ovpn-runtime` GID. The OpenVPN
management listener is created by the root-started process with that primary
GID, so `OVPNCP_MANAGEMENT_UID=0`. Set exact Entra tenant/API UUIDs and role
names. Missing authentication or an agent UID makes native API startup fail.
Systemd reads the root-only API env file before dropping to `ovpn-api`; the
agent's `ovpn-control` membership does not grant it access to API secrets.
Keep database/storage credentials only in this protected file or a reviewed
systemd credential source. Use `ovpncp[api,azure]` when Azure Blob Storage is
configured; the Entra token validator is always an API dependency.

## Provision isolated state

The API owns only `/opt/ovpncp`, which holds SQLite by default, credential
archives and the generated shared client profile. Keep the API data tree
mode 0750 and its `certs` directory mode 0700. Set
`SQLALCHEMY_DATABASE_URI` in `api.env` for another database and protect its
credential. The API service masks the agent PKI, journal, OpenVPN directory
and management/event sockets, and has no Linux capabilities.

```shell
sudo install -d -o ovpn-api -g ovpn-control -m 0750 /opt/ovpncp
sudo install -d -o ovpn-api -g ovpn-control -m 0700 /opt/ovpncp/certs
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
sudo systemd-tmpfiles --create /etc/tmpfiles.d/ovpncp.conf
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
  "$OVPNCP_TEMPLATES/server.conf.example" \
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
[VPN agent operation](vpn-agent.md) and [migration](openvpn-migration.md)
for the supported certificate and recovery contracts.
Replace the bind address, VPN pool and hook `REPLACE_WITH_AGENT_UID` with the
exact numeric identity. OpenVPN runs `ovpncp-vpn-event` from the absolute
agent virtual environment path; it needs no checkout or `PYTHONPATH`.
The agent keeps the projected CCD/CRL current after each enabled mutation.

## Safe startup and owned firewall

The packaged `ovpncp-forward-policy.service` runs as `ovpn-agent` with only
`CAP_NET_ADMIN`. OpenVPN **requires** this one-shot unit in its startup
transaction. It uses `iptables-nft-restore --noflush` to create only the
agent-owned `OVPNCP_FORWARD` chain, first-position `tun0` ingress/egress
anchors and terminal deny when the ownership manifest has no grants. It
never flushes foreign rules or changes the global FORWARD policy. Once
access grants exist, it verifies that the kernel rules exactly match the
manifest; if they were lost after reboot, OpenVPN stays stopped until a
reviewed recovery restores them. A foreign or partial owned chain also
stops startup. Preserve the exact journal/ownership state for recovery.

Set `OVPNCP_FIREWALL_DEVICE` to the same numbered TUN device in server
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
      /etc/sysctl.d/90-ovpncp.conf
sudo sysctl -p /etc/sysctl.d/90-ovpncp.conf
```

The host firewall still owns VPN UDP ingress, broader LAN forwarding and
other system rules. The scoped anchor and terminal deny persist as the
agent's reviewed ownership state; the guard recreates only the empty
baseline after a clean reboot, before OpenVPN accepts traffic. When grants
exist, restore the complete matching owned state through the reviewed
recovery procedure before restarting OpenVPN. Enable `ovpncp-openvpn.service`
instead of an unreviewed distro OpenVPN unit for the same configuration and
disable any duplicate listener. On a manual OpenVPN restart, stop it first,
then start the policy guard and OpenVPN together; verify the chain before
admitting clients. Automatic restart behavior depends on the host systemd
version, so monitor the guard and agent health after any restart.

```shell
sudo systemctl daemon-reload
sudo systemctl enable ovpncp-openvpn ovpncp-vpn-agent ovpncp
sudo systemctl start ovpncp-forward-policy ovpncp-openvpn
sudo systemctl start ovpncp-vpn-agent
sudo systemctl start ovpncp
sudo systemctl status ovpncp-forward-policy ovpncp-openvpn \
  ovpncp-vpn-agent ovpncp
sudo iptables-nft-save -t filter
```

The API's `After=`/`Wants=` ordering does not make VPN availability depend
on the API process. Stop or restart the API independently. The OpenVPN hook
records a producer gap if the agent is unavailable; reconcile events and
agent journal before enabling background consumers. Start with
`OVPNCP_AGENT_MUTATIONS=` empty, `OVPNCP_VPN_EVENTS=0` and
`OVPNCP_VPN_RECONCILE=0`. Enable `assignments`, `routes`, `access`, `pki`,
`events` and `management` individually after reviewing ownership, projection,
Easy-RSA, event socket, route protocol and rollback state. Allocate a unique
route protocol before enabling route writes. See [VPN agent operation](vpn-agent.md)
for each mutation family's exact readiness contract.

## Browser UI and HTTPS proxy

The UI is not served by the wheel or API. Build a versioned static release
from the matching source tag with Node 22.22.2+ or 24.15.0+, or deploy the
matching verified UI release artifact. Use the runtime-configured Vite mode:
it contains `/api` and no tenant-specific identifiers. Keep its files
root-owned and readable to Nginx at `/srv/ovpncp/frontend/current`.

```shell
cd frontend
npm ci
npm run build:runtime
sudo install -d -o root -g root -m 0755 \
  "/srv/ovpncp/frontend/releases/${OVPNCP_VERSION}"
sudo cp -a dist/. "/srv/ovpncp/frontend/releases/${OVPNCP_VERSION}/"
sudo chown -R root:root "/srv/ovpncp/frontend/releases/${OVPNCP_VERSION}"
sudo chmod -R u=rwX,go=rX \
  "/srv/ovpncp/frontend/releases/${OVPNCP_VERSION}"
sudo ln -sfn "/srv/ovpncp/frontend/releases/${OVPNCP_VERSION}" \
  /srv/ovpncp/frontend/current
```

Set the public `OVPNCP_UI_ENTRA_TENANT_ID`, `OVPNCP_UI_ENTRA_CLIENT_ID`
and `OVPNCP_UI_ENTRA_API_SCOPE` to the reviewed SPA values and render
`runtime-config.js` with the exported `web-config.sh`. This script validates
UUIDs and scope characters before printing JavaScript. Keep the generated
file outside the immutable UI release and serve it with `no-store`:

```shell
OVPNCP_UI_ENTRA_TENANT_ID='REPLACE_WITH_TENANT_UUID' \
OVPNCP_UI_ENTRA_CLIENT_ID='REPLACE_WITH_SPA_APP_UUID' \
OVPNCP_UI_ENTRA_API_SCOPE='api://REPLACE_WITH_API_APP_UUID/access_as_user' \
  "$OVPNCP_TEMPLATES/web-config.sh" \
  | sudo install -o root -g root -m 0644 /dev/stdin \
      /srv/ovpncp/frontend/runtime-config.js
export OVPNCP_FRONTEND_ROOT=/srv/ovpncp/frontend/current
envsubst '${OVPNCP_FRONTEND_ROOT}' \
  < "$OVPNCP_TEMPLATES/nginx.conf.template" \
  | sudo install -o root -g root -m 0644 /dev/stdin \
      /etc/nginx/conf.d/ovpncp.conf
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

The native layout was verified on an approved systemd test host using a private
copy of VPN state. OpenVPN, the agent, API and Nginx started with the expected
identities, capabilities and sockets. The API denied unauthenticated direct and
proxied requests, the UI served its no-store runtime settings, and a client was
issued, assigned, connected, unassigned and revoked through the typed agent
socket under the API OS identity. A fresh connection after revocation did not
establish a tunnel. Native state was removed, the previous Compose stack was
restored healthy, and its unchanged client reconnected and passed traffic.
Production deployments still need their own Entra token,
TLS gateway, firewall ingress, PKI and recovery verification under local
conditions.
