# OpenVPN Control Panel for Restricted Network

[![Tests](https://github.com/scia-iot/ovpncp/actions/workflows/tests.yml/badge.svg)](https://github.com/scia-iot/ovpncp/actions/workflows/tests.yml)
[![CodeQL Advanced](https://github.com/scia-iot/ovpncp/actions/workflows/codeql.yml/badge.svg)](https://github.com/scia-iot/ovpncp/actions/workflows/codeql.yml)
[![Package](https://github.com/scia-iot/ovpncp/actions/workflows/package.yml/badge.svg)](https://github.com/scia-iot/ovpncp/actions/workflows/package.yml)

## Development

Contributor and coding-agent guidance is maintained in
[`AGENTS.md`](AGENTS.md). It is self-contained and includes the project
architecture, security constraints, code conventions, and required quality
checks.

Install the development dependencies and run the standard checks:

```shell
python -m pip install -r requirements-dev.txt
ruff format --check .
ruff check .
mypy .
pytest --cov=src/sciaiot/ovpncp --cov-report=term-missing
```

## Local full-stack development

Run FastAPI and the Vite frontend in separate terminals by following the
[local full-stack development guide](docs/local-development.md). The guide
covers runtime-directory setup, matching backend and frontend Entra settings,
the local `/api` proxy, identity prerequisites, and the UI-only and Playwright
alternatives.

## Frontend

The complete React, TypeScript, Vite, Tailwind CSS, shadcn/ui, and MSAL
application lives in [`frontend/`](frontend/README.md). It includes admin and
device-user workflows, fine-grained authorization presentation, and
Playwright coverage. The phased implementation source of truth is
[`docs/frontend-implementation-plan.md`](docs/frontend-implementation-plan.md).
Use the [production deployment runbook](docs/production-deployment.md) for the
reviewed Nginx, systemd, security-header, build, smoke, and rollback workflow.

```shell
cd frontend
npm ci
cp .env.example .env.local
npm run dev
```

## Installation

Python 3.14 or newer is required. The service needs root privileges because it
manages OpenVPN, firewall rules, routes, and protected certificate files.

The current application imports the Entra token validator during startup, so
install the `security` extra even when SQLite and local certificate storage are
used:

```shell
sudo pipx install "ovpncp[security]"
```

Use the `azure` extra when Azure Blob Storage is configured. It includes the
`security` dependencies:

```shell
sudo pipx install "ovpncp[azure]"
```

Add `mysql` or `postgres` to the selected extras when using either database,
for example `ovpncp[azure,postgres]`.

Wheels contain dependency metadata, not copies of third-party packages. A
local wheel installation must therefore select the same extras explicitly and
allow pipx to resolve them:

```shell
sudo pipx install \
  "ovpncp[azure] @ file:///absolute/path/to/ovpncp-0.1.7-py3-none-any.whl"
```

To replace an existing pipx installation, stop the service, run
`sudo pipx uninstall ovpncp`, install the new package with the appropriate
extras, and start the service again. Verify the installed version and service
health before removing the wheel used for deployment.

## OpenVPN Server Setup

Make sure the `client-to-client` directive is disabled:

```shell
;client-to-client
```

Enable CCD & make it exclusive:

```shell
client-config-dir /etc/openvpn/ccd
ccd_exclusive
```

Enable the scripts of client connection:

```shell
client-connect /opt/ovpncp/scripts/client-connect.sh
client-disconnect /opt/ovpncp/scripts/client-disconnect.sh
```

Start the application:

```shell
sudo -i ovpncp
```

Restart the server:

```shell
sudo systemctl restart openvpn
```

## Running as a systemd Service (Recommended)

Production terminates public TLS and hostname matching at Azure Application
Gateway, which forwards private HTTP to Nginx. Nginx serves the UI and proxies
`/api` to FastAPI on loopback. The reviewed
[`deploy/systemd/ovpncp.service`](deploy/systemd/ovpncp.service) publishes that
external API root and restricts filesystem writes while retaining required
host privileges.

```shell
sudo install -m 0644 deploy/systemd/ovpncp.service \
  /etc/systemd/system/ovpncp.service
sudo systemctl daemon-reload
sudo systemctl enable ovpncp
sudo systemctl restart ovpncp
```

Complete the remaining production steps in the
[production deployment runbook](docs/production-deployment.md).

## API - Basic Usage

Init server by calling API with cURL:

```shell
curl -X POST http://127.0.0.1:8000/server \
  -H 'Content-Type: application/json' \
  --data '{"remote_host":"vpn.example.com"}'
```

Check the health of OpenVPN server:

```shell
curl -X GET http://127.0.0.1:8000/server/health
```

### Client Setup

Create a client:

```shell
curl -X POST http://127.0.0.1:8000/clients \ 
    --data-binary @- << EOF
    {
        "name": "client_1"
    }
    EOF
```

Import every valid existing client from Easy-RSA. With no request body, the
operation imports VPN Clients only:

```shell
curl -X POST http://127.0.0.1:8000/clients/import
```

To also create matching edge Devices, make the option explicit:

```shell
curl -X POST http://127.0.0.1:8000/clients/import \
    -H "Content-Type: application/json" \
    --data '{"create_devices": true}'
```

The response reports Clients added, updated, and skipped. It also reports
Devices created, already linked, and in conflict. A Device is already linked
only when its name matches the Client and it already links to that Client. A
same-name unlinked Device, a same-name Device linked elsewhere, or a
differently named Device already linked to the Client is a conflict; imports
never reassign those relationships.

Create a gateway client with the private network behind it:

```shell
curl -X POST http://127.0.0.1:8000/clients \ 
    --data-binary @- << EOF 
    {
        "name": "gateway_1", 
        "cidr": "192.168.1.0/24"
    }
    EOF
```

Package the client certificate:

```shell
curl -X PUT http://127.0.0.1:8000/clients/client_1/package-cert
```

Download the archive:

```shell
curl -X GET http://127.0.0.1:8000/clients/client_1/download-cert
```

Assign IP to the client:

```shell
curl -X PUT http://127.0.0.1:8000/clients/client_1/assign-ip \ 
    --data-binary @- << EOF  
    {
        "ip": "10.8.0.2"
    }
    EOF
```

Only active clients can receive a virtual address. The API returns an
actionable `409 Conflict` for revoked clients; an address already held by a
revoked client can still be unassigned and returned to the pool.

Unassign IP from the client:

```shell
curl -X DELETE http://127.0.0.1:8000/clients/client_1/unassign-ip
```

Delete a client only after revoking its certificate:

```shell
curl -X PUT http://127.0.0.1:8000/clients/client_1/revoke
curl -X DELETE http://127.0.0.1:8000/clients/client_1
```

Deletion requires `clients:write` and returns `409 Conflict` with an actionable
RFC 7807 response while the client is active. A successful deletion releases
the virtual address; removes ownership links, connection and certificate
records, the client configuration, local package, and Easy-RSA client files;
and detaches linked edge Devices without deleting them or their AccessGrant
records. The CA index and CRL remain intact, and bulk import skips names marked
revoked in the CA index so the deleted credential cannot reappear.

When Azure Blob Storage is enabled, the archive blob is deleted best-effort
after the local and database deletion commits. A cloud deletion failure does
not misreport the completed client deletion; operators receive a redacted log
message to remove the orphaned archive blob manually.

### Restricted Network Setup

IMPORTANT:
make sure drop all forwarding on `tun0` by default:

```shell
sudo iptables -A FORWARD -i tun0 -j DROP
```

Create a restricted network between two clients:

```shell
curl -X POST http://127.0.0.1:8000/networks \ 
    --data-binary @- << EOF 
    {
        "source_name": "client_1", 
        "destination_name": "edge_device_1",
    }
    EOF
```

Create a restricted network between a client and a gateway:

```shell
curl -X POST http://127.0.0.1:8000/networks \ 
    --data-binary @- << EOF 
    {
        "source_name": "client_1", 
        "destination_name": "edge_gateway_1", 
        "private_network_addresses": "192.168.1.1,192.168.1.2,192.168.1.3"
    }
    EOF
```

Add an IP route for allowing traffic on the OpenVPN server:

```shell
curl -X POST http://127.0.0.1:8000/server/routes \
    --data-binary @- << EOF 
    {
        "network": 192.168.1.0/24"
    }
    EOF
```

Drop the network:

```shell
curl -X DELETE http://127.0.0.1:8000/networks/1
```

### Device and User Access

A device is a stable business identity. Its optional `client_id` points to the
current OpenVPN client, which can be replaced or removed without replacing the
device. A user is mapped to an OAuth identity by the unique combination of
`issuer` and `subject`.

Register a device and a user:

```shell
curl -X POST http://127.0.0.1:8000/devices \
    -H "Content-Type: application/json" \
    -d '{"name": "edge-device-1", "client_id": 1}'

curl -X POST http://127.0.0.1:8000/users \
    -H "Content-Type: application/json" \
    -d '{
        "display_name": "Edge Operator",
        "issuer": "https://login.microsoftonline.com/<tenant-id>/v2.0",
        "subject": "<oauth-subject>"
    }'
```

Administratively assign a laptop's VPN client to the user:

```shell
curl -X PUT http://127.0.0.1:8000/users/1/clients/2
curl http://127.0.0.1:8000/users/1/clients
curl -X DELETE http://127.0.0.1:8000/users/1/clients/2
```

A user may own multiple VPN clients, but each client can belong to only one
user. FastAPI enforces explicit `users:read` and `users:write` permissions
on these management endpoints. Frontend presentation does not grant API access.

Grant, list, and revoke individual device access:

```shell
curl -X PUT http://127.0.0.1:8000/users/1/devices/1
curl http://127.0.0.1:8000/users/1/devices
curl -X DELETE http://127.0.0.1:8000/users/1/devices/1
```

The client assignment and grant record application-level authorization. Existing OpenVPN client,
restricted-network, certificate, and firewall operations remain unchanged.
The API also provides `GET`, `PATCH`, and `DELETE` operations under `/devices`
and `/users`. Deleting a device does not delete or revoke its OpenVPN client.

### Configure Required Authentication with Microsoft Entra ID

Register the API in Microsoft Entra ID and set these five required backend
environment variables before starting ovpncp:

1. `AZURE_ENTRAID_TENANT_ID` - the tenant ID containing the API registration.

2. `AZURE_ENTRAID_APP_CLIENT_ID` - the Application (client) ID of the API
   registration.

3. `AZURE_ENTRAID_USER_ROLE` - the delegated user app-role value
   (`device_user`).

4. `AZURE_ENTRAID_ADMIN_ROLE` - the delegated administrator app-role value
   (`sysadmin`).

5. `AZURE_ENTRAID_SERVICE_ADMIN_ROLE` - the app-only service app-role value
   (`ServiceAdmin`).

Set `AZURE_ENTRAID_AUTO_REGISTER_USERS=true` to control automatic local User
registration. It defaults to enabled. Only exact `true` or `false` values,
matched case-insensitively without surrounding whitespace, are accepted.
Invalid values make `GET /me` fail closed, including for an existing user.
Set it to `false` to require administrative User creation and retain the fixed
`403` response for an unknown identity.

All five required values must be non-empty, and the three role values must be
distinct. Missing, partial, or duplicate configuration fails closed.
Authentication validates the token signature, audience, issuer, and stable
identity before authorization.

Delegated `device_user` and `sysadmin` tokens must contain the
`access_as_user` scope and a non-empty `oid` distinct from `sub`. App-only
`ServiceAdmin` tokens must have `oid` equal to `sub` and must not contain
`scp`; they map to `service_admin`. Both `sysadmin` and `service_admin`
receive these FastAPI-enforced permissions:
`devices:read`, `devices:write`, `users:read`, `users:write`,
`clients:read`, `clients:write`, `access:read`, `access:grant`,
`server:read`, and `server:write`.

Authenticated callers can use `GET /me` to resolve the validated token issuer
and subject to a local User. The endpoint never accepts a caller-supplied user
ID, registration identity, display name, or role. With automatic registration
enabled, the first successful delegated `GET /me` creates a missing local
`device_user` or `sysadmin` from the validated `iss` and `sub` claims. Its
display name uses a validated printable `name`, then `preferred_username`,
bounded to 255 characters, or the fixed `Microsoft Entra user` fallback.
Existing local records and administrator-renamed display names are never
overwritten. Concurrent first requests resolve to the same User. App-only
`ServiceAdmin` identities are never auto-registered.

Missing, unknown, or multiple token roles are rejected instead of defaulting
to `device_user`. Ownership of VPN clients and explicit device AccessGrant
records are separate resource policies; they do not grant management-route
access. The frontend continues to resolve sign-in only through `GET /me` and
does not decode tokens or call a registration/bootstrap route. OpenAPI
operations publish their enforced policy as `x-required-permission`.

Migration: remove `AZURE_ENTRAID_APP_ROLE` and define all three explicit role
variables before restarting the service. There is deliberately no legacy
fallback; an existing `ServiceAdmin` value is never interpreted as an
interactive administrator role.

Initialize the server from the Server page with an explicit reachable VPN
hostname or IP address. The backend derives the shared credential-free profile
from the active `server.conf` and atomically writes it to
`/opt/ovpncp/client.ovpn`; `OVPNCP_CLIENT_CONFIG_PATH` can override that
absolute service-writable path. Existing deployments can generate or refresh
the profile from **Server > Shared client profile** or
`PUT /server/client-config`. The endpoint is never inferred from an HTTP or
tunnel address.

Every recognized authenticated role can download the same no-store profile
from `GET /me/client-config`; the portal exposes this once in Connection setup.
To connect, place it beside the extracted client ZIP, replace
`<client-name>` in the command, and run:

~~~shell
openvpn --config ovpncp-client.ovpn --ca ca.crt \
  --cert <client-name>.crt --key <client-name>.key
~~~

See the production runbook for validation, migration, and rollback details.

Current-user portal APIs derive the local user only from verified token
`issuer` and `subject` claims. `GET /me/clients` returns only client `id`,
`name`, and `revoked` state; `GET /me/devices` and
`GET /me/devices/{device_id}` expose only explicitly granted resources. Owned,
active credential packaging and no-store ZIP download use
`PUT /me/clients/{client_name}/package-cert` and
`GET /me/clients/{client_name}/download-cert`. Revoked credentials receive a
fixed `409` before packaging, file access, or cloud storage. Existing but
unowned
and nonexistent resources receive the same `403` response, so these APIs cannot
be used to enumerate another user's resources. None of the `/me/...` operations
accepts a user ID. Admin and portal certificate routes share the same validated
archive service after their distinct authorization checks.

Only exact localhost `POST` and `PUT` requests to
`/clients/{client_name}/connections` bypass bearer authentication for the
OpenVPN connection scripts. Remote callers to those endpoints require
`clients:write`; all other localhost API traffic remains protected. The hook
operations are documented as `x-local-hook-or-permission`.

Notice: for the consumer client app, two things must be configured on the client app registration:

1. copy `Application ID URI` of the previous registered App.
2. add permission of the previous registered App on the `API permissions`, and grant admin consent.

Example of calling API with an access token:
```shell
# Request an access token 
curl -X POST -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=$AZURE_ENTRAID_CONSUMER_CLIENT_ID" \
    -d "scope=api://$EXPOSED_API_ID/.default" \
    -d "client_secret=$AZURE_ENTRAID_CONSUMER_CLIENT_SECRET" \
    -d "grant_type=client_credentials" \
    "https://login.microsoftonline.com/$AZURE_ENTRAID_TENANT_ID/oauth2/v2.0/token"

# Call an API
curl -X POST http://REMOTE_HOST/clients -H "Authorization: Bearer $ACCESS_TOKEN"
```

### [Optional] Enable Cert Management with Azure Blob Storage

1. Create a storage account on Azure Portal.

2. Create a container named `ovpncp` on the storage account.

3. Obtain the access key and set it to the `AZURE_STORAGE_CONNECTION_STRING`
