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

## Frontend scaffold

The React, TypeScript, Vite, Tailwind CSS, shadcn/ui, and MSAL scaffold lives in
[`frontend/`](frontend/README.md). Feature workflows and production static-file
integration are intentionally deferred. The phased implementation source of
truth is [`docs/frontend-implementation-plan.md`](docs/frontend-implementation-plan.md).

```shell
cd frontend
npm ci
cp .env.example .env.local
npm run dev
```

## Installation

In order to run along with OpenVPN server, the ROOT privilege is required.

```shell
sudo pipx install ovpncp
```

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

To ensure the application starts automatically on boot and restarts if it crashes:

1. Create a service file at `/etc/systemd/system/ovpncp.service`:

```ini
[Unit]
Description=OpenVPN Control Panel
After=network.target openvpn.service

[Service]
Type=simple
User=root
Group=root
# Use 'which ovpncp' to find the absolute path if different
ExecStart=/root/.local/bin/ovpncp
# Path to your environment variables file
EnvironmentFile=/opt/ovpncp/.env
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

2. Enable and start the service:

```shell
sudo systemctl daemon-reload
sudo systemctl enable ovpncp
sudo systemctl start ovpncp
```

## API - Basic Usage

Init server by calling API with cURL:

```shell
curl -X POST http://127.0.0.1:8000/server
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

Import existing clients from Easy-RSA:

```shell
curl -X POST http://127.0.0.1:8000/clients/import
```

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

Unassign IP from the client:

```shell
curl -X DELETE http://127.0.0.1:8000/clients/client_1/unassign-ip
```

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

### [Optional] Enable Security with Azure Entra ID

Register this app on Azure Entra ID first, then sets three ENVs to enable the security middleware:

1. `AZURE_ENTRAID_TENANT_ID` - the tenant ID of Azure Entra ID directory.

2. `AZURE_ENTRAID_APP_CLIENT_ID` - the application (client) ID of this app that registered.

3. `AZURE_ENTRAID_APP_ROLE` - the app role assigned by this app.

All three values are required together; missing or partial configuration fails
closed. Authentication validates the token signature, audience, issuer, and
stable identity before authorization. The configured Entra app role maps to the
canonical `sysadmin` role and these FastAPI-enforced permissions:
`devices:read`, `devices:write`, `users:read`, `users:write`,
`clients:read`, `clients:write`, `access:read`, `access:grant`,
`server:read`, and `server:write`.

Authenticated callers can use `GET /me` to resolve the validated token issuer
and subject to a local User. The endpoint never accepts a caller-supplied user
ID. A registered caller without the configured admin role resolves as
`device_user` with no control-plane management permissions. Ownership of VPN
clients and explicit device AccessGrant records are separate resource policies;
they do not grant management-route access. Create the matching local User record
before signing in to the frontend. OpenAPI operations publish their enforced
policy as `x-required-permission`.

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
