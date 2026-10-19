# Configuration and authentication

Use the deployment's own template as the starting point:

- Compose: [container.env.example](../deploy/container.env.example).
- Native API and agent: templates exported by `rivet-export-native`;
  see [native installation](deployment.md#native-installation).
- Local Vite development: [frontend/.env.example](../frontend/.env.example).

Environment variables are read at startup unless documented otherwise. Restart
the affected service after changing them. Keep private settings out of Git,
build arguments, browser variables, shell history, and logs.

- [API and agent](#api-and-agent)
- [Entra registrations and roles](#entra-registrations-and-roles)
- [Browser configuration](#browser-configuration)
- [Optional database and Blob secrets](#optional-database-and-blob-secrets)
- [Generate the shared OpenVPN client profile](#generate-the-shared-openvpn-client-profile)

## API and agent

| Setting | Contract |
| --- | --- |
| `RIVET_VPN_BACKEND` | `agent` for native/container releases. Lower-level source default is `host`; `shadow` is a compatibility comparison mode. |
| `RIVET_AGENT_SOCKET` | Canonical absolute Unix socket path; default `/run/ovpn-agent/agent.sock`. |
| `RIVET_AGENT_UID` | Numeric trusted agent UID, required for agent/shadow. |
| `RIVET_VPN_EVENTS` | `0` by default; `1` enables durable connection-event ingestion in agent mode. |
| `RIVET_VPN_RECONCILE` | `0` by default; `1` enables pending-workflow lookup in agent mode. |
| `RIVET_CLIENT_CONFIG_PATH` | Absolute API-writable shared profile path; default `/opt/rivet/client.ovpn`. Compose selects its separate profile mount. |
| `SQLALCHEMY_DATABASE_URI` | Defaults to SQLite `/opt/rivet/ovpncp.db`. Native `mysql`/`postgres` extras supply the optional drivers. |
| `HOST`, `PORT` | Native API defaults to `127.0.0.1:8000`. Container entrypoint owns its listener settings. |
| `RIVET_ROOT_PATH` | Native/source runner accepts empty or `/api`; native Nginx deployment uses `/api`. |
| `RIVET_PROXY_IP` | Container API's sole trusted forwarded-header peer; must match the Nginx bridge address. |
| `RIVET_STORAGE_PROVIDER` | `local` or `azure_blob`. If unset, a configured `AZURE_STORAGE_CONNECTION_STRING` selects Blob; otherwise local. Blank and unsupported values fail startup. Explicit `local` ignores legacy Blob credentials. |

Agent configuration, mutation-family requirements, route protocol allocation,
and ownership checks are defined in [agent operation](vpn-control.md#agent-operation).
The API's reconciliation flag does not import VPN clients into the database;
use the reviewed import workflow.

## Entra registrations and roles

The supplied API and UI require an API registration and a separate SPA
registration. Configure the API registration's delegated `access_as_user`
scope, appropriate app roles, and tenant consent. Configure the SPA to request
that API scope; its client ID is not the API audience ID.

| Backend variable | Meaning |
| --- | --- |
| `RIVET_AUTH_PROVIDER` | `entra` (default). Blank and unsupported values prevent startup. |
| `AZURE_ENTRAID_TENANT_ID` | Tenant containing the API registration. |
| `AZURE_ENTRAID_APP_CLIENT_ID` | API registration's Application (client) ID. |
| `AZURE_ENTRAID_USER_ROLE` | Delegated user app-role value; templates use `device_user`. |
| `AZURE_ENTRAID_ADMIN_ROLE` | Delegated administrator app-role value; templates use `sysadmin`. |
| `AZURE_ENTRAID_SERVICE_ADMIN_ROLE` | App-only administrator value; templates use `ServiceAdmin`. |
| `RIVET_AUTH_AUTO_REGISTER_USERS` | Automatic local-user registration. Accepts only `true`/`false`, case-insensitive, with no surrounding whitespace. Falls back to the legacy setting, then `true`. |
| `AZURE_ENTRAID_AUTO_REGISTER_USERS` | Legacy registration alias. If both aliases are supplied, their values must agree. |

All five required values must be nonempty; the three role values must differ.
Missing, partial, duplicate, or invalid policy configuration fails closed.
There is no fallback to the old `AZURE_ENTRAID_APP_ROLE` variable.
Direct ASGI, native, and container startup share the same validation. Provider
selection and registration policy are fixed for the API lifecycle; restart the
API after changing them. Missing authentication dependencies prevent startup.

The backend validates RS256 token signature, issuer, audience, expiry, and
stable identity. Tokens must include audience and expiration claims; a valid
signature alone is insufficient. Signing keys come only from the configured
tenant endpoint, with a five-second fetch timeout and a 256 KiB response limit.
Delegated user/admin tokens require `access_as_user` in
`scp` and a nonempty `oid` different from `sub`. App-only service-admin tokens
require `oid == sub` and no `scp`. Missing, unknown, or multiple roles are
rejected. Delegated admin and app-only service admin receive the management
permissions shown in [the route matrix](vpn-control.md#api-route-mapping).

`GET /me` resolves verified `iss` and `sub` to the local User. With automatic
registration enabled, a missing delegated user/admin is created using verified
claims; existing display names are preserved. App-only identities are never
auto-registered. When registration is disabled, unknown local identities
receive `403`. Invalid or conflicting registration values prevent startup.
Identity remains keyed by issuer and subject; changing a provider does not
merge accounts by name/email or transfer grants.

UserClient ownership and device AccessGrants are separate local policies.
Neither grants management permissions or installs VPN firewall rules. Portal
requests never accept a caller-selected user ID. Revoked client credentials
are refused before packaging or file access.

`/docs` and `/openapi.json` are documentation exceptions. Agent deployments
have no unauthenticated connection callback. Host/shadow compatibility modes
retain only the exact loopback POST/PUT connection-hook exception; all other
API traffic remains protected. Keep API listeners private in every deployment.

## Browser configuration

Build deployment-neutral assets with `npm run build:runtime` (also named
`build:container`). Runtime mode ignores dotenv and process `VITE_*` input,
fixes the API base to `/api`, and requires authentication.

| Runtime variable | Value |
| --- | --- |
| `RIVET_UI_AUTH_PROVIDER` | `entra` (default). Blank and unsupported values fail validation. |
| `RIVET_UI_ENTRA_TENANT_ID` | Tenant UUID matching the API. |
| `RIVET_UI_ENTRA_CLIENT_ID` | SPA registration UUID. |
| `RIVET_UI_ENTRA_API_SCOPE` | Concrete API scope such as `api://API_UUID/access_as_user`. |

The web entrypoint validates these public values and serves
`window.__RIVET_CONFIG__` from `/runtime-config.js` with `Cache-Control:
no-store`. Native deployments render it with the exported `web-config.sh`.
Missing or malformed configuration blocks startup/sign-in; it cannot enable
an auth bypass. Changing the deployment does not require rebuilding the UI.
New renderers include `"provider":"entra"` alongside `tenantId`, `clientId`,
and `apiScope`. The browser also accepts the legacy three-field Entra payload
during rollout. A malformed runtime payload never falls back to build settings.

Register the exact public HTTPS origin plus `/` as an Entra **SPA** redirect
URI. MSAL returns to that origin before the router restores the requested
page. Use the browser-facing origin, not the private API address. Local
development uses its own registered localhost origin and `VITE_*` settings.

The optional `build:production` mode still embeds reviewed public settings
from `.env.production.local`; it requires rebuilding when those settings
change. Runtime configuration is the native/container reference.
Optional build-time `VITE_AUTH_PROVIDER` accepts only `entra` when supplied.

## Optional database and Blob secrets

Use `sciaiot-rivet[api,azure]` for native Blob support. Set
`RIVET_STORAGE_PROVIDER=azure_blob` and `AZURE_STORAGE_CONNECTION_STRING`, or
leave the provider unset to infer Blob from the legacy connection string. The
private container remains `ovpncp`; its name and `<client>.zip` archive keys
are persistent identifiers. `RIVET_STORAGE_PROVIDER=local` selects the
configured certificate directory even when a legacy Blob connection string is
present. Unsupported providers fail startup; changing providers requires an
API restart and does not migrate existing archives.

Both administrator and owned-client download routes use the selected store for
host archives. Agent and shadow downloads always verify fresh agent bytes and
active generation. Archives are bounded to 16 MiB and served as private ZIP
attachments with `Cache-Control: no-store`. Blob upload failures fail the
package request. Archive cleanup follows durable client deletion; if cleanup
fails, deletion still returns `204` and the operator must remove the orphaned
archive manually.

The API container supports `SQLALCHEMY_DATABASE_URI_FILE` and
`AZURE_STORAGE_CONNECTION_STRING_FILE` through a reviewed Compose override.
Use direct regular files beneath `/run/secrets`, owned by UID 65531, mode
0400 or 0600, at most 16 KiB, without symlinks or hard links. Conflicting
inline/file values fail startup. Native services use protected root-owned
environment files or an explicitly configured credential-delivery mechanism;
the container's `_FILE` loader is not a general native environment feature.
An explicit `local` selection leaves any Blob credential file unused. For the
reference Compose deployment, pass `RIVET_STORAGE_PROVIDER` through the same
reviewed API service override used for optional Blob secrets; values in
`deploy/container.env` are not forwarded automatically.

The reference container lock uses SQLite. MySQL/PostgreSQL require a reviewed
driver lock and image variant, plus database-specific backup/restore. Never
put database or storage credentials into browser settings.

## Generate the shared OpenVPN client profile

During first-time initialization, open **Server**, enter the reachable VPN
hostname or IP address, and confirm initialization. The API reads the active
OpenVPN `server.conf`, validates its port, protocol, device, cipher, and related
client-compatible options, then atomically writes the credential-free shared
profile before committing the server record. It never derives the endpoint
from the HTTP Host header, tunnel address, or Application Gateway.

The profile defaults to `/opt/rivet/client.ovpn`. Set
`RIVET_CLIENT_CONFIG_PATH` before starting the service only when deployment
policy requires another absolute path writable by the service account.
`deploy/client.ovpn.example` is an illustrative reviewed example, not the
source used during generation.

For an already initialized deployment, open **Server > Shared client profile**,
enter the reachable endpoint, and choose **Generate shared profile**. API-only
operators can call `PUT /server/client-config` with the same request body:

~~~json
{"remote_host": "vpn.example.com"}
~~~

This explicit regeneration path migrates a manually installed profile and
refreshes transport settings after `server.conf` changes. A generation failure
keeps the previous complete profile; initialization failures roll back the
database and profile together. Errors are fixed RFC 7807 responses and never
include filesystem paths.

The API serves the result to every authenticated `device_user`, `sysadmin`, and
app-only `ServiceAdmin` through `GET /me/client-config`. Interactive
administrators can discover the same download under **Portal > My VPN clients**;
app-only callers use the API directly. The response is named
`rivet-client.ovpn` and includes `Cache-Control: no-store`.

This shared file must not contain any client certificate or private key, SAS
URL, password, token, or other per-client credential. The API validates strict
UTF-8 text, requires active `client` and configured `remote` directives, and
rejects binary controls, unresolved placeholders, credential file directives
or inline blocks, and PEM private keys before returning any bytes.

Keep `ca.crt`, the named client certificate, and the named private key in each
client-specific credential archive. Place the downloaded shared profile beside
the extracted archive, substitute the assigned client name, and connect with
the exact credential flags:

~~~shell
RIVET_CLIENT_NAME=assigned-client-name
sudo openvpn \
  --config rivet-client.ovpn \
  --ca ca.crt \
  --cert "${RIVET_CLIENT_NAME}.crt" \
  --key "${RIVET_CLIENT_NAME}.key"
~~~

Graphical OpenVPN clients must be configured equivalently: import the shared
transport profile, then select the extracted `ca.crt`, named client
certificate, and named private key in their separate credential fields. Never
upload one client's credentials into the shared profile path.

The generated transport profile follows the active server's UDP/TCP family,
tun/tap family, listening port, persistence, configured data ciphers, verbosity,
and UDP exit notification. It adds server-certificate verification and
deliberately omits compression, `tls-auth`, and `tls-crypt`.
