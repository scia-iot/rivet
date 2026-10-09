# Production deployment

This source-checkout runbook describes the previous root API deployment and
is retained for transition reference. New non-container releases use the
[native PyPI deployment guide](native-deployment.md), which runs an
unprivileged API and separate VPN agent. Do not install this page's root API
unit on a new deployment.

This runbook deploys the React application and FastAPI service behind one
HTTPS origin. The API can change OpenVPN, routes, firewall rules, and
certificate material with root privileges, so the boundary is deliberately
narrow.

## Selected topology

TLS terminates at Azure Application Gateway. Its HTTPS listener owns public
hostname matching and HTTPS enforcement, then forwards plain HTTP over the
restricted virtual network to Nginx on port 80.

Nginx serves frontend/dist and proxies browser API requests under /api to
FastAPI on 127.0.0.1:8000.

~~~text
Browser
  |
  | HTTPS
  v
Azure Application Gateway
  |
  | private HTTP :80
  v
Nginx
  |-- /assets/*, /favicon.svg, and SPA routes -> frontend/dist
  `-- /api/* -> http://127.0.0.1:8000/* -> FastAPI
~~~

The /api prefix prevents collisions between browser routes such as /devices
and FastAPI routes with the same paths. Nginx strips the prefix once. FastAPI
remains the authorization boundary and is not exposed publicly.

Configure Application Gateway manually with these backend settings:

- Backend protocol: `HTTP`
- Backend port: `80`
- Backend pool target: the VM private address reachable through peering
- Host-name override: disabled, preserving the listener-selected host
- Custom health probe: HTTP port 80, path `/`, expected status `200`
- Public HTTP listener: redirect to the public HTTPS listener

Plain HTTP is acceptable only inside this restricted backend hop. The VM
network security group must enforce both rules:

- Allow port 80 only from the Application Gateway subnet.
- Do not allow port 8000 from any remote network.

Nginx is deliberately the default backend virtual host because the Application
Gateway listener owns hostname matching. It preserves the selected Host header
and reports `X-Forwarded-Proto: https` to FastAPI because every accepted public
request has already passed the gateway's HTTPS-only listener.

The Nginx template provides:

- SPA history fallback that cannot intercept /api;
- no-store caching for index.html and API responses;
- immutable caching only for Vite's fingerprinted /assets files;
- Content Security Policy, HSTS, framing, MIME-sniffing, referrer, resource,
  opener, and browser-permission protections;
- disabled proxy buffering so certificate archives do not reach Nginx
  temporary files;
- disabled Nginx access/error logs and Uvicorn access logs so authentication
  query strings, caller addresses, and resource paths are not recorded.

Application logs remain in the systemd journal and must continue to follow the
repository's secret-safe logging rules.

## Prerequisites

- Python 3.14 and a virtual environment under /opt/rivet/venv
- Node.js 22.22.2+ or 24.15.0+
- Nginx with HTTP and proxy modules
- Azure Application Gateway, peering, and the restricted backend NSG rule
- OpenVPN, Easy-RSA, iptables, and iproute2
- an Entra API registration and SPA registration

Run the following commands from the reviewed source checkout.

## Install and configure FastAPI

~~~shell
sudo install -d -m 0700 /opt/rivet
sudo python3.14 -m venv /opt/rivet/venv
sudo /opt/rivet/venv/bin/python -m pip install --upgrade pip
sudo /opt/rivet/venv/bin/python -m pip install '.[security]'

sudo install -d -m 0750 /etc/rivet
sudo install -m 0600 deploy/rivet.env.example /etc/rivet/rivet.env
sudoedit /etc/rivet/rivet.env
~~~

Use the azure extra instead when Azure Blob Storage is required. Add the MySQL
or PostgreSQL extra for those database backends.

Replace every angle-bracket placeholder in `/etc/rivet/rivet.env`. The five
tenant, client, and role `AZURE_ENTRAID_*` values are required together.
Authentication fails closed. Storage connection strings and database
credentials are secrets and must stay in the mode-0600 environment file or an
equivalent secret manager.

`AZURE_ENTRAID_AUTO_REGISTER_USERS` is optional and defaults to `true`.
It accepts only exact `true` or `false` values, case-insensitively and without
surrounding whitespace. An invalid value makes every `GET /me` request fail
closed. Set it to `false` to require administrators to create local User
records before sign-in; unknown identities then retain the fixed `403`
response.

### Generate the shared OpenVPN client profile

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

## Build the environment-specific frontend

Vite identifiers and the API scope are compiled into the bundle. Each deployed
origin therefore needs its own reviewed build.

~~~shell
cd frontend
npm ci
cp .env.production.example .env.production.local
~~~

Replace the placeholders:

~~~dotenv
VITE_AUTH_DISABLED=false
VITE_ENTRA_TENANT_ID=<tenant-uuid>
VITE_ENTRA_CLIENT_ID=<spa-application-client-uuid>
VITE_ENTRA_API_SCOPE=api://<api-application-client-uuid>/access_as_user
VITE_API_BASE_URL=/api
~~~

Build through the production guard:

~~~shell
npm run build:production
~~~

The command refuses disabled authentication, missing or placeholder
identifiers, unreviewed browser-exposed `VITE_*` variables, and an API base
other than the same-origin /api boundary. `.env.production.local` is gitignored.

Install the output in a versioned directory, then switch the stable symlink:

~~~shell
RIVET_RELEASE=0.1.7
sudo install -d -o root -g root -m 0755 /srv/rivet/frontend/releases
sudo install -d -o root -g root -m 0755 \
  "/srv/rivet/frontend/releases/${RIVET_RELEASE}"
sudo cp -a dist/. \
  "/srv/rivet/frontend/releases/${RIVET_RELEASE}/"
sudo chown -R root:root \
  "/srv/rivet/frontend/releases/${RIVET_RELEASE}"
sudo chmod -R u=rwX,go=rX \
  "/srv/rivet/frontend/releases/${RIVET_RELEASE}"
sudo ln -sfn \
  "/srv/rivet/frontend/releases/${RIVET_RELEASE}" \
  /srv/rivet/frontend/current
cd ..
~~~

Use a package version plus source revision when multiple builds can share a
package version. The root-owned static tree is traversable by Nginx but remains
outside `/opt/rivet`, the privileged API service's writable application tree.

## Install the systemd service

The unit keeps FastAPI on IPv4 loopback, publishes its external root path as
/api, restricts filesystem writes, and retains the root privileges required by
the existing OpenVPN and network operations.

~~~shell
sudo install -m 0644 \
  deploy/systemd/rivet.service \
  /etc/systemd/system/rivet.service
sudo systemctl daemon-reload
sudo systemctl enable rivet
sudo systemctl restart rivet
sudo systemctl status rivet
~~~

Do not expose port 8000, set HOST=0.0.0.0, or place an untrusted proxy between
Nginx and FastAPI. FastAPI trusts forwarding headers only from 127.0.0.1.
Nginx overwrites rather than appends X-Forwarded-For, preserving the exact
loopback-only OpenVPN connection-hook exception.

## Install Nginx

Only the release root is rendered locally; the public hostname and TLS
certificate remain Application Gateway concerns. The envsubst allowlist leaves
Nginx variables such as $uri, $http_host, and $remote_addr intact.

~~~shell
export RIVET_FRONTEND_ROOT=/srv/rivet/frontend/current

RIVET_TEMPLATE_VARIABLES='${RIVET_FRONTEND_ROOT}'
envsubst "${RIVET_TEMPLATE_VARIABLES}" < deploy/nginx/rivet.conf.template \
  | sudo tee /etc/nginx/conf.d/rivet.conf >/dev/null

if [ -L /etc/nginx/sites-enabled/default ]; then
  sudo mv /etc/nginx/sites-enabled/default /etc/nginx/default-site.disabled
fi

sudo nginx -t
sudo systemctl enable nginx
sudo systemctl reload-or-restart nginx
~~~

The template belongs inside Nginx's http context. Adjust the include path on
distributions that do not load /etc/nginx/conf.d/*.conf. Do not serve the
source checkout or put frontend/dist below an API-writable directory.

## Configure Entra redirects

For each environment, register the exact public root using the Entra
Single-page application platform:

~~~text
https://rivet.example.com/
~~~

Use the same root as the front-channel logout URL when configured. The SPA
registration needs delegated access to `VITE_ENTRA_API_SCOPE`, which must be
`api://<api-application-client-id>/access_as_user`.

The API registration defines three distinct app roles:

- `device_user`, allowed for Users/Groups;
- `sysadmin`, allowed for Users/Groups;
- `ServiceAdmin`, allowed for Applications.

Assign users and groups only to `device_user` or `sysadmin`. Assign the
business platform service principal to `ServiceAdmin`. The API accepts
delegated roles only with the `access_as_user` scope, while `ServiceAdmin`
requires an app-only token and receives all management permissions.

With automatic registration enabled, the frontend's first authenticated
`GET /me` creates a missing delegated `device_user` or `sysadmin` exactly
once. The identity comes only from the middleware-validated `iss` and `sub`
claims. A bounded display name comes from validated `name`, then
`preferred_username`, then a fixed safe fallback. The browser supplies none
of these values and does not decode its token or use a registration/bootstrap
route. Existing users and locally renamed display names are preserved.
App-only `ServiceAdmin` identities are never automatically registered.

Before upgrading an existing installation, remove `AZURE_ENTRAID_APP_ROLE`
and configure the three explicit role variables in the environment file.
Never put a client secret in frontend configuration.

## Verify the release

Run the repository quality gates and frontend production checks:

~~~shell
ruff format --check .
ruff check .
mypy .
pytest --cov=src/sciaiot/rivet --cov-report=term-missing

cd frontend
npm audit
npm run api:check
npm run lint
npm run typecheck
npm run test
npm run test:production
npm run test:e2e:production-guard
npm run test:e2e
npm run build:production
~~~

After Nginx and FastAPI start with complete Entra configuration, run:

~~~shell
RIVET_BASE_URL=https://rivet.example.com npm run smoke:production
~~~

This credential-free check covers the public shell, an authentication-return
URL, direct SPA fallback, favicon, a fingerprinted asset, browser headers,
cache policy, and an RFC 7807 401 from unauthenticated /api/me. It accepts no
token and prints no response body or deployment URL.

Complete these environment-specific checks on an isolated deployment:

1. Sign in through the real tenant and confirm the intended route is restored.
2. Refresh one admin route and one portal detail route directly.
3. Sign out and confirm return to the public root.
4. Confirm device-user navigation to an admin route is forbidden.
5. Exercise privileged VPN, route, firewall, and certificate operations only
   on a disposable host, then reconcile host and database state.

## Rollback

Keep a previously verified frontend release and backend wheel. Switch the
frontend symlink atomically:

~~~shell
sudo ln -sfn \
  /srv/rivet/frontend/releases/<previous-release> \
  /srv/rivet/frontend/current
sudo nginx -t
sudo systemctl reload nginx
~~~

Reinstall the previous backend wheel into /opt/rivet/venv and restart rivet.
Restore a compatible database backup if a release included a schema migration.
Re-run the live smoke check after either rollback. Never overwrite the active
release directory in place.
