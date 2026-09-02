# Production deployment

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

- Python 3.14 and a virtual environment under /opt/ovpncp/venv
- Node.js 22.22.2+ or 24.15.0+
- Nginx with HTTP and proxy modules
- Azure Application Gateway, peering, and the restricted backend NSG rule
- OpenVPN, Easy-RSA, iptables, and iproute2
- an Entra API registration and SPA registration

Run the following commands from the reviewed source checkout.

## Install and configure FastAPI

~~~shell
sudo install -d -m 0700 /opt/ovpncp
sudo python3.14 -m venv /opt/ovpncp/venv
sudo /opt/ovpncp/venv/bin/python -m pip install --upgrade pip
sudo /opt/ovpncp/venv/bin/python -m pip install '.[security]'

sudo install -d -m 0750 /etc/ovpncp
sudo install -m 0600 deploy/ovpncp.env.example /etc/ovpncp/ovpncp.env
sudoedit /etc/ovpncp/ovpncp.env
~~~

Use the azure extra instead when Azure Blob Storage is required. Add the MySQL
or PostgreSQL extra for those database backends.

Replace every angle-bracket placeholder in `/etc/ovpncp/ovpncp.env`. The five
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
OVPNCP_RELEASE=0.1.7
sudo install -d -o root -g root -m 0755 /srv/ovpncp/frontend/releases
sudo install -d -o root -g root -m 0755 \
  "/srv/ovpncp/frontend/releases/${OVPNCP_RELEASE}"
sudo cp -a dist/. \
  "/srv/ovpncp/frontend/releases/${OVPNCP_RELEASE}/"
sudo chown -R root:root \
  "/srv/ovpncp/frontend/releases/${OVPNCP_RELEASE}"
sudo chmod -R u=rwX,go=rX \
  "/srv/ovpncp/frontend/releases/${OVPNCP_RELEASE}"
sudo ln -sfn \
  "/srv/ovpncp/frontend/releases/${OVPNCP_RELEASE}" \
  /srv/ovpncp/frontend/current
cd ..
~~~

Use a package version plus source revision when multiple builds can share a
package version. The root-owned static tree is traversable by Nginx but remains
outside `/opt/ovpncp`, the privileged API service's writable application tree.

## Install the systemd service

The unit keeps FastAPI on IPv4 loopback, publishes its external root path as
/api, restricts filesystem writes, and retains the root privileges required by
the existing OpenVPN and network operations.

~~~shell
sudo install -m 0644 \
  deploy/systemd/ovpncp.service \
  /etc/systemd/system/ovpncp.service
sudo systemctl daemon-reload
sudo systemctl enable ovpncp
sudo systemctl restart ovpncp
sudo systemctl status ovpncp
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
export OVPNCP_FRONTEND_ROOT=/srv/ovpncp/frontend/current

OVPNCP_TEMPLATE_VARIABLES='${OVPNCP_FRONTEND_ROOT}'
envsubst "${OVPNCP_TEMPLATE_VARIABLES}" < deploy/nginx/ovpncp.conf.template \
  | sudo tee /etc/nginx/conf.d/ovpncp.conf >/dev/null

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
https://ovpncp.example.com/
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
pytest --cov=src/sciaiot/ovpncp --cov-report=term-missing

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
OVPNCP_BASE_URL=https://ovpncp.example.com npm run smoke:production
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
  /srv/ovpncp/frontend/releases/<previous-release> \
  /srv/ovpncp/frontend/current
sudo nginx -t
sudo systemctl reload nginx
~~~

Reinstall the previous backend wheel into /opt/ovpncp/venv and restart ovpncp.
Restore a compatible database backup if a release included a schema migration.
Re-run the live smoke check after either rollback. Never overwrite the active
release directory in place.
