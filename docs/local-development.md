# Local full-stack development

This guide runs FastAPI on `http://127.0.0.1:8000` and the Vite frontend on
`http://localhost:5173`. Vite proxies browser requests from `/api/*` to the
backend and removes the `/api` prefix before forwarding them.

Use a disposable Linux development machine or container. The API initializes
files under `/opt/ovpncp`, and its OpenVPN, routing, and firewall operations
are privileged system boundaries that can change the host when invoked.

## Prerequisites

- CPython 3.14 or newer
- Node.js 22.22.2+ or 24.15.0+
- npm
- For real sign-in, a Microsoft Entra tenant with separate API and SPA
  application registrations
- Write access to `/opt/ovpncp` for the account running the backend

The backend also needs outbound access to Microsoft Entra while validating
access tokens.

## Prepare the backend

From the repository root, create a virtual environment and install the
development dependencies and package:

```shell
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pip install -e .
```

The API creates its SQLite database, generated hook scripts, and certificate
working directory under `/opt/ovpncp`. On a disposable development host where
that path is not already used by an installation, create both required
directories for the current user:

```shell
sudo install -d -m 0700 -o "$(id -un)" -g "$(id -gn)" /opt/ovpncp
sudo install -d -m 0700 -o "$(id -un)" -g "$(id -gn)" \
  /opt/ovpncp/certs
```

Do not change the ownership of an existing deployment. Use an isolated
development environment or run as that deployment's service account instead.

## Configure authentication

The backend validates API access tokens against the Entra API registration.
Set these variables before starting it:

```shell
export AZURE_ENTRAID_TENANT_ID="<tenant-id>"
export AZURE_ENTRAID_APP_CLIENT_ID="<api-application-client-id>"
export AZURE_ENTRAID_APP_ROLE="<administrator-app-role-value>"
```

`AZURE_ENTRAID_APP_CLIENT_ID` is the Application (client) ID of the API
registration, not the SPA registration. `AZURE_ENTRAID_APP_ROLE` is the app
role value that maps an authenticated user to the `sysadmin` role.

The SPA needs the corresponding browser-facing settings. Create its local
environment file:

```shell
cd frontend
cp .env.example .env.local
```

Edit `frontend/.env.local`:

```dotenv
VITE_AUTH_DISABLED=false
VITE_ENTRA_TENANT_ID=<tenant-id>
VITE_ENTRA_CLIENT_ID=<spa-application-client-id>
VITE_ENTRA_API_SCOPE=api://<api-application-client-id>/access_as_user
VITE_API_BASE_URL=/api
```

The tenant IDs must match. The frontend client ID belongs to the SPA
registration, while the API scope belongs to the API registration.

Register `http://localhost:5173/` as an SPA redirect URI in Entra and use
`localhost` consistently in the browser. If Vite serves a different origin,
register that exact root URI, including its scheme, host, port, and trailing
slash.

After token validation, `GET /me` resolves the token's exact `iss` and `sub`
claims to a local `User`. That record must already exist before the frontend
can finish signing in. Provision it through an authenticated administrator
workflow or use an existing development database. Possessing the configured
Entra app role does not by itself create the local record.

## Start both applications

Start the backend in the first terminal from the repository root:

```shell
source .venv/bin/activate
export HOST=127.0.0.1
export PORT=8000
export OVPNCP_ROOT_PATH=""
ovpncp
```

Keep `OVPNCP_ROOT_PATH` empty for local Vite development. Vite removes `/api`
before forwarding each request to FastAPI.

Start the frontend in a second terminal:

```shell
cd frontend
npm ci
npm run dev
```

Open the URL reported by Vite, normally `http://localhost:5173/`. Confirm the
backend independently at `http://127.0.0.1:8000/docs` or with:

```shell
curl --fail http://127.0.0.1:8000/openapi.json > /dev/null
```

## UI-only development

To work only on the unauthenticated frontend shell, set this value in
`frontend/.env.local`:

```dotenv
VITE_AUTH_DISABLED=true
```

This setting bypasses only the frontend sign-in gate. It does not disable
backend authentication and therefore does not support real API workflows.
The frontend displays a persistent warning while this mode is active.

## Deterministic E2E verification

The Playwright suite provides a controlled test identity and a loopback-only
FastAPI test server, so it does not require a real Entra tenant or invoke host
OpenVPN and firewall operations:

```shell
cd frontend
npx playwright install chromium
npm run test:e2e
```

This is a test-only authentication seam. The test runner owns the temporary
servers and credentials; do not use E2E mode as a general development auth
bypass.

## Troubleshooting

- A backend `500` saying authentication is misconfigured means one or more
  `AZURE_ENTRAID_*` variables were absent when the process started. Stop it,
  export all three values, and start it again.
- A `401` usually indicates a token issuer, audience, scope, or expiry problem.
  Confirm that the API client ID and tenant match on both sides.
- A `403` from `/me` after successful token validation commonly means that no
  local `User` matches the token's issuer and subject.
- A frontend proxy failure usually means FastAPI is not listening on
  `127.0.0.1:8000`.
- A startup permission error under `/opt/ovpncp` means the backend account
  cannot initialize its runtime files.
- OpenVPN, `iptables`, or route operations can fail on an ordinary workstation
  without the corresponding services, tools, and privileges. Run those flows
  only in an isolated environment intended for system-level testing.
