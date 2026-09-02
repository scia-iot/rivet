# ovpncp frontend

React frontend for the OpenVPN control panel. Device, user, VPN-client,
individual-access, server, network, fine-grained authorization, and device-user
portal workflows are implemented. Production delivery uses the reviewed
[Nginx and systemd runbook](../docs/production-deployment.md), and progress is
recorded in the
[frontend implementation plan](../docs/frontend-implementation-plan.md).

## Stack

- React and TypeScript
- Vite
- Tailwind CSS 4
- shadcn/ui-compatible local components
- React Router
- Microsoft Authentication Library (MSAL) for React
- TanStack Query for server state
- generated OpenAPI types and openapi-fetch
- Vitest and Testing Library
- Playwright

## Setup

Node.js 22.22.2+ or 24.15.0+ is required.

For the complete two-terminal FastAPI and Vite workflow, follow the
[local full-stack development guide](../docs/local-development.md).

```shell
cd frontend
npm ci
cp .env.example .env.local
npm run dev
```

Configure the Entra SPA registration in `.env.local`. Missing or partial values
produce a blocking configuration error. For explicit local UI development only,
set `VITE_AUTH_DISABLED=true`; the header always shows when this unsafe local
mode is active, and it does not disable backend authentication. Vite proxies
`/api/*` to `http://127.0.0.1:8000/*` during local development.
Login and logout use the exact root of the current origin; register that HTTPS
root URI for every deployed Entra SPA environment.

Configured sessions use an MSAL redirect, preserve the requested frontend URL,
select the returned account, acquire API tokens silently, and resolve the local
user through `GET /me`. The API matches only the validated token issuer and
subject; a matching local User record must already exist. A `401` or an MSAL
interaction-required response may start one controlled redirect. Signed-out
users remain on the unauthenticated layout until they explicitly choose Sign in;
the redirect guard clears only after `/me` succeeds. Logout failures are handled
with a generic safe message. A `403` shows the forbidden layout.
Navigation and route presentation are filtered by typed `/me` permissions
for usability, but FastAPI remains the authorization boundary. The account
Access menu explains the canonical role and recognized management permissions
without displaying issuer or subject claims. Sign-out clears the active MSAL
account and frontend query cache before redirecting.

## Administrative workflows

Administrators can manage devices, including linking and unlinking VPN clients,
through `/devices`. User lifecycle and multi-client ownership are available
through `/users`; unlinking or deleting a user does not delete or revoke the
VPN client. The user-detail Device access tab lists application-level
AccessGrant records and lets administrators grant or revoke those records.
`/clients` supports creation and deliberate bulk Easy-RSA import,
virtual-address assignment, certificate renewal and packaging,
typed-confirmation revocation, and ZIP download. Bulk import always scans all
existing Easy-RSA client certificates. It defaults to importing VPN Clients
only; creating matching edge Devices requires selecting an unchecked option in
the confirmation dialog. The completion summary reports Clients added,
updated, and skipped, plus Devices created, already linked, and in conflict
when Device creation was selected. Existing Device names and Client links are
never reassigned to resolve a conflict.

Certificate downloads are fetched directly as `application/zip` with
`Cache-Control: no-store`. Azure Blob Storage deployments proxy the archive
bytes through the API and never return or retain a SAS URL in the browser. The
frontend creates a short-lived object URL only to start the download, then
removes the anchor and revokes the URL immediately. Archives and URLs are not
stored in TanStack Query, `localStorage`, or `sessionStorage`.

Device access deliberately separates `Authorized` from `Enforced`.
`Authorized` means an AccessGrant exists in the application database. Network
enforcement remains deferred: creating or removing a grant does not apply an
OpenVPN or firewall policy and does not confirm connectivity. The frontend
waits for backend confirmation before refreshing grant state. `access:read`
controls read presentation and `access:grant` controls mutation presentation;
FastAPI remains authoritative for every request. The backend maps the exact
Entra role value `user` to `device_user` with no management permissions and
maps `admin` to `sysadmin`. App-only tokens carrying exactly `ServiceAdmin`
map to `service_admin` and receive the same management permissions as
`sysadmin`. Missing, unknown, or multiple roles are denied. Each management
operation documents and enforces its required permission.

## Device-user portal

Registered non-admin users land on `/portal`. The portal lists only the
`id`, `name`, and `revoked` state of VPN clients owned by their current verified
identity, plus devices with an explicit AccessGrant. It never accepts or places
a user ID in a portal URL or API request. Device users can download credentials
for an active owned client; the backend rejects revoked credentials before
packaging, file access, or cloud storage. The same short-lived, no-store Blob
download behavior used by administrators removes temporary anchors and object
URLs immediately.

Device detail URLs require a canonical positive decimal ID. A fixed forbidden
state does not reveal whether an ungranted device exists; transient failures
show a safe retry action without exposing backend details.

Portal device pages show `Authorized` separately from `Not enforced`. An
AccessGrant alone does not apply OpenVPN or firewall policy and does not
confirm connectivity. Device users cannot create or change clients, identities,
grants, devices, server state, routes, or networks, and direct navigation to
those administrative routes remains forbidden.

## Production and E2E

Copy `.env.production.example` to the gitignored
`.env.production.local`, replace every placeholder, and build with:

```shell
npm run build:production
```

The production guard requires authentication, concrete Entra UUIDs and API
scope, only reviewed browser-exposed variables, and the same-origin `/api` base.
Azure Application Gateway terminates public TLS and enforces the listener
hostname. Nginx receives restricted plain HTTP, serves `dist`, applies SPA
fallback and browser security headers, and proxies `/api` to loopback FastAPI.
No hostname or TLS key is compiled into or installed with the frontend. See the
[production deployment runbook](../docs/production-deployment.md).

The Playwright suite covers the authentication shell and redirect return,
admin navigation, device create/edit/delete confirmation, client assignment,
access grant/revoke, device-user denial, and a Vite-proxy request to a
loopback-only test FastAPI instance:

```shell
npx playwright install chromium
npm run test:e2e
```

The controlled identity is available only when Vite is simultaneously in
development, `e2e` mode, and explicitly opted in by the Playwright server.
A separate dual-build check proves the seam is absent from both ordinary
production output and `vite build --mode e2e`.

Use `npm run smoke:production` with `OVPNCP_BASE_URL` after deployment. The
credential-free checker validates static fallback, asset caching, security
headers, and the unauthenticated API boundary without printing response data.

## Checks

Regenerate the checked-in FastAPI contract and TypeScript declarations after
an API response changes:

```shell
npm run api:generate
npm run api:check
```

The generator currently declares a TypeScript 5 peer range, while the frontend
uses TypeScript 6. The repository-local `.npmrc` permits this single known peer
mismatch so plain `npm ci` remains reproducible. The generator, typecheck, and
build are CI-verified together.

```shell
npm audit
npm run api:check
npm run lint
npm run typecheck
npm run test
npm run test:production
npm run test:e2e:production-guard
npm run test:e2e
npm run build
npm run build:production
```

Use `npx shadcn@latest add <component>` from this directory when another local
UI primitive is needed. Components under `src/components/ui/` are application
source and should be reviewed like any other code.
