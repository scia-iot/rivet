# ovpncp frontend

React frontend for the OpenVPN control panel. Device, user, VPN-client,
individual-access, server, network, and fine-grained authorization workflows
are implemented; the portal and production-integration work remain phased in
the
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

## Setup

Node.js 22.22.2+ or 24.15.0+ is required.

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
`/clients` supports creation and Easy-RSA import, virtual-address
assignment, certificate renewal and packaging, typed-confirmation revocation,
and ZIP download.

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
FastAPI remains authoritative for every request. The backend maps the
configured Entra app role to `sysadmin`; registered non-admin users receive the
canonical `device_user` role and no management permissions. Each management
operation documents and enforces its required permission.

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
npm run build
```

Use `npx shadcn@latest add <component>` from this directory when another local
UI primitive is needed. Components under `src/components/ui/` are application
source and should be reviewed like any other code.
