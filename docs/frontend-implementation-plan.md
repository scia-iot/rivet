# Frontend Implementation Plan

## Purpose and status rules

This document is the source of truth for phased implementation of the ovpncp
frontend. It is intentionally self-contained so a new session or coding agent
can implement one phase without relying on previous conversation history.

Before starting a phase, an agent must:

1. Read `AGENTS.md` and this document completely.
2. Select the first `pending` phase unless the user explicitly selects another.
3. Inspect the related backend routes, models, frontend code, and tests.
4. Change the phase status to `in_progress` before implementation.
5. Follow test-driven development and preserve unrelated worktree changes.
6. Mark the phase `completed` only after every exit criterion passes.
7. Record important decisions, verification results, and deferred work in the
   phase notes.

Allowed phase states are `pending`, `in_progress`, and `completed`. At most one
phase may be `in_progress`. A phase blocked by a backend prerequisite remains
`pending`; document the blocker rather than weakening security or fabricating
frontend-only authorization.

## Current baseline

The frontend scaffold is complete. It includes:

- React 19 and TypeScript 6
- Vite 8
- Tailwind CSS 4
- shadcn/ui-compatible local components
- React Router 8
- MSAL Browser and MSAL React
- an authenticated API-client foundation
- Vitest and Testing Library
- fail-closed Entra configuration
- zero known npm audit vulnerabilities at the time of scaffolding

The scaffold contains route placeholders only. It does not implement domain
workflows, fine-grained authorization, or production static-file delivery.

## Phase status

| Phase | Name | Status | Primary dependency |
| --- | --- | --- | --- |
| 0 | Frontend scaffold | completed | None |
| 1 | Typed API and server-state foundation | completed | Stable OpenAPI responses |
| 2 | Authentication and current principal | completed | Backend `GET /me` |
| 3 | Shared UI, forms, and error handling | pending | Phases 1-2 |
| 4 | Device administration | pending | Phase 3 |
| 5 | User and VPN-client administration | pending | Phase 4 |
| 6 | Individual access management | pending | Phase 5 |
| 7 | Server and network administration | pending | Phase 3 |
| 8 | Fine-grained authorization contract | pending | Phase 6 backend behavior |
| 9 | Device-user portal | pending | Phase 8 |
| 10 | Production integration and E2E hardening | pending | Phases 4-9 |

## Target architecture

```text
Microsoft Entra ID
        |
        v
MSAL authentication
        |
        v
Application providers
|-- authentication and current principal
|-- React Router
|-- TanStack Query
`-- global error handling
        |
        v
Feature routes and query/mutation hooks
        |
        v
Generated OpenAPI types + authenticated fetch client
        |
        v
FastAPI authorization and business services
```

The frontend may use permissions to improve navigation and presentation, but
FastAPI remains the authorization boundary.

## Planned dependencies

Technology changes must be introduced only in their owning phase.

- Phase 1:
  - `@tanstack/react-query` for server state
  - `openapi-typescript` for generated OpenAPI types
  - `openapi-fetch` for a typed Fetch API client
- Phase 3:
  - `react-hook-form`
  - `zod`
  - `@hookform/resolvers`
  - required shadcn/ui primitives added individually
- Feature-testing phases:
  - Mock Service Worker when fetch-level scenarios become numerous
- Phase 10:
  - Playwright for a small end-to-end suite

Do not add Redux or another global state store unless a later requirement shows
that router state, component state, MSAL, and TanStack Query are insufficient.
Do not adopt `openapi-react-query` initially; explicit feature hooks keep cache
keys and invalidation behavior visible.

## Proposed frontend structure

```text
frontend/src/
|-- app/
|   |-- error-boundary.tsx
|   |-- providers.tsx
|   |-- query-client.ts
|   `-- router.tsx
|-- api/
|   |-- generated/schema.d.ts
|   |-- client.ts
|   |-- problem-details.ts
|   `-- query-keys.ts
|-- auth/
|-- components/
|   |-- shared/
|   `-- ui/
|-- features/
|   |-- access/
|   |-- clients/
|   |-- devices/
|   |-- networks/
|   |-- server/
|   `-- users/
|-- pages/
`-- test/
```

Each feature should own its API hooks, schemas, components, page composition,
and tests. Shared components must contain no domain-specific behavior.

## Phase 1: Typed API and server-state foundation

### Objective

Create one typed, authenticated, testable path from React feature hooks to the
FastAPI OpenAPI contract.

### Backend preparation

- Add explicit response models to endpoints whose OpenAPI responses are vague.
- Ensure success and RFC 7807 error responses are represented consistently.
- Ensure OpenAPI generation does not execute privileged OpenVPN, firewall,
  routing, certificate, or cloud operations.
- Keep existing API paths compatible; URL versioning is not required here.

### Frontend work

- Add `@tanstack/react-query` and a configured `QueryClientProvider`.
- Add deterministic OpenAPI export and `npm run api:generate` commands.
- Generate `src/api/generated/schema.d.ts` with `openapi-typescript`.
- Build an `openapi-fetch` client with MSAL bearer-token middleware.
- Preserve fail-closed behavior when no account or token is available.
- Add an RFC 7807 normalization function and typed `ApiProblemError`.
- Add central query-key factories, for example:

```ts
export const queryKeys = {
  devices: {
    all: ["devices"] as const,
    detail: (id: number) => ["devices", id] as const,
  },
}
```

- Add CI verification that regenerated API types produce no diff.

### Tests

- Bearer tokens are attached without being logged.
- `204 No Content` is handled.
- JSON success responses remain typed.
- RFC 7807 responses retain type, title, status, detail, and instance.
- Non-JSON failures receive a safe fallback problem.
- Query defaults do not retry `401`, `403`, `404`, `409`, or `412` blindly.

### Exit criteria

- A typed query can retrieve `/devices` through the Vite proxy.
- Generated types are reproducible.
- Authentication and problem-response tests pass.
- Frontend audit, lint, typecheck, tests, and build pass.
- Backend tests and applicable quality gates pass.

### Notes

- OpenAPI export is deterministic and side-effect free:
  `npm run api:export` writes sorted `frontend/openapi.json`;
  `npm run api:generate` then writes
  `src/api/generated/schema.d.ts`; `npm run api:check` snapshots both
  files, regenerates them, and compares their content directly.
- FastAPI now documents explicit success models for previously vague client,
  network, server, service-health, route, connection, package, import, and
  download responses. Handled HTTP, validation, authentication, and unexpected
  failures share a documented RFC 7807 `ProblemDetails` response.
- The frontend uses an `openapi-fetch` client with fail-closed MSAL token
  middleware, safe problem normalization, stable query keys, and a shared
  TanStack Query client whose retry policy excludes 401, 403, 404, 409, and
  412 responses.
- `openapi-typescript` 7.13.0 is the latest stable npm release and declares
  TypeScript `^5.x`; the npm `next` tag also declares `^5.x`. No tagged
  release supports the scaffold's TypeScript 6 version. A repository-local
  `.npmrc` enables legacy peer resolution for this one reviewed mismatch.
  `npm ls --all` reported no other non-optional peer conflict, and generation,
  typecheck, tests, and build all pass.
- Verification: clean frontend install and audit passed with zero
  vulnerabilities; generated-file verification, lint, typecheck, 16 tests, and
  production build passed. Backend mypy passed, 82 tests passed with 86%
  coverage, repository formatting passed, and every Phase 1 changed backend
  file passed Ruff.
- Deferred: the repository-wide Ruff lint gate still reports 31 pre-existing
  findings in untouched data, Azure storage, routing/firewall/OpenVPN utility,
  and legacy test files. The existing Starlette/httpx deprecation warning also
  remains. Authentication lifecycle and `GET /me` remain Phase 2 work.

## Phase 2: Authentication and current principal

### Objective

Resolve the signed-in Entra identity to a local user and expose one trusted
frontend representation of roles and permissions.

### Required backend contract

Add an authenticated endpoint:

```http
GET /me
```

Suggested response:

```json
{
  "id": 12,
  "display_name": "Alice",
  "issuer": "https://login.microsoftonline.com/tenant/v2.0",
  "subject": "stable-subject",
  "roles": ["sysadmin"],
  "permissions": ["devices:read", "devices:write", "access:grant"]
}
```

The backend must map the validated token by issuer and subject. It must not
accept a browser-supplied user ID as the current identity.

### Frontend work

- Complete MSAL redirect handling and active-account selection.
- Call `acquireTokenSilent` before protected API requests.
- Handle interaction-required failures with one controlled redirect.
- Add `useCurrentPrincipal()` backed by `GET /me`.
- Add authenticated, unauthenticated, forbidden, and configuration-error
  layouts.
- Preserve the intended route through login redirects.
- Add permission-aware navigation and action presentation.
- Keep permission checks on the backend; frontend guards are user experience.

### Tests

- Missing or partial Entra configuration blocks the application.
- Explicit local/test disablement is clearly visible.
- Login does not enter a redirect loop.
- `401` initiates authentication once.
- `403` renders a forbidden state.
- Sign-out clears the active frontend session.
- Tokens and OAuth subjects are absent from logs and errors.

### Exit criteria

- A configured user can sign in, resolve `/me`, refresh, and sign out.
- Unauthorized navigation does not expose management controls.
- Backend authorization tests cover the `/me` endpoint.

### Notes

- `GET /me` resolves a local User only by the validated token's exact `iss` and
  `sub` claims. It accepts no user ID and returns `403` when the external
  identity is not registered locally.
- The final `CurrentPrincipal` schema is:
  `id: number`, `display_name: string`, `issuer: string`, `subject: string`,
  `roles: string[]`, and `permissions: string[]`. The current validated Entra
  application role maps to the canonical local role `sysadmin`.
- The authoritative Phase 2 permission vocabulary is `devices:read`,
  `devices:write`, `users:read`, `users:write`, `clients:read`,
  `clients:write`, `access:read`, `access:grant`, `server:read`, and
  `server:write`. FastAPI's existing required Entra application role remains
  authoritative; frontend permission checks only filter navigation and render
  route-level forbidden states. Fine-grained backend policies remain Phase 8.
- Token roles are checked only after signature and claim validation. Missing or
  partial Entra configuration fails closed, unexpected security failures do not
  log exception contents, and tokens/OAuth subjects are absent from frontend
  logs and safe errors.
- The localhost security exception is limited to actual loopback peers making
  exact `POST` or `PUT` requests to `/clients/{client_name}/connections`.
  A loopback Host header from a remote peer does not grant the bypass.
- MSAL selects the active returned account and acquires tokens silently. Signed
  out users remain on a stable unauthenticated layout until they explicitly
  choose Sign in, which preserves the current URL. The pending redirect guard is
  cleared only after `/me` resolves successfully, so a persistent `401` cannot
  create a redirect loop. Interaction-required acquisition also permits only one
  pending redirect.
- Sign-out clears the query cache, active MSAL account, and redirect guard before
  logout redirect. Rejected logout redirects are normalized to a generic error,
  caught by the UI, and never log or render raw MSAL/account details.
- Malformed and whitespace-only bearer headers return RFC 7807 `401` responses.
  The sysadmin permission vocabulary is stored as an immutable tuple and copied
  into the response model at the API boundary.
- Missing/partial frontend Entra configuration blocks the application. Explicit
  `VITE_AUTH_DISABLED=true` remains visibly labeled and does not disable backend
  authentication.
- Real-tenant browser smoke testing was not possible without deployment-specific
  Entra credentials and redirect registration; deterministic MSAL mocks cover
  sign-in redirects, refresh-equivalent `/me` resolution, interaction fallback,
  route preservation, permission presentation, and sign-out state clearing.

## Phase 3: Shared UI, forms, and error handling

### Objective

Create the reusable interaction patterns required by all administration pages.

### Frontend work

Add only the shadcn/ui primitives needed for this phase:

```text
alert
badge
button
command
dialog
dropdown-menu
field
input
label
select
separator
skeleton
sonner
table
tabs
textarea
tooltip
```

Create shared application components:

```text
PageHeader
ProblemAlert
EmptyState
LoadingTable
ConfirmActionDialog
EntitySelect
StatusBadge
CopyButton
```

- Add React Hook Form and Zod.
- Use browser validation plus accessible inline validation messages.
- Standardize loading, empty, stale, forbidden, and failure states.
- Add a route-level error boundary and safe unexpected-error screen.
- Add toast notifications for completed mutations; keep field and domain errors
  inline when the user can correct them.
- Require explicit confirmation for destructive operations.

### Tests

- Keyboard operation and accessible names for dialogs and forms.
- Focus moves into dialogs and returns to the trigger.
- Validation errors are associated with fields.
- Problem details never render as unsafe HTML.
- Repeated submission is prevented while a mutation is pending.

### Exit criteria

- Feature pages can be composed without creating new ad hoc loading, error,
  confirmation, or form patterns.
- Shared components contain no device/user-specific business rules.

### Notes

Record generated shadcn components and deliberate customizations here.

## Phase 4: Device administration

### Objective

Implement the complete existing Device API for sysadmins.

### Routes

```text
/devices
/devices/new
/devices/:deviceId
/devices/:deviceId/edit
```

### Feature work

- List device ID, name, current VPN client, and provisioning state.
- Add create, detail, edit, and delete flows.
- Allow a device to exist without a VPN client.
- Link, replace, or unlink the current VPN client.
- Clearly state that deleting a Device does not delete or revoke its Client.
- Use a searchable client selector that excludes already assigned clients.
- Invalidate device and client queries after successful mutations.
- Do not optimistically show client assignment changes.

### Tests

Cover success and these failures:

- duplicate device name
- unknown client
- client assigned to another device
- missing device
- deletion confirmation
- mutation failure preserving the current UI state

### Exit criteria

- Every current Device endpoint has an accessible frontend workflow.
- No workflow implies that a linked OpenVPN client was revoked or deleted.

### Notes

Record any backend list/filter additions here.

## Phase 5: User and VPN-client administration

### Objective

Implement user lifecycle, user-owned laptop clients, and privileged OpenVPN
client operations.

### Routes

```text
/users
/users/new
/users/:userId
/users/:userId/edit
/clients
/clients/:clientName
```

### User work

- List, create, view, rename, and delete users.
- Present issuer and subject only to authorized admins and avoid logging them.
- Add user-detail tabs for Overview, VPN clients, and Device access.
- Assign multiple VPN clients to a user.
- Prevent a VPN client from belonging to multiple users.
- Unlink without deleting or revoking the client.

### VPN-client work

- List, retrieve, create, and import clients.
- Assign and unassign virtual addresses.
- Show certificate expiry and revocation state.
- Renew, package, download, and revoke certificates.
- Treat certificate revocation as destructive and require typed confirmation.
- Do not persist certificate archives, SAS URLs, or sensitive download URLs in
  local storage, query caches, logs, or analytics.

### Tests

- duplicate external identity
- unknown user or client
- client ownership conflict
- virtual-address conflict
- certificate operation failure
- revoked-client presentation
- download cleanup and absence from persistent browser storage

### Exit criteria

- Existing User, UserClient, and Client endpoints have complete admin workflows.
- Sensitive material is never exposed in diagnostic output.

### Notes

Record certificate-download behavior and any backend contract changes here.

## Phase 6: Individual access management

### Objective

Allow admins to grant and revoke application-level user access to devices
without overstating network enforcement.

### Initial interaction

Use a user-centric flow first:

```text
User detail
`-- Device access tab
    |-- accessible devices
    |-- add device access
    `-- revoke device access
```

Add a device-centric authorized-user view only after the primary flow is
stable. Do not begin with a large access matrix.

### Frontend work

- Add `useUserDevices`, `useGrantDeviceAccess`, and
  `useRevokeDeviceAccess` hooks.
- Filter already granted devices from the grant selector.
- Do not optimistically change authorization state.
- Clearly distinguish:
  - `Authorized`: an AccessGrant exists in the database.
  - `Enforced`: OpenVPN/firewall policy has been applied successfully.
- Until enforcement exists, show an explicit application-authorization-only
  explanation.

### Backend dependency

The current AccessGrant does not create a RestrictedNetwork or firewall rules.
If enforcement is added, model an observable state such as pending, active, or
failed and make reconciliation idempotent.

### Tests

- idempotent grant
- revoke success and missing grant
- device or user not found
- authorization state is unchanged after failed mutation
- application-only access is never presented as enforced network access

### Exit criteria

- Admins can accurately manage and understand current AccessGrant records.
- The UI never claims network connectivity that the backend has not confirmed.

### Notes

Record whether enforcement remains deferred or was implemented.

## Phase 7: Server and network administration

### Objective

Expose privileged server, route, virtual-address, and restricted-network
operations with safe confirmations and actionable failures.

### Routes

```text
/server
/server/routes
/networks
/networks/:networkId
```

### Feature work

- Display OpenVPN health and server configuration summary.
- Poll health only while the page is visible.
- List assignable virtual addresses.
- List, add, and remove server routes.
- List, create, inspect, and close restricted networks.
- Show source, destination, private networks, start time, and end time.
- Require confirmation for route and firewall changes.
- Never optimistically report privileged system changes as successful.

### Tests

- health loading and polling lifecycle
- invalid route validation
- command failure and retry presentation
- missing restricted network
- already-ended network presentation
- no sensitive IP addresses in client diagnostics beyond authorized UI fields

### Exit criteria

- Every privileged mutation waits for backend confirmation.
- Failures identify what failed and a safe next action.

### Notes

Record polling intervals and privileged-operation UX decisions here.

## Phase 8: Fine-grained authorization contract

### Objective

Replace the coarse global APP_ROLE assumption with explicit backend policies
needed by both sysadmins and device users.

### Backend work

- Normalize a validated token into a principal.
- Separate authentication from authorization.
- Add explicit admin dependencies to management routes.
- Add resource-level policies for user-owned clients and granted devices.
- Preserve localhost hook access only for the exact required connection-script
  endpoints; do not create a broad security bypass.
- Return consistent `401` and `403` RFC 7807 responses.

Suggested permissions include:

```text
devices:read
devices:write
users:read
users:write
clients:read
clients:write
access:read
access:grant
server:read
server:write
```

### Frontend work

- Consume permissions from `/me`.
- Add route metadata for required permissions.
- Hide unavailable actions while still handling backend `403` responses.
- Add a role/permission explanation to the account menu.

### Exit criteria

- Admin actions require explicit backend permissions.
- A normal device user cannot call admin endpoints directly.
- Invalid security configuration fails closed.
- Authentication and authorization tests cover success and failure cases.

### Notes

Record the authoritative permission vocabulary here.

## Phase 9: Device-user portal

### Objective

Provide a minimal, safe portal for users accessing edge devices from their
assigned laptop VPN clients.

### Required backend endpoints

```http
GET /me
GET /me/clients
GET /me/devices
GET /me/devices/{device_id}
```

These endpoints must derive identity from the validated token and must not
accept an arbitrary user ID.

### Routes

```text
/portal
/portal/clients
/portal/devices
/portal/devices/:deviceId
```

### Feature work

- List only the current user's VPN clients.
- List only explicitly granted devices.
- Show connection and setup instructions.
- Show Authorized and Enforced as distinct states.
- Permit credential download only for an owned client when backend policy
  explicitly allows it.
- Do not expose admin navigation, identity management, or arbitrary user IDs.

### Tests

- current-user data only
- direct navigation to admin routes is forbidden
- another user's client/device cannot be requested successfully
- credential-download authorization and cleanup
- empty portal states for users with no clients or grants

### Exit criteria

- A device user can understand which laptop client and edge device they may use
  without receiving any broader administrative data.

### Notes

Record final user-facing capabilities and intentionally unavailable actions.

## Phase 10: Production integration and E2E hardening

### Objective

Package, serve, secure, and verify the completed SPA in its production shape.

### Deployment work

- Decide whether FastAPI or a reverse proxy serves `frontend/dist`.
- Add SPA history fallback without intercepting API paths.
- Keep the SPA shell, hashed assets, favicon, and Entra redirect path reachable
  before authentication.
- Keep every API path bearer-token protected except narrowly documented hooks.
- Add Content Security Policy and other secure response headers.
- Configure exact Entra redirect URIs for each environment.
- Cache hashed assets; do not long-cache `index.html`.
- Document build, installation, rollback, and environment configuration.

### E2E work

Add a small Playwright suite covering:

- authentication shell and redirect return
- admin navigation
- device create/edit
- user-to-client assignment
- access grant and revoke
- destructive confirmation
- forbidden device-user navigation

Use test-only explicit authentication disablement or a controlled test identity.
Production builds must continue to fail closed.

### Exit criteria

- A production artifact can be built and deployed reproducibly.
- Static and API routing do not conflict.
- Security headers and auth redirects work in the deployed topology.
- Smoke tests pass against a test FastAPI instance.

### Notes

Record the selected serving topology and deployment commands here.

## Cross-phase security rules

Every phase must preserve these rules:

- Treat frontend authorization as presentation only; enforce it in FastAPI.
- Never log or persist access tokens, client secrets, private keys, certificate
  material, SAS URLs, or sensitive download URLs.
- Avoid exposing OAuth subject identifiers outside authorized admin views.
- Do not use `dangerouslySetInnerHTML` for server-provided error content.
- Validate user input in the browser for usability and again at the API boundary.
- Wait for server confirmation before showing access, firewall, certificate, or
  routing mutations as successful.
- Clear sensitive Blob URLs and in-memory download data promptly.
- Keep npm audit free of known vulnerabilities; document any unavoidable and
  demonstrably non-applicable advisory before accepting it.

## Query and mutation conventions

- Keep query hooks under their owning feature.
- Use stable key factories rather than inline string arrays.
- Invalidate the narrowest affected queries after mutations.
- Use optimistic updates only for non-security-sensitive presentation changes.
- Do not optimistically update access grants, certificate state, IP assignment,
  routes, firewall state, or ownership.
- Cancel polling when the page is hidden or the component unmounts.
- Keep pagination, filters, and sort state in the URL when users may share or
  revisit a view.

## Verification required for every phase

Run frontend checks from `frontend/`:

```shell
npm ci
npm audit
npm run lint
npm run typecheck
npm run test
npm run build
```

Run backend checks from the repository root when a phase changes Python or API
contracts:

```shell
ruff format --check .
ruff check .
mypy .
pytest --cov=src/sciaiot/ovpncp --cov-report=term-missing
```

If a repository-wide check fails because of an existing baseline finding,
verify all changed files separately and document the exact baseline failure.
Never declare a phase complete without recording what was and was not verified.

## Completion log

Add one entry when a phase is completed:

```text
YYYY-MM-DD - Phase N completed
Implementation:
- ...
Verification:
- command: result
Deferred:
- ...
```

Do not rewrite earlier completion entries except to correct factual errors.

2026-08-04 - Phase 1 completed
Implementation:
- Added generated OpenAPI types, an authenticated typed fetch client, RFC 7807
  normalization, query keys, TanStack Query defaults/providers, deterministic
  generation checks, and CI/frontend documentation.
- Added explicit backend response models and consistent RFC 7807 responses
  without changing API paths or invoking privileged operations during schema
  generation.
Verification:
- `npm ci && npm audit && npm run api:check && npm run lint && npm run
  typecheck && npm run test && npm run build`: passed; 0 vulnerabilities,
  16 tests passed, and the production build completed.
- repeated `npm run api:generate` with SHA-256 comparison: both generated
  files were byte-for-byte stable.
- `ruff format --check .`: passed for 40 files.
- `ruff check <Phase 1 changed backend files>`: passed.
- `mypy .`: passed for 36 source files.
- `pytest --cov=src/sciaiot/ovpncp --cov-report=term-missing`: 82 passed,
  86% total coverage.
Deferred:
- `ruff check .` retains 31 pre-existing findings in untouched files; the
  TypeScript 6/openapi-typescript peer metadata mismatch and one existing
  Starlette/httpx deprecation warning remain documented above.
- Phase 2 authentication lifecycle and current-principal work.

2026-08-04 - Phase 2 completed
Implementation:
- Added authenticated `GET /me`, exact validated issuer/subject local-user
  mapping, the typed canonical principal/permission contract, post-validation
  application-role checks, secret-safe security errors, and a loopback-peer-only
  OpenVPN hook exception.
- Added MSAL account/redirect lifecycle handling, silent token acquisition with
  one controlled interaction fallback, the typed current-principal query,
  authenticated/unauthenticated/forbidden/configuration layouts, permission-aware
  navigation/routes, intended-route preservation, and frontend state clearing on
  sign-out.
- Regenerated OpenAPI files and synchronized backend/frontend authentication
  documentation.
- Review corrections keep signed-out users stable until explicit login, retain
  the redirect guard until trusted principal resolution, safely handle normalized
  logout failures, return `401` for whitespace-only authorization headers, and
  keep the permission constant immutable.
Verification:
- `npm ci`: passed; 181 packages installed and 0 vulnerabilities reported.
- `npm audit`: passed; 0 vulnerabilities.
- `npm run api:check`: passed; regenerated OpenAPI JSON and TypeScript schema had
  no drift.
- `npm run lint`, `npm run typecheck`, `npm run test`, and `npm run build`:
  passed; 11 test files and 28 tests passed, and the Vite production build
  completed.
- `ruff format --check .`: passed for 40 files.
- `ruff check <Phase 2 changed Python files>`: passed. `ruff check .
  --statistics` retained exactly 31 documented pre-existing findings.
- `mypy .`: passed for 36 source files.
- `pytest --cov=src/sciaiot/ovpncp --cov-report=term-missing`: 91 passed,
  87% total coverage; one existing Starlette/httpx deprecation warning remains.
Deferred:
- A real Entra tenant/browser smoke test requires deployment-specific credentials
  and redirect registration; production deployed-topology E2E remains Phase 10.
- Fine-grained backend policies remain Phase 8. The 31 pre-existing Ruff
  findings, TypeScript 6/openapi-typescript peer metadata mismatch, and existing
  Starlette/httpx deprecation warning remain unchanged.
