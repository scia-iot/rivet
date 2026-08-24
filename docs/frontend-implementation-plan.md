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

The frontend now includes device, user, VPN-client, individual-access,
and server/network administration. Fine-grained authorization, the device-user
portal, and production static-file delivery remain pending.

## Phase status

| Phase | Name | Status | Primary dependency |
| --- | --- | --- | --- |
| 0 | Frontend scaffold | completed | None |
| 1 | Typed API and server-state foundation | completed | Stable OpenAPI responses |
| 2 | Authentication and current principal | completed | Backend `GET /me` |
| 3 | Shared UI, forms, and error handling | completed | Phases 1-2 |
| 4 | Device administration | completed | Phase 3 |
| 5 | User and VPN-client administration | completed | Phase 4 |
| 6 | Individual access management | completed | Phase 5 |
| 7 | Server and network administration | completed | Phase 3 |
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

- Added local shadcn-compatible `alert`, `badge`, `button`, `command`, `dialog`,
  `dropdown-menu`, `field`, `input`, `label`, `select`, `separator`, `skeleton`,
  `sonner`, `table`, `tabs`, `textarea`, and `tooltip` primitives. The existing
  Radix-backed new-york approach is preserved with one unified `radix-ui`
  dependency; `cmdk` and `sonner` are the only component-specific additions.
- Added React Hook Form, Zod, and the Hook Form resolvers. `Field` composes
  native required/minimum constraints with associated inline validation, and
  `useLockedSubmit` synchronously blocks duplicate async submissions before a
  React rerender.
- Added domain-neutral `PageHeader`, `ProblemAlert`, `EmptyState`,
  `LoadingTable`, `ConfirmActionDialog`, `EntitySelect`, `StatusBadge`, and
  `CopyButton`. `LoadingTable` exposes a named busy table, headers, rows, and
  cells while separately announcing loading; it does not hide table semantics.
- `ConfirmActionDialog` requires explicit confirmation and an explicit pending
  label, locks repeated actions with a ref, keeps failed dialogs open, moves
  focus inside, and lets Radix restore focus to the trigger. `EntitySelect`
  combines the listed dialog and command primitives rather than adding a
  popover dependency. Tests install deterministic ResizeObserver and scrolling
  stubs before cmdk loads.
- Review corrections give `EntitySelect` explicit `id`, `aria-describedby`, and
  `aria-invalid` trigger props plus a dialog description containing its current
  selection. One global `TooltipProvider` now serves feature content without
  changing authentication, query, or toast ordering. Rejected confirmations are
  tested through retry and explicit close, including focus containment and safe
  errors. All Phase 3 additions remain within 80 columns.
- Mutation completion uses a global Sonner host and a helper that accepts only
  caller-supplied safe success/error text. Correctable field/domain errors stay
  inline. Sonner's component export is separate from non-component helpers.
- The location-keyed route error boundary renders only fixed recovery text and
  resets explicitly; it neither renders exception content nor calls `setState`
  from `componentDidUpdate`. Existing principal forbidden and failure layouts
  now use the same safe problem-alert pattern without exposing backend details.
- No backend or OpenAPI contract changes were required.

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

- Added typed device/client queries and create, update, and delete mutations.
  Successful mutations invalidate both device and client query prefixes. Delete
  marks both prefixes stale without refetching the active deleted-device detail;
  the destination list refetches after the confirmation dialog closes.
- Added accessible list, create, detail, edit, link, replace, unlink, and delete
  workflows. The client picker searches existing clients, excludes clients
  assigned to other devices, and retains the current client while editing.
- Provisioning presentation is derived from the existing contract: no linked
  client is `Not provisioned`, an active linked client is `Provisioned`, and a
  revoked linked client is `Client revoked`. Assignment changes are shown only
  after successful server responses.
- Delete confirmation and detail copy explicitly state that deleting a Device
  neither deletes nor revokes its Client. Failed mutations preserve form or
  detail state and render only fixed, actionable errors.
- No backend list/filter or OpenAPI additions were required. The existing typed
  `GET /devices` and `GET /clients` responses provide the IDs, names,
  assignments, and revocation state needed for local eligibility filtering.
- Focused TDD covered linked and unlinked creation, duplicate and
  whitespace-only names, unknown and concurrently assigned clients,
  replacement, unlinking, missing devices, deletion confirmation, cache
  invalidation, and failed mutation state preservation.
- Verification passed: 13 focused Phase 4 tests; 17 combined dialog/device
  tests; two consecutive full runs with 20 files and 65 tests; lint with zero
  warnings; typecheck; generated API check; production build; npm audit with
  zero vulnerabilities; scoped sensitive-output and line-length review; and
  `git diff --check`.

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

- Added permission-aware user list, create, detail, rename, and delete routes.
  User detail provides Overview, VPN clients, and intentionally informational
  Device access tabs. Issuer and subject are omitted from list and read-only
  presentation, and user deletion or unlinking never deletes or revokes a VPN
  client.
- Added multi-client ownership workflows with unowned-client filtering and
  conflict-safe server confirmation. Ownership mutations invalidate the user,
  assignment, and ownership caches; renames also invalidate the current
  principal so a renamed signed-in administrator is not presented stale.
- Added permission-aware VPN-client list and detail workflows for creation,
  Easy-RSA import, virtual-address assignment and removal, certificate expiry
  and revocation state, renewal, packaging, download, and typed-confirmation
  revocation. Security-sensitive mutations are never optimistic and invalidate
  the narrow affected client, address, user-client, and list caches.
- Certificate download first packages the client, fetches the archive directly
  as `application/zip` with `Cache-Control: no-store`, and uses a temporary Blob
  URL that is revoked immediately after the hidden download anchor is removed.
  No archive, Blob URL, storage URL, or SAS URL enters TanStack Query,
  `localStorage`, `sessionStorage`, logs, or analytics. Azure deployments proxy
  Blob Storage bytes through the API and support cloud-only archives without a
  leftover local ZIP.
- `PUT /clients/{client_name}/package-cert` now returns an empty `204` instead
  of a filesystem-path JSON body. `GET /clients/{client_name}/download-cert`
  now documents and returns binary `application/zip` bytes with `no-store` and
  an attachment filename; Azure no longer returns a JSON SAS URL.
- Client creation, renewal, revocation, import, packaging, local download, and
  Azure upload/download failures now use fixed safe certificate-operation
  errors. Database changes roll back on applicable failures; creation verifies
  Easy-RSA success, renewal rejects empty certificate details, and revocation
  requires both certificate revocation and CRL generation before persistence.
- Virtual-address assignment now returns a fixed `404` for an unknown address
  and `409` when another client owns it. Phase 5 also removed certificate paths,
  storage locations, exception contents, and virtual addresses from affected
  application logs.
- The reviewed lockfile-only advisory update keeps all direct dependencies and
  OpenAPI tooling versions unchanged while resolving
  `@redocly/openapi-core` 1.34.19, `js-yaml` 4.3.1, and `nanoid` 3.3.18.

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

- Added a user-centric Device access tab with authorized-device listing,
  searchable grant selection that excludes existing grants, confirmed revoke,
  accessible loading/empty/error states, and permission-aware presentation.
- Added `useUserDevices`, `useGrantDeviceAccess`, and
  `useRevokeDeviceAccess` with stable user-device keys, exact affected-query
  invalidation after backend confirmation, and no optimistic access updates.
- `Authorized` explicitly means an AccessGrant exists. `Enforced` is shown as
  `Not enforced`; the UI explains that grants do not apply OpenVPN or firewall
  policy and do not confirm connectivity.
- Enforcement remains deferred. No RestrictedNetwork, route, firewall,
  OpenVPN, reconciliation-state, or privileged-operation behavior was added.
- The existing backend/API contract already supports idempotent grant, device
  listing, revoke, and safe not-found behavior, so no application Python or
  OpenAPI contract change was required. Added characterization coverage for
  missing users, devices, and grants.

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

- OpenVPN health polls every 15 seconds only while the document is visible.
  Polling stops when the page is hidden or unmounted and resumes with an
  immediate refresh when visibility returns. Inactive states use negative
  presentation, and a failed refresh keeps the last report visible with a
  fixed, actionable stale-data warning and retry.
- Added permission-aware `/server`, `/server/routes`, `/networks`, and
  `/networks/:networkId` workflows. Server and restricted-network pages are
  lazy-loaded as separate production chunks.
- Server presentation includes service health, a deliberately limited
  configuration summary, and assignable virtual addresses. Certificate/key
  paths and other security-sensitive configuration values are not rendered.
- Route additions/removals, server initialization, restricted-network
  creation, and active-network closure all require explicit confirmation.
  Mutations never update privileged state optimistically; current data remains
  visible after failures and is invalidated only after backend confirmation.
- Browser and backend validation accept only canonical RFC 1918 IPv4
  values. A shared typed backend helper rejects loopback, link-local,
  documentation, public, IPv6, and host-bit-bearing CIDRs before route,
  firewall, or OpenVPN operations.
- Restricted-network creation rejects identical source and destination clients
  at the backend boundary before client lookup or privileged operations.
- `GET /networks` now lists all records by default while retaining its optional
  source filter. Closing an already-ended record is idempotent, route deletion
  matches the exact route destination, and privileged command failures return
  fixed actionable RFC 7807 details without exposing IPs or exception content
  in logs or responses.
- Firewall/OpenVPN/route operations were mocked in automated tests. No real
  host route, firewall, VPN service, or client configuration was changed.

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

2026-08-04 - Phase 3 completed
Implementation:
- Added the planned form stack and local shadcn-compatible UI primitives using
  the existing Radix-backed new-york approach, one unified `radix-ui` package,
  and only the required `cmdk` and `sonner` component dependencies.
- Added all eight domain-neutral shared components, accessible native and inline
  form validation, synchronous duplicate-submit locking, explicit destructive
  confirmation, searchable entity selection, safe copy feedback, standardized
  loading/empty/stale/forbidden/failure states, and safe mutation toasts.
- Added a location-keyed route error boundary with fixed-text recovery. All
  Phase 2 authentication/session behavior is preserved, and existing principal
  forbidden/failure presentation is standardized without exposing backend
  details.
- Review corrections added global tooltip context, stable EntitySelect form
  association and dialog descriptions, destructive-rejection retry coverage,
  and repository-compliant line wrapping without changing dependencies.
Verification:
- Focused incremental TDD captured the intended missing-component and behavior
  failures. The final review-focused command passed 9 test files and 29 tests;
  dialogs/entity selection finished with 6 tests and provider integration added
  1 test.
- `npm ci`: passed; 258 packages installed, 259 audited, and 0 vulnerabilities.
- `npm audit`: passed; 0 vulnerabilities.
- `npm run api:check`: passed; OpenAPI JSON and generated TypeScript had no
  drift.
- `npm run lint`: passed with zero warnings.
- `npm run typecheck`: passed.
- `npm run test`: passed; 18 test files and 52 tests.
- `npm run build`: passed; Vite transformed 2,176 modules and produced the
  production bundle.
- `git diff --check`: passed. A scoped security scan found no unsafe HTML APIs,
  console logging, persistent browser storage, sensitive tokens, OAuth subjects,
  SAS URLs, or private-key handling in changed application paths. Tests confirm
  server problem text renders literally and unexpected errors do not render
  exception content.
Deferred:
- Frontend coverage instrumentation is not configured:
  `npm ls @vitest/coverage-v8 --depth=0` returned `(empty)`. No coverage
  dependency was added solely for this phase; focused and full behavioral tests
  provide the recorded verification.
- Domain feature pages will adopt these shared patterns in their owning phases.
  No backend checks were run because Phase 3 changed no Python or API contract.

2026-08-06 - Phase 4 completed
Implementation:
- Added typed Device API hooks and all four planned routes with sysadmin
  permission presentation, accessible loading/empty/failure states, and complete
  list, create, detail, edit, and delete workflows.
- Added React Hook Form and Zod device forms supporting nullable client links,
  searchable eligible-client selection, link/replace/unlink operations, and
  correctable domain errors without optimistic assignment changes.
- Derived provisioning state from nullable assignment and client revocation,
  invalidated device/client caches after every successful mutation, and delayed
  delete refetch/navigation until the confirmation focus lifecycle completes.
- Strengthened existing EntitySelect tests so open dialogs close explicitly and
  deferred Radix focus restoration completes before jsdom teardown.
Verification:
- `npm test -- --run src/features/devices/device-api.test.tsx
  src/features/devices/device-pages.test.tsx`: passed; 2 files and 13 tests.
- `npm test -- --run src/components/shared/dialog-and-select.test.tsx
  src/features/devices/device-pages.test.tsx`: passed; 2 files and 17 tests.
- `npm test`: passed twice consecutively; each run completed 20 files and 65
  tests without unhandled errors.
- `npm run lint`: passed with zero warnings.
- `npm run typecheck`: passed.
- `npm run api:check`: passed; generated OpenAPI JSON and TypeScript had no
  drift.
- `npm run build`: passed; Vite transformed 2,277 modules and produced the
  production bundle.
- `npm audit`: passed with zero vulnerabilities.
- `git diff --check`, scoped line-length inspection, and scoped sensitive-output
  scan: passed.
Deferred:
- Vite retains its advisory that the main minified chunk exceeds 500 kB;
  broader route-level code splitting remains production hardening work.
- No backend, Python, database, privileged system, VPN, firewall, cloud, or API
  contract changes were made, so backend quality gates were not applicable.

2026-08-24 - Phase 5 completed
Implementation:
- Added permission-aware user list, create, detail, rename, and delete routes;
  external-identity presentation controls; Overview, VPN clients, and Device
  access tabs; multi-client ownership; conflict handling; and cache invalidation
  without deleting or revoking clients during unlink or user deletion.
- Added permission-aware VPN-client list and detail routes with creation,
  Easy-RSA import, virtual-address assignment and removal, certificate state and
  expiry, renewal, packaging, direct download, and typed-confirmation revocation.
- Changed packaging to an empty `204` and download to no-store binary ZIP bytes.
  Azure storage now proxies bytes without SAS URLs and supports cloud-only
  archives. Certificate boundaries return fixed safe failures and roll back
  applicable database work; affected logs no longer expose paths, addresses,
  storage locations, or exception contents.
- Regenerated the OpenAPI contract and updated frontend documentation. Updated
  only reviewed vulnerable transitive lockfile resolutions:
  `@redocly/openapi-core` 1.34.19, `js-yaml` 4.3.1, and `nanoid` 3.3.18.
Verification:
- `npm test -- --run src/features/users/user-pages.test.tsx
  src/features/clients/client-pages.test.tsx`: passed; 2 files and 19 tests.
- `npm ci`: passed; 258 packages installed and 259 audited with 0
  vulnerabilities. `npm audit`: passed with 0 vulnerabilities.
- `npm run api:check`, `npm run lint`, and `npm run typecheck`: passed; generated
  OpenAPI JSON and TypeScript declarations had no drift and direct tool versions
  remained compatible with the patched transitive graph.
- `npm run test`: passed; 22 files and 84 tests. `npm run build`: passed; Vite
  transformed 2,284 modules and produced the production bundle.
- `pytest -q tests/test_identity_api.py tests/test_api.py tests/test_openvpn.py
  tests/test_azure_storage.py`: passed; 72 focused tests.
- `ruff format --check .`: passed for 41 files. `ruff check` passed for every
  Phase 5-touched Python and test file. Repository-wide `ruff check .` retains
  exactly 21 pre-existing findings outside Phase 5 scope.
- `mypy .`: passed for 37 source files.
- `pytest --cov=src/sciaiot/ovpncp --cov-report=term-missing`: 109 passed with
  90% total coverage and one existing Starlette/httpx deprecation warning.
- `git diff --check` and the scoped sensitive-output review passed. Azure,
  OpenVPN, filesystem, and privileged operations were mocked in focused tests;
  no real cloud, VPN, firewall, route, or certificate store was changed.
Deferred:
- Device-access grant management remains Phase 6; the current tab explicitly
  avoids presenting application grants as enforced network access.
- Fine-grained backend authorization remains Phase 8, and deployed Entra/Azure
  browser smoke testing plus production topology E2E remains Phase 10.
- The existing Vite main-chunk size advisory, 21 untouched repository Ruff
  findings, and Starlette/httpx deprecation warning remain unchanged.

2026-08-24 - Phase 6 completed
Implementation:
- Added the primary user-centric Device access workflow with an authorized
  device table, searchable eligible-device selector, confirmed revoke actions,
  safe failures, and `access:read` versus `access:grant` presentation.
- Added typed access query/mutation hooks with stable keys, exact invalidation,
  backend-confirmed refreshes, and no optimistic security-state changes.
- Presented AccessGrant records as application authorization only. `Authorized`
  and `Not enforced` remain distinct, with explicit OpenVPN, firewall, and
  connectivity limitations in the UI and frontend documentation.
- Added frontend and backend characterization coverage for idempotent grant,
  successful and missing revoke, missing users/devices, failed-state
  preservation, filtering, accessibility, permissions, and narrow cache
  invalidation. No backend or OpenAPI contract change was required.
Verification:
- `npm test -- --run src/features/users/user-pages.test.tsx
  src/features/access/access-api.test.tsx src/features/devices/device-api.test.tsx
  src/api/query-keys.test.ts`: passed; 4 files and 20 tests.
- `npm ci`: passed; 258 packages installed and 259 audited. `npm audit` passed
  with 0 vulnerabilities.
- `npm run api:check`, `npm run lint`, and `npm run typecheck`: passed; generated
  OpenAPI JSON and TypeScript declarations had no drift.
- `npm run test`: passed; 23 files and 91 tests. `npm run build`: passed; Vite
  transformed 2,286 modules and produced the production bundle.
- `ruff format --check .`: passed for 41 files. `ruff check
  tests/test_identity_api.py`: passed. Repository-wide `ruff check .` retains
  exactly 21 pre-existing findings outside Phase 6 scope.
- `mypy .`: passed for 37 source files.
- `pytest --cov=src/sciaiot/ovpncp --cov-report=term-missing`: 110 passed with
  91% total coverage and one existing Starlette/httpx deprecation warning.
- `git diff --check` and the scoped sensitive-output/security review passed. No
  cloud, VPN, firewall, route, network, or certificate operation was invoked.
Deferred:
- AccessGrant enforcement remains deferred; no OpenVPN/firewall policy,
  RestrictedNetwork, reconciliation state, or connectivity guarantee exists.
- Fine-grained backend authorization remains Phase 8, and deployed browser/E2E
  verification remains Phase 10.
- The existing Vite main-chunk size advisory, 21 untouched repository Ruff
  findings, and Starlette/httpx deprecation warning remain unchanged.

2026-08-24 - Phase 7 completed
Implementation:
- Added permission-aware server health/configuration/address administration,
  confirmed route changes, restricted-network list/create/detail/close flows,
  stable typed hooks, visibility-aware polling, and private IPv4 validation.
- Added safe backend boundaries for route and firewall command failures,
  optional all-network retrieval, exact route matching, shared canonical RFC
  1918 validation, distinct-client enforcement, transaction rollback, and
  idempotent already-ended closure.
- Corrected inactive health classification and made cached health refresh
  failures visible through a fixed stale-data warning and retry without
  exposing backend error content.
- Regenerated the OpenAPI contract and kept diagnostics free of sensitive IP
  and host-command details outside authorized data fields.
Verification:
- `npm ci`: passed; 258 packages installed and 259 audited. `npm audit` passed
  with 0 vulnerabilities.
- `npm run api:check`, `npm run lint`, and `npm run typecheck`: passed;
  generated OpenAPI files were reproducible and frontend code was lint/type
  clean.
- Focused Phase 7 frontend suites passed 21 tests. `npm run test` passed 27
  files and 113 tests. `npm run build` passed with 2,292 transformed modules
  and separate server/network page chunks.
- `pytest -q tests/test_network_validation.py tests/test_api.py -x`:
  passed; 60 focused backend tests.
- `ruff format --check .`, `ruff check .`, and `mypy .`: passed for the full
  repository.
- `pytest --cov=src/sciaiot/ovpncp --cov-report=term-missing`: 138 passed with
  90% total coverage; changed `utils/network.py` reached 100%,
  `routes/network.py` reached 96%, and `routes/server.py` reached 87%.
- `git diff --check` and scoped sensitive-output/line-length review passed.
  Privileged system operations were mocked; no external system was altered.
Deferred:
- Real-host route/firewall/OpenVPN smoke testing requires an isolated privileged
  deployment and remains manual. Multi-command firewall/client-route changes
  cannot be atomic across host tools and the database; operators should
  reconcile host state after an interrupted partial system change.
- Frontend coverage instrumentation remains unavailable. Fine-grained backend
  authorization is Phase 8, and deployed browser/E2E verification is Phase 10.
