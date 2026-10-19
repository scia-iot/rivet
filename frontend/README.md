# Rivet frontend

The browser UI manages devices, users, VPN clients, access grants, server
settings, and restricted networks, and provides the device-user portal.
FastAPI remains the authorization boundary. End-user procedures are in the
[user guide](../docs/user-guide.md); identity and shared-profile behavior are
in [configuration](../docs/configuration.md).

## Stack and source layout

The implementation uses React 19, TypeScript 5.9.3, Vite 8, React Router,
TanStack Query, MSAL, React Hook Form/Zod, Tailwind, and local Radix/shadcn-style
components. [package.json](package.json) and [package-lock.json](package-lock.json)
are the dependency source of truth. TypeScript satisfies the OpenAPI generator's
peer range; `.npmrc` does not permit bypassing peer resolution.

| Directory | Responsibility |
| --- | --- |
| `src/api` | Generated schema, authenticated client, problems, query keys, downloads |
| `src/app` | Providers, query client, error boundary |
| `src/auth` | Browser authentication context, Entra adapter, principal session, permission presentation |
| `src/features` | Domain API hooks, forms, and pages |
| `src/components/shared` | Reusable forms, status/error/loading states, dialogs |
| `src/components/ui` | Local UI primitives |
| `src/test`, `e2e` | Unit setup and isolated browser test identity/API |

The API client acquires bearer tokens and normalizes RFC 7807 errors. The
principal comes from `/me`; the UI does not assign roles by decoding unverified
claims. Permission-based navigation is presentation, never authorization.
Portal calls derive ownership from the authenticated principal and do not send
a user ID. An AccessGrant is distinct from VPN traffic enforcement.

Authentication gates, account controls, and API access consume
`BrowserAuthentication`. Only the Entra adapter owns MSAL account selection,
token refresh, and redirect coordination. It preserves the session token cache,
redirect-loop guard, and query-cache cleanup on sign-out. Add future providers
behind this boundary; application components must not import MSAL hooks.

Feature hooks own explicit query keys and mutation invalidation. Keep domain
behavior out of generic components. Credential downloads use no-store Blobs
with prompt object-URL cleanup, never local storage. Do not log tokens,
credential contents, private API responses, or sensitive resource details.

## Development

From this directory:

```bash
npm ci --ignore-scripts --no-audit --no-fund --legacy-peer-deps=false
cp .env.example .env.local
npm run dev
```

Follow [local development](../docs/deployment.md#local-development) for public `VITE_*`
settings, Entra registrations, an agent-backed API, or UI-only mode. The
dev proxy forwards `/api` to the loopback API. The controlled E2E runner is
the supported way to exercise complete deterministic flows without real VPN
services or an Entra tenant.

## Generated API contract

When an API response changes, regenerate and review both checked-in artifacts:

```bash
npm run api:generate
npm run api:check
```

`scripts/export_openapi.py` imports the app without starting its lifespan;
`openapi-typescript` creates `src/api/generated/schema.d.ts` from `openapi.json`.
`api:check` regenerates and rejects drift. Run it with the repository's Python
development dependencies installed. Never hand-edit the generated schema to
hide a backend/frontend mismatch.

## Deployment builds

Use `npm run build:runtime` (alias `build:container`) for native and container
deployment. It ignores dotenv and build-time `VITE_*` values, fixes `/api`,
and requires authentication. Supply the validated public Entra settings through
`window.__RIVET_CONFIG__` in `/runtime-config.js`; see
[configuration](../docs/configuration.md#browser-configuration).
Runtime payloads include `provider: 'entra'`; legacy payloads containing only
`tenantId`, `clientId`, and `apiScope` remain accepted. Unknown providers or
invalid runtime configuration block authentication without falling back to
build settings. `RIVET_UI_AUTH_PROVIDER` selects the renderer's provider;
Entra is the only supported value.

The optional `npm run build:production` mode reads reviewed public settings
from `.env.production.local`. Its guard requires authentication, concrete
Entra identifiers, and a same-origin API base. These assets must be rebuilt
when the embedded settings change; runtime builds avoid that requirement.
If supplied, `VITE_AUTH_PROVIDER` must be `entra`. Development/E2E authentication
modes remain excluded from production runtime deployments.

Serve static output from a root-owned release separate from API-writable
state, through the supplied Nginx boundary and a deployment-owned HTTPS
gateway. See [native deployment](../docs/deployment.md#native-installation) or
[container deployment](../docs/deployment.md#container-deployment). No TLS key, private
credential, or cloud identity belongs in the browser bundle.

## Verification

```bash
npm audit
npm run api:check
npm run lint
npm run typecheck
npm run test
npm run test:production
npm run build:runtime
npx playwright install chromium
CI=true npm run test:e2e
CI=true npm run test:container
```

The E2E suite checks sign-in/redirect behavior, admin workflows, client address
assignment, grants, portal denial, and proxy requests against a controlled
loopback API. The test identity exists only in explicitly opted-in Vite
development `e2e` mode. It is absent from production, built `e2e`, and runtime
assets. `test:container` includes the production-auth guard and browser checks
for missing/invalid settings and two different runtime configurations using
one build. Provider requests are mocked; these tests do not prove real sign-in.

After deployment, set `RIVET_BASE_URL` and run `npm run smoke:production`.
It checks static fallback, caching, security headers, and unauthenticated API
denial without printing response bodies. Real login, API authorization, and
VPN traffic still require deployment acceptance.
