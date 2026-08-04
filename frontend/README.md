# ovpncp frontend

Frontend scaffold for the OpenVPN control panel. Detailed domain workflows are
intentionally deferred. Implement them phase by phase using the
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
set `VITE_AUTH_DISABLED=true`. Vite proxies `/api/*` to
`http://127.0.0.1:8000/*` during local
development.

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
npm run api:check
npm run lint
npm run typecheck
npm run test
npm run build
```

Use `npx shadcn@latest add <component>` from this directory when another local
UI primitive is needed. Components under `src/components/ui/` are application
source and should be reviewed like any other code.
