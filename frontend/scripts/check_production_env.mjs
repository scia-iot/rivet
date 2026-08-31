import { pathToFileURL } from 'node:url'

import { loadEnv } from 'vite'

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

const PRODUCTION_ENVIRONMENT_KEYS = new Set([
  'VITE_API_BASE_URL',
  'VITE_AUTH_DISABLED',
  'VITE_ENTRA_API_SCOPE',
  'VITE_ENTRA_CLIENT_ID',
  'VITE_ENTRA_TENANT_ID',
])

function isConcreteScope(value) {
  if (
    typeof value !== 'string' ||
    value.includes('<') ||
    value.includes('>') ||
    /\s/.test(value)
  ) {
    return false
  }
  try {
    const scope = new URL(value)
    return (
      (scope.protocol === 'api:' || scope.protocol === 'https:') &&
      scope.hostname.length > 0 &&
      scope.pathname.length > 1
    )
  } catch {
    return false
  }
}

export function validateProductionEnvironment(environment) {
  const failures = []
  const tenantId = environment.VITE_ENTRA_TENANT_ID?.trim()
  const clientId = environment.VITE_ENTRA_CLIENT_ID?.trim()
  const apiScope = environment.VITE_ENTRA_API_SCOPE?.trim()

  for (const key of Object.keys(environment).sort()) {
    if (key.startsWith('VITE_') && !PRODUCTION_ENVIRONMENT_KEYS.has(key)) {
      failures.push(`${key} is not allowed in production`)
    }
  }

  if (environment.VITE_AUTH_DISABLED !== 'false') {
    failures.push('VITE_AUTH_DISABLED must be false')
  }
  if (environment.VITE_API_BASE_URL !== '/api') {
    failures.push('VITE_API_BASE_URL must be /api')
  }
  if (!UUID_PATTERN.test(tenantId ?? '')) {
    failures.push('VITE_ENTRA_TENANT_ID must be a UUID')
  }
  if (!UUID_PATTERN.test(clientId ?? '')) {
    failures.push('VITE_ENTRA_CLIENT_ID must be a UUID')
  }
  if (!apiScope) {
    failures.push('VITE_ENTRA_API_SCOPE must be configured')
  } else if (!isConcreteScope(apiScope)) {
    failures.push(
      'VITE_ENTRA_API_SCOPE must be a concrete api:// or https:// scope',
    )
  }
  return failures
}

async function main() {
  const environment = loadEnv('production', process.cwd(), 'VITE_')
  const failures = validateProductionEnvironment(environment)
  if (failures.length === 0) {
    process.stdout.write('Production frontend configuration is valid.\n')
    return
  }

  process.stderr.write('Production frontend configuration is invalid:\n')
  for (const failure of failures) {
    process.stderr.write(`- ${failure}\n`)
  }
  process.exitCode = 1
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  await main()
}
