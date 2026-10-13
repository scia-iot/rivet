import { pathToFileURL } from 'node:url'

const REQUIRED_HEADERS = [
  ['content-security-policy', "default-src 'self'"],
  ['content-security-policy', "frame-ancestors 'none'"],
  ['cross-origin-opener-policy', 'same-origin-allow-popups'],
  ['cross-origin-resource-policy', 'same-origin'],
  ['permissions-policy', 'camera=()'],
  ['referrer-policy', 'no-referrer'],
  ['strict-transport-security', 'max-age=31536000'],
  ['x-content-type-options', 'nosniff'],
  ['x-frame-options', 'DENY'],
]

function deploymentOrigin(value) {
  let url
  try {
    url = new URL(value)
  } catch {
    throw new Error('RIVET_BASE_URL must be a valid HTTPS origin.')
  }
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.pathname !== '/' ||
    url.search ||
    url.hash
  ) {
    throw new Error('RIVET_BASE_URL must be a valid HTTPS origin.')
  }
  return url
}

async function safeFetch(fetchImplementation, origin, path, label) {
  try {
    return await fetchImplementation(new URL(path, origin))
  } catch {
    throw new Error(`${label} request failed.`)
  }
}

function requireStatus(response, status, label) {
  if (response.status !== status) {
    throw new Error(`${label} returned an unexpected status.`)
  }
}

function requireContentType(response, expected, label) {
  const contentType = response.headers.get('content-type') ?? ''
  if (!contentType.toLowerCase().includes(expected)) {
    throw new Error(`${label} returned an unexpected content type.`)
  }
}

function requireSecurityHeaders(response, label) {
  for (const [name, expected] of REQUIRED_HEADERS) {
    const value = response.headers.get(name) ?? ''
    if (!value.includes(expected)) {
      throw new Error(`${label} is missing a required header.`)
    }
  }
}

function requireCachePolicy(response, expected, label) {
  const cacheControl = response.headers.get('cache-control') ?? ''
  if (!cacheControl.includes(expected)) {
    throw new Error(`${label} returned an unsafe cache policy.`)
  }
}

async function requireShell(fetchImplementation, origin, path, label) {
  const response = await safeFetch(
    fetchImplementation,
    origin,
    path,
    label,
  )
  requireStatus(response, 200, label)
  requireContentType(response, 'text/html', label)
  requireSecurityHeaders(response, label)
  requireCachePolicy(response, 'no-store', label)
  const content = await response.text()
  if (!content.includes('<div id="root"></div>')) {
    throw new Error(`${label} did not return the application shell.`)
  }
  return content
}

function firstFingerprintAsset(shell) {
  const match = shell.match(
    /(?:href|src)=["'](\/assets\/[^"'?]+)["']/,
  )
  if (match === null) {
    throw new Error('Root shell did not reference a fingerprinted asset.')
  }
  return match[1]
}

export async function smokeProductionDeployment(
  baseUrl,
  fetchImplementation = globalThis.fetch,
) {
  const origin = deploymentOrigin(baseUrl)
  const shell = await requireShell(
    fetchImplementation,
    origin,
    '/',
    'Root shell',
  )
  await requireShell(
    fetchImplementation,
    origin,
    '/?code=phase10-placeholder&state=phase10-placeholder',
    'Authentication return shell',
  )
  await requireShell(
    fetchImplementation,
    origin,
    '/portal/devices/123',
    'SPA history fallback',
  )

  const favicon = await safeFetch(
    fetchImplementation,
    origin,
    '/favicon.svg',
    'Favicon',
  )
  requireStatus(favicon, 200, 'Favicon')
  requireContentType(favicon, 'image/svg+xml', 'Favicon')
  requireSecurityHeaders(favicon, 'Favicon')
  requireCachePolicy(favicon, 'max-age=3600', 'Favicon')

  const asset = await safeFetch(
    fetchImplementation,
    origin,
    firstFingerprintAsset(shell),
    'Fingerprint asset',
  )
  requireStatus(asset, 200, 'Fingerprint asset')
  requireSecurityHeaders(asset, 'Fingerprint asset')
  requireCachePolicy(
    asset,
    'max-age=31536000, immutable',
    'Fingerprint asset',
  )

  const api = await safeFetch(
    fetchImplementation,
    origin,
    '/api/me',
    'Protected API',
  )
  requireStatus(api, 401, 'Protected API')
  requireContentType(api, 'application/problem+json', 'Protected API')
  requireSecurityHeaders(api, 'Protected API')
  requireCachePolicy(api, 'no-store', 'Protected API')
  try {
    const problem = await api.json()
    if (problem.status !== 401) {
      throw new Error()
    }
  } catch {
    throw new Error('Protected API did not return a valid problem response.')
  }
}

async function main() {
  try {
    await smokeProductionDeployment(process.env.RIVET_BASE_URL ?? '')
    process.stdout.write('Production deployment smoke checks passed.\n')
  } catch (error) {
    const message =
      error instanceof Error ? error.message : 'Production smoke check failed.'
    process.stderr.write(`${message}\n`)
    process.exitCode = 1
  }
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  await main()
}
