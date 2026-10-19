import { afterEach, describe, expect, it, vi } from 'vitest'

const runtime = {
  tenantId: '11111111-1111-1111-1111-111111111111',
  clientId: '22222222-2222-2222-2222-222222222222',
  apiScope: 'api://runtime-api/access',
}

afterEach(() => {
  delete window.__RIVET_CONFIG__
  vi.unstubAllEnvs()
  vi.resetModules()
})

describe('runtime authentication configuration', () => {
  it('uses runtime values and prevents build-time bypass and API overrides', async () => {
    window.__RIVET_CONFIG__ = runtime
    vi.stubEnv('VITE_AUTH_DISABLED', 'true')
    vi.stubEnv('VITE_ENTRA_API_SCOPE', 'api://build-api/access')
    vi.stubEnv('VITE_API_BASE_URL', 'https://other.example/api')
    vi.stubEnv('VITE_E2E_AUTH_MODE', 'true')
    vi.stubEnv('VITE_E2E_ACCESS_TOKEN', 'controlled-test-token')
    vi.stubEnv('MODE', 'e2e')
    const config = await import('./config')
    expect(config.isAuthenticationDisabled).toBe(false)
    expect(config.isE2EAuthenticationMode).toBe(false)
    expect(config.e2eAccessToken).toBeNull()
    expect(config.apiScopes).toEqual([runtime.apiScope])
    const { msalInstance } = await import('./entra-client')
    expect(msalInstance?.getConfiguration().auth.clientId).toBe(runtime.clientId)
    expect(msalInstance?.getConfiguration().auth.authority).toBe(
      `https://login.microsoftonline.com/${runtime.tenantId}`,
    )
    expect((await import('@/api/client')).apiBaseUrl).toBe('/api')
  })

  it.each([
    undefined, null, {}, 'invalid',
    { ...runtime, tenantId: 'common' },
    { ...runtime, tenantId: `${runtime.tenantId}\n` },
    { ...runtime, apiScope: `${runtime.apiScope}\n` },
    { ...runtime, clientId: 'invalid' },
    { ...runtime, apiScope: 'https://host/path?secret=value' },
    { ...runtime, apiScope: 'api://host/' },
    { ...runtime, apiScope: `api://host/${'a'.repeat(2048)}` },
    { ...runtime, authDisabled: true },
    { ...runtime, provider: '' },
    { ...runtime, provider: 'keycloak' },
    { ...runtime, provider: 'ENTRA' },
    { ...runtime, provider: 'entra', extra: 'ignored' },
  ])('fails closed for invalid runtime configuration %#', async (value) => {
    vi.stubEnv('VITE_RUNTIME_CONFIG', 'true')
    vi.stubEnv('VITE_AUTH_DISABLED', 'true')
    vi.stubEnv('VITE_ENTRA_TENANT_ID', runtime.tenantId)
    vi.stubEnv('VITE_ENTRA_CLIENT_ID', runtime.clientId)
    vi.stubEnv('VITE_ENTRA_API_SCOPE', runtime.apiScope)
    window.__RIVET_CONFIG__ = value
    const config = await import('./config')
    expect(config.isAuthenticationDisabled).toBe(false)
    expect(config.isAuthenticationConfigured).toBe(false)
    expect(config.apiScopes).toEqual([])
    expect((await import('./entra-client')).msalInstance).toBeNull()
  })

  it('rejects malformed runtime data without falling back to local bypass', async () => {
    window.__RIVET_CONFIG__ = null
    vi.stubEnv('VITE_AUTH_DISABLED', 'true')
    const config = await import('./config')
    expect(config.isAuthenticationDisabled).toBe(false)
    expect((await import('./entra-client')).msalInstance).toBeNull()
  })

  it('preserves explicit local development configuration without runtime data', async () => {
    vi.stubEnv('VITE_AUTH_DISABLED', 'true')
    const config = await import('./config')
    expect(config.isAuthenticationDisabled).toBe(true)
  })

  it.each([runtime, { ...runtime, provider: 'entra' }])(
    'accepts legacy and provider-tagged runtime configuration %#', async (value) => {
      window.__RIVET_CONFIG__ = value
      const config = await import('./config')
      expect(config.isAuthenticationConfigured).toBe(true)
      expect((await import('@/runtime-config')).runtimeConfiguration).toEqual({
        ...runtime, provider: 'entra',
      })
    },
  )

  it('does not construct MSAL for disabled local authentication', async () => {
    vi.stubEnv('VITE_AUTH_DISABLED', 'true')
    vi.stubEnv('VITE_ENTRA_TENANT_ID', runtime.tenantId)
    vi.stubEnv('VITE_ENTRA_CLIENT_ID', runtime.clientId)
    vi.stubEnv('VITE_ENTRA_API_SCOPE', runtime.apiScope)
    expect((await import('./entra-client')).msalInstance).toBeNull()
  })

  it.each(['', 'keycloak', 'ENTRA'])(
    'rejects an unsupported build-time provider %s', async (provider) => {
      vi.stubEnv('VITE_AUTH_PROVIDER', provider)
      vi.stubEnv('VITE_ENTRA_TENANT_ID', runtime.tenantId)
      vi.stubEnv('VITE_ENTRA_CLIENT_ID', runtime.clientId)
      vi.stubEnv('VITE_ENTRA_API_SCOPE', runtime.apiScope)
      expect((await import('./config')).isAuthenticationConfigured).toBe(false)
      expect((await import('./entra-client')).msalInstance).toBeNull()
    },
  )
})
