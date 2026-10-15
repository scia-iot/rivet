import { runtimeConfiguration, usesRuntimeConfiguration } from '@/runtime-config'
import { allowsE2EAuthenticationMode } from '@/test/e2e-auth-mode'

export const tenantId = usesRuntimeConfiguration
  ? runtimeConfiguration?.tenantId
  : import.meta.env.VITE_ENTRA_TENANT_ID?.trim()
export const clientId = usesRuntimeConfiguration
  ? runtimeConfiguration?.clientId
  : import.meta.env.VITE_ENTRA_CLIENT_ID?.trim()
const apiScope = usesRuntimeConfiguration
  ? runtimeConfiguration?.apiScope
  : import.meta.env.VITE_ENTRA_API_SCOPE?.trim()

export const isAuthenticationDisabled =
  !usesRuntimeConfiguration && import.meta.env.VITE_AUTH_DISABLED === 'true'

const configuredE2EAccessToken = import.meta.env.DEV && !usesRuntimeConfiguration
  ? import.meta.env.VITE_E2E_ACCESS_TOKEN?.trim() || null
  : null

export const isE2EAuthenticationMode = import.meta.env.DEV && !usesRuntimeConfiguration
  ? allowsE2EAuthenticationMode({
      accessToken: configuredE2EAccessToken ?? undefined,
      development: true,
      mode: import.meta.env.MODE,
      requested: import.meta.env.VITE_E2E_AUTH_MODE,
    })
  : false

export const e2eAccessToken = isE2EAuthenticationMode
  ? configuredE2EAccessToken
  : null

export const isAuthenticationConfigured = Boolean(
  tenantId && clientId && apiScope &&
  (usesRuntimeConfiguration ||
    import.meta.env.VITE_AUTH_PROVIDER === undefined ||
    import.meta.env.VITE_AUTH_PROVIDER === 'entra') &&
  (!usesRuntimeConfiguration || runtimeConfiguration?.provider === 'entra'),
)

export const apiScopes = apiScope ? [apiScope] : []
