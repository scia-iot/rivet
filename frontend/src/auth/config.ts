import {
  BrowserCacheLocation,
  PublicClientApplication,
  type Configuration,
  type RedirectRequest,
} from '@azure/msal-browser'

import { runtimeConfiguration, usesRuntimeConfiguration } from '@/runtime-config'
import { rootRedirectUri } from '@/auth/redirect-uri'
import { allowsE2EAuthenticationMode } from '@/test/e2e-auth-mode'

const tenantId = usesRuntimeConfiguration
  ? runtimeConfiguration?.tenantId
  : import.meta.env.VITE_ENTRA_TENANT_ID?.trim()
const clientId = usesRuntimeConfiguration
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
  tenantId && clientId && apiScope,
)

export const apiScopes = apiScope ? [apiScope] : []

const msalConfiguration: Configuration = {
  auth: {
    clientId: clientId ?? '',
    authority: `https://login.microsoftonline.com/${tenantId ?? 'common'}`,
    redirectUri: rootRedirectUri(window.location.origin),
    postLogoutRedirectUri: rootRedirectUri(window.location.origin),
  },
  cache: {
    cacheLocation: BrowserCacheLocation.SessionStorage,
  },
}

export const loginRequest: RedirectRequest = {
  scopes: apiScopes,
}

export const msalInstance =
  !isAuthenticationDisabled && isAuthenticationConfigured
    ? new PublicClientApplication(msalConfiguration)
    : null
