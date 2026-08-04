import {
  BrowserCacheLocation,
  PublicClientApplication,
  type Configuration,
  type RedirectRequest,
} from '@azure/msal-browser'

const tenantId = import.meta.env.VITE_ENTRA_TENANT_ID?.trim()
const clientId = import.meta.env.VITE_ENTRA_CLIENT_ID?.trim()
const apiScope = import.meta.env.VITE_ENTRA_API_SCOPE?.trim()

export const isAuthenticationDisabled =
  import.meta.env.VITE_AUTH_DISABLED === 'true'

export const isAuthenticationConfigured = Boolean(
  tenantId && clientId && apiScope,
)

export const apiScopes = apiScope ? [apiScope] : []

const msalConfiguration: Configuration = {
  auth: {
    clientId: clientId ?? '',
    authority: `https://login.microsoftonline.com/${tenantId ?? 'common'}`,
    redirectUri: window.location.origin,
    postLogoutRedirectUri: window.location.origin,
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
