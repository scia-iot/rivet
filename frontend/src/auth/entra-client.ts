import {
  BrowserCacheLocation,
  InteractionRequiredAuthError,
  PublicClientApplication,
  type AccountInfo,
  type Configuration,
  type IPublicClientApplication,
} from '@azure/msal-browser'

import {
  apiScopes,
  clientId,
  isAuthenticationDisabled,
  isAuthenticationConfigured,
  isE2EAuthenticationMode,
  tenantId,
} from '@/auth/config'
import { redirectForInteraction } from '@/auth/redirect-coordinator'
import { rootRedirectUri } from '@/auth/redirect-uri'

const msalConfiguration: Configuration = {
  auth: {
    clientId: clientId ?? '',
    authority: `https://login.microsoftonline.com/${tenantId ?? 'common'}`,
    redirectUri: rootRedirectUri(window.location.origin),
    postLogoutRedirectUri: rootRedirectUri(window.location.origin),
  },
  cache: { cacheLocation: BrowserCacheLocation.SessionStorage },
}

export const msalInstance = isAuthenticationConfigured &&
  !isAuthenticationDisabled && !isE2EAuthenticationMode
  ? new PublicClientApplication(msalConfiguration)
  : null

export async function acquireAccessToken(
  instance: IPublicClientApplication,
  accounts: readonly AccountInfo[],
): Promise<string> {
  const account = instance.getActiveAccount() ?? accounts[0]
  if (account === undefined) {
    throw new Error('An authenticated account is required for API requests.')
  }
  try {
    const result = await instance.acquireTokenSilent({ account, scopes: apiScopes })
    return result.accessToken
  } catch (error) {
    if (error instanceof InteractionRequiredAuthError) {
      await redirectForInteraction(instance, account)
      throw new Error('Authentication interaction is required.')
    }
    throw new Error('An access token could not be acquired.')
  }
}

